"""Throwaway bounded forward experiment; no model/checkpoint files are changed."""
import sys,json,time,inspect,textwrap,statistics,resource,importlib.util,types,random
from pathlib import Path
sys.path.insert(0,str(Path('perf-next/src').resolve()))
import torch
from packet_pii.ml import bilstm
torch.set_num_threads(2)
spec=importlib.util.spec_from_file_location('fixture','perf-next/scripts/ml/bench_v2_inference.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
pairs=fixture.synthetic_pairs(256)
pred,meta=bilstm.load_predictor('perf-next/src/packet_pii/ml/artifacts/bilstm_v2')
original=bilstm.BiLSTMTagger.forward
src=textwrap.dedent(inspect.getsource(original))
basebatches=pred._batches
def variant(kind):
 s=src
 if 'dedup' in kind:
  s=s.replace('convs = [self.conv]', '''inverse = None
        if compact and flat_chars.shape[0] > 1:
            unique, inverse = torch.unique(flat_chars, dim=0, return_inverse=True)
            flat_chars = unique
        convs = [self.conv]''')
  s=s.replace('if rows is not None:', 'if inverse is not None:\n                    h = h.index_select(0, inverse)\n                if rows is not None:')
 if 'dense' in kind:
  s=s.replace('packed = pack_padded_sequence(x, lengths, batch_first=True, enforce_sorted=False)\n    y, _ = self.lstm(packed)\n    y, _ = pad_packed_sequence(y, batch_first=True, total_length=T)', '''if not torch.is_grad_enabled() and bool(torch.all(lengths == T)):
        y, _ = self.lstm(x)
    else:
        packed = pack_padded_sequence(x, lengths, batch_first=True, enforce_sorted=False)
        y, _ = self.lstm(packed)
        y, _ = pad_packed_sequence(y, batch_first=True, total_length=T)''')
 ns=dict(vars(bilstm));exec(s,ns);bilstm.BiLSTMTagger.forward=ns['forward']
 if 'exact' in kind:
  def exact(jobs):
   result=[]
   for part in basebatches(jobs):
    current=[];prev=None
    for j in part:
     n=len(jobs[j][1])
     if current and n!=prev:result.append(current);current=[]
     current.append(j);prev=n
    if current:result.append(current)
   return result
  pred._batches=exact
 else:pred._batches=basebatches

results=[];reference=pred.predict_pairs(pairs)
for kind in ['baseline','dedup','dense','exact-dense','exact-dedup-dense']:
 variant(kind);times=[];cpu=[]
 for _ in range(4):
  t=time.perf_counter();c=time.process_time();out=pred.predict_pairs(pairs);times.append(time.perf_counter()-t);cpu.append(time.process_time()-c)
 labels=lambda o:[[s[:3] for s in f] for f in o]
 accepted=lambda o:[[s[:3] for s in f if s[3]>=meta['min_score']] for f in o]
 same=labels(reference)==labels(out)
 results.append({'variant':kind,'cold':times[0],'warm':times[1:],'median':statistics.median(times[1:]),'cpu_seconds':cpu,'same_labels':same,'same_decisions':accepted(reference)==accepted(out),'bit_exact':out==reference,'max_score_difference':max([abs(a[3]-b[3]) for f,g in zip(reference,out) for a,b in zip(f,g)],default=0) if same else None,'lifetime_peak_rss':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024})
 print(json.dumps(results[-1]),flush=True)
Path('perf-next-results/forward-experiments.json').write_text(json.dumps({'torch':torch.__version__,'threads':2,'scope':'256 fictional model-only fields, sequential candidates in one process; lifetime RSS is cumulative, not per variant','results':results},indent=2))
