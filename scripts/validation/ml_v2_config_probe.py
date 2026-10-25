"""Random weights matching V2 member dimensions. NOT frozen V2 or model quality acceptance."""
import hashlib,json,resource,sys,time
from pathlib import Path
import torch
from packet_pii.ml.bilstm import BiLSTMTagger,ModelConfig,SpanPredictor

torch.set_num_threads(2);torch.manual_seed(91)
cfg=ModelConfig.from_dict(json.loads(Path('src/packet_pii/ml/artifacts/bilstm_v2/seed12/meta.json').read_text())['config'])
m=BiLSTMTagger(cfg).eval();predictor=SpanPredictor(m,None)
b,t,c=64,192,20
lengths=torch.full((b,),t,dtype=torch.long)
word=torch.randint(1,cfg.vocab_size,(b,t));shape=torch.zeros_like(word);ctx=torch.zeros_like(word);ctx[:,:3]=1
chars=torch.randint(1,cfg.char_vocab_size,(b,t,c))
parts=predictor._batches([(i,range(t)) for i in range(b)])

def run():
 return torch.cat([m(word[part],shape[part],ctx[part],chars[part],lengths[part]) for part in parts])
with torch.inference_mode():
 run();times=[]
 for _ in range(3):
  start=time.perf_counter();out=run();times.append(time.perf_counter()-start)
torch.save(out,sys.argv[1]+'.pt')
current_rss=int(Path('/proc/self/statm').read_text().split()[1])*resource.getpagesize()
print(json.dumps(dict(kind='random-weights-V2-member-dimensions-NOT-V2-acceptance',torch=torch.__version__,threads=2,config=cfg.__dict__,batch_rows=[len(p) for p in parts],times_seconds=times,median_seconds=sorted(times)[1],current_rss_bytes=current_rss,peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024)))
