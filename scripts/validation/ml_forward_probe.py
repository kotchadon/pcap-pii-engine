"""Random weights only: allocation/kernel experiment, NOT V2 quality or capture throughput."""
import json, os, resource, sys, time
import torch
from packet_pii.ml.bilstm import BiLSTMTagger, ModelConfig

torch.set_num_threads(2)
torch.manual_seed(77)
cfg=ModelConfig(512,96,word_dim=64,char_dim=24,char_filters=48,hidden=96,char_widths=(2,3,4),key_broadcast=True)
m=BiLSTMTagger(cfg).eval()
results=[]
for lengths in ([192]*64, [192]*8+[12]*56):
 b,t,c=len(lengths),max(lengths),32
 lengths=torch.tensor(lengths)
 valid=torch.arange(t)[None,:]<lengths[:,None]
 word=torch.randint(1,512,(b,t))*valid
 shape=torch.zeros_like(word); ctx=torch.zeros_like(word);ctx[:,:3]=1
 chars=torch.randint(1,96,(b,t,c))*valid[:,:,None]
 with torch.inference_mode():
  m(word,shape,ctx,chars,lengths)
  times=[]
  for _ in range(3):
   start=time.perf_counter();out=m(word,shape,ctx,chars,lengths);times.append(time.perf_counter()-start)
 results.append(dict(lengths=lengths.tolist(),seconds=times,median_seconds=sorted(times)[1],peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,checksum=float(out.sum())))
 if os.getenv('OUTPUT_TENSORS'): torch.save(out,os.getenv('OUTPUT_TENSORS')+('-dense.pt' if bool(valid.all()) else '-ragged.pt'))
print(json.dumps(dict(kind='random-network-algorithmic-probe-NOT-V2',torch=torch.__version__,threads=2,results=results)))
