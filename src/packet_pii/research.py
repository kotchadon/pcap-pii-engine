"""Version-bound offline research disclosure; never evaluates an uploaded capture."""
from pathlib import Path
import json
import math


def benchmark_metadata():
    root = Path(__file__).resolve().parents[2]
    try:
        data = json.loads((root/'docs/ml/results/v2_eval_challenge.json').read_text())
        ensemble = json.loads((Path(__file__).parent/'ml/artifacts/bilstm_v2/ensemble.json').read_text())
        model = data['models']['v2']
        if model['model_version'] != ensemble['model_version'] or model['min_score'] != ensemble['min_score']:
            raise ValueError('Research/model metadata mismatch')
        dataset = data['datasets']['challenge']
        measured = dataset['systems']['bilstm:v2']
        values = [measured['micro'][k] for k in ('precision','recall','f1')]
        interval = measured['ci95_bootstrap']['f1']
        if not all(type(v) in (int,float) and math.isfinite(v) and 0 <= v <= 1 for v in values+interval):
            raise ValueError('Invalid research metrics')
        return dict(available=True, model_version=model['model_version'],
                    dataset=dict(name='Frozen synthetic challenge', fields=dataset['examples']),
                    precision=values[0],recall=values[1],f1=values[2],bootstrap_ci=interval,
                    scope='Offline exact-span/label evaluation; not accuracy of an uploaded PCAP',
                    source='docs/ml/results/v2_eval_challenge.json')
    except (OSError, ValueError, KeyError, TypeError):
        return dict(available=False,scope='Versioned research metadata unavailable or incompatible')
