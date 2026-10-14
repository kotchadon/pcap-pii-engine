"""PyTorch BiLSTM sequence tagger (BIO), training loop and checkpoint I/O. CPU-only friendly.

Importing this module requires PyTorch (optional extra ``pcap-pii-engine[ml]``); the rest of
``packet_pii`` and ``packet_pii.ml`` (schema, detector contract, tokenizer, data, baselines)
do not.

Checkpoint format (a directory):
  model.pt   state_dict of tensors only, loaded with ``torch.load(weights_only=True)`` (no pickled code)
  meta.json  config, vocab, version, thresholds, training record, sha256 of model.pt
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import time
from dataclasses import asdict, dataclass, fields
from typing import Callable, Sequence

try:
    import torch
    from torch import nn
    from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence
except ImportError as exc:  # pragma: no cover - exercised via sys.modules patching in tests
    raise ImportError("PyTorch is required for the BiLSTM detector: pip install 'pcap-pii-engine[ml]'") from exc

from .encoding import IGNORE, MAX_CHARS, N_SHAPES, SPECIALS, UNK, Encoded, Vocab, chunk_ranges, encode
from .metrics import entity_metrics
from .spans import TAGS, tags_to_spans, tokenize, viterbi_decode

FORMAT_VERSION = 1


class CheckpointError(ValueError):
    """Missing/corrupt/incompatible checkpoint. Messages never contain input text."""


@dataclass
class ModelConfig:
    vocab_size: int
    char_vocab_size: int
    n_tags: int = len(TAGS)
    word_dim: int = 64
    shape_dim: int = 8
    char_dim: int = 24
    char_filters: int = 48           # 0 disables the char-CNN
    hidden: int = 96
    layers: int = 1
    dropout: float = 0.3
    max_seq: int = 192               # context + text tokens per forward pass (hard bound)
    char_widths: tuple = (3,)        # char-CNN kernel widths (V1: (3,))
    key_broadcast: bool = False      # V2: summarise the field-key tokens and feed the summary to every text position
    key_dim: int = 32

    def validate(self) -> "ModelConfig":
        ints = {"vocab_size": 4, "char_vocab_size": 2, "n_tags": 2, "word_dim": 1, "shape_dim": 1, "char_dim": 1,
                "char_filters": 0, "hidden": 1, "layers": 1, "max_seq": 16}
        for k, lo in ints.items():
            v = getattr(self, k)
            if type(v) is not int or v < lo:
                raise ValueError(f"invalid model config: {k} must be an int >= {lo}")
        if self.n_tags != len(TAGS):
            raise ValueError("invalid model config: n_tags must equal len(TAGS)")
        if self.layers > 4 or self.hidden > 1024 or self.max_seq > 4096 or self.word_dim > 1024:
            raise ValueError("invalid model config: size out of bounds")
        if not isinstance(self.dropout, (int, float)) or not 0.0 <= self.dropout < 1.0:
            raise ValueError("invalid model config: dropout must be in [0, 1)")
        if not isinstance(self.char_widths, (tuple, list)) or not 1 <= len(self.char_widths) <= 4 \
                or any(type(w) is not int or not 1 <= w <= 7 for w in self.char_widths):
            raise ValueError("invalid model config: char_widths must be 1-4 ints in [1, 7]")
        self.char_widths = tuple(self.char_widths)
        if type(self.key_broadcast) is not bool or type(self.key_dim) is not int or not 1 <= self.key_dim <= 256:
            raise ValueError("invalid model config: key_broadcast/key_dim")
        return self

    @staticmethod
    def from_dict(d: dict) -> "ModelConfig":
        names = {f.name for f in fields(ModelConfig)}
        if not isinstance(d, dict) or set(d) - names:
            raise ValueError("invalid model config: unknown or malformed keys")
        try:
            return ModelConfig(**d).validate()
        except TypeError:
            raise ValueError("invalid model config: missing keys") from None


class BiLSTMTagger(nn.Module):
    def __init__(self, cfg: ModelConfig):
        super().__init__()
        cfg.validate()
        self.cfg = cfg
        self.word = nn.Embedding(cfg.vocab_size, cfg.word_dim, padding_idx=0)
        self.shape = nn.Embedding(N_SHAPES, cfg.shape_dim)
        self.ctx = nn.Embedding(2, 4)
        in_dim = cfg.word_dim + cfg.shape_dim + 4
        if cfg.char_filters:
            self.char = nn.Embedding(cfg.char_vocab_size, cfg.char_dim, padding_idx=0)
            w0 = cfg.char_widths[0]
            self.conv = nn.Conv1d(cfg.char_dim, cfg.char_filters, kernel_size=w0, padding=w0 // 2)  # name kept for V1 checkpoints
            if len(cfg.char_widths) > 1:
                self.conv_extra = nn.ModuleList([nn.Conv1d(cfg.char_dim, cfg.char_filters, kernel_size=w, padding=w // 2)
                                                 for w in cfg.char_widths[1:]])
            in_dim += cfg.char_filters * len(cfg.char_widths)
        feat_dim = in_dim
        if cfg.key_broadcast:
            self.key_proj = nn.Linear(feat_dim, cfg.key_dim)
            in_dim += cfg.key_dim
        self.drop = nn.Dropout(cfg.dropout)
        self.lstm = nn.LSTM(in_dim, cfg.hidden, num_layers=cfg.layers, bidirectional=True, batch_first=True,
                            dropout=cfg.dropout if cfg.layers > 1 else 0.0)
        self.out = nn.Linear(2 * cfg.hidden, cfg.n_tags)

    def forward(self, word_ids, shape_ids, ctx_ids, char_ids, lengths):
        """word_ids/shape_ids/ctx_ids: [B,T]; char_ids: [B,T,C]; lengths: [B] (cpu). Returns logits [B,T,n_tags]."""
        B, T = word_ids.shape
        feats = [self.word(word_ids), self.shape(shape_ids), self.ctx(ctx_ids)]
        if self.cfg.char_filters:
            ce = self.char(char_ids.reshape(B * T, -1)).transpose(1, 2)           # [BT, cd, C]
            mask = (char_ids.reshape(B * T, -1) != 0).unsqueeze(1)
            convs = [self.conv] + (list(self.conv_extra) if self.cfg.char_widths[1:] else [])
            for cv in convs:
                h = torch.relu(cv(ce))[:, :, :ce.shape[2]]                         # [BT, F, C]
                h = h.masked_fill(~mask, float("-inf")).amax(dim=2)
                h = torch.where(torch.isfinite(h), h, torch.zeros_like(h))         # all-pad tokens -> 0
                feats.append(h.reshape(B, T, -1))
        x = torch.cat(feats, dim=-1)
        if self.cfg.key_broadcast:  # masked mean of key/<sep> positions -> broadcast to all positions
            valid = (torch.arange(T).unsqueeze(0) < lengths.unsqueeze(1))
            km = ((ctx_ids == 1) & valid).unsqueeze(-1).to(x.dtype)
            kv = (x * km).sum(1) / km.sum(1).clamp(min=1.0)
            kv = torch.relu(self.key_proj(kv)).unsqueeze(1).expand(B, T, -1)
            x = torch.cat([x, kv], dim=-1)
        x = self.drop(x)
        packed = pack_padded_sequence(x, lengths, batch_first=True, enforce_sorted=False)
        y, _ = self.lstm(packed)
        y, _ = pad_packed_sequence(y, batch_first=True, total_length=T)
        return self.out(self.drop(y))


# ------------------------------------------------------------------ batching
def collate(batch: Sequence[Encoded], max_seq: int, unk_id: int = 1, word_dropout: float = 0.0,
            rng: random.Random | None = None, ctx_dropout: float = 0.0) -> dict:
    lens = [len(e) for e in batch]
    if not lens or max(lens) > max_seq:
        raise ValueError("batch empty or sequence longer than max_seq (chunk before encoding)")
    B, T = len(batch), max(lens)
    C = max(1, min(MAX_CHARS, max((len(c) for e in batch for c in e.char_ids), default=1)))
    word = torch.zeros(B, T, dtype=torch.long); shape = torch.zeros(B, T, dtype=torch.long)
    ctx = torch.zeros(B, T, dtype=torch.long); chars = torch.zeros(B, T, C, dtype=torch.long)
    labels = torch.full((B, T), IGNORE, dtype=torch.long)
    for i, e in enumerate(batch):
        n = len(e)
        wids = list(e.word_ids)
        if word_dropout > 0 and rng is not None:  # train the <unk> embedding on realistic OOV contexts
            for k in range(e.n_ctx, n):
                if rng.random() < word_dropout:
                    wids[k] = unk_id
        if ctx_dropout > 0 and rng is not None:  # simulate unseen field keys (not the <sep> marker at n_ctx-1)
            for k in range(e.n_ctx - 1):
                if rng.random() < ctx_dropout:
                    wids[k] = unk_id
        word[i, :n] = torch.tensor(wids); shape[i, :n] = torch.tensor(e.shape_ids)
        ctx[i, :n] = torch.tensor(e.ctx_flags)
        for k, cid in enumerate(e.char_ids):
            if cid:
                chars[i, k, :len(cid)] = torch.tensor(cid[:C])
        if e.tags is not None:
            labels[i, e.n_ctx:n] = torch.tensor(e.tags)
    return {"word": word, "shape": shape, "ctx": ctx, "chars": chars, "labels": labels,
            "lengths": torch.tensor(lens, dtype=torch.long)}


def _forward(model: BiLSTMTagger, b: dict):
    return model(b["word"], b["shape"], b["ctx"], b["chars"], b["lengths"])


# ------------------------------------------------------------------ prediction
class SpanPredictor:
    """(location, text) pairs -> unthresholded spans ``(start, end, label, raw_score)``."""

    def __init__(self, model, vocab: Vocab, batch_size: int = 64):
        """``model`` may be one tagger or a list of taggers with identical config/vocab (probability-averaging ensemble)."""
        self.models = list(model) if isinstance(model, (list, tuple)) else [model]
        if any(m.cfg != self.models[0].cfg for m in self.models):
            raise ValueError("ensemble members must share one model configuration")
        self.model, self.vocab, self.batch_size = self.models[0], vocab, batch_size

    def predict_pairs(self, pairs: Sequence[tuple[str, str]]) -> list[list[tuple[int, int, str, float]]]:
        max_seq = self.model.cfg.max_seq
        jobs = []  # (pair_index, Encoded, chunk token slice offset)
        results: list[list] = [[] for _ in pairs]
        for pi, (loc, text) in enumerate(pairs):
            toks = tokenize(text)
            probe = encode(self.vocab, loc, [])
            room = max_seq - probe.n_ctx
            if room < 1:
                raise ValueError("location context leaves no room for text tokens")
            for a, b in chunk_ranges(len(toks), room):
                jobs.append((pi, encode(self.vocab, loc, toks[a:b])))
        was_training = [m.training for m in self.models]
        for m in self.models:
            m.eval()
        try:
            with torch.inference_mode():
                for i in range(0, len(jobs), self.batch_size):
                    part = jobs[i:i + self.batch_size]
                    batch = collate([e for _, e in part], max_seq)
                    if len(self.models) == 1:
                        lp = torch.log_softmax(_forward(self.models[0], batch), dim=-1)
                    else:  # average member probabilities, then log
                        lp = torch.log(torch.stack([torch.softmax(_forward(m, batch), dim=-1) for m in self.models]).mean(0).clamp_min(1e-12))
                    for k, (pi, enc) in enumerate(part):
                        rows = lp[k, enc.n_ctx:len(enc)].tolist()
                        if not rows:
                            continue
                        path = viterbi_decode(rows)
                        probs = [2.718281828459045 ** rows[t][tag] for t, tag in enumerate(path)]
                        for s, e, label, sc in tags_to_spans(enc.tokens, path, probs):
                            results[pi].append((s, e, label, min(1.0, max(0.0, float(sc)))))
        finally:
            for m, t in zip(self.models, was_training):
                m.train(t)
        return results


def evaluate_examples(predictor: SpanPredictor, examples: Sequence, min_score: float = 0.0) -> dict:
    preds = predictor.predict_pairs([(e.location, e.text) for e in examples])
    gold = {e.id: e.spans for e in examples}
    pred = {e.id: [(s, t, l) for s, t, l, sc in p if sc >= min_score] for e, p in zip(examples, preds)}
    return entity_metrics(gold, pred)


# ------------------------------------------------------------------ training
def train_model(train_ex: Sequence, val_ex: Sequence, vocab: Vocab, cfg: ModelConfig, *, seed: int = 1337,
                epochs: int = 30, patience: int = 6, batch_size: int = 64, lr: float = 2e-3,
                weight_decay: float = 1e-2, clip: float = 1.0, word_dropout: float = 0.15, ctx_dropout: float = 0.0,
                hn_boost: int = 0, tag_weights: Sequence[float] | None = None,
                max_minutes: float = 20.0, log: Callable[[str], None] = print) -> tuple[BiLSTMTagger, dict]:
    """Mini-batch training with val-entity-F1 checkpoint selection, early stopping and a wall-clock limit."""
    from .encoding import encode_example
    random.seed(seed); torch.manual_seed(seed)
    rng = random.Random(seed)
    model = BiLSTMTagger(cfg)
    enc_train = [encode_example(vocab, e.location, e.text, e.spans) for e in train_ex]
    boost = [i for i, e in enumerate(train_ex) if 'hard_negative' in getattr(e, 'tags', ())]  # V2: extra copies of hard negatives
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    w = None if tag_weights is None else torch.tensor(list(tag_weights), dtype=torch.float)
    loss_fn = nn.CrossEntropyLoss(weight=w, ignore_index=IGNORE)
    predictor = SpanPredictor(model, vocab)
    history, best, best_state, bad = [], -1.0, None, 0
    t0 = time.time()
    for epoch in range(1, epochs + 1):
        model.train()
        order = list(range(len(enc_train))) + boost * hn_boost; rng.shuffle(order)
        tot, n = 0.0, 0
        for i in range(0, len(order), batch_size):
            b = collate([enc_train[j] for j in order[i:i + batch_size]], cfg.max_seq, vocab.words[UNK], word_dropout, rng, ctx_dropout)
            logits = _forward(model, b)
            loss = loss_fn(logits.reshape(-1, cfg.n_tags), b["labels"].reshape(-1))
            opt.zero_grad(); loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), clip)
            opt.step()
            tot += loss.item(); n += 1
        m = evaluate_examples(predictor, val_ex)
        rec = {"epoch": epoch, "train_loss": tot / max(n, 1), "val_micro_f1": m["micro"]["f1"],
               "val_precision": m["micro"]["precision"], "val_recall": m["micro"]["recall"],
               "seconds": round(time.time() - t0, 1)}
        history.append(rec)
        log(f"epoch {epoch:02d} loss {rec['train_loss']:.4f} val_f1 {rec['val_micro_f1']:.4f} "
            f"(P {rec['val_precision']:.3f} R {rec['val_recall']:.3f}) {rec['seconds']}s")
        if rec["val_micro_f1"] > best:
            best, bad, best_state = rec["val_micro_f1"], 0, copy.deepcopy(model.state_dict())
            rec["best"] = True
        else:
            bad += 1
        if bad >= patience:
            log("early stopping"); break
        if (time.time() - t0) / 60 > max_minutes:
            log("time limit reached"); break
    model.load_state_dict(best_state)
    model.eval()
    return model, {"history": history, "best_val_micro_f1": best, "epochs_run": len(history),
                   "seed": seed, "batch_size": batch_size, "lr": lr, "weight_decay": weight_decay, "clip": clip,
                   "word_dropout": word_dropout, "ctx_dropout": ctx_dropout, "hn_boost": hn_boost, "tag_weights": None if tag_weights is None else list(tag_weights), "patience": patience, "wall_seconds": round(time.time() - t0, 1)}


# ------------------------------------------------------------------ checkpoint I/O
def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save_checkpoint(directory: str, model: BiLSTMTagger, vocab: Vocab, *, version_prefix: str = "bilstm-v1",
                    training: dict | None = None, extra: dict | None = None) -> dict:
    os.makedirs(directory, exist_ok=True)
    mp = os.path.join(directory, "model.pt")
    torch.save({k: v.detach().cpu() for k, v in model.state_dict().items()}, mp)
    digest = _sha256(mp)
    meta = {"format": FORMAT_VERSION, "model_version": f"{version_prefix}-{digest[:12]}", "config": asdict(model.cfg),
            "vocab": vocab.to_json(), "tags": list(TAGS), "model_sha256": digest, "torch_version": torch.__version__,
            "score_semantics": "uncalibrated_model_score", "training": training or {}}
    meta.update(extra or {})
    write_meta(directory, meta)
    return meta


def write_meta(directory: str, meta: dict) -> None:
    with open(os.path.join(directory, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1, sort_keys=True)


def load_checkpoint(directory: str) -> tuple[BiLSTMTagger, Vocab, dict]:
    """Load on CPU. Verifies checksum, config and tensor shapes; no network, no pickle execution."""
    mp, jp = os.path.join(str(directory), "model.pt"), os.path.join(str(directory), "meta.json")
    if not (os.path.isfile(mp) and os.path.isfile(jp)):
        raise CheckpointError("checkpoint directory must contain model.pt and meta.json")
    try:
        with open(jp, encoding="utf-8") as f:
            meta = json.load(f)
        if meta.get("format") != FORMAT_VERSION or list(meta.get("tags", [])) != list(TAGS):
            raise CheckpointError("unsupported checkpoint format or tag set")
        cfg = ModelConfig.from_dict(meta["config"])
        vocab = Vocab.from_json(meta["vocab"])
        if len(vocab.words) != cfg.vocab_size or len(vocab.chars) != cfg.char_vocab_size \
                or any(vocab.words.get(s) != i for i, s in enumerate(SPECIALS)):
            raise CheckpointError("vocabulary does not match model configuration")
        if _sha256(mp) != meta.get("model_sha256"):
            raise CheckpointError("model.pt checksum mismatch (corrupt or modified checkpoint)")
        state = torch.load(mp, map_location="cpu", weights_only=True)
        model = BiLSTMTagger(cfg)
        model.load_state_dict(state, strict=True)
    except CheckpointError:
        raise
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, EOFError) as exc:
        raise CheckpointError(f"cannot load checkpoint: {type(exc).__name__}") from None
    model.eval()
    return model, vocab, meta


# ------------------------------------------------------------------ ensembles (V2)
ENSEMBLE_FILE = "ensemble.json"
ENSEMBLE_FORMAT = 1
MAX_ENSEMBLE_MEMBERS = 8


def ensemble_version(member_sha256: list[str], prefix: str = "bilstm-v2") -> str:
    return f"{prefix}-{hashlib.sha256('|'.join(member_sha256).encode()).hexdigest()[:12]}"


def load_predictor(path: str, batch_size: int = 64) -> tuple["SpanPredictor", dict]:
    """Load a single checkpoint directory OR an ensemble directory (``ensemble.json`` + member subdirectories).

    Returns ``(SpanPredictor, meta)`` where ``meta`` has ``model_version``, ``min_score`` and ``model_sha256`` (ensemble: the
    sha256 of the member digests). Verifies every member checksum against ensemble.json; members must share config + vocab.
    """
    path = str(path)
    ej = os.path.join(path, ENSEMBLE_FILE)
    if not os.path.isfile(ej):
        model, vocab, meta = load_checkpoint(path)
        return SpanPredictor(model, vocab, batch_size), meta
    try:
        with open(ej, encoding="utf-8") as f:
            ens = json.load(f)
        if ens.get("format") != ENSEMBLE_FORMAT or not isinstance(ens.get("members"), list) \
                or not 1 <= len(ens["members"]) <= MAX_ENSEMBLE_MEMBERS:
            raise CheckpointError("unsupported or malformed ensemble.json")
        loaded = []
        for m in ens["members"]:
            sub = os.path.normpath(os.path.join(path, m["dir"]))
            if os.path.dirname(sub) != os.path.normpath(path):          # members must be direct children
                raise CheckpointError("ensemble member path escapes the ensemble directory")
            model, vocab, meta = load_checkpoint(sub)
            if meta["model_sha256"] != m["model_sha256"]:
                raise CheckpointError("ensemble member checksum differs from ensemble.json")
            loaded.append((model, vocab, meta))
        if any(l[1].words != loaded[0][1].words or l[1].chars != loaded[0][1].chars or l[0].cfg != loaded[0][0].cfg for l in loaded):
            raise CheckpointError("ensemble members must share vocabulary and configuration")
        shas = [m["model_sha256"] for m in ens["members"]]
        version = ensemble_version(shas, ens.get("version_prefix", "bilstm-v2"))
        if ens.get("model_version") != version:
            raise CheckpointError("ensemble model_version does not match its members")
        ms = ens.get("min_score", 0.0)
        if type(ms) not in (int, float) or not 0.0 <= ms <= 1.0:
            raise CheckpointError("invalid ensemble min_score")
    except CheckpointError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CheckpointError(f"cannot load ensemble: {type(exc).__name__}") from None
    meta = {"model_version": version, "min_score": float(ms), "model_sha256": hashlib.sha256("|".join(shas).encode()).hexdigest(),
            "members": len(loaded), "score_semantics": "uncalibrated_model_score", "training": ens.get("selection", {})}
    return SpanPredictor([l[0] for l in loaded], loaded[0][1], batch_size), meta
