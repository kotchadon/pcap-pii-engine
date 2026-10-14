"""Vocabulary, features and encoding for the BiLSTM tagger. Pure standard library.

Model input = location-context tokens + ``<sep>`` + text tokens. Only text
positions carry gold tags / are decoded; context positions are masked
(``IGNORE``) in the loss.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Sequence

from .spans import Token, spans_to_tags, tokenize

IGNORE = -100
PAD, UNK, SEP, NUM = "<pad>", "<unk>", "<sep>", "<num>"
SPECIALS = (PAD, UNK, SEP, NUM)
MAX_CTX_TOKENS = 12
MAX_CHARS = 20
N_SHAPES = 10

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^0-9A-Za-zÀ-￿]+")


def location_tokens(location: str, limit: int = MAX_CTX_TOKENS) -> list[str]:
    """``json_body.user[0].fullName`` -> [json, body, user, <num>, full, name] (last ``limit`` kept)."""
    parts = []
    for chunk in _SPLIT.split(_CAMEL.sub("_", location)):
        if not chunk:
            continue
        parts.append(NUM if chunk.isdigit() else chunk.lower())
    return parts[-limit:]


def shape_id(tok: str) -> int:
    """Coarse orthographic class (0..N_SHAPES-1); lets unseen words share representations."""
    if tok.isdigit():
        return 4
    alpha = [c for c in tok if c.isalpha()]
    has_digit = any(c.isdigit() for c in tok)
    if not alpha:
        return 7 if not has_digit else 5
    if "_" in tok:
        return 6
    if has_digit:
        return 5
    if not any(c.isupper() or c.islower() for c in alpha):
        return 8  # caseless scripts (CJK, ...)
    if tok.isupper():
        return 2
    if tok.islower():
        return 0
    if tok[0].isupper() and tok[1:].islower():
        return 1
    return 3


@dataclass
class Vocab:
    words: dict[str, int]
    chars: dict[str, int]

    def word_id(self, w: str) -> int:
        return self.words.get(w, self.words[UNK])

    def char_ids(self, tok: str) -> list[int]:
        return [self.chars.get(c, self.chars[UNK]) for c in tok[:MAX_CHARS]]

    def to_json(self) -> dict:
        return {"words": list(self.words), "chars": list(self.chars)}

    @staticmethod
    def from_json(d: dict) -> "Vocab":
        return Vocab({w: i for i, w in enumerate(d["words"])}, {c: i for i, c in enumerate(d["chars"])})


def build_vocab(examples: Iterable[tuple[str, str]], min_word_count: int = 2, min_char_count: int = 2) -> Vocab:
    """Build from TRAINING (location, text) pairs only."""
    wc: Counter = Counter()
    cc: Counter = Counter()
    for loc, text in examples:
        wc.update(location_tokens(loc))
        for t in tokenize(text):
            wc[t.text.lower()] += 1
            cc.update(t.text)
    words = {s: i for i, s in enumerate(SPECIALS)}
    for w, c in sorted(wc.items(), key=lambda x: (-x[1], x[0])):
        if c >= min_word_count and w not in words:
            words[w] = len(words)
    chars = {PAD: 0, UNK: 1}
    for ch, c in sorted(cc.items(), key=lambda x: (-x[1], x[0])):
        if c >= min_char_count and ch not in chars:
            chars[ch] = len(chars)
    return Vocab(words, chars)


@dataclass
class Encoded:
    word_ids: list[int]
    shape_ids: list[int]
    ctx_flags: list[int]          # 1 for location/sep positions, 0 for text positions
    char_ids: list[list[int]]
    n_ctx: int                    # number of leading context positions
    tokens: list[Token]           # text tokens (offsets into the original text)
    tags: list[int] | None = None  # gold tags for text positions (None at inference)

    def __len__(self) -> int:
        return len(self.word_ids)


def encode(vocab: Vocab, location: str, tokens: Sequence[Token], tags: Sequence[int] | None = None) -> Encoded:
    ctx = location_tokens(location)
    wids = [vocab.word_id(w) for w in ctx] + [vocab.words[SEP]]
    shapes = [shape_id(w) if w not in SPECIALS else 9 for w in ctx] + [9]
    chars = [vocab.char_ids(w) if w not in SPECIALS else [1] for w in ctx] + [[1]]
    n_ctx = len(wids)
    for t in tokens:
        wids.append(vocab.word_id(t.text.lower()))
        shapes.append(shape_id(t.text))
        chars.append(vocab.char_ids(t.text))
    return Encoded(wids, shapes, [1] * n_ctx + [0] * len(tokens), chars, n_ctx, list(tokens),
                   None if tags is None else list(tags))


def encode_example(vocab: Vocab, location: str, text: str, spans: Sequence[tuple[int, int, str]]) -> Encoded:
    toks = tokenize(text)
    return encode(vocab, location, toks, spans_to_tags(toks, spans))


def chunk_ranges(n_tokens: int, max_tokens: int) -> list[tuple[int, int]]:
    """Non-overlapping [a, b) token windows of at most ``max_tokens`` (entities crossing a boundary are split)."""
    if max_tokens <= 0:
        raise ValueError("max_tokens must be positive")
    return [(a, min(a + max_tokens, n_tokens)) for a in range(0, n_tokens, max_tokens)]
