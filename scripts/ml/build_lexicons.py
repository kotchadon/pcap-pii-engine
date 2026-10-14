#!/usr/bin/env python
"""Dump frozen lexicons from Faker (MIT licence; synthetic names/places, no real individuals) to JSON.

  pip install faker==40.43.0
  python scripts/ml/build_lexicons.py --out src/packet_pii/ml/datasets/lexicons_v2.json

Faker is a DEV-TIME source only. The V2 generator reads the committed JSON, so dataset generation and the
runtime never depend on Faker (whose output may change between versions).
"""
import argparse, json, os, re, sys

import faker
from faker import Faker

LATIN = ["en_US", "en_GB", "en_IN", "de_DE", "fr_FR", "es_ES", "es_MX", "it_IT", "pl_PL", "tr_TR", "pt_BR", "pt_PT",
         "sv_SE", "nl_NL", "cs_CZ", "id_ID", "da_DK", "fi_FI", "hu_HU", "ro_RO", "hr_HR", "sk_SK", "no_NO", "en_AU"]
OTHER = ["ja_JP", "ru_RU", "zh_CN", "ko_KR", "el_GR", "uk_UA", "he_IL", "ar_AA", "th_TH", "hi_IN", "fa_IR"]
NAME = re.compile(r"^[^\W\d_]+(?:[-'’][^\W\d_]+)?$", re.U)


def collect(fn_name, locales, n, seed, post=None):
    out = set()
    for i, loc in enumerate(locales):
        f = Faker(loc); f.seed_instance(seed + i)
        for _ in range(n):
            v = getattr(f, fn_name)()
            if post: v = post(v)
            if v: out.add(v)
    return out


def tok(v):
    v = v.strip().split()[0] if v.strip() else ""
    return v if NAME.match(v) and 2 <= len(v) <= 20 else ""


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True); a = ap.parse_args()
    lex = {"faker_version": faker.VERSION}
    lex["first"] = sorted(collect("first_name", LATIN, 700, 1, tok) | collect("first_name", OTHER, 250, 2, tok))
    lex["last"] = sorted(collect("last_name", LATIN, 700, 3, tok) | collect("last_name", OTHER, 250, 4, tok))
    city = lambda v: v if 3 <= len(v) <= 24 and len(v.split()) <= 2 and not re.search(r"\d", v) else ""
    lex["city"] = sorted(collect("city", LATIN, 250, 5, city) | collect("city", OTHER[:6], 80, 6, city))
    comp = lambda v: v if 3 <= len(v) <= 40 else ""
    lex["company"] = sorted(collect("company", LATIN[:12], 250, 7, comp))
    uname = lambda v: v if 3 <= len(v) <= 24 else ""
    lex["username"] = sorted(collect("user_name", LATIN[:14], 400, 8, uname))
    job = lambda v: v if 4 <= len(v) <= 40 else ""
    lex["job"] = sorted(collect("job", ["en_US"], 600, 9, job))
    lex["street"] = sorted(collect("street_name", ["en_US", "en_GB", "de_DE", "fr_FR"], 200, 10, lambda v: v if len(v) <= 28 else ""))
    from faker.providers.lorem.en_US import Provider as L
    lex["word"] = sorted({w for w in L.word_list if w.isalpha() and 3 <= len(w) <= 12})
    f = Faker("en_US"); f.seed_instance(11)
    lex["file_ext"] = sorted({f.file_extension() for _ in range(300)})
    lex["color"] = sorted({f.color_name().lower() for _ in range(300) if " " not in f.color_name()})
    lex["country"] = sorted({c for loc in LATIN[:6] for c in [Faker(loc).country() for _ in range(60)] if len(c) <= 24})
    lex["user_agent"] = sorted({f.user_agent() for _ in range(60)})
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(lex, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=0, sort_keys=True)
    print({k: (len(v) if isinstance(v, list) else v) for k, v in lex.items()})


if __name__ == "__main__":
    main()
