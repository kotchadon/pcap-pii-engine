"""Token-aware credential-key matcher: the fast pre-filter must never change a result."""
import random

from packet_pii.detect import SECRET_KEYS

VOCAB = ['password', 'passwd', 'pwd', 'secret', 'client', 'api', 'key', 'apiKey', 'access', 'token', 'refresh', 'auth', 'author', 'authority',
         'Authorization', 'session', 'id', 'sid', 'jwt', 'otp', 'pin', 'pinned', 'private', 'set', 'cookie', 'bearer', 'user', 'name', 'item',
         'type', 'max', 'count', 'expires', 'header', 'json_body', 'form', 'query_parameter', 'x', 'Id', 'Token', 'passphrase', 'secrets', 'sidebar']


def test_prefilter_never_changes_the_matcher_result():
    rng = random.Random(20250602)
    for _ in range(20000):
        parts = [rng.choice(VOCAB) for _ in range(rng.randint(1, 5))]
        location = rng.choice(['.', '_', '-', '', '[0].'])
        location = location.join(parts)
        assert SECRET_KEYS.search(location) == SECRET_KEYS._search(location), location
