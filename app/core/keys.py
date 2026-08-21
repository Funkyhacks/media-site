"""Key lifecycle management — derive, use, zeroize (zero-knowledge, directive #2).

The server NEVER stores the security keys. Per request the API layer:

1. derives a master key from ``key1``/``key2`` (dual-key, directive #1),
2. unwraps the per-record key(s) it needs,
3. does the crypto,
4. **zeroizes** every derived buffer before the response returns.

:class:`key_scope` is the context manager that guarantees step 4 runs even if
the body raises.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterable, Iterator, List

from app.core import crypto


def _collect(bufs: Iterable[object]) -> List[crypto.KeyMaterial]:
    out: List[crypto.KeyMaterial] = []
    for b in bufs:
        if isinstance(b, (bytes, bytearray)):
            out.append(b)
    return out


@contextmanager
def key_scope(*buffers: object) -> Iterator[None]:
    """Run a block of code, then zeroize every key buffer passed in.

    Usage::

        with key_scope(master, content_key):
            ...  # do crypto

    Guarantees zeroization on both success and exception paths (standing
    default: "key zeroization ... after use").
    """
    try:
        yield
    finally:
        for b in _collect(buffers):
            crypto.zeroize(b)
