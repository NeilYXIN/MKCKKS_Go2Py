from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import ExitStack

import numpy as np
import pytest

import mkckks

# Context.create dominates test setup at roughly 300ms, while party and
# evaluation-key generation cost single-digit milliseconds, so the context is
# the only setup worth sharing across a module.


@pytest.fixture(scope="module")
def context() -> Iterator[mkckks.Context]:
    value = mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), workers=2)
    yield value
    value.close()


@pytest.fixture(scope="module")
def property_party(context: mkckks.Context) -> Iterator[mkckks.Party]:
    value = mkckks.Party.generate(context, "property-party")
    yield value
    value.close()


def decrypt(
    context: mkckks.Context,
    ciphertext: mkckks.Ciphertext,
    parties: Sequence[mkckks.Party],
) -> np.ndarray:
    """Collect one share per party and recover the plaintext, closing the shares."""
    with ExitStack() as stack:
        shares = [stack.enter_context(party.partial_decrypt(ciphertext)) for party in parties]
        return context.collective_decrypt(ciphertext, shares)


def decrypt_one(
    context: mkckks.Context, party: mkckks.Party, ciphertext: mkckks.Ciphertext
) -> np.ndarray:
    """Decrypt a single-party ciphertext; argument order matches the party-first call sites."""
    return decrypt(context, ciphertext, [party])
