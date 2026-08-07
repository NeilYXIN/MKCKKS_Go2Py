from __future__ import annotations

import pytest

import mkckks


@pytest.fixture(scope="module")
def context() -> mkckks.Context:
    value = mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), workers=2)
    yield value
    value.close()


@pytest.fixture(scope="module")
def property_party(context: mkckks.Context) -> mkckks.Party:
    value = mkckks.Party.generate(context, "property-party")
    yield value
    value.close()
