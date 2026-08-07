from __future__ import annotations

import gc
import os
import pickle
import subprocess
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import psutil
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import mkckks
from mkckks import _native
from mkckks._artifacts import pack, unpack
from mkckks.api import _NativeObject
from tests.precision_model import addition, assert_precision, local, transform


def decrypt_one(
    context: mkckks.Context, party: mkckks.Party, ciphertext: mkckks.Ciphertext
) -> np.ndarray:
    share = party.partial_decrypt(ciphertext)
    try:
        return context.collective_decrypt(ciphertext, [share])
    finally:
        share.close()


def test_context_metadata_lifecycle_and_pickle(context: mkckks.Context) -> None:
    assert context.slots == 8192
    assert context.workers == 2
    assert context.max_level == 5
    assert len(context.fingerprint) == 64
    party = context.create_party("contract-lifecycle")
    assert not party.closed
    with pytest.raises(TypeError, match="not pickleable"):
        pickle.dumps(party)
    with party.public_key as public_key:
        assert not public_key.closed
    assert public_key.closed
    party.close()
    party.close()
    assert party.closed


def test_public_key_plaintext_and_key_serialization(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "contract-artifacts")
    values = np.array([1 + 0.25j, -2 + 0.5j])

    restored_public = mkckks.PublicKey.from_bytes(context, party.public_key.to_bytes())
    ciphertext = restored_public.encrypt(values)
    ciphertext_error = local(ciphertext)
    assert_precision(decrypt_one(context, party, ciphertext), values, ciphertext_error)

    plaintext = mkckks.Plaintext.from_bytes(context, context.encode(values).to_bytes())
    added = mkckks.Evaluator(context).add(ciphertext, plaintext)
    assert_precision(
        decrypt_one(context, party, added),
        values * 2,
        addition(added, ciphertext_error, local(context.parameters)),
    )

    contribution = party.generate_evaluation_keys(
        relinearization=True, rotations=[1], conjugation=True
    )
    restored_contribution = mkckks.EvaluationKeyContribution.from_bytes(
        context, contribution.to_bytes()
    )
    keys = mkckks.EvaluationKeySet.combine(context, [restored_contribution])
    restored_keys = mkckks.EvaluationKeySet.from_bytes(context, keys.to_bytes())
    conjugated = mkckks.Evaluator(context, restored_keys).conjugate(ciphertext)
    assert_precision(
        decrypt_one(context, party, conjugated),
        np.conj(values),
        transform(conjugated, ciphertext_error, mkckks.PrecisionClass.ROTATION),
    )

    _, public_native = unpack(party.public_key.to_bytes(), "public_key")
    forged_plaintext = pack("plaintext", {"shape": [2], "complex": True}, public_native)
    with pytest.raises(mkckks.SerializationError, match="not plaintext"):
        mkckks.Plaintext.from_bytes(context, forged_plaintext)


def test_add_subtract_scalar_plaintext_and_ciphertext(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "contract-arithmetic")
    values = np.array([1 + 2j, -3 + 0.5j])
    ciphertext = party.encrypt(values)
    ciphertext_error = local(ciphertext)
    evaluator = mkckks.Evaluator(context)

    scalar_add = evaluator.add(ciphertext, 2 - 0.25j)
    scalar_subtract = evaluator.subtract(ciphertext, 2 - 0.25j)
    plaintext = context.encode(values)
    plaintext_subtract = evaluator.subtract(ciphertext, plaintext)
    second = party.encrypt(values)
    ciphertext_subtract = evaluator.subtract(ciphertext, second)
    encoded_error = local(context.parameters)
    cases = [
        (
            scalar_add,
            values + (2 - 0.25j),
            addition(scalar_add, ciphertext_error, encoded_error),
        ),
        (
            scalar_subtract,
            values - (2 - 0.25j),
            addition(scalar_subtract, ciphertext_error, encoded_error),
        ),
        (
            plaintext_subtract,
            np.zeros_like(values),
            addition(plaintext_subtract, ciphertext_error, encoded_error),
        ),
        (
            ciphertext_subtract,
            np.zeros_like(values),
            addition(ciphertext_subtract, ciphertext_error, local(second)),
        ),
    ]
    for result, expected, bound in cases:
        assert_precision(decrypt_one(context, party, result), expected, bound)
    with pytest.raises(ValueError, match="finite"):
        evaluator.add(ciphertext, float("nan"))
    with pytest.raises(ValueError, match="finite"):
        evaluator.multiply_scalar(ciphertext, float("inf"))


def test_shape_missing_keys_levels_and_shares(context: mkckks.Context) -> None:
    alice = mkckks.Party.generate(context, "contract-errors-a")
    bob = mkckks.Party.generate(context, "contract-errors-b")
    one = alice.encrypt([1.0])
    two = bob.encrypt([1.0, 2.0])
    evaluator = mkckks.Evaluator(context)
    with pytest.raises(mkckks.ShapeMismatchError):
        evaluator.add(one, two)
    with pytest.raises(mkckks.ShapeMismatchError):
        evaluator.multiply_plaintext(one, context.encode([1.0, 2.0]))
    with pytest.raises(mkckks.MissingKeyError):
        evaluator.multiply(one, one)
    with pytest.raises(mkckks.MissingKeyError):
        evaluator.rotate_slots(one, 1)
    with pytest.raises(mkckks.MissingKeyError):
        evaluator.conjugate(one)
    empty_contribution = alice.generate_evaluation_keys()
    empty_keys = mkckks.EvaluationKeySet.combine(context, [empty_contribution])
    incomplete = mkckks.Evaluator(context, empty_keys)
    with pytest.raises(mkckks.MissingKeyError, match="relinearization"):
        incomplete.multiply(one, one)
    with pytest.raises(mkckks.MissingKeyError, match="rotation"):
        incomplete.rotate_slots(one, 1)
    with pytest.raises(mkckks.MissingKeyError, match="conjugation"):
        incomplete.conjugate(one)
    with pytest.raises(mkckks.LevelError):
        evaluator.drop_level(one, context.max_level + 1)
    with pytest.raises(mkckks.MissingShareError, match="need 1"):
        context.collective_decrypt(one, [])
    combined = evaluator.add(one, bob.encrypt([2.0]))
    share = alice.partial_decrypt(combined)
    with pytest.raises(mkckks.MissingShareError, match="duplicate"):
        context.collective_decrypt(combined, [share, share])


def test_input_and_parameter_validation(context: mkckks.Context) -> None:
    assert mkckks.Parameters.preset("pn15qp880").log_n == 15
    with pytest.raises(ValueError, match="unknown preset"):
        mkckks.Parameters.preset("unknown")
    literal = dict(log_n=14, log_slots=13, q=[17], p=[19, 23], scale=2.0, sigma=3.2)
    with pytest.raises(ValueError, match="1-64 Q"):
        mkckks.Parameters.from_literal(**{**literal, "q": []})
    with pytest.raises(ValueError, match="finite and positive"):
        mkckks.Parameters.from_literal(**{**literal, "scale": float("nan")})
    for values in ([], [True], [1], [float("inf")], np.array([], dtype=np.float64)):
        with pytest.raises((ValueError, mkckks.InvalidDTypeError)):
            context.encode(values)


def test_context_mismatch(context: mkckks.Context) -> None:
    other = mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), workers=1)
    party = mkckks.Party.generate(context, "contract-context")
    ciphertext = party.encrypt([1.0])
    share = party.partial_decrypt(ciphertext)
    with pytest.raises(mkckks.ContextMismatchError):
        other.collective_decrypt(ciphertext, [share])
    other.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is unavailable")
def test_inherited_handle_fails_after_fork(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "contract-fork")
    child = os.fork()
    if child == 0:
        try:
            party.encrypt([1.0])
        except mkckks.ForkSafetyError:
            os._exit(0)
        os._exit(1)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0


def test_concurrent_read_only_use_and_close_race(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "contract-threads")
    evaluator = mkckks.Evaluator(context)
    shared = party.encrypt(np.arange(16, dtype=np.float64))

    def use_shared() -> None:
        result = evaluator.add(shared, shared)
        result.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: use_shared(), range(32)))

    racing = party.encrypt([1.0])
    with ThreadPoolExecutor(max_workers=2) as pool:
        use_future = pool.submit(evaluator.add, racing, racing)
        close_future = pool.submit(racing.close)
        close_future.result()
        try:
            result = use_future.result()
        except mkckks.ClosedHandleError:
            pass
        else:
            result.close()


def test_concurrent_complete_operation_set(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "contract-complete-threads")
    contribution = party.generate_evaluation_keys(
        relinearization=True, rotations=[1], conjugation=True
    )
    keys = mkckks.EvaluationKeySet.combine(context, [contribution])
    evaluator = mkckks.Evaluator(context, keys)
    values = np.linspace(-0.5, 0.5, 16) + 0.125j
    shared = party.encrypt(values)
    plaintext = context.encode(np.linspace(0.25, 0.75, 16))

    def exercise(index: int) -> None:
        operation = index % 7
        if operation == 0:
            output = evaluator.add(shared, shared)
        elif operation == 1:
            output = evaluator.multiply(shared, shared)
        elif operation == 2:
            output = evaluator.rotate_slots(shared, 1)
        elif operation == 3:
            output = evaluator.conjugate(shared)
        elif operation == 4:
            output = evaluator.multiply_plaintext(shared, plaintext)
        elif operation == 5:
            assert shared.to_bytes()
            return
        else:
            share = party.partial_decrypt(shared)
            share.close()
            return
        output.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(exercise, range(56)))


def run_close_use_race(use: Callable[[], object], close: Callable[[], object]) -> None:
    barrier = threading.Barrier(2)

    def invoke(function: Callable[[], object]) -> object:
        barrier.wait()
        return function()

    with ThreadPoolExecutor(max_workers=2) as pool:
        use_future = pool.submit(invoke, use)
        close_future = pool.submit(invoke, close)
        close_future.result()
        try:
            result = use_future.result()
        except mkckks.ClosedHandleError:
            return
        if isinstance(result, _NativeObject):
            result.close()


@pytest.mark.slow
def test_close_use_race_every_native_handle_kind() -> None:
    parameters = mkckks.Parameters.preset("PN14QP439")

    context = mkckks.Context.create(parameters, workers=2)
    run_close_use_race(lambda: context.encode([1.0]), context.close)

    context = mkckks.Context.create(parameters, workers=2)
    party = mkckks.Party.generate(context, "race-party")
    run_close_use_race(lambda: party.encrypt([1.0]), party.close)
    context.close()

    context = mkckks.Context.create(parameters, workers=2)
    party = mkckks.Party.generate(context, "race-public")
    public_key = party.public_key
    run_close_use_race(lambda: public_key.encrypt([1.0]), public_key.close)
    context.close()

    context = mkckks.Context.create(parameters, workers=2)
    party = mkckks.Party.generate(context, "race-plaintext")
    ciphertext = party.encrypt([1.0])
    plaintext = context.encode([1.0])
    evaluator = mkckks.Evaluator(context)
    run_close_use_race(lambda: evaluator.add(ciphertext, plaintext), plaintext.close)
    context.close()

    context = mkckks.Context.create(parameters, workers=2)
    party = mkckks.Party.generate(context, "race-ciphertext")
    ciphertext = party.encrypt([1.0])
    evaluator = mkckks.Evaluator(context)
    run_close_use_race(lambda: evaluator.add(ciphertext, ciphertext), ciphertext.close)
    context.close()

    context = mkckks.Context.create(parameters, workers=2)
    party = mkckks.Party.generate(context, "race-contribution")
    contribution = party.generate_evaluation_keys()
    run_close_use_race(
        lambda: mkckks.EvaluationKeySet.combine(context, [contribution]),
        contribution.close,
    )
    context.close()

    context = mkckks.Context.create(parameters, workers=2)
    party = mkckks.Party.generate(context, "race-keyset")
    ciphertext = party.encrypt([1.0])
    contribution = party.generate_evaluation_keys(rotations=[1])
    keyset = mkckks.EvaluationKeySet.combine(context, [contribution])
    evaluator = mkckks.Evaluator(context, keyset)
    run_close_use_race(lambda: evaluator.rotate_slots(ciphertext, 1), keyset.close)
    context.close()

    context = mkckks.Context.create(parameters, workers=2)
    party = mkckks.Party.generate(context, "race-share")
    ciphertext = party.encrypt([1.0])
    share = party.partial_decrypt(ciphertext)
    run_close_use_race(lambda: context.collective_decrypt(ciphertext, [share]), share.close)
    context.close()


def test_interpreter_shutdown_finalizers(tmp_path: Path) -> None:
    program = """
import mkckks
context = mkckks.Context.create(mkckks.Parameters.preset('PN14QP439'), workers=1)
party = mkckks.Party.generate(context, 'shutdown-party')
ciphertext = party.encrypt([1.0])
"""
    completed = subprocess.run(
        [sys.executable, "-c", program],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("COVERAGE_", "COV_CORE_"))
        },
    )
    assert completed.returncode == 0, completed.stderr


@settings(max_examples=8, deadline=None)
@given(st.lists(st.floats(min_value=-10, max_value=10, allow_nan=False), min_size=1, max_size=8))
def test_real_round_trip_property(
    context: mkckks.Context, property_party: mkckks.Party, values: list[float]
) -> None:
    normalized = np.asarray(values, dtype=np.float32)
    ciphertext = property_party.encrypt(normalized)
    assert_precision(
        decrypt_one(context, property_party, ciphertext),
        normalized.astype(np.float64),
        local(ciphertext),
    )


@settings(max_examples=8, deadline=None)
@given(
    st.lists(
        st.tuples(
            st.floats(min_value=-0.5, max_value=0.5, allow_nan=False),
            st.floats(min_value=-0.5, max_value=0.5, allow_nan=False),
        ),
        min_size=1,
        max_size=8,
    )
)
def test_complex_metamorphic_property(
    context: mkckks.Context,
    property_party: mkckks.Party,
    components: list[tuple[float, float]],
) -> None:
    values = np.asarray([complex(real, imag) for real, imag in components])
    ciphertext = property_party.encrypt(values)
    evaluator = mkckks.Evaluator(context)
    restored = evaluator.subtract(evaluator.add(ciphertext, 0.125 - 0.25j), 0.125 - 0.25j)
    decoded = decrypt_one(context, property_party, restored)
    bound = mkckks.precision_bound(context.parameters, mkckks.PrecisionClass.BASIC) * 3
    report = mkckks.measure_precision(decoded, values)
    assert report.maximum_real_error <= bound
    assert report.maximum_imaginary_error <= bound


@pytest.mark.slow
def test_slot_boundary_chunking(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "contract-chunks")
    values = np.linspace(-1, 1, context.slots + 1)
    ciphertext = party.encrypt(values)
    assert ciphertext.chunks == 2
    assert ciphertext.chunk_count == 2
    assert ciphertext.slots == context.slots
    assert ciphertext.context_fingerprint == context.fingerprint
    with pytest.raises(ValueError, match="one chunk"):
        mkckks.Evaluator(context).rotate_slots(ciphertext, 1)
    assert_precision(decrypt_one(context, party, ciphertext), values, local(ciphertext))


@pytest.mark.slow
@pytest.mark.parametrize("party_count", [4, 8])
def test_collective_decryption_party_counts(context: mkckks.Context, party_count: int) -> None:
    parties = [
        mkckks.Party.generate(context, f"contract-parties-{party_count}-{index}")
        for index in range(party_count)
    ]
    expected = np.arange(8, dtype=np.float64).reshape(2, 2, 2) / party_count
    evaluator = mkckks.Evaluator(context)
    ciphertext = parties[0].encrypt(expected)
    error = local(ciphertext)
    for party in parties[1:]:
        addition_input = party.encrypt(np.zeros_like(expected))
        added = evaluator.add(ciphertext, addition_input)
        error = addition(added, error, local(addition_input))
        ciphertext = added
    shares = [party.partial_decrypt(ciphertext) for party in parties]
    assert_precision(context.collective_decrypt(ciphertext, shares), expected, error)


@pytest.mark.slow
def test_pn15_complex_round_trip() -> None:
    context = mkckks.Context.create(mkckks.Parameters.preset("PN15QP880"), workers=2)
    party = mkckks.Party.generate(context, "contract-pn15")
    values = np.array([1 + 0.5j, -2.25j])
    ciphertext = party.encrypt(values)
    assert_precision(decrypt_one(context, party, ciphertext), values, local(ciphertext))
    context.close()


@pytest.mark.slow
def test_handle_stress_is_bounded(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "contract-stress")
    evaluator = mkckks.Evaluator(context)
    baseline = int(_native.live_handles())
    process = psutil.Process()
    rss_samples: list[int] = []
    cycles = int(os.environ.get("MKCKKS_STRESS_CYCLES", "1000"))
    sample_interval = max(cycles // 10, 1)
    sample_cycles: list[int] = []
    for index in range(cycles):
        ciphertext = party.encrypt([1.0 + 0.25j])
        evaluated = evaluator.add(ciphertext, 0.5 - 0.25j)
        serialized = evaluated.to_bytes()
        assert serialized
        share = party.partial_decrypt(evaluated)
        assert_precision(
            context.collective_decrypt(evaluated, [share]),
            [1.5 + 0j],
            addition(evaluated, local(ciphertext), local(context.parameters)),
        )
        share.close()
        evaluated.close()
        ciphertext.close()
        if index % sample_interval == sample_interval - 1:
            gc.collect()
            rss_samples.append(process.memory_info().rss)
            sample_cycles.append(index + 1)
    assert int(_native.live_handles()) <= baseline
    assert rss_samples[-1] <= min(rss_samples) + 128 * 1024 * 1024
    slope = float(np.polyfit(sample_cycles, rss_samples, 1)[0])
    assert slope <= 16 * 1024
