# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import warnings
from contextlib import ExitStack
from itertools import product
from pathlib import Path

import numpy as np
import pytest

import mkckks
from mkckks._artifacts import pack, unpack


def decrypt(
    context: mkckks.Context,
    ciphertext: mkckks.Ciphertext,
    parties: list[mkckks.Party],
) -> np.ndarray:
    with ExitStack() as stack:
        shares = [stack.enter_context(party.partial_decrypt(ciphertext)) for party in parties]
        return context.collective_decrypt(ciphertext, shares)


def assert_within_contract(
    context: mkckks.Context,
    ciphertext: mkckks.Ciphertext,
    parties: list[mkckks.Party],
    expected: np.ndarray,
) -> None:
    assert ciphertext.correctness_status is mkckks.CorrectnessStatus.WITHIN_TESTED_CONTRACT
    assert math.isfinite(ciphertext.tracked_magnitude_bound)
    assert math.isfinite(ciphertext.tracked_error_bound)
    assert math.isfinite(ciphertext.range_margin_bits)
    assert ciphertext.range_margin_bits >= 0
    expected_magnitude = float(np.max(np.abs(expected), initial=0.0))
    assert expected_magnitude <= np.nextafter(ciphertext.tracked_magnitude_bound, math.inf)
    report = mkckks.measure_precision(decrypt(context, ciphertext, parties), expected)
    assert report.maximum_real_error <= ciphertext.tracked_error_bound
    assert report.maximum_imaginary_error <= ciphertext.tracked_error_bound


def write_circuit_failure(
    *,
    preset: str,
    seed: int,
    trace: list[str],
    ciphertext: mkckks.Ciphertext,
    expected: np.ndarray,
    initial: np.ndarray,
) -> None:
    configured = os.environ.get("MKCKKS_FAILURE_DIR")
    if not configured:
        return
    directory = Path(configured)
    directory.mkdir(parents=True, exist_ok=True)
    stem = f"{preset.lower()}-{seed}-{len(trace)}"
    artifact_name = f"{stem}.ciphertext.bin"
    (directory / artifact_name).write_bytes(ciphertext.to_bytes())
    report = {
        "schema_version": 1,
        "preset": preset,
        "seed": seed,
        "operations": trace,
        "initial_real": initial.real.tolist(),
        "initial_imaginary": initial.imag.tolist(),
        "expected_real": expected.real.tolist(),
        "expected_imaginary": expected.imag.tolist(),
        "level": ciphertext.level,
        "scale": ciphertext.scale,
        "participants": ciphertext.participants,
        "shape": ciphertext.shape,
        "chunks": ciphertext.chunks,
        "correctness_status": ciphertext.correctness_status,
        "tracked_magnitude_bound": ciphertext.tracked_magnitude_bound,
        "tracked_error_bound": ciphertext.tracked_error_bound,
        "range_margin_bits": ciphertext.range_margin_bits,
        "serialized_ciphertext": artifact_name,
    }
    (directory / f"{stem}.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_correctness_metadata_status_and_artifact_binding() -> None:
    parameters = mkckks.Parameters.preset("PN14QP439")
    with ExitStack() as stack:
        context = stack.enter_context(mkckks.Context.create(parameters, workers=1))
        party = stack.enter_context(mkckks.Party.generate(context, "tracking-artifact"))
        plaintext = stack.enter_context(context.encode(np.array([0.25 + 0.5j, -0.125j])))
        ciphertext = stack.enter_context(party.encrypt(np.array([0.25 + 0.5j, -0.125j])))

        for value in (plaintext, ciphertext):
            assert value.correctness_status is mkckks.CorrectnessStatus.WITHIN_TESTED_CONTRACT
            assert value.tracked_magnitude_bound == pytest.approx(math.hypot(0.25, 0.5))
            assert value.tracked_error_bound > 0
            assert value.range_margin_bits > 0

        artifact = ciphertext.to_bytes()
        metadata, native = unpack(artifact, "ciphertext")
        altered = dict(metadata)
        altered_correctness = dict(altered["correctness"])
        altered_correctness["range_exceeded"] = True
        altered["correctness"] = altered_correctness
        with pytest.raises(mkckks.SerializationError, match="correctness metadata disagree"):
            mkckks.Ciphertext.from_bytes(context, pack("ciphertext", altered, native))

        restored = stack.enter_context(mkckks.Ciphertext.from_bytes(context, artifact))
        assert restored.correctness_status is ciphertext.correctness_status
        assert restored.tracked_magnitude_bound == ciphertext.tracked_magnitude_bound
        assert restored.tracked_error_bound == ciphertext.tracked_error_bound
        assert restored.range_margin_bits == ciphertext.range_margin_bits

    with pytest.warns(RuntimeWarning, match="outside the project's correctness-certified"):
        expert = mkckks.Context.create(
            parameters,
            workers=1,
            input_policy=mkckks.InputPolicy.EXPERT,
        )
    with expert, mkckks.Party.generate(expert, "tracking-expert") as party:
        ciphertext = party.encrypt(np.array([0.25]))
        assert ciphertext.correctness_status is mkckks.CorrectnessStatus.EXPERT_CONTEXT
        ciphertext.close()

        contribution = party.generate_evaluation_keys(relinearization=True)
        with contribution, mkckks.EvaluationKeySet.combine(expert, [contribution]) as keys:
            evaluator = mkckks.Evaluator(expert, keys)
            ciphertext = party.encrypt(np.array([2.0]))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", mkckks.CorrectnessRangeWarning)
                while ciphertext.correctness_status is mkckks.CorrectnessStatus.EXPERT_CONTEXT:
                    previous = ciphertext
                    ciphertext = evaluator.multiply(previous, previous)
                    previous.close()
            assert (
                ciphertext.correctness_status is mkckks.CorrectnessStatus.EXPERT_AND_OUTSIDE_RANGE
            )
            ciphertext.close()


def test_range_warning_is_once_sticky_and_serialized() -> None:
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), workers=1)
        )
        party = stack.enter_context(mkckks.Party.generate(context, "tracking-range"))
        contribution = stack.enter_context(party.generate_evaluation_keys(relinearization=True))
        keys = stack.enter_context(mkckks.EvaluationKeySet.combine(context, [contribution]))
        evaluator = mkckks.Evaluator(context, keys)
        ciphertext = party.encrypt(np.array([2.0]))
        expected = np.array([2.0])
        warning_count = 0
        while ciphertext.level > 0:
            previous = ciphertext
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", mkckks.CorrectnessRangeWarning)
                ciphertext = evaluator.multiply(previous, previous)
            previous.close()
            expected *= expected
            warning_count += sum(
                issubclass(item.category, mkckks.CorrectnessRangeWarning) for item in caught
            )
            if ciphertext.correctness_status is mkckks.CorrectnessStatus.WITHIN_TESTED_CONTRACT:
                assert_within_contract(context, ciphertext, [party], expected)

        assert warning_count == 1
        assert ciphertext.correctness_status is mkckks.CorrectnessStatus.OUTSIDE_TRACKED_RANGE
        assert ciphertext.range_margin_bits < 0

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", mkckks.CorrectnessRangeWarning)
            zeroed = evaluator.multiply_scalar(ciphertext, 0.0)
        assert not caught
        assert zeroed.correctness_status is mkckks.CorrectnessStatus.OUTSIDE_TRACKED_RANGE
        assert zeroed.tracked_magnitude_bound == 0

        restored = mkckks.Ciphertext.from_bytes(context, zeroed.to_bytes())
        assert restored.correctness_status is mkckks.CorrectnessStatus.OUTSIDE_TRACKED_RANGE
        restored.close()
        zeroed.close()
        ciphertext.close()


@pytest.mark.release
@pytest.mark.parametrize("preset", ["PN14QP439", "PN15QP880"])
@pytest.mark.parametrize("start", [1.01, 2.0, 16.0, float(1 << 10), float(1 << 20)])
def test_repeated_squaring_range_boundaries(preset: str, start: float) -> None:
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset(preset), workers=1)
        )
        party = stack.enter_context(
            mkckks.Party.generate(context, f"range-probe-{preset}-{start:g}")
        )
        contribution = stack.enter_context(party.generate_evaluation_keys(relinearization=True))
        keys = stack.enter_context(mkckks.EvaluationKeySet.combine(context, [contribution]))
        evaluator = mkckks.Evaluator(context, keys)
        ciphertext = party.encrypt(np.array([start]))
        expected = np.array([start])
        crossed = False
        try:
            while ciphertext.level > 0:
                if not crossed:
                    assert_within_contract(context, ciphertext, [party], expected)
                previous = ciphertext
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always", mkckks.CorrectnessRangeWarning)
                    ciphertext = evaluator.multiply(previous, previous)
                previous.close()
                expected *= expected
                transition_warnings = [
                    item
                    for item in caught
                    if issubclass(item.category, mkckks.CorrectnessRangeWarning)
                ]
                if transition_warnings:
                    assert len(transition_warnings) == 1
                    assert not crossed
                    crossed = True
                    assert (
                        ciphertext.correctness_status
                        is mkckks.CorrectnessStatus.OUTSIDE_TRACKED_RANGE
                    )
                    assert ciphertext.range_margin_bits < 0
                    break
            if not crossed:
                assert_within_contract(context, ciphertext, [party], expected)
        finally:
            ciphertext.close()


@pytest.mark.release
def test_outside_range_artifact_resumes_sticky_in_fresh_process(tmp_path: Path) -> None:
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), workers=1)
        )
        party = stack.enter_context(mkckks.Party.generate(context, "range-spawn"))
        contribution = stack.enter_context(party.generate_evaluation_keys(relinearization=True))
        keys = stack.enter_context(mkckks.EvaluationKeySet.combine(context, [contribution]))
        evaluator = mkckks.Evaluator(context, keys)
        ciphertext = party.encrypt(np.array([2.0]))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", mkckks.CorrectnessRangeWarning)
            while ciphertext.correctness_status is mkckks.CorrectnessStatus.WITHIN_TESTED_CONTRACT:
                previous = ciphertext
                ciphertext = evaluator.multiply(previous, previous)
                previous.close()
        assert ciphertext.correctness_status is mkckks.CorrectnessStatus.OUTSIDE_TRACKED_RANGE
        (tmp_path / "context.bin").write_bytes(context.to_bytes())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            (tmp_path / "party.bin").write_bytes(party.export_private_state())
        (tmp_path / "ciphertext.bin").write_bytes(ciphertext.to_bytes())
        ciphertext.close()

    program = """
import sys
import warnings
from pathlib import Path
import numpy as np
import mkckks

root = Path(sys.argv[1])
with mkckks.Context.from_bytes((root / 'context.bin').read_bytes()) as context:
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', RuntimeWarning)
        party = mkckks.Party.from_private_state(context, (root / 'party.bin').read_bytes())
    with party, mkckks.Ciphertext.from_bytes(
        context, (root / 'ciphertext.bin').read_bytes()
    ) as ciphertext:
        assert ciphertext.correctness_status is mkckks.CorrectnessStatus.OUTSIDE_TRACKED_RANGE
        with mkckks.Evaluator(context).multiply_scalar(ciphertext, 0.0) as descendant:
            assert descendant.correctness_status is mkckks.CorrectnessStatus.OUTSIDE_TRACKED_RANGE
            assert descendant.tracked_magnitude_bound == 0.0
            with party.partial_decrypt(descendant) as share:
                decoded = context.collective_decrypt(descendant, [share])
            assert np.array_equal(decoded, np.zeros(1))
"""
    completed = subprocess.run(
        [sys.executable, "-c", program, str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_identity_operations_preserve_tracking_with_independent_handles() -> None:
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), workers=1)
        )
        party = stack.enter_context(mkckks.Party.generate(context, "tracking-identities"))
        ciphertext = stack.enter_context(party.encrypt(np.array([0.25, -0.5, 0.75])))
        zero = stack.enter_context(context.encode(np.zeros(3)))
        evaluator = mkckks.Evaluator(context)
        results = [
            stack.enter_context(evaluator.add(ciphertext, 0.0)),
            stack.enter_context(evaluator.subtract(ciphertext, -0.0)),
            stack.enter_context(evaluator.add(ciphertext, zero)),
            stack.enter_context(evaluator.multiply_scalar(ciphertext, 1.0)),
            stack.enter_context(evaluator.multiply_scalar(ciphertext, -1.0)),
            stack.enter_context(evaluator.drop_level(ciphertext, 0)),
            stack.enter_context(evaluator.rescale(ciphertext)),
            stack.enter_context(evaluator.rotate_slots(ciphertext, context.slots)),
        ]
        for result in results:
            assert result.artifact_id != ciphertext.artifact_id
            assert result.tracked_magnitude_bound == ciphertext.tracked_magnitude_bound
            assert result.tracked_error_bound == ciphertext.tracked_error_bound
            assert result.range_margin_bits == ciphertext.range_margin_bits
            assert result.correctness_status is ciphertext.correctness_status

        zeroed = stack.enter_context(evaluator.multiply_scalar(ciphertext, 0.0))
        assert zeroed.artifact_id != ciphertext.artifact_id
        assert zeroed.level == ciphertext.level
        assert zeroed.scale == ciphertext.scale
        assert zeroed.tracked_magnitude_bound == 0
        assert zeroed.tracked_error_bound == 0
        assert np.array_equal(decrypt(context, zeroed, [party]), np.zeros(3))


def test_participant_evolution_and_maximum_unicode_id() -> None:
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), workers=1)
        )
        unicode_id = "é" * 64  # 128 UTF-8 bytes, the documented maximum.
        alice = stack.enter_context(mkckks.Party.generate(context, unicode_id))
        bob = stack.enter_context(mkckks.Party.generate(context, "participant-bob"))
        with pytest.raises(mkckks.InvalidParameterError, match="duplicate party ID"):
            mkckks.Party.generate(context, unicode_id)

        evaluator = mkckks.Evaluator(context)
        alice_left = stack.enter_context(alice.encrypt(np.array([0.25, -0.5])))
        alice_right = stack.enter_context(alice.encrypt(np.array([0.125, 0.25])))
        bob_value = stack.enter_context(bob.encrypt(np.array([0.5, -0.125])))
        same_party = stack.enter_context(evaluator.add(alice_left, alice_right))
        disjoint = stack.enter_context(evaluator.add(same_party, bob_value))
        overlap = stack.enter_context(evaluator.add(disjoint, bob_value))

        assert same_party.participants == (unicode_id,)
        assert disjoint.participants == ("participant-bob", unicode_id)
        assert overlap.participants == ("participant-bob", unicode_id)
        assert_within_contract(
            context,
            overlap,
            [alice, bob],
            np.array([1.375, -0.5]),
        )


@pytest.mark.parametrize("preset", ["PN14QP439", "PN15QP880"])
def test_array_layout_and_numeric_edge_patterns(preset: str) -> None:
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset(preset), workers=2)
        )
        party = stack.enter_context(mkckks.Party.generate(context, f"tracking-layout-{preset}"))
        base = np.arange(24, dtype=np.float64).reshape(4, 6) / 32
        readonly = base.copy()
        readonly.flags.writeable = False
        impulse = np.zeros(32, dtype=np.complex128)
        impulse[17] = -0.75 + 0.5j
        phases = np.exp(1j * np.linspace(-math.pi, math.pi, 31, endpoint=False))
        patterns = [
            np.array(0.25, dtype=np.float64),
            base.T,
            np.asfortranarray(base),
            readonly,
            np.array([0.25, -0.5, 0.75], dtype=">f8"),
            np.array([0.0, -0.0, np.nextafter(0.0, 1.0), np.finfo(np.float64).tiny]),
            np.full(32, 0.125 - 0.25j, dtype=np.complex128),
            impulse,
            np.tile(np.array([0.5, -0.5], dtype=np.float64), 16),
            np.tile(np.array([0.75 + 0.25j, -0.75 - 0.25j]), 16),
            phases,
            np.array(
                [
                    np.nextafter(float(1 << 20), 0.0),
                    np.nextafter(float(-(1 << 20)), 0.0),
                    0.25j,
                    -0.5j,
                    complex(float(1 << 20), float(1 << 20)),
                    complex(float(-(1 << 20)), float(1 << 20)),
                ],
                dtype=np.complex128,
            ),
        ]
        for values in patterns:
            ciphertext = stack.enter_context(party.encrypt(values))
            expected = np.asarray(values).astype(
                np.complex128 if np.iscomplexobj(values) else np.float64
            )
            assert ciphertext.shape == expected.shape
            assert_within_contract(context, ciphertext, [party], expected)
            if expected.shape == ():
                restored = stack.enter_context(
                    mkckks.Ciphertext.from_bytes(context, ciphertext.to_bytes())
                )
                assert restored.shape == ()
                assert_within_contract(context, restored, [party], expected)


@pytest.mark.parametrize("preset", ["PN14QP439", "PN15QP880"])
def test_deterministic_generated_circuits(preset: str) -> None:
    default_count = 20
    env_name = "MKCKKS_CIRCUIT_COUNT_PN14" if preset == "PN14QP439" else "MKCKKS_CIRCUIT_COUNT_PN15"
    circuit_count = int(os.environ.get(env_name, default_count))
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset(preset), workers=2)
        )
        alice = stack.enter_context(mkckks.Party.generate(context, f"circuits-alice-{preset}"))
        bob = stack.enter_context(mkckks.Party.generate(context, f"circuits-bob-{preset}"))
        contributions = [
            stack.enter_context(
                party.generate_evaluation_keys(
                    relinearization=True,
                    rotations=[-1, 1, 3],
                    conjugation=True,
                )
            )
            for party in (alice, bob)
        ]
        keys = stack.enter_context(mkckks.EvaluationKeySet.combine(context, contributions))
        evaluator = mkckks.Evaluator(context, keys)
        no_keys = mkckks.Evaluator(context)
        plaintext_values = np.array(
            [0.5 + 0.125j, -0.25, 0.75 - 0.125j, 0.125j, -0.5, 0.25, 0.5j, -0.125]
        )
        plaintext = stack.enter_context(context.encode(plaintext_values))

        for circuit_index in range(circuit_count):
            rng = np.random.default_rng(0x4D4B_0000 + circuit_index)
            logical = rng.uniform(-0.25, 0.25, 8) + 1j * rng.uniform(-0.25, 0.25, 8)
            initial = logical.copy()
            expected = np.zeros(context.slots, dtype=np.complex128)
            expected[: logical.size] = logical
            ciphertext = alice.encrypt(logical)
            parties = [alice]
            trace: list[str] = []
            operation_count = int(rng.integers(3, 11))
            try:
                for _ in range(operation_count):
                    operations = ["add", "subtract", "integer", "rotate", "serialize", "drop0"]
                    if ciphertext.level > 0:
                        operations.extend(["fractional", "plaintext", "square", "drop1", "rescale"])
                    if ciphertext.level == context.max_level:
                        operations.extend(["conjugate", "aggregate"])
                    operation = operations[int(rng.integers(0, len(operations)))]
                    trace.append(operation)
                    previous = ciphertext
                    if operation == "add":
                        scalar = 0.0625 - 0.03125j
                        ciphertext = evaluator.add(previous, scalar)
                        expected[: logical.size] += scalar
                    elif operation == "subtract":
                        scalar = -0.03125 + 0.0625j
                        ciphertext = evaluator.subtract(previous, scalar)
                        expected[: logical.size] -= scalar
                    elif operation == "integer":
                        scalar = (-1.0, 0.0, 1.0, 2.0)[int(rng.integers(0, 4))]
                        ciphertext = evaluator.multiply_scalar(previous, scalar)
                        expected = expected * scalar
                    elif operation == "fractional":
                        scalar = 0.5 - 0.125j
                        ciphertext = evaluator.multiply_scalar(previous, scalar)
                        expected = expected * scalar
                    elif operation == "plaintext":
                        ciphertext = evaluator.multiply_plaintext(previous, plaintext)
                        padded_plaintext = np.zeros(context.slots, dtype=np.complex128)
                        padded_plaintext[: plaintext_values.size] = plaintext_values
                        expected = expected * padded_plaintext
                    elif operation == "square":
                        ciphertext = evaluator.multiply(previous, previous)
                        expected = expected * expected
                    elif operation == "rotate":
                        rotation = (-1, 1, 3)[int(rng.integers(0, 3))]
                        ciphertext = evaluator.rotate_slots(previous, rotation)
                        expected = np.roll(expected, -(rotation % context.slots))
                    elif operation == "conjugate":
                        ciphertext = evaluator.conjugate(previous)
                        expected = np.conj(expected)
                    elif operation == "drop1":
                        ciphertext = evaluator.drop_level(previous, 1)
                    elif operation == "drop0":
                        ciphertext = evaluator.drop_level(previous, 0)
                    elif operation == "rescale":
                        ciphertext = evaluator.rescale(previous)
                    elif operation == "aggregate":
                        addition = bob.encrypt(np.zeros(logical.size, dtype=np.complex128))
                        ciphertext = evaluator.add(previous, addition)
                        addition.close()
                        parties = [alice, bob]
                    else:
                        ciphertext = mkckks.Ciphertext.from_bytes(context, previous.to_bytes())
                    previous.close()
                    try:
                        assert_within_contract(
                            context, ciphertext, parties, expected[: logical.size]
                        )
                    except AssertionError as exc:
                        write_circuit_failure(
                            preset=preset,
                            seed=0x4D4B_0000 + circuit_index,
                            trace=trace,
                            ciphertext=ciphertext,
                            expected=expected[: logical.size],
                            initial=initial,
                        )
                        raise AssertionError(
                            f"preset={preset} seed={0x4D4B_0000 + circuit_index} "
                            f"trace={trace} level={ciphertext.level} scale={ciphertext.scale}"
                        ) from exc

                if circuit_index % 5 == 0:
                    before = ciphertext.to_bytes()
                    with pytest.raises(mkckks.MissingKeyError):
                        no_keys.multiply(ciphertext, ciphertext)
                    assert ciphertext.to_bytes() == before
                    assert_within_contract(context, ciphertext, parties, expected[: logical.size])
            finally:
                ciphertext.close()


@pytest.mark.parametrize("preset", ["PN14QP439", "PN15QP880"])
def test_ordered_operation_pairs(preset: str) -> None:
    operation_names = (
        "add",
        "subtract",
        "integer",
        "fractional",
        "plaintext",
        "square",
        "rotate",
        "conjugate",
        "drop",
        "rescale",
        "serialize",
        "aggregate",
    )
    all_pairs = list(product(operation_names, repeat=2))
    requested = int(os.environ.get("MKCKKS_OPERATION_PAIR_LIMIT", "20"))
    if 0 < requested < len(all_pairs):
        indexes = np.linspace(0, len(all_pairs) - 1, requested, dtype=np.int64)
        selected_pairs = [all_pairs[int(index)] for index in indexes]
    else:
        selected_pairs = all_pairs

    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset(preset), workers=2)
        )
        alice = stack.enter_context(mkckks.Party.generate(context, f"pairs-alice-{preset}"))
        bob = stack.enter_context(mkckks.Party.generate(context, f"pairs-bob-{preset}"))
        contributions = [
            stack.enter_context(
                party.generate_evaluation_keys(
                    relinearization=True, rotations=[1], conjugation=True
                )
            )
            for party in (alice, bob)
        ]
        keys = stack.enter_context(mkckks.EvaluationKeySet.combine(context, contributions))
        evaluator = mkckks.Evaluator(context, keys)
        plaintext_values = np.array([0.5 + 0.125j, -0.25, 0.75j, -0.125])
        plaintext = stack.enter_context(context.encode(plaintext_values))

        def apply_operation(
            name: str,
            source: mkckks.Ciphertext,
            expected: np.ndarray,
            parties: list[mkckks.Party],
        ) -> tuple[mkckks.Ciphertext, np.ndarray, list[mkckks.Party]]:
            if name == "add":
                result = evaluator.add(source, 0.0625 - 0.03125j)
                expected[:4] += 0.0625 - 0.03125j
            elif name == "subtract":
                result = evaluator.subtract(source, -0.03125 + 0.0625j)
                expected[:4] -= -0.03125 + 0.0625j
            elif name == "integer":
                result = evaluator.multiply_scalar(source, -1.0)
                expected *= -1
            elif name == "fractional":
                result = evaluator.multiply_scalar(source, 0.5 - 0.125j)
                expected *= 0.5 - 0.125j
            elif name == "plaintext":
                result = evaluator.multiply_plaintext(source, plaintext)
                factors = np.zeros(context.slots, dtype=np.complex128)
                factors[:4] = plaintext_values
                expected *= factors
            elif name == "square":
                result = evaluator.multiply(source, source)
                expected *= expected
            elif name == "rotate":
                result = evaluator.rotate_slots(source, 1)
                expected = np.roll(expected, -1)
            elif name == "conjugate":
                result = evaluator.conjugate(source)
                expected = np.conj(expected)
            elif name == "drop":
                result = evaluator.drop_level(source, 1)
            elif name == "rescale":
                result = evaluator.rescale(source)
            elif name == "serialize":
                result = mkckks.Ciphertext.from_bytes(context, source.to_bytes())
            else:
                addition = bob.encrypt(np.zeros(4, dtype=np.complex128))
                if addition.level != source.level:
                    lowered = evaluator.drop_level(addition, addition.level - source.level)
                    addition.close()
                    addition = lowered
                result = evaluator.add(source, addition)
                addition.close()
                parties = [alice, bob]
            return result, expected, parties

        initial_values = np.array([0.125 + 0.25j, -0.25 + 0.125j, 0.5j, -0.375])
        for first, second in selected_pairs:
            expected = np.zeros(context.slots, dtype=np.complex128)
            expected[:4] = initial_values
            parties = [alice]
            current = alice.encrypt(initial_values)
            try:
                previous = current
                current, expected, parties = apply_operation(first, previous, expected, parties)
                previous.close()
                assert_within_contract(context, current, parties, expected[:4])
                before = current.to_bytes()
                try:
                    result, expected, parties = apply_operation(second, current, expected, parties)
                except mkckks.LevelError:
                    assert second == "conjugate" and current.level < context.max_level
                    assert current.to_bytes() == before
                    assert_within_contract(context, current, parties, expected[:4])
                else:
                    current.close()
                    current = result
                    assert_within_contract(context, current, parties, expected[:4])
            finally:
                current.close()
