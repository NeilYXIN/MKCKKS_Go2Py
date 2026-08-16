# SPDX-License-Identifier: MIT
from __future__ import annotations

from contextlib import ExitStack

import numpy as np
import pytest

import mkckks
from tests.conftest import decrypt

pytestmark = pytest.mark.release


def assert_precision(actual: np.ndarray, expected: np.ndarray, bound: float) -> None:
    report = mkckks.measure_precision(actual, expected)
    assert report.maximum_real_error <= bound
    assert report.maximum_imaginary_error <= bound


@pytest.mark.parametrize("preset", ["PN14QP439", "PN15QP880"])
def test_pairwise_dtype_shape_and_mixed_operand_matrix(preset: str) -> None:
    cases = [
        (np.float32, (1,)),
        (np.float64, (2, 3)),
        (np.complex64, (2, 2, 2)),
        (np.complex128, (1, 2, 1, 2, 2)),
    ]
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset(preset), workers=2)
        )
        party = stack.enter_context(mkckks.Party.generate(context, f"matrix-{preset}"))
        public_key = stack.enter_context(party.public_key)
        for index, (dtype, shape) in enumerate(cases):
            count = int(np.prod(shape))
            real = np.linspace(-0.75, 0.75, count).reshape(shape)
            values = real if np.issubdtype(dtype, np.floating) else real + 0.25j * real[::-1]
            normalized = np.asarray(values, dtype=dtype)
            ciphertext = stack.enter_context(
                party.encrypt(normalized) if index % 2 == 0 else public_key.encrypt(normalized)
            )
            expected = normalized.astype(
                np.complex128 if np.issubdtype(dtype, np.complexfloating) else np.float64
            )
            assert ciphertext.shape == shape
            assert_precision(
                decrypt(context, ciphertext, [party]),
                expected,
                mkckks.precision_bound(ciphertext, mkckks.PrecisionClass.BASIC),
            )

        mixed_real = np.linspace(-0.5, 0.5, 12, dtype=np.float32).reshape(3, 4)
        complex_values = (mixed_real + 0.125j).astype(np.complex64)
        left = stack.enter_context(party.encrypt(mixed_real))
        right = stack.enter_context(party.encrypt(complex_values))
        result = stack.enter_context(mkckks.Evaluator(context).add(left, right))
        bound = (
            mkckks.precision_bound(left, mkckks.PrecisionClass.BASIC)
            + mkckks.precision_bound(right, mkckks.PrecisionClass.BASIC)
            + mkckks.precision_bound(result, mkckks.PrecisionClass.BASIC)
        )
        assert result.dtype == np.dtype(np.complex128)
        assert_precision(decrypt(context, result, [party]), mixed_real + complex_values, bound)


@pytest.mark.parametrize("preset", ["PN14QP439", "PN15QP880"])
def test_chunk_boundaries_and_validated_magnitudes(preset: str) -> None:
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset(preset), workers=4)
        )
        party = stack.enter_context(mkckks.Party.generate(context, f"boundaries-{preset}"))
        sizes = [
            1,
            context.slots - 1,
            context.slots,
            context.slots + 1,
            2 * context.slots,
            2 * context.slots + 3,
        ]
        if preset == "PN14QP439":
            sizes.append(8 * context.slots)
        for size in sizes:
            values = np.linspace(-1.0, 1.0, size, dtype=np.float64)
            ciphertext = party.encrypt(values)
            try:
                assert ciphertext.chunks == (size + context.slots - 1) // context.slots
                assert_precision(
                    decrypt(context, ciphertext, [party]),
                    values,
                    mkckks.precision_bound(ciphertext, mkckks.PrecisionClass.BASIC),
                )
            finally:
                ciphertext.close()

        boundary_values = np.array(
            [0.0, -0.0, 2**-30, -(2**-30), 1.0, -1.0, 2**20, -(2**20)],
            dtype=np.float64,
        )
        boundary_ciphertext = stack.enter_context(party.encrypt(boundary_values))
        assert_precision(
            decrypt(context, boundary_ciphertext, [party]),
            boundary_values,
            mkckks.precision_bound(boundary_ciphertext, mkckks.PrecisionClass.BASIC),
        )


@pytest.mark.parametrize("preset", ["PN14QP439", "PN15QP880"])
def test_full_slot_rotation_matrix(preset: str) -> None:
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset(preset), workers=2)
        )
        party = stack.enter_context(mkckks.Party.generate(context, f"rotations-{preset}"))
        rotations = [0, 1, -1, 2, 3, context.slots - 1, context.slots, context.slots + 1]
        rotations.extend([-(1 << 31), (1 << 31) - 1])
        contribution = stack.enter_context(party.generate_evaluation_keys(rotations=rotations))
        keyset = stack.enter_context(mkckks.EvaluationKeySet.combine(context, [contribution]))
        evaluator = mkckks.Evaluator(context, keyset)
        values = (np.arange(context.slots, dtype=np.float64) % 257 - 128) / 256.0
        ciphertext = stack.enter_context(party.encrypt(values))
        incoming = mkckks.precision_bound(ciphertext, mkckks.PrecisionClass.BASIC)
        for rotation in rotations:
            rotated = stack.enter_context(evaluator.rotate_slots(ciphertext, rotation))
            local_class = (
                mkckks.PrecisionClass.BASIC
                if rotation % context.slots == 0
                else mkckks.PrecisionClass.ROTATION
            )
            bound = incoming + mkckks.precision_bound(rotated, local_class)
            assert_precision(
                decrypt(context, rotated, [party]),
                np.roll(values, -(rotation % context.slots)),
                bound,
            )


@pytest.mark.parametrize("preset", ["PN14QP439", "PN15QP880"])
@pytest.mark.parametrize("party_count", [1, 2, 4, 8])
def test_collective_decryption_release_matrix(preset: str, party_count: int) -> None:
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset(preset), workers=2)
        )
        parties = [
            stack.enter_context(mkckks.Party.generate(context, f"collective-{index}"))
            for index in range(party_count)
        ]
        values = np.array([0.125 + 0.25j, -0.5 + 0.125j, 0.75 - 0.25j])
        evaluator = mkckks.Evaluator(context)
        ciphertext = stack.enter_context(parties[0].encrypt(values))
        error = mkckks.precision_bound(ciphertext, mkckks.PrecisionClass.BASIC)
        for party in parties[1:]:
            addition = stack.enter_context(party.encrypt(np.zeros_like(values)))
            added = stack.enter_context(evaluator.add(ciphertext, addition))
            error += mkckks.precision_bound(addition, mkckks.PrecisionClass.BASIC)
            error += mkckks.precision_bound(added, mkckks.PrecisionClass.BASIC)
            ciphertext = added
        assert ciphertext.participants == tuple(party.party_id for party in parties)
        assert_precision(decrypt(context, ciphertext, parties), values, error)
