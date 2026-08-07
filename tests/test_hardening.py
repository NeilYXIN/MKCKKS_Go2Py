# SPDX-License-Identifier: MIT
from __future__ import annotations

import warnings

import numpy as np
import pytest

import mkckks
from mkckks._artifacts import pack, unpack
from tests.precision_model import assert_precision, local


def decrypt_one(
    context: mkckks.Context, party: mkckks.Party, ciphertext: mkckks.Ciphertext
) -> np.ndarray:
    with party.partial_decrypt(ciphertext) as share:
        return context.collective_decrypt(ciphertext, [share])


def test_precision_contract_and_randomized_encryption(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "hardening-precision")
    values = np.array([0.125 + 0.25j, -0.5 + 0.125j, 0.75 - 0.25j])
    ciphertexts = [party.encrypt(values) for _ in range(8)]
    try:
        assert len({ciphertext.artifact_id for ciphertext in ciphertexts}) == len(ciphertexts)
        assert len({ciphertext.to_bytes() for ciphertext in ciphertexts}) == len(ciphertexts)
        bound = mkckks.precision_bound(context.parameters, mkckks.PrecisionClass.BASIC)
        for ciphertext in ciphertexts:
            report = mkckks.measure_precision(decrypt_one(context, party, ciphertext), values)
            assert report.maximum_real_error <= bound
            assert report.maximum_imaginary_error <= bound
    finally:
        for ciphertext in ciphertexts:
            ciphertext.close()


def test_rotation_and_rescale_reject_before_upstream_panic(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "hardening-rotation")
    ciphertext = party.encrypt([1.0, 2.0, 3.0, 4.0])
    evaluator = mkckks.Evaluator(context)
    with pytest.raises(mkckks.InvalidParameterError, match="rotation must be an integer"):
        party.generate_evaluation_keys(rotations=[1.5])
    with pytest.raises(mkckks.InvalidParameterError, match="rotation must be an integer"):
        evaluator.rotate_slots(ciphertext, True)
    identity = evaluator.rotate_slots(ciphertext, context.slots)
    assert_precision(
        decrypt_one(context, party, identity),
        [1.0, 2.0, 3.0, 4.0],
        local(ciphertext),
    )
    with pytest.raises(mkckks.LevelError, match="consume all remaining levels"):
        evaluator.rescale(ciphertext, 1e-300)

    contribution = party.generate_evaluation_keys(relinearization=True)
    keyset = mkckks.EvaluationKeySet.combine(context, [contribution])
    product = mkckks.Evaluator(context, keyset).multiply(ciphertext, ciphertext)
    with pytest.raises(mkckks.LevelError, match="below supported minimum"):
        evaluator.rescale(product, 1.0)


def test_validated_input_policy_and_resource_limits() -> None:
    parameters = mkckks.Parameters.preset("PN14QP439")
    context = mkckks.Context.create(parameters, workers=1)
    party = mkckks.Party.generate(context, "hardening-limits")
    with pytest.raises(mkckks.InvalidParameterError, match="validated bound"):
        party.encrypt([float((1 << 20) + 1)])
    context.close()

    with pytest.warns(RuntimeWarning, match="correctness-certified"):
        expert = mkckks.Context.create(
            parameters, workers=1, input_policy=mkckks.InputPolicy.EXPERT
        )
    expert_party = mkckks.Party.generate(expert, "hardening-expert")
    with pytest.warns(RuntimeWarning, match="outside"):
        ciphertext = expert_party.encrypt([float((1 << 20) + 1)])
    ciphertext.close()
    expert.close()

    limited = mkckks.Context.create(
        parameters,
        workers=1,
        limits=mkckks.ResourceLimits(max_chunks=1, max_values=2),
    )
    limited_party = mkckks.Party.generate(limited, "hardening-resource")
    with pytest.raises(mkckks.InvalidParameterError, match="at most 2"):
        limited_party.encrypt([1.0, 2.0, 3.0])
    limited.close()


def test_native_metadata_cannot_be_relabelled(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "hardening-metadata")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        private = party.export_private_state()
    metadata, native = unpack(private, "private_party")
    metadata["party_id"] = "different-valid-party"
    restored_context = mkckks.Context.from_bytes(context.to_bytes())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        with pytest.raises(mkckks.SerializationError, match="does not match"):
            mkckks.Party.from_private_state(
                restored_context, pack("private_party", metadata, native)
            )
    restored_context.close()

    plaintext = context.encode([1.0, 2.0])
    plain_metadata, plain_native = unpack(plaintext.to_bytes(), "plaintext")
    plain_metadata["complex"] = True
    with pytest.raises(mkckks.SerializationError, match="complex metadata"):
        mkckks.Plaintext.from_bytes(context, pack("plaintext", plain_metadata, plain_native))


def test_serialization_is_canonical(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "hardening-canonical")
    public_key = party.public_key
    ciphertext = party.encrypt([1.0])
    objects = [context, public_key, ciphertext]
    assert all(value.to_bytes() == value.to_bytes() for value in objects)


def test_scalar_broadcast_does_not_fill_padding_exposed_by_rotation(
    context: mkckks.Context,
) -> None:
    party = mkckks.Party.generate(context, "hardening-scalar-padding")
    contribution = party.generate_evaluation_keys(rotations=[1])
    keys = mkckks.EvaluationKeySet.combine(context, [contribution])
    evaluator = mkckks.Evaluator(context, keys)
    values = np.array([0.125, -0.25, 0.5, -0.75])
    ciphertext = party.encrypt(values)
    added = evaluator.add(ciphertext, 0.375)
    rotated = evaluator.rotate_slots(added, 1)
    expected = np.array([0.125, 0.875, -0.375, 0.0])
    incoming = mkckks.precision_bound(ciphertext, mkckks.PrecisionClass.BASIC)
    scalar_encoded = mkckks.precision_bound(context.parameters, mkckks.PrecisionClass.BASIC)
    add_bound = (
        incoming + scalar_encoded + mkckks.precision_bound(added, mkckks.PrecisionClass.BASIC)
    )
    bound = add_bound + mkckks.precision_bound(rotated, mkckks.PrecisionClass.ROTATION)
    report = mkckks.measure_precision(decrypt_one(context, party, rotated), expected)
    assert report.maximum_real_error <= bound
    assert report.maximum_imaginary_error <= bound


def test_generated_concatenated_operation_sequence_tracks_state(
    context: mkckks.Context,
) -> None:
    party = mkckks.Party.generate(context, "hardening-operation-sequence")
    contribution = party.generate_evaluation_keys(
        relinearization=True, rotations=[1], conjugation=True
    )
    keys = mkckks.EvaluationKeySet.combine(context, [contribution])
    evaluator = mkckks.Evaluator(context, keys)
    values = np.array([0.125 + 0.25j, -0.25 + 0.125j, 0.5 - 0.25j, -0.375j])
    offset = np.array([0.125j, -0.0625, 0.25 - 0.125j, 0.5])
    ciphertext = party.encrypt(values)
    expected = values.copy()
    error = mkckks.precision_bound(ciphertext, mkckks.PrecisionClass.BASIC)
    initial_level = ciphertext.level

    added = evaluator.add(ciphertext, 0.125 - 0.0625j)
    expected += 0.125 - 0.0625j
    error += mkckks.precision_bound(context.parameters, mkckks.PrecisionClass.BASIC)
    error += mkckks.precision_bound(added, mkckks.PrecisionClass.BASIC)
    assert added.level == initial_level

    conjugated = evaluator.conjugate(added)
    expected = np.conj(expected)
    error += mkckks.precision_bound(conjugated, mkckks.PrecisionClass.ROTATION)

    scalar = 0.75 - 0.125j
    scaled = evaluator.multiply_scalar(conjugated, scalar)
    expected *= scalar
    error = abs(scalar) * error + mkckks.precision_bound(
        scaled, mkckks.PrecisionClass.MULTIPLICATION
    )
    assert scaled.level == initial_level - 1

    encoded = context.encode(offset)
    offset_error = mkckks.precision_bound(context.parameters, mkckks.PrecisionClass.BASIC)
    shifted = evaluator.add(scaled, encoded)
    expected += offset
    error += offset_error + mkckks.precision_bound(shifted, mkckks.PrecisionClass.BASIC)
    assert shifted.level == scaled.level

    with pytest.raises(mkckks.LevelError, match="only at the maximum level"):
        evaluator.conjugate(shifted)
    rotated = evaluator.rotate_slots(shifted, 1)
    expected = np.concatenate((expected[1:], np.zeros(1, dtype=np.complex128)))
    error += mkckks.precision_bound(rotated, mkckks.PrecisionClass.ROTATION)

    dropped = evaluator.drop_level(rotated, 1)
    error += mkckks.precision_bound(dropped, mkckks.PrecisionClass.BASIC)
    assert dropped.level == initial_level - 2

    squared = evaluator.multiply(dropped, dropped)
    maximum = float(np.max(np.abs(expected)))
    error = (
        2 * maximum * error
        + error * error
        + mkckks.precision_bound(squared, mkckks.PrecisionClass.MULTIPLICATION)
    )
    expected *= expected
    assert squared.level == initial_level - 3
    assert squared.participants == (party.party_id,)
    assert squared.dtype == np.dtype(np.complex128)
    assert squared.chunks == 1
    report = mkckks.measure_precision(decrypt_one(context, party, squared), expected)
    assert report.maximum_real_error <= error
    assert report.maximum_imaginary_error <= error
