from __future__ import annotations

import warnings

import numpy as np
import pytest

import mkckks
from mkckks._artifacts import pack, unpack
from tests.conftest import decrypt
from tests.precision_model import addition, assert_precision, local, scalar, transform
from tests.precision_model import product as propagated_product


def test_real_and_complex_addition(context: mkckks.Context) -> None:
    alice = mkckks.Party.generate(context, "alice-add")
    bob = mkckks.Party.generate(context, "bob-add")
    x = np.array([[1.25, -2.5], [3.75, 0.125]], dtype=np.float32)
    y = np.array([[2 + 1j, 4 - 2j], [-1 + 0.5j, 3 + 0j]], dtype=np.complex64)
    ca, cb = alice.encrypt(x), bob.encrypt(y)
    result = mkckks.Evaluator(context).add(ca, cb)
    assert result.dtype == np.dtype(np.complex128)
    assert result.shape == x.shape
    assert result.participants == ("alice-add", "bob-add")
    bound = addition(result, local(ca), local(cb))
    assert_precision(decrypt(context, result, [alice, bob]), x + y, bound)


def test_scalar_and_plaintext_multiplication(context: mkckks.Context) -> None:
    alice = mkckks.Party.generate(context, "alice-plain")
    x = np.array([0.25 + 0.5j, -0.75 + 0.125j])
    factors = np.array([2 - 0.5j, -1 + 0.25j])
    ciphertext = alice.encrypt(x)
    ciphertext_error = local(ciphertext)
    evaluator = mkckks.Evaluator(context)
    scaled = evaluator.multiply_scalar(ciphertext, 2.5 - 0.25j)
    assert_precision(
        decrypt(context, scaled, [alice]),
        x * (2.5 - 0.25j),
        scalar(scaled, ciphertext_error, 2.5 - 0.25j, fractional=True),
    )
    plaintext = context.encode(factors)
    multiplied = evaluator.multiply_plaintext(ciphertext, plaintext)
    assert multiplied.level == ciphertext.level - 1
    assert_precision(
        decrypt(context, multiplied, [alice]),
        x * factors,
        propagated_product(multiplied, x, factors, ciphertext_error, local(context.parameters)),
    )


def test_ciphertext_multiplication_rotation_and_conjugation(context: mkckks.Context) -> None:
    alice = mkckks.Party.generate(context, "alice-eval")
    bob = mkckks.Party.generate(context, "bob-eval")
    x = np.array([0.25 + 0.5j, -0.5 + 0.25j, 0.75 - 0.125j])
    y = np.array([0.5 - 0.25j, 0.125 + 0.5j, -0.25 + 0.75j])
    contributions = [
        party.generate_evaluation_keys(relinearization=True, rotations=[1], conjugation=True)
        for party in (alice, bob)
    ]
    keys = mkckks.EvaluationKeySet.combine(context, contributions)
    evaluator = mkckks.Evaluator(context, keys)
    encrypted_x = alice.encrypt(x)
    encrypted_y = bob.encrypt(y)
    summed = evaluator.add(encrypted_x, encrypted_y)
    summed_error = addition(summed, local(encrypted_x), local(encrypted_y))
    product = evaluator.multiply(summed, summed)
    assert product.level == summed.level - 1
    product_bound = product_error = propagated_product(
        product, x + y, x + y, summed_error, summed_error
    )
    assert_precision(decrypt(context, product, [alice, bob]), (x + y) ** 2, product_bound)
    rescaled = evaluator.rescale(product)
    assert rescaled.level == product.level
    assert rescaled.artifact_id != product.artifact_id
    assert_precision(
        decrypt(context, rescaled, [alice, bob]),
        (x + y) ** 2,
        transform(rescaled, product_error),
    )
    conjugated = evaluator.conjugate(summed)
    assert_precision(
        decrypt(context, conjugated, [alice, bob]),
        np.conj(x + y),
        transform(conjugated, summed_error, mkckks.PrecisionClass.ROTATION),
    )
    dropped = evaluator.drop_level(summed)
    dropped_error = transform(dropped, summed_error)
    rotated = evaluator.rotate_slots(dropped, 1)
    expected = np.zeros_like(x)
    expected[:-1] = (x + y)[1:]
    assert_precision(
        decrypt(context, rotated, [alice, bob]),
        expected,
        transform(rotated, dropped_error, mkckks.PrecisionClass.ROTATION),
    )


def test_validation_and_share_binding(context: mkckks.Context) -> None:
    with pytest.raises(mkckks.InvalidDTypeError):
        context.encode(np.array([1, 2], dtype=np.int64))
    with pytest.raises(mkckks.InvalidParameterError):
        context.encode(np.array([np.nan]))
    alice = mkckks.Party.generate(context, "alice-binding")
    first, second = alice.encrypt([1.0]), alice.encrypt([2.0])
    wrong_share = alice.partial_decrypt(first)
    with pytest.raises(mkckks.MissingShareError, match="different ciphertext"):
        context.collective_decrypt(second, [wrong_share])

    with pytest.raises(mkckks.InvalidParameterError, match="duplicate party ID"):
        mkckks.Party.generate(context, "alice-binding")


def test_closed_handle(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "alice-close")
    party.close()
    with pytest.raises(mkckks.ClosedHandleError):
        party.encrypt([1.0])


def test_serialization_metadata_validation(context: mkckks.Context) -> None:
    with pytest.raises(mkckks.SerializationError, match="parameters must be an object"):
        mkckks.Context.from_bytes(pack("context", {}, b"unused"))
    with pytest.raises(mkckks.SerializationError, match="parameters are invalid"):
        mkckks.Context.from_bytes(pack("context", {"parameters": {}}, b"unused"))
    with pytest.raises(mkckks.SerializationError, match="party_id must be a string"):
        mkckks.EvaluationKeyContribution.from_bytes(
            context, pack("evaluation_key_contribution", {}, b"unused")
        )
    with pytest.raises(mkckks.SerializationError, match="party_id is invalid"):
        mkckks.EvaluationKeyContribution.from_bytes(
            context,
            pack("evaluation_key_contribution", {"party_id": ""}, b"unused"),
        )

    party = mkckks.Party.generate(context, "metadata-validation")
    plaintext = context.encode([1 + 0.25j])
    _, plaintext_native = unpack(plaintext.to_bytes(), "plaintext")
    with pytest.raises(mkckks.SerializationError, match="complex flag"):
        mkckks.Plaintext.from_bytes(
            context,
            pack("plaintext", {"shape": [1], "complex": "yes"}, plaintext_native),
        )

    ciphertext = party.encrypt([1.0])
    _, ciphertext_native = unpack(ciphertext.to_bytes(), "ciphertext")
    with pytest.raises(mkckks.SerializationError, match="shape"):
        mkckks.Ciphertext.from_bytes(context, pack("ciphertext", {}, ciphertext_native))

    share = party.partial_decrypt(ciphertext)
    share_metadata, share_native = unpack(share.to_bytes(), "decryption_share")
    share_metadata["artifact_id"] = "not-an-artifact-id"
    with pytest.raises(mkckks.SerializationError, match="ciphertext ID"):
        mkckks.DecryptionShare.from_bytes(
            context, pack("decryption_share", share_metadata, share_native)
        )


@pytest.mark.slow
def test_versioned_serialization_round_trip(context: mkckks.Context) -> None:
    alice = mkckks.Party.generate(context, "alice-serialize")
    values = np.array([[1 + 2j, 3 - 1j], [0.5 + 0.25j, -2 + 0j]])
    ciphertext = alice.encrypt(values)
    context_bytes = context.to_bytes()
    restored_context = mkckks.Context.from_bytes(context_bytes)
    context_metadata, context_native = unpack(context_bytes, "context")
    context_metadata["parameters"]["scale"] /= 2
    with pytest.raises(mkckks.SerializationError, match="does not match native context"):
        mkckks.Context.from_bytes(pack("context", context_metadata, context_native))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        restored_party = mkckks.Party.from_private_state(
            restored_context, alice.export_private_state()
        )
    restored_ciphertext = mkckks.Ciphertext.from_bytes(restored_context, ciphertext.to_bytes())
    share = restored_party.partial_decrypt(restored_ciphertext)
    restored_share = mkckks.DecryptionShare.from_bytes(restored_context, share.to_bytes())
    assert_precision(
        restored_context.collective_decrypt(restored_ciphertext, [restored_share]),
        values,
        local(restored_ciphertext),
    )

    # Context replicas may exchange artifacts for the same public key. The
    # bridge must preserve that identity while rejecting a fresh, same-name key.
    restored_public = mkckks.PublicKey.from_bytes(restored_context, alice.public_key.to_bytes())
    cross_context = mkckks.Evaluator(context).add(
        ciphertext, restored_public.encrypt(np.ones_like(values))
    )
    cross_share = alice.partial_decrypt(cross_context)
    assert_precision(
        context.collective_decrypt(cross_context, [cross_share]),
        values + 1,
        addition(cross_context, local(ciphertext), local(context.parameters)),
    )

    other_replica = mkckks.Context.from_bytes(context_bytes)
    impostor = mkckks.Party.generate(other_replica, "alice-serialize")
    with pytest.raises(mkckks.MissingKeyError, match="different public keys") as collision:
        mkckks.Evaluator(context).add(ciphertext, impostor.encrypt(values))
    assert isinstance(collision.value, mkckks.MKCKKSError)
    with pytest.raises(mkckks.MissingShareError, match="different public key") as wrong_share:
        impostor.partial_decrypt(ciphertext)
    assert isinstance(wrong_share.value, mkckks.MKCKKSError)


def test_parameter_validation() -> None:
    with pytest.raises(mkckks.InvalidParameterError):
        mkckks.Parameters.from_literal(
            log_n=14, log_slots=14, q=[17], p=[19, 23], scale=2.0, sigma=3.2
        )
