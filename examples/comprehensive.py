# SPDX-License-Identifier: MIT
"""Comprehensive, executable MKCKKS tutorial and correctness demonstration."""

from __future__ import annotations

import argparse
import json
import math
import platform
import warnings
from collections.abc import Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt

import mkckks

Array = npt.NDArray[Any]
PRECISION_RECORDS: list[dict[str, Any]] = []


def heading(title: str) -> None:
    print(f"\n{'=' * 88}\n{title}\n{'=' * 88}")


def preview(values: Array, limit: int = 8) -> str:
    flat = np.asarray(values).reshape(-1)
    shown = flat[:limit]
    suffix = f" ... ({flat.size} values total)" if flat.size > limit else ""
    return np.array2string(shown, precision=8, suppress_small=False) + suffix


def check_result(
    name: str,
    actual: Array,
    expected: Array,
    *,
    bound: float,
) -> None:
    actual_array = np.asarray(actual)
    expected_array = np.asarray(expected)
    report = mkckks.measure_precision(actual_array, expected_array)
    print(f"\n[{name}]")
    print(f"  expected : {preview(expected_array)}")
    print(f"  decrypted: {preview(actual_array)}")
    print(
        f"  max real error={report.maximum_real_error:.3e}; "
        f"max imaginary error={report.maximum_imaginary_error:.3e}; "
        f"RMS error={report.rms_error:.3e}; "
        f"minimum precision={report.minimum_precision_bits:.2f} bits; "
        f"propagated bound={bound:.3e}"
    )
    if report.maximum_component_error > bound:
        raise AssertionError(
            f"{name}: component error {report.maximum_component_error:.3e} "
            f"exceeds propagated CKKS bound {bound:.3e}"
        )
    PRECISION_RECORDS.append(
        {
            "operation": name,
            "maximum_real_error": report.maximum_real_error,
            "maximum_imaginary_error": report.maximum_imaginary_error,
            "rms_error": report.rms_error,
            "minimum_precision_bits": (
                report.minimum_precision_bits
                if math.isfinite(report.minimum_precision_bits)
                else None
            ),
            "sample_count": report.sample_count,
            "propagated_bound": bound,
            "passed": True,
        }
    )
    print("  status   : PASS")


def primitive_bound(
    source: mkckks.Parameters | mkckks.Ciphertext,
    operation: mkckks.PrecisionClass,
) -> float:
    return mkckks.precision_bound(source, operation)


def add_error(result: mkckks.Ciphertext, *incoming: float) -> float:
    return sum(incoming) + primitive_bound(result, mkckks.PrecisionClass.BASIC)


def transform_error(
    result: mkckks.Ciphertext,
    incoming: float,
    operation: mkckks.PrecisionClass,
) -> float:
    return incoming + primitive_bound(result, operation)


def scalar_error(
    result: mkckks.Ciphertext,
    incoming: float,
    scalar: complex,
    *,
    fractional: bool,
) -> float:
    operation = mkckks.PrecisionClass.MULTIPLICATION if fractional else mkckks.PrecisionClass.BASIC
    return abs(scalar) * incoming + primitive_bound(result, operation)


def product_error(
    result: mkckks.Ciphertext,
    left: Array,
    right: Array,
    left_error: float,
    right_error: float,
) -> float:
    left_magnitude = float(np.max(np.abs(np.asarray(left))))
    right_magnitude = float(np.max(np.abs(np.asarray(right))))
    return (
        right_magnitude * left_error
        + left_magnitude * right_error
        + left_error * right_error
        + primitive_bound(result, mkckks.PrecisionClass.MULTIPLICATION)
    )


def show_ciphertext(label: str, ciphertext: mkckks.Ciphertext) -> None:
    print(
        f"  {label}: shape={ciphertext.shape}, dtype={ciphertext.dtype}, "
        f"participants={ciphertext.participants}, chunks={ciphertext.chunks}, "
        f"level={ciphertext.level}, scale={ciphertext.scale:.6e}, "
        f"status={ciphertext.correctness_status.value}, "
        f"tracked_magnitude={ciphertext.tracked_magnitude_bound:.3e}, "
        f"tracked_error={ciphertext.tracked_error_bound:.3e}, "
        f"range_margin={ciphertext.range_margin_bits:.2f} bits, "
        f"artifact_id={ciphertext.artifact_id}"
    )


def collective_decrypt(
    context: mkckks.Context,
    ciphertext: mkckks.Ciphertext,
    parties: Sequence[mkckks.Party],
) -> Array:
    print("  collecting decryption shares from:", ", ".join(party.party_id for party in parties))
    with ExitStack() as shares:
        contributions = [
            shares.enter_context(party.partial_decrypt(ciphertext)) for party in parties
        ]
        return context.collective_decrypt(ciphertext, contributions)


def run_serialization_demo(
    stack: ExitStack,
    context: mkckks.Context,
    alice: mkckks.Party,
    alice_public: mkckks.PublicKey,
    alice_ciphertext: mkckks.Ciphertext,
    plaintext: mkckks.Plaintext,
    plaintext_values: Array,
    alice_contribution: mkckks.EvaluationKeyContribution,
    keyset: mkckks.EvaluationKeySet,
    expected: Array,
    ciphertext_error: float,
    plaintext_error: float,
) -> None:
    heading("16. Deterministic artifact envelopes and fresh-context restoration")
    print("  Context artifacts contain the actual CRS and are intentionally large.")

    context_bytes = context.to_bytes()
    print(f"  context artifact: {len(context_bytes) / (1024**2):.2f} MiB")
    restored_context = stack.enter_context(mkckks.Context.from_bytes(context_bytes))
    del context_bytes
    print("  restored context fingerprint:", restored_context.fingerprint)
    if restored_context.fingerprint != context.fingerprint:
        raise AssertionError("restored context fingerprint changed")

    print("  SECURITY NOTE: private state below is raw and unencrypted.")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        private_bytes = alice.export_private_state()
        restored_alice = stack.enter_context(
            mkckks.Party.from_private_state(restored_context, private_bytes)
        )
    print(f"  private party artifact: {len(private_bytes) / (1024**2):.2f} MiB")
    del private_bytes

    public_bytes = alice_public.to_bytes()
    restored_public = stack.enter_context(
        mkckks.PublicKey.from_bytes(restored_context, public_bytes)
    )
    print(f"  public-key artifact: {len(public_bytes) / (1024**2):.2f} MiB")
    del public_bytes

    plaintext_bytes = plaintext.to_bytes()
    restored_plaintext = stack.enter_context(
        mkckks.Plaintext.from_bytes(restored_context, plaintext_bytes)
    )
    print(f"  plaintext artifact: {len(plaintext_bytes) / 1024:.2f} KiB")
    del plaintext_bytes

    ciphertext_bytes = alice_ciphertext.to_bytes()
    restored_ciphertext = stack.enter_context(
        mkckks.Ciphertext.from_bytes(restored_context, ciphertext_bytes)
    )
    print(f"  ciphertext artifact: {len(ciphertext_bytes) / (1024**2):.2f} MiB")
    del ciphertext_bytes

    contribution_bytes = alice_contribution.to_bytes()
    restored_contribution = stack.enter_context(
        mkckks.EvaluationKeyContribution.from_bytes(restored_context, contribution_bytes)
    )
    print(f"  evaluation-key contribution: {len(contribution_bytes) / (1024**2):.2f} MiB")
    del contribution_bytes

    keyset_bytes = keyset.to_bytes()
    restored_keyset = stack.enter_context(
        mkckks.EvaluationKeySet.from_bytes(restored_context, keyset_bytes)
    )
    print(f"  evaluation-key set: {len(keyset_bytes) / (1024**2):.2f} MiB")
    del keyset_bytes

    original_share = stack.enter_context(alice.partial_decrypt(alice_ciphertext))
    share_bytes = original_share.to_bytes()
    restored_share = stack.enter_context(
        mkckks.DecryptionShare.from_bytes(restored_context, share_bytes)
    )
    print(f"  decryption-share artifact: {len(share_bytes) / (1024**2):.2f} MiB")
    del share_bytes

    decoded = restored_context.collective_decrypt(restored_ciphertext, [restored_share])
    check_result(
        "fresh-context ciphertext/share round trip",
        decoded,
        expected,
        bound=ciphertext_error,
    )

    public_ciphertext = stack.enter_context(restored_public.encrypt(expected))
    public_decoded = collective_decrypt(restored_context, public_ciphertext, [restored_alice])
    public_error = primitive_bound(public_ciphertext, mkckks.PrecisionClass.BASIC)
    check_result("restored public-key encryption", public_decoded, expected, bound=public_error)

    restored_evaluator = mkckks.Evaluator(restored_context, restored_keyset)
    restored_added = stack.enter_context(
        restored_evaluator.add(restored_ciphertext, restored_plaintext)
    )
    restored_added_decoded = collective_decrypt(restored_context, restored_added, [restored_alice])
    check_result(
        "restored reusable plaintext and key set",
        restored_added_decoded,
        expected + plaintext_values,
        bound=add_error(restored_added, ciphertext_error, plaintext_error),
    )

    single_party_keys = stack.enter_context(
        mkckks.EvaluationKeySet.combine(restored_context, [restored_contribution])
    )
    restored_rotated = stack.enter_context(
        mkckks.Evaluator(restored_context, single_party_keys).rotate_slots(restored_ciphertext, 1)
    )
    rotation_expected = np.concatenate((expected.reshape(-1)[1:], np.zeros(1))).reshape(
        expected.shape
    )
    check_result(
        "restored evaluation-key contribution",
        collective_decrypt(restored_context, restored_rotated, [restored_alice]),
        rotation_expected,
        bound=transform_error(restored_rotated, ciphertext_error, mkckks.PrecisionClass.ROTATION),
    )


def run(
    preset: str,
    workers: int,
    include_serialization: bool,
    report_path: Path | None = None,
) -> None:
    PRECISION_RECORDS.clear()
    np.set_printoptions(precision=8, suppress=False)
    heading("MKCKKS comprehensive real/complex and multi-party tutorial")
    print(f"Preset={preset}; workers={workers}")
    print("Presets are upstream-tested, not independently security-vetted.")

    parameters = mkckks.Parameters.preset(preset)
    literal_copy = mkckks.Parameters.from_literal(
        log_n=parameters.log_n,
        log_slots=parameters.log_slots,
        q=parameters.q,
        p=parameters.p,
        scale=parameters.scale,
        sigma=parameters.sigma,
    )
    if literal_copy != parameters:
        raise AssertionError("expert parameter literal did not round-trip")

    with ExitStack() as stack:
        context = stack.enter_context(mkckks.Context.create(parameters, workers=workers))
        print(
            f"Context: slots={context.slots}, max_level={context.max_level}, "
            f"fingerprint={context.fingerprint}"
        )

        alice = stack.enter_context(mkckks.Party.generate(context, "alice"))
        bob = stack.enter_context(mkckks.Party.generate(context, "bob"))
        carol = stack.enter_context(mkckks.Party.generate(context, "carol"))
        parties = [alice, bob, carol]
        print("Parties:", ", ".join(party.party_id for party in parties))

        alice_values = np.array([[0.1, 0.2, 2.1], [-2.2, 0.75, -0.125]], dtype=np.float32)
        bob_values = np.array(
            [[0.2 + 0.1j, 0.3 - 0.2j, 1.2], [-1.2 + 0.5j, 0.5j, 0.25]],
            dtype=np.complex64,
        )
        carol_values = np.array(
            [[0.3 - 0.2j, 0.5, 1.5 + 0.125j], [-1.5, 0.25 - 0.5j, 0.75]],
            dtype=np.complex128,
        )
        alice_expected = alice_values.astype(np.float64)
        bob_expected = bob_values.astype(np.complex128)
        carol_expected = carol_values.astype(np.complex128)

        alice_public = stack.enter_context(alice.public_key)
        bob_public = stack.enter_context(bob.public_key)
        alice_ct = stack.enter_context(alice.encrypt(alice_values))
        bob_ct = stack.enter_context(bob_public.encrypt(bob_values))
        carol_ct = stack.enter_context(carol.encrypt(carol_values))
        alice_error = primitive_bound(alice_ct, mkckks.PrecisionClass.BASIC)
        bob_error = primitive_bound(bob_ct, mkckks.PrecisionClass.BASIC)
        carol_error = primitive_bound(carol_ct, mkckks.PrecisionClass.BASIC)

        heading("1. Party encryption, public-key encryption, and collective decryption")
        show_ciphertext("Alice real ciphertext", alice_ct)
        show_ciphertext("Bob complex public-key ciphertext", bob_ct)
        check_result(
            "Alice real round trip",
            collective_decrypt(context, alice_ct, [alice]),
            alice_expected,
            bound=alice_error,
        )
        check_result(
            "Bob complex public-key round trip",
            collective_decrypt(context, bob_ct, [bob]),
            bob_expected,
            bound=bob_error,
        )
        randomized = stack.enter_context(alice_public.encrypt(alice_values))
        print(
            "  randomized encryption IDs differ:",
            alice_ct.artifact_id,
            "!=",
            randomized.artifact_id,
        )
        if alice_ct.artifact_id == randomized.artifact_id:
            raise AssertionError("independent encryptions unexpectedly reused an artifact ID")

        heading("2. Evaluation-key generation")
        contributions = [
            stack.enter_context(
                party.generate_evaluation_keys(
                    relinearization=True, rotations=[1], conjugation=True
                )
            )
            for party in parties
        ]
        keyset = stack.enter_context(mkckks.EvaluationKeySet.combine(context, contributions))
        evaluator = mkckks.Evaluator(context, keyset)
        print("  generated relinearization, rotation(+1), and conjugation keys for all parties")

        heading("3. Ciphertext addition and three-party aggregation")
        alice_bob = stack.enter_context(evaluator.add(alice_ct, bob_ct))
        alice_bob_error = add_error(alice_bob, alice_error, bob_error)
        total = stack.enter_context(evaluator.add(alice_bob, carol_ct))
        total_error = add_error(total, alice_bob_error, carol_error)
        show_ciphertext("Alice + Bob", alice_bob)
        show_ciphertext("Alice + Bob + Carol", total)
        expected_total = alice_expected + bob_expected + carol_expected
        check_result(
            "three-party ciphertext addition",
            collective_decrypt(context, total, parties),
            expected_total,
            bound=total_error,
        )

        heading("4. Ciphertext subtraction")
        subtraction = stack.enter_context(evaluator.subtract(alice_bob, bob_ct))
        subtraction_error = add_error(subtraction, alice_bob_error, bob_error)
        check_result(
            "(Alice + Bob) - Bob",
            collective_decrypt(context, subtraction, [alice, bob]),
            alice_expected,
            bound=subtraction_error,
        )

        heading("5. Scalar broadcasting: addition and subtraction")
        scalar = 0.375 - 0.125j
        scalar_added = stack.enter_context(evaluator.add(alice_bob, scalar))
        scalar_subtracted = stack.enter_context(evaluator.subtract(alice_bob, scalar))
        scalar_encoding_error = primitive_bound(parameters, mkckks.PrecisionClass.BASIC)
        scalar_added_error = add_error(alice_bob, alice_bob_error, scalar_encoding_error)
        scalar_subtracted_error = add_error(alice_bob, alice_bob_error, scalar_encoding_error)
        check_result(
            "ciphertext + complex scalar",
            collective_decrypt(context, scalar_added, [alice, bob]),
            alice_expected + bob_expected + scalar,
            bound=scalar_added_error,
        )
        check_result(
            "ciphertext - complex scalar",
            collective_decrypt(context, scalar_subtracted, [alice, bob]),
            alice_expected + bob_expected - scalar,
            bound=scalar_subtracted_error,
        )

        heading("6. Reusable plaintext encoding, addition, and subtraction")
        offset = np.array(
            [[0.5 - 0.25j, -0.25 + 0.5j, 0.125], [1.0j, -0.5, 0.75]],
            dtype=np.complex128,
        )
        encoded_offset = stack.enter_context(context.encode(offset))
        offset_error = primitive_bound(parameters, mkckks.PrecisionClass.BASIC)
        plaintext_added = stack.enter_context(evaluator.add(alice_ct, encoded_offset))
        plaintext_subtracted = stack.enter_context(evaluator.subtract(alice_ct, encoded_offset))
        check_result(
            "ciphertext + plaintext",
            collective_decrypt(context, plaintext_added, [alice]),
            alice_expected + offset,
            bound=add_error(plaintext_added, alice_error, offset_error),
        )
        check_result(
            "ciphertext - plaintext",
            collective_decrypt(context, plaintext_subtracted, [alice]),
            alice_expected - offset,
            bound=add_error(plaintext_subtracted, alice_error, offset_error),
        )

        heading("7. Real and complex scalar multiplication")
        real_scaled = stack.enter_context(evaluator.multiply_scalar(total, 2.5))
        complex_scaled = stack.enter_context(evaluator.multiply_scalar(total, 0.75 - 0.125j))
        real_scaled_error = scalar_error(real_scaled, total_error, 2.5, fractional=True)
        complex_scaled_error = scalar_error(
            complex_scaled, total_error, 0.75 - 0.125j, fractional=True
        )
        check_result(
            "ciphertext * real scalar",
            collective_decrypt(context, real_scaled, parties),
            expected_total * 2.5,
            bound=real_scaled_error,
        )
        check_result(
            "ciphertext * complex scalar",
            collective_decrypt(context, complex_scaled, parties),
            expected_total * (0.75 - 0.125j),
            bound=complex_scaled_error,
        )

        heading("8. Ciphertext/plaintext multiplication and an explicit rescale request")
        factors = np.array(
            [[1.25, -0.5 + 0.25j, 0.75], [0.5j, -1.0, 1.5 - 0.25j]],
            dtype=np.complex128,
        )
        encoded_factors = stack.enter_context(context.encode(factors))
        factors_error = primitive_bound(parameters, mkckks.PrecisionClass.BASIC)
        plaintext_product = stack.enter_context(
            evaluator.multiply_plaintext(alice_bob, encoded_factors)
        )
        plaintext_product_expected = (alice_expected + bob_expected) * factors
        plaintext_product_error = product_error(
            plaintext_product,
            alice_expected + bob_expected,
            factors,
            alice_bob_error,
            factors_error,
        )
        show_ciphertext("before rescale", plaintext_product)
        check_result(
            "ciphertext * plaintext",
            collective_decrypt(context, plaintext_product, [alice, bob]),
            plaintext_product_expected,
            bound=plaintext_product_error,
        )
        rescaled_plaintext_product = stack.enter_context(evaluator.rescale(plaintext_product))
        show_ciphertext("after rescale", rescaled_plaintext_product)
        if rescaled_plaintext_product.level == plaintext_product.level:
            print("  input was already normalized; rescale returned an immutable no-op copy")
        rescaled_plaintext_error = transform_error(
            rescaled_plaintext_product,
            plaintext_product_error,
            mkckks.PrecisionClass.BASIC,
        )
        check_result(
            "explicitly rescaled plaintext product",
            collective_decrypt(context, rescaled_plaintext_product, [alice, bob]),
            plaintext_product_expected,
            bound=rescaled_plaintext_error,
        )

        heading("9. Ciphertext/ciphertext multiplication and relinearization")
        square = stack.enter_context(evaluator.multiply(alice_bob, alice_bob))
        show_ciphertext("regular multiplication", square)
        square_expected = (alice_expected + bob_expected) ** 2
        square_error = product_error(
            square,
            alice_expected + bob_expected,
            alice_expected + bob_expected,
            alice_bob_error,
            alice_bob_error,
        )
        check_result(
            "ciphertext square",
            collective_decrypt(context, square, [alice, bob]),
            square_expected,
            bound=square_error,
        )

        heading("10. Explicit level dropping")
        dropped = stack.enter_context(evaluator.drop_level(alice_bob, 1))
        show_ciphertext("before drop", alice_bob)
        show_ciphertext("after drop", dropped)
        check_result(
            "drop one level",
            collective_decrypt(context, dropped, [alice, bob]),
            alice_expected + bob_expected,
            bound=transform_error(dropped, alice_bob_error, mkckks.PrecisionClass.BASIC),
        )

        heading("11. Rotation on a single chunk")
        rotated = stack.enter_context(evaluator.rotate_slots(alice_bob, 1))
        rotation_expected = np.concatenate(
            ((alice_expected + bob_expected).reshape(-1)[1:], np.zeros(1))
        ).reshape(alice_expected.shape)
        check_result(
            "rotate slots left by one",
            collective_decrypt(context, rotated, [alice, bob]),
            rotation_expected,
            bound=transform_error(rotated, alice_bob_error, mkckks.PrecisionClass.ROTATION),
        )

        heading("12. Conjugation")
        conjugated = stack.enter_context(evaluator.conjugate(alice_bob))
        check_result(
            "complex conjugation",
            collective_decrypt(context, conjugated, [alice, bob]),
            np.conj(alice_expected + bob_expected),
            bound=transform_error(conjugated, alice_bob_error, mkckks.PrecisionClass.ROTATION),
        )

        heading("13. Explicit blockwise rotation for a multi-chunk array")
        large_values = np.linspace(-1.0, 1.0, context.slots + 3, dtype=np.float64)
        large_ciphertext = stack.enter_context(alice.encrypt(large_values))
        large_rotated = stack.enter_context(evaluator.rotate_each_chunk(large_ciphertext, 1))
        show_ciphertext("multi-chunk input", large_ciphertext)
        first_block = np.roll(large_values[: context.slots], -1)
        final_prefix = np.array([large_values[-2], large_values[-1], 0.0])
        blockwise_expected = np.concatenate((first_block, final_prefix))
        check_result(
            "rotate each chunk left by one",
            collective_decrypt(context, large_rotated, [alice]),
            blockwise_expected,
            bound=transform_error(
                large_rotated,
                primitive_bound(large_ciphertext, mkckks.PrecisionClass.BASIC),
                mkckks.PrecisionClass.ROTATION,
            ),
        )

        heading("14. Concatenated multi-party circuit")
        print("  Circuit:")
        print("    sum       = Enc(Alice) + Enc(Bob)")
        print("    centered  = sum - Encode(offset)")
        print("    weighted  = centered * (0.75 - 0.125j)")
        print("    federated = weighted + Enc(Carol)")
        print("    masked    = federated * Encode(factors)")
        print("    normalized= Rescale(masked)")
        print("    squared   = normalized * normalized (internally hoisted/relinearized)")
        print("    result    = squared + (-0.125 + 0.05j)")
        centered = stack.enter_context(evaluator.subtract(alice_bob, encoded_offset))
        centered_expected = alice_expected + bob_expected - offset
        centered_error = add_error(centered, alice_bob_error, offset_error)
        show_ciphertext("centered", centered)
        weighted = stack.enter_context(evaluator.multiply_scalar(centered, 0.75 - 0.125j))
        weighted_expected = centered_expected * (0.75 - 0.125j)
        weighted_error = scalar_error(weighted, centered_error, 0.75 - 0.125j, fractional=True)
        show_ciphertext("weighted", weighted)
        federated = stack.enter_context(evaluator.add(weighted, carol_ct))
        federated_expected = weighted_expected + carol_expected
        federated_error = add_error(federated, weighted_error, carol_error)
        show_ciphertext("federated", federated)
        masked = stack.enter_context(evaluator.multiply_plaintext(federated, encoded_factors))
        masked_expected = federated_expected * factors
        masked_error = product_error(
            masked,
            federated_expected,
            factors,
            federated_error,
            factors_error,
        )
        show_ciphertext("masked", masked)
        normalized = stack.enter_context(evaluator.rescale(masked))
        normalized_error = transform_error(normalized, masked_error, mkckks.PrecisionClass.BASIC)
        show_ciphertext("normalized", normalized)
        chained_square = stack.enter_context(evaluator.multiply(normalized, normalized))
        chained_square_error = product_error(
            chained_square,
            masked_expected,
            masked_expected,
            normalized_error,
            normalized_error,
        )
        show_ciphertext("squared", chained_square)
        chained_result = stack.enter_context(evaluator.add(chained_square, -0.125 + 0.05j))
        chained_result_error = add_error(
            chained_result, chained_square_error, scalar_encoding_error
        )
        show_ciphertext("final", chained_result)
        chained_expected = (
            (((alice_expected + bob_expected - offset) * (0.75 - 0.125j)) + carol_expected)
            * factors
        ) ** 2 + (-0.125 + 0.05j)
        check_result(
            "concatenated circuit",
            collective_decrypt(context, chained_result, parties),
            chained_expected,
            bound=chained_result_error,
        )

        heading("15. Artifact metadata and deterministic cleanup")
        show_ciphertext("final result metadata", chained_result)
        print("  native-backed objects are managed by context managers and close deterministically")

        if include_serialization:
            run_serialization_demo(
                stack,
                context,
                alice,
                alice_public,
                alice_ct,
                encoded_offset,
                offset,
                contributions[0],
                keyset,
                alice_expected,
                alice_error,
                offset_error,
            )
        else:
            heading("16. Serialization demo skipped by request")

    heading("All comprehensive MKCKKS checks passed")
    if report_path is not None:
        report = {
            "schema_version": 1,
            "preset": preset,
            "workers": workers,
            "environment": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "numpy": np.__version__,
                "native": mkckks.BUILD_INFO,
            },
            "results": PRECISION_RECORDS,
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print("Precision report:", report_path)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preset", choices=["PN14QP439", "PN15QP880"], default="PN14QP439")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--skip-serialization",
        action="store_true",
        help="skip the large context/key artifact round-trip section",
    )
    parser.add_argument("--report", type=Path, help="write machine-readable precision JSON")
    args = parser.parse_args(argv)
    run(args.preset, args.workers, not args.skip_serialization, args.report)


if __name__ == "__main__":
    main()
