# SPDX-License-Identifier: MIT
"""Reproduce and verify the computations from the original test.ipynb notebook."""

from __future__ import annotations

import argparse
import math
from collections.abc import Sequence
from contextlib import ExitStack

import numpy as np
import numpy.typing as npt

import mkckks

Array = npt.NDArray[np.float64]
ORIGINAL_NOTEBOOK_COMMIT = "b8acb4f0a05d8337c43c8d6450811f0b104f9788"

WEIGHTS_1 = np.array([0.1, 0.2, 2.1, -2.2], dtype=np.float64)
WEIGHTS_2 = np.array([0.2, 0.3, 1.2, -1.2], dtype=np.float64)
WEIGHTS_3 = np.array([0.3, 0.5, 1.5, -1.5], dtype=np.float64)


def heading(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def show_ciphertext(label: str, ciphertext: mkckks.Ciphertext) -> None:
    print(
        f"{label}: participants={ciphertext.participants}, "
        f"level={ciphertext.level}, scale={ciphertext.scale:.6e}, "
        f"status={ciphertext.correctness_status.value}"
    )


def collective_decrypt(
    context: mkckks.Context,
    ciphertext: mkckks.Ciphertext,
    parties: Sequence[mkckks.Party],
) -> Array:
    print("Generating shares from:", ", ".join(party.party_id for party in parties))
    with ExitStack() as share_stack:
        shares = [share_stack.enter_context(party.partial_decrypt(ciphertext)) for party in parties]
        return np.asarray(context.collective_decrypt(ciphertext, shares), dtype=np.float64)


def verify_result(name: str, actual: Array, expected: Array, bound: float) -> None:
    report = mkckks.measure_precision(actual, expected)
    print(f"\n{name}")
    print("Expected:                  ", np.array2string(expected, precision=12))
    print("Decrypted:                 ", np.array2string(actual, precision=12))
    print("Decrypted, rounded to 2 dp:", np.array2string(np.round(actual, 2)))
    print("Absolute error:            ", np.array2string(np.abs(actual - expected), precision=3))
    print(f"Maximum real error:         {report.maximum_real_error:.6e}")
    print(f"Maximum imaginary error:    {report.maximum_imaginary_error:.6e}")
    print(f"RMS error:                  {report.rms_error:.6e}")
    print(f"Minimum precision:          {report.minimum_precision_bits:.2f} bits")
    print(f"Permitted propagated bound: {bound:.6e}")
    if not math.isfinite(bound) or bound <= 0:
        raise AssertionError(f"{name}: precision bound is not finite and positive")
    if report.maximum_component_error > bound:
        raise AssertionError(
            f"{name}: error {report.maximum_component_error:.6e} exceeds {bound:.6e}"
        )
    print("Result: PASS")


def basic_bound(ciphertext: mkckks.Ciphertext) -> float:
    return mkckks.precision_bound(ciphertext, mkckks.PrecisionClass.BASIC)


def run(preset: str, workers: int) -> None:
    heading("Original notebook reproduction")
    print("Notebook source commit:  ", ORIGINAL_NOTEBOOK_COMMIT)
    print("Original notebook preset: PN14QP439")
    print("Selected preset:         ", preset)
    print("Workers:                 ", workers)
    print("The evaluator replaces the legacy server object with reserved ID 0.")
    print("collective_decrypt replaces manual polynomial/share aggregation.")
    print("Two-decimal rounding is displayed for comparison only; it is not the test.")

    with ExitStack() as stack:
        parameters = mkckks.Parameters.preset(preset)
        context = stack.enter_context(mkckks.Context.create(parameters, workers=workers))
        evaluator = mkckks.Evaluator(context)

        clients = [
            stack.enter_context(mkckks.Party.generate(context, party_id))
            for party_id in ("client-1", "client-2", "client-3")
        ]
        public_keys = [stack.enter_context(client.public_key) for client in clients]

        heading("1. Original input vectors")
        for index, weights in enumerate((WEIGHTS_1, WEIGHTS_2, WEIGHTS_3), start=1):
            print(f"weights{index} = {weights}")

        heading("2. Public-key encryption")
        ciphertexts = [
            stack.enter_context(public_key.encrypt(weights))
            for public_key, weights in zip(
                public_keys, (WEIGHTS_1, WEIGHTS_2, WEIGHTS_3), strict=True
            )
        ]
        encryption_errors = [basic_bound(ciphertext) for ciphertext in ciphertexts]
        for index, (ciphertext, client, weights, error) in enumerate(
            zip(
                ciphertexts,
                clients,
                (WEIGHTS_1, WEIGHTS_2, WEIGHTS_3),
                encryption_errors,
                strict=True,
            ),
            start=1,
        ):
            show_ciphertext(f"ct{index}", ciphertext)
            decoded = collective_decrypt(context, ciphertext, [client])
            verify_result(f"ct{index}: public-key encryption", decoded, weights, error)

        heading("3. ct4 = ct1 + ct2 (two-party result)")
        ct4 = stack.enter_context(evaluator.add(ciphertexts[0], ciphertexts[1]))
        expected4 = WEIGHTS_1 + WEIGHTS_2
        error4 = encryption_errors[0] + encryption_errors[1] + basic_bound(ct4)
        if ct4.participants != ("client-1", "client-2"):
            raise AssertionError(f"ct4 participant mismatch: {ct4.participants}")
        show_ciphertext("ct4", ct4)
        decoded4 = collective_decrypt(context, ct4, clients[:2])
        verify_result("ct4: weights1 + weights2", decoded4, expected4, error4)

        heading("4. ct5 = ct3 + ct4 (three-party result)")
        ct5 = stack.enter_context(evaluator.add(ciphertexts[2], ct4))
        expected5 = WEIGHTS_1 + WEIGHTS_2 + WEIGHTS_3
        error5 = encryption_errors[2] + error4 + basic_bound(ct5)
        if ct5.participants != ("client-1", "client-2", "client-3"):
            raise AssertionError(f"ct5 participant mismatch: {ct5.participants}")
        show_ciphertext("ct5", ct5)
        decoded5 = collective_decrypt(context, ct5, clients)
        verify_result("ct5: weights1 + weights2 + weights3", decoded5, expected5, error5)

        heading("5. ct6 = ct5 * 2.5 (concatenated operation)")
        ct6 = stack.enter_context(evaluator.multiply_scalar(ct5, 2.5))
        expected6 = expected5 * 2.5
        error6 = 2.5 * error5 + mkckks.precision_bound(ct6, mkckks.PrecisionClass.MULTIPLICATION)
        if ct6.participants != ct5.participants:
            raise AssertionError("scalar multiplication changed the participant set")
        show_ciphertext("ct6", ct6)
        decoded6 = collective_decrypt(context, ct6, clients)
        verify_result("ct6: (weights1 + weights2 + weights3) * 2.5", decoded6, expected6, error6)

    heading("Verification complete")
    print("All computations from the original notebook passed.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preset",
        choices=("PN14QP439", "PN15QP880"),
        default="PN14QP439",
        help="PN14QP439 exactly matches the original notebook",
    )
    parser.add_argument("--workers", type=int, default=1)
    arguments = parser.parse_args()
    run(arguments.preset, arguments.workers)


if __name__ == "__main__":
    main()
