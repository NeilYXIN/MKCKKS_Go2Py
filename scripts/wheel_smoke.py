# SPDX-License-Identifier: MIT
"""Exercise a real two-party complex workflow from an installed wheel."""

from contextlib import ExitStack

import numpy as np

import mkckks


def main() -> None:
    expected = np.array([[1.25 + 0.5j, -2.0j], [3.0 - 0.25j, -0.5 + 1.5j]])
    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), workers=2)
        )
        alice = stack.enter_context(mkckks.Party.generate(context, "wheel-alice"))
        bob = stack.enter_context(mkckks.Party.generate(context, "wheel-bob"))
        real_part = np.real(expected) / 2
        left = stack.enter_context(alice.encrypt(real_part))
        right = stack.enter_context(bob.encrypt(expected - real_part))
        summed = stack.enter_context(mkckks.Evaluator(context).add(left, right))
        alice_share = stack.enter_context(alice.partial_decrypt(summed))
        bob_share = stack.enter_context(bob.partial_decrypt(summed))
        serialized = (
            context.to_bytes(),
            summed.to_bytes(),
            alice_share.to_bytes(),
            bob_share.to_bytes(),
        )
        bound = sum(
            mkckks.precision_bound(value, mkckks.PrecisionClass.BASIC)
            for value in (left, right, summed)
        )

    with ExitStack() as stack:
        restored_context = stack.enter_context(mkckks.Context.from_bytes(serialized[0]))
        restored_sum = stack.enter_context(
            mkckks.Ciphertext.from_bytes(restored_context, serialized[1])
        )
        restored_alice_share = stack.enter_context(
            mkckks.DecryptionShare.from_bytes(restored_context, serialized[2])
        )
        restored_bob_share = stack.enter_context(
            mkckks.DecryptionShare.from_bytes(restored_context, serialized[3])
        )
        decoded = restored_context.collective_decrypt(
            restored_sum,
            [restored_alice_share, restored_bob_share],
        )

    report = mkckks.measure_precision(decoded, expected)
    if report.maximum_component_error > bound:
        raise AssertionError(
            "installed-wheel workflow exceeded its propagated CKKS bound: "
            f"error={report.maximum_component_error:.3e}, bound={bound:.3e}"
        )
    if mkckks.BUILD_INFO["abi_version"] != 1:
        raise RuntimeError("unexpected native ABI version")


if __name__ == "__main__":
    main()
