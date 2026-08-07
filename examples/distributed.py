"""Two-process-style workflow using explicit, versioned artifacts."""

from __future__ import annotations

import warnings
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context

import numpy as np

import mkckks


def party_process(context_blob: bytes, party_blob: bytes, ciphertext_blob: bytes) -> bytes:
    """Run in a spawned worker or a separately authenticated party service."""
    context = mkckks.Context.from_bytes(context_blob)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        party = mkckks.Party.from_private_state(context, party_blob)
    ciphertext = mkckks.Ciphertext.from_bytes(context, ciphertext_blob)
    return party.partial_decrypt(ciphertext).to_bytes()


def main() -> None:
    context = mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), workers=2)
    alice = mkckks.Party.generate(context, "alice")
    bob = mkckks.Party.generate(context, "bob")

    values = np.array([[1 + 0.5j, -2j], [3.25, -4 + 1j]], dtype=np.complex128)
    alice_ciphertext = alice.encrypt(values)
    bob_ciphertext = bob.encrypt(np.zeros_like(values))
    ciphertext = mkckks.Evaluator(context).add(alice_ciphertext, bob_ciphertext)
    bound = sum(
        mkckks.precision_bound(value, mkckks.PrecisionClass.BASIC)
        for value in (alice_ciphertext, bob_ciphertext, ciphertext)
    )
    context_blob = context.to_bytes()
    ciphertext_blob = ciphertext.to_bytes()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        private_blobs = [alice.export_private_state(), bob.export_private_state()]

    # In a real deployment, authenticate every party and transport. These private
    # blobs and the returned decryption shares are sensitive and unencrypted.
    with ProcessPoolExecutor(max_workers=2, mp_context=get_context("spawn")) as pool:
        futures = [
            pool.submit(party_process, context_blob, private_blob, ciphertext_blob)
            for private_blob in private_blobs
        ]
        share_blobs = [future.result() for future in futures]
    restored = mkckks.Context.from_bytes(context_blob)
    restored_ciphertext = mkckks.Ciphertext.from_bytes(restored, ciphertext_blob)
    shares = [mkckks.DecryptionShare.from_bytes(restored, blob) for blob in share_blobs]
    decoded = restored.collective_decrypt(restored_ciphertext, shares)
    report = mkckks.measure_precision(decoded, values)
    print("Expected:\n", values)
    print("Decrypted:\n", decoded)
    print(f"Maximum component error: {report.maximum_component_error:.3e}")
    print(f"Propagated CKKS bound:    {bound:.3e}")
    if report.maximum_component_error > bound:
        raise AssertionError("distributed result exceeded the propagated CKKS bound")


if __name__ == "__main__":
    main()
