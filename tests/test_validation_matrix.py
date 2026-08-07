# SPDX-License-Identifier: MIT
from __future__ import annotations

import ctypes
import os
from typing import Any

import numpy as np
import pytest

import mkckks
from mkckks import api


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_chunks": 0},
        {"max_values": True},
        {"max_values": (1 << 26) + 1},
        {"max_artifact_bytes": 0},
    ],
)
def test_resource_limit_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(mkckks.InvalidParameterError):
        mkckks.ResourceLimits(**kwargs)


@pytest.mark.parametrize(
    "changes",
    [
        {"log_n": True},
        {"log_n": 14.5},
        {"q": ["17"]},
        {"q": [True]},
        {"q": [2**64]},
        {"p": [19, 23, 29]},
        {"scale": True},
        {"scale": object()},
        {"sigma": float("inf")},
    ],
)
def test_parameter_literal_type_matrix(changes: dict[str, Any]) -> None:
    literal: dict[str, Any] = {
        "log_n": 14,
        "log_slots": 13,
        "q": [17],
        "p": [19, 23],
        "scale": 2.0,
        "sigma": 3.2,
    }
    with pytest.raises(ValueError):
        mkckks.Parameters.from_literal(**{**literal, **changes})


def test_context_policy_and_worker_validation() -> None:
    preset = mkckks.Parameters.preset("PN14QP439")
    with pytest.raises(mkckks.InvalidParameterError, match="input_policy"):
        mkckks.Context.create(preset, input_policy="not-a-policy")  # type: ignore[arg-type]
    with pytest.raises(mkckks.InvalidParameterError, match="workers"):
        mkckks.Context.create(preset, workers=True)
    expert = mkckks.Parameters.from_literal(
        log_n=preset.log_n,
        log_slots=preset.log_slots,
        q=preset.q,
        p=preset.p,
        scale=preset.scale,
        sigma=preset.sigma,
    )
    with pytest.raises(mkckks.InvalidParameterError, match="expert parameter"):
        mkckks.Context.create(expert)


def test_scalar_integer_shape_and_identifier_validation(context: mkckks.Context) -> None:
    party = mkckks.Party.generate(context, "validation-matrix")
    ciphertext = party.encrypt([1.0])
    evaluator = mkckks.Evaluator(context)
    for scalar in (True, 1, np.int64(1), object()):
        with pytest.raises(mkckks.InvalidDTypeError):
            evaluator.add(ciphertext, scalar)
    with pytest.raises(mkckks.InvalidParameterError):
        evaluator.drop_level(ciphertext, 1.5)  # type: ignore[arg-type]
    with pytest.raises(mkckks.InvalidParameterError):
        evaluator.drop_level(ciphertext, 1 << 31)
    with pytest.raises(ValueError, match="finite"):
        evaluator.rescale(ciphertext, 0)
    with pytest.raises(mkckks.InvalidParameterError, match="Boolean"):
        party.generate_evaluation_keys(relinearization=1)  # type: ignore[arg-type]
    for party_id in (1, "", "0", "nul\x00id", "x" * 129, "\ud800"):
        with pytest.raises(mkckks.InvalidParameterError):
            mkckks.Party.generate(context, party_id)  # type: ignore[arg-type]


def test_shape_and_precision_validation() -> None:
    with pytest.raises(mkckks.SerializationError, match="array"):
        api._validated_shape("bad")
    with pytest.raises(mkckks.SerializationError, match="positive"):
        api._validated_shape([True])
    with pytest.raises(mkckks.SerializationError, match="product"):
        api._validated_shape([1 << 20, 1 << 20])
    with pytest.raises(ValueError, match="identical"):
        mkckks.measure_precision([1.0], [1.0, 2.0])
    report = mkckks.measure_precision([1.0], [1.0])
    assert report.minimum_precision_bits == float("inf")
    assert report.maximum_component_error == 0


def test_release_safely_shutdown_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    api._release_safely(0, os.getpid())
    api._release_safely(1, os.getpid() + 1)
    monkeypatch.setattr(api._native, "release_fn", None)
    api._release_safely(1, os.getpid())

    def broken_release(_handle: int, _error: Any) -> int:
        raise RuntimeError("shutdown")

    monkeypatch.setattr(api._native, "release_fn", broken_release)
    api._release_safely(1, os.getpid())


def test_native_error_translation_unknown_status(monkeypatch: pytest.MonkeyPatch) -> None:
    error = ctypes.c_char_p(b"unknown status")
    monkeypatch.setattr(api._native, "error_free", lambda _value: None)
    with pytest.raises(mkckks.NativeError, match="unknown status"):
        api._native.check(99, error)


def test_native_error_and_json_defensive_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(mkckks.NativeError, match="unknown native error"):
        api._native.check(99, ctypes.c_char_p())

    monkeypatch.setattr(api._native.json, "loads", lambda _raw: [])
    with pytest.raises(mkckks.NativeError, match="must be an object"):
        api._native.call_json(api._native.build_info_fn)


def test_fork_guard_paths() -> None:
    value = api._NativeObject(1)
    value._pid = os.getpid() + 1
    with pytest.raises(mkckks.ForkSafetyError):
        _ = value._native_handle
    value.close()
    assert value.closed


def test_native_metadata_defensive_paths(
    context: mkckks.Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(api._native, "call_json", lambda *_args: {"kind": 99})
    with pytest.raises(mkckks.SerializationError, match="expected"):
        api._native_object_metadata(1, 3, context)
    monkeypatch.setattr(
        api._native,
        "call_json",
        lambda *_args: {"kind": 3, "context_fingerprint": "wrong"},
    )
    with pytest.raises(mkckks.SerializationError, match="fingerprint"):
        api._native_object_metadata(1, 3, context)


def test_all_imports_reject_wrong_native_kind(
    context: mkckks.Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    party = mkckks.Party.generate(context, "wrong-kind-party")
    public_key = party.public_key
    contribution = party.generate_evaluation_keys()
    keyset = mkckks.EvaluationKeySet.combine(context, [contribution])
    plaintext = context.encode([1.0])
    ciphertext = party.encrypt([1.0])
    share = party.partial_decrypt(ciphertext)
    with pytest.warns(RuntimeWarning):
        private_state = party.export_private_state()

    artifacts: list[tuple[Any, bytes]] = [
        (mkckks.PublicKey.from_bytes, public_key.to_bytes()),
        (mkckks.EvaluationKeyContribution.from_bytes, contribution.to_bytes()),
        (mkckks.EvaluationKeySet.from_bytes, keyset.to_bytes()),
        (mkckks.Plaintext.from_bytes, plaintext.to_bytes()),
        (mkckks.Ciphertext.from_bytes, ciphertext.to_bytes()),
        (mkckks.DecryptionShare.from_bytes, share.to_bytes()),
    ]
    monkeypatch.setattr(api._native, "import_artifact", lambda *_args: (0, 255))
    for importer, serialized in artifacts:
        with pytest.raises(mkckks.SerializationError, match="native artifact"):
            importer(context, serialized)
    with pytest.warns(RuntimeWarning), pytest.raises(mkckks.SerializationError, match="native"):
        mkckks.Party.from_private_state(context, private_state)

    context_bytes = context.to_bytes()
    with pytest.raises(mkckks.SerializationError, match="not a context"):
        mkckks.Context.from_bytes(context_bytes)


def test_context_import_limits_and_policy(context: mkckks.Context) -> None:
    serialized = context.to_bytes()
    with pytest.raises(mkckks.SerializationError, match="resource"):
        mkckks.Context.from_bytes(serialized, limits=mkckks.ResourceLimits(max_artifact_bytes=1))
    with pytest.raises(mkckks.InvalidParameterError, match="policy"):
        mkckks.Context.from_bytes(serialized, input_policy="invalid")  # type: ignore[arg-type]
