# Migration from the original notebook

This page is only for users of the pre-refactor API. New users can start with
the README and API reference. The legacy implementation remains available at
commit
[`7870ebb`](https://github.com/NeilYXIN/MKCKKS_Go2Py/tree/7870ebbb865522b9977171660ef4db26bb73b86f).

The original `MPHEServer` and pickleable coefficient-copying classes are
removed. Use `Context` for parameters/CRS, `Party` for private state,
`Evaluator` for homomorphic operations, and explicit `to_bytes`/`from_bytes`
methods for transport.

`encryptFromPk` becomes `PublicKey.encrypt` or `Party.encrypt`.
`addCTs` becomes `Evaluator.add`; `multiplyCTConst` becomes
`Evaluator.multiply_scalar`. Manual `ringQAddLvl` share aggregation becomes
`Context.collective_decrypt`, which validates participant and ciphertext
binding.

Server ID `0` is no longer modeled as a cryptographic party because upstream
reserves it as the ciphertext constant component.

## Reproduce the original notebook example

The executable
[`examples/original_notebook_verification.py`](../examples/original_notebook_verification.py)
recreates the inputs and operation sequence from the last content-bearing
revision of
[`test.ipynb`](https://github.com/NeilYXIN/MKCKKS_Go2Py/blob/b8acb4f0a05d8337c43c8d6450811f0b104f9788/test.ipynb):
`PN14QP439` public-key encryption, two-party addition, three-party addition,
multiplication by `2.5`, and collective decryption. It also decrypts the three
input ciphertexts separately and checks every result against a scale-aware
CKKS error bound.

From a source checkout with `uv` installed, run:

```console
uv sync --locked --all-groups
uv run python examples/original_notebook_verification.py
```

The command exits with a nonzero status if any value, participant set, or
precision bound check fails. Because CKKS encryption is randomized, exact
decrypted errors vary between runs, but each run must print six `Result: PASS`
lines and end with `All computations from the original notebook passed.`

## v0.1 to v0.2

Remove the `hoisted=` argument from `multiply`, `rotate_slots`, and
`rotate_each_chunk`. Multiplication now uses safe operation-local hoisting
internally, while one-shot rotations use the normal compositional upstream
path. This is an intentional v0.x breaking change: the old Boolean did not
provide reusable decomposition and composite hoisted rotations could panic in
the pinned upstream implementation.

Contexts now default to `InputPolicy.VALIDATED` and `ResourceLimits()`. Existing
code using either named preset and values through `2**20` needs no change.
Literal parameters require `input_policy=InputPolicy.EXPERT`.
