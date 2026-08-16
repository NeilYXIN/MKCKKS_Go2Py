# Performance methodology

Benchmarks must separate direct Go, C ABI, and Python end-to-end timings. Each
report records parameter preset, party count, logical size, chunk count, worker
count, platform, CPU, compiler, Go, Python, NumPy, warm-up, repetitions, median,
confidence interval, allocations, and peak RSS.

The v0.2 release does not claim a fixed wrapper-overhead ratio. Direct upstream
Go, bridge model, C ABI, and Python add/multiply/rotate results are recorded so
regressions are visible without turning noisy hosted runners into performance
certification. The only local throughput gate is at least 1.5x for four workers
versus one worker on an eight-chunk workload and a four-core-or-larger
controlled host.

## v0.2 local reference

A pre-release reference run on an Apple M3 used CPython 3.13.14, NumPy 2.5.1,
Go 1.26.5, PN14QP439, one 1,024-value chunk, five warm-up iterations, and 30
timed repetitions. It measured the public Python API against the same process's
C ABI path:

| Operation | C ABI median | Python median | Python/C ABI ratio |
| --- | ---: | ---: | ---: |
| Add | 0.153 ms | 0.167 ms | 1.089x |
| Multiply | 26.574 ms | 26.557 ms | 0.999x |
| Rotate | 14.933 ms | 14.953 ms | 1.001x |

On the same host, eight-chunk complex encryption processed approximately 2.27
million values per second with one worker and 7.15 million with four workers, a
3.16x throughput ratio. These measurements demonstrate low wrapper overhead
and useful chunk-level parallelism on that host; they are not predictions for
other hardware or workloads. The attached release reports are the authoritative
record for each certified release commit.

Local benchmark JSON is intentionally ignored by Git. Generate disposable
development measurements with:

```console
uv run python benchmarks/benchmark.py --workers 1 --size 1024 \
  --warmup 10 --repetitions 100 --output benchmark-results/native-python.json
uv run python benchmarks/workflow_benchmark.py \
  --output benchmark-results/workflows.json
uv run python benchmarks/encryption_throughput.py --workers 1 --chunks 8 \
  --output benchmark-results/encrypt-workers1.json
uv run python benchmarks/encryption_throughput.py --workers 4 --chunks 8 \
  --output benchmark-results/encrypt-workers4.json
go test -run '^$' \
  -bench 'Benchmark(DirectGo|BridgeModel)(Add|Multiply|Rotate)$' \
  -benchmem -count=3 ./bridge
```

Release candidates also record context/key generation, real and complex
encryption, partial-plus-collective decryption, conjugation, serialization, Go
allocations, and peak RSS. Hosted reports are evidence and regression signals;
they are not cross-machine performance claims. Release-relevant reports are
generated from the release commit and attached to its GitHub prerelease rather
than stored as source files.
