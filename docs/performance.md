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
