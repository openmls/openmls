# Benchmarks

To generate benchmarks use some of the following commands.

```bash
cargo criterion --message-format=json | jq -s 'map(select(.reason == "benchmark-complete") | {id: .id, median: .median})' > benchmark_results.json
```

```bash
argo criterion --message-format=json | jq -s 'map(select(.reason == "benchmark-complete"))' > benchmark_results.json
./bench.py < benchmark_results.json > benches/BENCHMARKS.md
```
