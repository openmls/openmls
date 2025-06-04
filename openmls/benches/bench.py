#!/usr/bin/env python3

import sys
import json


def main():
    benchmarks = []

    # Read JSON object from stdin
    data = json.load(sys.stdin)
    # print(data)
    for date in data:
        # We assume date.get("reason") == "benchmark-complete":
        benchmark_id = date.get("id", "N/A")
        median = date.get("median", {})
        median_value = median.get("estimate", "N/A")
        unit = median.get("unit")
        benchmarks.append(
            {"id": benchmark_id, "median": median_value, "unit": unit}
        )

    if not benchmarks:
        print("No benchmark-complete results found.", file=sys.stderr)
        return

    # --- Generate Markdown Table ---

    # Header
    print(f"| Benchmark ID | Median ({unit}) |")
    # Separator
    print("|--------------|-----------|")

    # Data Rows
    for bench in benchmarks:
        # Use f-strings for easy formatting
        print(f"| {bench['id']} | {bench['median']} |")


if __name__ == "__main__":
    main()
