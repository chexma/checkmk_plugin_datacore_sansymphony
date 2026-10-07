#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

"""
DataCore SANsymphony Test Data Wrapper

This standalone script reads static CheckMK agent output and applies test mode
increments to performance counters, allowing get_rate() to return non-zero values
when testing with static data.

Usage:
    python3 datacore_test_wrapper.py <static_data_file>

    Or as a datasource_programs entry:
    python3 ~/local/bin/datacore_test_wrapper.py ~/local/tmp/akf-ssv1-09.txt

The script:
1. Reads the static agent output file
2. Parses JSON sections containing PerformanceData
3. Applies time-based increments to performance counters
4. Updates CollectionTime to current time
5. Outputs the modified data to stdout

This allows CheckMK's get_rate() function to calculate meaningful rates
from static test data by simulating counter increments.

WARNING: This produces FAKE performance metrics!
         For DEVELOPMENT and TESTING purposes only!

Author: Andre Eckstein <andre.eckstein@bechtle.com>
"""

import json
import sys
import time


def apply_test_mode_increments(data_object: dict) -> dict:
    """
    Apply time-based increments to performance counters for test mode.
    This allows get_rate() to return non-zero values with static test data.

    The increments are calculated based on elapsed time since a reference point,
    ensuring counters always monotonically increase between runs.

    Args:
        data_object: Dictionary containing PerformanceData

    Returns:
        Modified data_object with incremented counters
    """
    if "PerformanceData" not in data_object or data_object["PerformanceData"] is None:
        return data_object

    perf = data_object["PerformanceData"]

    # Get current time
    current_time_s = time.time()
    current_time_ms = int(current_time_s * 1000)

    # Update CollectionTime to current time
    perf["CollectionTime"] = f"/Date({current_time_ms})/"

    # Reference time: use a fixed epoch for consistent increments
    # Using 2024-01-01 00:00:00 UTC as reference
    reference_epoch = 1704067200  # 2024-01-01 00:00:00 UTC
    elapsed_seconds = current_time_s - reference_epoch

    # Base rates per second (fixed values for consistency)
    base_read_iops = 500
    base_write_iops = 200
    base_read_bytes = 50_000_000   # 50 MB/s
    base_write_bytes = 20_000_000  # 20 MB/s

    # Calculate cumulative increments based on elapsed time
    # This ensures counters always increase monotonically
    counter_increments = {
        # I/O operations (cumulative since reference time)
        "TotalReads": int(base_read_iops * elapsed_seconds),
        "TotalWrites": int(base_write_iops * elapsed_seconds),
        "TotalOperations": int((base_read_iops + base_write_iops) * elapsed_seconds),
        "InitiatorReads": int(base_read_iops * 0.1 * elapsed_seconds),
        "InitiatorWrites": int(base_write_iops * 0.5 * elapsed_seconds),
        "TargetReads": int(base_read_iops * elapsed_seconds),
        "TargetWrites": int(base_write_iops * elapsed_seconds),
        # Throughput (bytes cumulative)
        "TotalBytesRead": int(base_read_bytes * elapsed_seconds),
        "TotalBytesWritten": int(base_write_bytes * elapsed_seconds),
        "TotalBytesTransferred": int((base_read_bytes + base_write_bytes) * elapsed_seconds),
        "BytesRead": int(base_read_bytes * elapsed_seconds),
        "BytesWritten": int(base_write_bytes * elapsed_seconds),
        "InitiatorBytesRead": int(base_read_bytes * 0.1 * elapsed_seconds),
        "InitiatorBytesWritten": int(base_write_bytes * 0.5 * elapsed_seconds),
        "TargetBytesRead": int(base_read_bytes * elapsed_seconds),
        "TargetBytesWritten": int(base_write_bytes * elapsed_seconds),
        # Time counters (in ticks: 1 tick = 100 nanoseconds)
        # Avg 1ms per operation = 10,000 ticks per op
        "TotalReadTime": int(base_read_iops * elapsed_seconds * 10000),
        "TotalWriteTime": int(base_write_iops * elapsed_seconds * 10000),
        "TotalReadsTime": int(base_read_iops * elapsed_seconds * 10000),
        "TotalWritesTime": int(base_write_iops * elapsed_seconds * 10000),
        "TotalOperationsTime": int((base_read_iops + base_write_iops) * elapsed_seconds * 10000),
    }

    # Apply increments to existing counters
    for counter, increment in counter_increments.items():
        if counter in perf and isinstance(perf[counter], (int, float)):
            perf[counter] += increment

    return data_object


def process_static_file(filepath: str) -> None:
    """
    Read static agent output file, apply test mode increments to JSON sections,
    and output the modified data.

    Args:
        filepath: Path to the static agent output file
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied: {filepath}", file=sys.stderr)
        sys.exit(1)

    lines = content.split('\n')
    output_lines = []

    for line in lines:
        # Check if this line contains JSON data with PerformanceData
        if line.strip().startswith('{'):
            try:
                data = json.loads(line)

                # Apply test mode increments if this is a dict with PerformanceData
                if isinstance(data, dict):
                    data = apply_test_mode_increments(data)

                output_lines.append(json.dumps(data))
            except json.JSONDecodeError:
                # Not valid JSON, output as-is
                output_lines.append(line)
        elif line.strip().startswith('['):
            try:
                data = json.loads(line)

                # Apply to list items if they're dicts
                if isinstance(data, list):
                    data = [
                        apply_test_mode_increments(item) if isinstance(item, dict) else item
                        for item in data
                    ]

                output_lines.append(json.dumps(data))
            except json.JSONDecodeError:
                # Not valid JSON, output as-is
                output_lines.append(line)
        else:
            # Section headers and other lines pass through unchanged
            output_lines.append(line)

    # Output the modified content
    print('\n'.join(output_lines))


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <static_data_file>", file=sys.stderr)
        print(file=sys.stderr)
        print("Example:", file=sys.stderr)
        print(f"  {sys.argv[0]} ~/local/tmp/akf-ssv1-09.txt", file=sys.stderr)
        print(file=sys.stderr)
        print("For datasource_programs configuration:", file=sys.stderr)
        print(f"  python3 ~/local/bin/datacore_test_wrapper.py ~/local/tmp/akf-ssv1-09.txt", file=sys.stderr)
        sys.exit(1)

    filepath = sys.argv[1]

    # Expand ~ to home directory
    if filepath.startswith('~'):
        import os
        filepath = os.path.expanduser(filepath)

    process_static_file(filepath)


if __name__ == "__main__":
    main()
