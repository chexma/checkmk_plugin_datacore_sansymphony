import pytest
from cmk.agent_based.v2 import GetRateError

from cmk_addons.plugins.datacore_rest.lib import calculate_performance_rates

COUNTERS = ["TotalReads", "TotalWrites", "TotalBytesRead"]


def test_performance_rates_initializes_all_counters_in_one_run() -> None:
    value_store: dict = {}
    first = {"TotalReads": 100, "TotalWrites": 50, "TotalBytesRead": 1000}
    second = {"TotalReads": 200, "TotalWrites": 70, "TotalBytesRead": 3000}

    with pytest.raises(GetRateError):
        calculate_performance_rates(value_store, "item", COUNTERS, 0.0, first)
    assert sorted(value_store) == sorted(f"item.{c}" for c in COUNTERS)

    rate = calculate_performance_rates(value_store, "item", COUNTERS, 10.0, second)
    assert rate == {"TotalReads": 10, "TotalWrites": 2, "TotalBytesRead": 200}
