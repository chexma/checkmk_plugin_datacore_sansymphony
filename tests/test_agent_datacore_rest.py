import pytest

from cmk_addons.plugins.datacore_rest.special_agents import agent_datacore_rest as agent

SERVER_ID = "srv-1"

API_DATA = {
    "servers": [{"Id": SERVER_ID, "Caption": "SSV1"}, {"Id": "srv-2", "Caption": "SSV2"}],
    "alerts": [{"MessageText": "a"}, {"MessageText": "b"}],
    "snapshots": [{"Id": "s1"}],
    "hosts": [{"Id": "h1"}, {"Id": "h2"}],
    "hostgroups": [{"Id": "hg1"}],
    "servergroups": [{"Id": "sg"}],
    "pools": [{"Id": "p1", "ServerId": SERVER_ID}, {"Id": "p2", "ServerId": "srv-2"}],
    "physicaldisks": [{"Id": "d1", "HostId": SERVER_ID}, {"Id": "d2", "HostId": "srv-2"}],
    "ports": [
        {"Id": "po1", "HostId": SERVER_ID, "Caption": "FC1"},
        {"Id": "po2", "HostId": SERVER_ID, "Caption": "Loopback Port"},
        {"Id": "po3", "HostId": "srv-2", "Caption": "FC2"},
    ],
    "virtualdisks": [
        {
            "Id": "v1",
            "IsSnapshotVirtualDisk": False,
            "FirstHostId": SERVER_ID,
            "SecondHostId": None,
        },
        {"Id": "v2", "IsSnapshotVirtualDisk": True, "FirstHostId": SERVER_ID, "SecondHostId": None},
        {"Id": "v3", "IsSnapshotVirtualDisk": False, "FirstHostId": "x", "SecondHostId": SERVER_ID},
        {"Id": "v4", "IsSnapshotVirtualDisk": False, "FirstHostId": "x", "SecondHostId": "y"},
    ],
}


class _Response:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self) -> None:
        pass

    def json(self):
        return self._data


def _fake_get(_session, url, **_kwargs):
    if "/performance/" in url:
        return _Response([{"Perf": url.rsplit("/", 1)[1]}])
    return _Response(API_DATA[url.rsplit("/", 1)[1]])


@pytest.fixture(name="agent_output")
def fixture_agent_output(monkeypatch, capsys) -> dict[str, list[str]]:
    monkeypatch.setattr("requests.Session.get", _fake_get)
    monkeypatch.setattr(agent, "lookup_password", lambda ref: "secret")
    assert agent.main(["-u", "user", "-s", "pw_id:/store", "-n", "ssv1", "10.0.0.1"]) == 0

    sections: dict[str, list[str]] = {}
    current = ""
    for line in capsys.readouterr().out.splitlines():
        if line.startswith("<<<"):
            assert line.endswith(":sep(0)>>>")
            current = line[3:].split(":")[0]
            sections.setdefault(current, [])
        else:
            sections[current].append(line)
    return sections


def _ids(lines: list[str]) -> list[str]:
    return [line.split('"Id": "')[1].split('"')[0] for line in lines]


def test_server_specific_filtering(agent_output: dict[str, list[str]]) -> None:
    assert _ids(agent_output["datacore_rest_pools"]) == ["p1"]
    assert _ids(agent_output["datacore_rest_physicaldisks"]) == ["d1"]
    assert _ids(agent_output["datacore_rest_ports"]) == ["po1"]
    assert _ids(agent_output["datacore_rest_virtualdisks"]) == ["v1", "v3"]
    assert _ids(agent_output["datacore_rest_servers"]) == [SERVER_ID]
    assert _ids(agent_output["datacore_rest_hosts"]) == ["h1", "h2"]


def test_alerts_and_snapshots_are_one_json_line(agent_output: dict[str, list[str]]) -> None:
    assert agent_output["datacore_rest_alerts"] == ['[{"MessageText": "a"}, {"MessageText": "b"}]']
    assert agent_output["datacore_rest_snapshots"] == ['[{"Id": "s1"}]']


def test_perfdata_is_attached(agent_output: dict[str, list[str]]) -> None:
    assert '"PerformanceData": {"Perf": "d1"}' in agent_output["datacore_rest_physicaldisks"][0]


def test_lookup_password_uses_password_store_reference(monkeypatch) -> None:
    calls = []

    class _Secret:
        def reveal(self) -> str:
            return "plain"

    def _dereference(raw: str) -> _Secret:
        calls.append(raw)
        return _Secret()

    monkeypatch.setattr(agent, "dereference_secret", _dereference)
    assert agent.lookup_password("pw_id:/omd/sites/cmk/stored_passwords") == "plain"
    assert calls == ["pw_id:/omd/sites/cmk/stored_passwords"]
