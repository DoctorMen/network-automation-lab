"""The routers' management plane: no daemon's vty answers on a lab link."""


def test_router_daemons_listen_on_localhost_only(node, expected):
    """Every TCP listener on every router is bound to 127.0.0.1, except BGP itself on port 179 and the NOC's
    exporters, on the router's own loopback (decision 0018)."""
    exporters = expected.get("monitoring", {}).get("exporters", {})
    exposed = []
    for router in expected["loopbacks"]:
        out = node(router).run("netstat", "-ltn").stdout
        listeners = [line.split()[3] for line in out.splitlines() if line.startswith("tcp")]
        assert listeners, f"{router}: netstat shows no TCP listener at all"
        allowed = {f"{exporters[router]['address']}:{p}" for p in exporters[router]["ports"]} if router in exporters else set()
        exposed += [f"{router} {addr}" for addr in listeners
                    if not addr.startswith("127.0.0.1:") and not addr.endswith(":179") and addr not in allowed]
    assert not exposed, f"daemons listening beyond localhost: {exposed}"
