"""The routers' management plane: no daemon's vty answers on a lab link."""


def test_router_daemons_listen_on_localhost_only(node, expected):
    """Every TCP listener on every router is bound to 127.0.0.1, except BGP itself on port 179."""
    exposed = []
    for router in expected["loopbacks"]:
        out = node(router).run("netstat", "-ltn").stdout
        listeners = [line.split()[3] for line in out.splitlines() if line.startswith("tcp")]
        assert listeners, f"{router}: netstat shows no TCP listener at all"
        exposed += [f"{router} {addr}" for addr in listeners
                    if not addr.startswith("127.0.0.1:") and not addr.endswith(":179")]
    assert not exposed, f"daemons listening beyond localhost: {exposed}"
