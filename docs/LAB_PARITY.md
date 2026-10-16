# Lab parity: where this lab differs from a production network

Every change is tested here before it goes anywhere, so this page says what "tested" can't mean.
Each pull request's description has a "Risks the lab could not cover" section, and the
change-record check ([`.github/workflows/change-record.yml`](../.github/workflows/change-record.yml),
[`netlab/changerecord.py`](../netlab/changerecord.py)) fails while it is empty. Fill it from the
rows below that matter for the change. If nothing here can test a change, the section says so and
names what limits the risk instead: one change at a time, the canary rollout and its automatic
rollback (`make apply`, [decision 0010](decisions/0010-canary-rollout.md)), a backup to restore
(`make drift` takes one).

Where it says "measured", the number is from this lab; nothing here has been compared with real gear.

| Area | This lab | A production network | What a change here can't show |
|---|---|---|---|
| Platform | FRR 8.4.1 on Alpine 3.15.6, one pinned image (`platform:` in the inventory) for all seven nodes | Vendor routers and switches (IOS-XE, Junos, EOS), several models and NOS versions | Vendor CLI and defaults, per-model quirks, how a vendor's config parser takes the same intent |
| Forwarding | The Linux kernel forwards every packet in software | ASICs with fixed table sizes (TCAM, FIB), hardware queues, control-plane policing | Table exhaustion, hardware queueing, what the CPU does when traffic is punted to it |
| Kernel | Every node shares the host's kernel (sandbox 6.18.44, GitHub's Azure kernel in CI) and installs none | Each box runs its own kernel or NOS image | Reboots and kernel upgrades per node. `make verify` compares running with installed kernels, but the test has to fake an installed one |
| Kernel features | The sandbox kernel has no netem, nftables, fq_codel, sfq or cake (measured) and no IPv6 ([V-008](verdicts.yml)); GitHub's Ubuntu runner kernel should have them (not checked) | All of them, and IPv6 | Delay, jitter and reordering; IPv6; nftables rule sets; AQM leaf queues under HTB |
| Firewall | iptables (legacy) on Linux, IPv4 only: the image has no ip6tables. Drops are counted, not logged ([V-006](verdicts.yml)) | A stateful firewall appliance or nftables, logging to a collector, often an HA pair | IPv6 policy, logging pipelines, firewall failover and session sync |
| L2 and STP | No switches, VLANs, STP, LACP or broadcast domains: each link is one veth pair, MTU 9500 | Access and distribution switches, trunks, STP or MLAG, MTU 1500 at the edge | Loops, STP convergence, VLAN mistakes, MAC flooding, MTU mismatches between 1500 and jumbo |
| Physical | A link fails because a test sets it down or drops packets with iptables | Optics, CRC errors, flapping, one-way faults | Anything that only shows on a physical layer, and how often it happens |
| TLS and management | No TLS anywhere: h2 serves plain HTTP (`python3 -m http.server`), its port 22 is a stand-in, not sshd. Nodes are reached with `docker exec`; no SSH, AAA, SNMP, syslog server or NTP | TLS on services and management, SSH with AAA (TACACS+ or RADIUS), SNMP polling, central logging, NTP | Certificate and cipher changes, login and authorization changes, anything that depends on a poller or collector |
| Patch levels | One image; nothing is ever upgraded in place | Mixed versions, a patch train per vendor, upgrades on a schedule | Behaviour that changed between versions; an upgrade itself |
| Scale | 4 routers, 1 firewall, 2 hosts; one OSPF area, about 15 routes; one BGP peer sending one prefix | Hundreds of devices, several areas, full BGP tables of about a million routes | Convergence time and memory at scale. The measured timings (BFD reroute in about 1 s, 90.5 MiB of RAM) are lab numbers |
| Load and impairment | Idle except for the tests. One capped link: h2's port, shaped to 20 Mbit by HTB ([decision 0011](decisions/0011-bulk-yields-htb.md)). Loss is injected with iptables `statistic`. 4 CPUs, shared with another lab in the sandbox | Real traffic mixes, busy links, propagation delay | Behaviour under real load and delay. The QoS test uses one bulk flow and one web client |
| Redundancy | One edge router (r2), one ISP, one firewall | Pairs, two carriers | Failover of the edge, the ISP link or the firewall |
| Rollout | A 10 s vetting delay on the canary; the change window is open all day so CI can run at any hour | A canary that soaks for hours or days, a maintenance window agreed with the business | Faults that take longer than 10 s to show; the window as an agreement between people |
| Deployment | CI deploys with real Containerlab 0.68.0. The development sandbox has no `/proc/modules`, so it uses a stand-in script, kept outside this repo, with the same names, binds, links and exec steps, without Containerlab's labels | Devices built from a provisioning system, not torn down after each test | Day-two behaviour: a box that has run for months, config history, state that survives a reboot |
