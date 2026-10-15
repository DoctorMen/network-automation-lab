# OROS: what network and security operators need, as a standard this lab is scored against

**OROS 0.3, the Operator-Ready Operations Standard**, is 61 pass/fail requirements in 10 families, written from what operators actually ask for in public, not from a vendor feature list. [standard.md](standard.md) is the standard. [scorecard.md](scorecard.md) scores this lab against every requirement, with the test that proves each pass.

## Where it comes from

| Source | Questions read | Relevant | Who asks |
|---|---|---|---|
| Network Engineering Stack Exchange (data dump) | 1,500 | 939 | Network engineers, sysadmins, ISP staff |
| Security Stack Exchange (data dump) | 1,500 | 1,112 | Developers, sysadmins, security engineers, GRC |
| Server Fault (data dump) | 1,800 | 1,734 | Sysadmins, developers |
| Mailing lists, vendor forums, feature trackers (first pass) | 103 | 103 | NOC and SOC staff, tool users |

Each question was coded for four things: what the person literally asked, the job they were really trying to get done, the constraint they didn't put in the question (SLA, policy, missing rights, budget, skill, politics, vendor, opsec, time), and their role. Needs that shared a code were grouped into families, and every family's requirement has a Pass test you can run.

The main finding: people mostly need **proof from the side they control**, not new features. Proof that a signal still arrives, that a fault sits where they say it does, that a change or backup really took effect, that a control works. And actions scoped so narrowly that nothing else breaks.

## How reliable it is

The coding was done with AI assistance (Claude), so every code with enough posts was checked twice more against the original posts: once for evidence (do the posts say this?) and once for depth (is this the real need behind the question?). About half of the individual codes had some flaw on recheck, but the families held. Treat the post counts as a ranking, not as population statistics. Some needs from the first pass (an owner on every alert, listable suppressions, shift handover, SLA clocks) did not survive the check; the standard lists them as unproven instead of requiring them.

Q&A sites draw people stuck on a how-to, and almost no NOC or SOC staff post there, so shift-process needs are under-sampled. The standard says so where it matters.

## License

Quoted posts are from Stack Exchange and are licensed [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); every quote links to its source post. The standard text in this folder is shared under the same license. The lab code in the rest of this repository stays under the repo's MIT license.
