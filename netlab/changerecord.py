"""Does a pull request say which risks the lab could not cover? The change-record CI job runs this.

python -m netlab.changerecord EVENT_JSON   (GitHub Actions passes $GITHUB_EVENT_PATH)

Every change reaches main as a pull request, and its description is the change record. It fails
when the "## Risks the lab could not cover" section is missing, empty once the template's guidance
comment is taken out, or only a filler word like "n/a". Standard library only, so the job needs no
pip install. docs/LAB_PARITY.md lists what the lab can't cover.
"""
from __future__ import annotations

import json
import re
import sys

HEADING = "## Risks the lab could not cover"
FILLER = {"", "n/a", "na", "none", "nothing", "no", "tbd", "todo", "see above", "same"}


def parity_problems(body: str | None) -> list[str]:
    # The template's guidance is an HTML comment: GitHub doesn't show it, so it isn't an answer.
    lines = re.sub(r"<!--.*?-->", "", body or "", flags=re.S).splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip().lower() == HEADING.lower()]
    if not starts:
        return [f'the description has no "{HEADING}" section (copy it from .github/pull_request_template.md)']
    section = []
    for line in lines[starts[0] + 1:]:
        if re.match(r"#{1,6} ", line):  # the next heading; "#42 has the same risk" is part of the answer
            break
        section.append(line.strip())
    answer = " ".join(section).strip(" -*_.:")
    if answer.lower() in FILLER:
        said = f"only {answer!r}" if answer else "nothing"
        return [f'"{HEADING[3:]}" says {said}. Name the differences in docs/LAB_PARITY.md that matter '
                "for this change, or what limits the risk instead"]
    return []


def main(argv: list[str] | None = None) -> int:
    path = (sys.argv[1:] if argv is None else argv)[0]
    with open(path) as fh:
        body = json.load(fh).get("pull_request", {}).get("body")
    problems = parity_problems(body)
    print("\n".join(problems) or f'OK: "{HEADING[3:]}" is filled in')
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
