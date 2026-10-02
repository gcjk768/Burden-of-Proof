"""Reads a process's capability sets and no_new_privs flag from /proc/<pid>/status.

Kept apart from ``bop.runner.jail`` so that importing the runner package never imports the jail
module, which runs as ``python -m bop.runner.jail``.
"""

from __future__ import annotations

CAP_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")


def privilege_state(status_text: str) -> dict[str, str]:
    """The capability sets and no_new_privs flag from a /proc/<pid>/status text."""
    fields = {}
    for line in status_text.splitlines():
        key, _, value = line.partition(":")
        if key in (*CAP_FIELDS, "NoNewPrivs"):
            fields[key] = value.strip()
    return fields


def privileges_dropped(state: dict[str, str]) -> bool:
    return all(key in state and int(state[key], 16) == 0 for key in CAP_FIELDS) and state.get("NoNewPrivs") == "1"
