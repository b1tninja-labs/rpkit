"""The `corpus` marker: real-data tests that are slow run only when asked for.

A test marked `corpus` skips, with the command that runs it, unless `RPKIT_CORPUS=1` is set or the
run selects the marker (`python -m pytest -m corpus`). The default gates and `python -O` stay fast.
"""

from __future__ import annotations

import os

import pytest

ENV = "RPKIT_CORPUS"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get(ENV) == "1" or "corpus" in (config.getoption("markexpr") or ""):
        return
    skip = pytest.mark.skip(
        reason=f"real-data corpus test, opt-in: run with {ENV}=1 python -m pytest -q "
        "(or python -m pytest -q -m corpus); the files come from python tools/fetch_corpus.py"
    )
    for item in items:
        if item.get_closest_marker("corpus") is not None:
            item.add_marker(skip)
