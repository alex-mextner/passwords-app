# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Suite-wide xdist scheduling: GUI tests share one worker (see tests/gui/conftest.py)."""

from __future__ import annotations

import pytest


# This lives at the repo root, not in tests/gui: under `pytest tests -n N` the controller
# picks its scheduler before it loads nested conftests.
@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    # The xdist_group marker only binds under --dist loadgroup; with plain `-n N` (dist
    # "load") GUI tests spread over workers that then queue on the machine-wide shell lock
    # until they time out. Ungrouped tests are scheduled the same way under loadgroup.
    if getattr(config.option, "dist", "no") == "load":
        config.option.dist = "loadgroup"  # controller: schedule by group
    if hasattr(config, "workerinput"):
        # Workers decided this before conftests load (xdist's setup_config); they must tag
        # node ids with the group for the controller's loadgroup scheduler.
        config.option.loadgroup = True
