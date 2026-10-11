# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""Screenshots and videos of a scenario's end state, for docs/proof/e2e/.

Captures go to `PASSWORDS_APP_E2E_PROOF_DIR` when set (the proof run sets it to
docs/proof/e2e) and to the ignored docs/proof/raw/e2e otherwise, so an ordinary run never
dirties the tree. A scenario video is a sequence of segments: real-time screencasts of the
app from the shell, and frame-by-frame recordings of the headless browsers (neither driver
records video), joined into one WebM.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from tests.browser.e2e_support import FrameRecorder, compress_proof

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.browser.e2e_support import Page
    from tests.e2e.desktop import AppWindow

REPO = Path(__file__).resolve().parents[2]
VIDEO_SIZE = (1280, 800)


def proof_dir() -> Path:
    configured = os.environ.get("PASSWORDS_APP_E2E_PROOF_DIR")
    target = Path(configured) if configured else REPO / "docs" / "proof" / "raw" / "e2e"
    target.mkdir(parents=True, exist_ok=True)
    return target


def capture_app(app: AppWindow, scenario: str) -> Path:
    path = app.screenshot(proof_dir() / f"{scenario}-app.png")
    assert path.stat().st_size > 10_000, f"{path} looks empty"
    return path


def capture_page(page: Page, scenario: str) -> Path:
    out = proof_dir() / f"{scenario}-{page.name}.png"
    raw = out.with_suffix(".raw.png")
    page.screenshot(raw)
    compress_proof(raw, out)
    return out


def _ffmpeg(*args: str) -> None:
    subprocess.run(  # noqa: S603 - fixed argv, ffmpeg from PATH
        [shutil.which("ffmpeg") or "ffmpeg", "-loglevel", "error", "-y", *args], check=True
    )


class Video:
    """Segments recorded in order, joined into `<proof>/<scenario>.webm` by `finish`."""

    def __init__(self, scenario: str, work: Path) -> None:
        self.scenario = scenario
        self.work = work
        work.mkdir(parents=True, exist_ok=True)
        self._segments: list[Path] = []
        self._app: AppWindow | None = None

    def _next(self, suffix: str) -> Path:
        return self.work / f"segment-{len(self._segments):02d}{suffix}"

    def start_app(self, app: AppWindow) -> None:
        """Start a real-time screencast of the desktop (the app window)."""
        assert self._app is None
        self._app = app
        app.shell.start_recording(self._next(".webm"))

    def stop_app(self) -> None:
        assert self._app is not None
        self._segments.append(self._app.shell.stop_recording())
        self._app = None

    def browser(self, page: Page) -> FrameRecorder:
        """A `Page` that records a frame after each action; close it with `end_browser`."""
        return FrameRecorder(page, self._next("-frames"))

    def end_browser(self, recorder: FrameRecorder) -> None:
        recorder.hold(1.5)
        segment = self._next(".webm")
        recorder.encode(segment)
        self._segments.append(segment)

    def finish(self) -> Path:
        if self._app is not None:
            self.stop_app()
        out = proof_dir() / f"{self.scenario}.webm"
        width, height = VIDEO_SIZE
        inputs: list[str] = []
        chains: list[str] = []
        for index, segment in enumerate(self._segments):
            inputs += ["-i", str(segment)]
            chains.append(
                f"[{index}:v]scale={width}:{height}:force_original_aspect_ratio=decrease,"
                f"pad={width}:{height}:(ow-iw)/2:(oh-ih)/2:color=white,fps=10,setsar=1,"
                f"format=yuv420p[v{index}]"
            )
        joined = "".join(f"[v{i}]" for i in range(len(self._segments)))
        chains.append(f"{joined}concat=n={len(self._segments)}:v=1:a=0[out]")
        _ffmpeg(
            *inputs,
            "-filter_complex",
            ";".join(chains),
            "-map",
            "[out]",
            "-c:v",
            "libvpx-vp9",
            "-b:v",
            "0",
            "-crf",
            "40",
            "-row-mt",
            "1",
            str(out),
        )
        assert out.stat().st_size > 20_000, f"{out} looks empty"
        return out


def overlay_shot(
    browser: Page, scenario: str, overlay: str, recorder: FrameRecorder | None = None
) -> Callable[[], None]:
    """For `fill(at_dropdown=…)` / `sign_up_and_save(at_prompt=…)`: capture the extension's
    `overlay` ("dropdown", "save-prompt") and hold it in the video."""

    def shoot() -> None:
        capture_page(browser, f"{scenario}-{overlay}")
        if recorder is not None:
            recorder.hold(1.8)

    return shoot
