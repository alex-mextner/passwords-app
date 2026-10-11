# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
"""A scripted `Terminal`: answers queued per prompt kind, everything shown is recorded."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScriptedTerminal:
    answers: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    secret_prompts: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)

    def ask(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def secret(self, prompt: str) -> str:
        self.secret_prompts.append(prompt)
        if not self.secrets:
            raise EOFError
        return self.secrets.pop(0)

    def say(self, text: str = "") -> None:
        self.lines.extend(text.split("\n"))

    @property
    def output(self) -> str:
        return "\n".join(self.lines)

    @property
    def everything(self) -> str:
        """All text the user saw, prompts included."""
        return "\n".join([*self.lines, *self.prompts, *self.secret_prompts])
