"""Shared logging helpers for kirby and scan modules."""

from __future__ import annotations

import sys
from collections.abc import Iterable, Iterator
from typing import TypeVar

T = TypeVar("T")


class KirbyLogger:
    def __init__(self, verbose: bool = True, prefix: str = "kirby") -> None:
        self.verbose = verbose
        self.prefix = prefix

    def info(self, message: str) -> None:
        if self.verbose:
            print(f"[{self.prefix}] {message}", file=sys.stderr, flush=True)

    def step(self, message: str) -> None:
        self.info(message)

    def flag(self, message: str) -> None:
        """Echo a flagged finding to the terminal without disrupting tqdm bars."""
        line = f"[{self.prefix}] FLAG: {message}"
        try:
            from tqdm import tqdm

            tqdm.write(line, file=sys.stderr)
        except ImportError:
            print(line, file=sys.stderr, flush=True)

    def progress(
        self,
        iterable: Iterable[T],
        *,
        total: int | None = None,
        desc: str = "",
        unit: str = "it",
    ) -> Iterator[T]:
        if not self.verbose:
            yield from iterable
            return

        try:
            from tqdm import tqdm

            label = f"[{self.prefix}] {desc}".strip()
            yield from tqdm(
                iterable,
                total=total,
                desc=label,
                unit=unit,
                file=sys.stderr,
            )
        except ImportError:
            if desc:
                self.info(f"{desc} ...")
            yield from iterable
