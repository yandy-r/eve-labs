"""Exception hierarchy. Every error has a stable ``code`` and a CLI ``exit_code``.

The base class and the generic subclasses live here because the shared building
blocks in :mod:`evelab.common` raise them; tools may subclass :class:`EveLabError`
for their own failures (``evelab.localize.errors`` does so by naming it
``LocalizeError``).
"""

from collections.abc import Sequence


class EveLabError(Exception):
    """Base class for all errors raised by evelab tools.

    ``code`` is a stable upper-case identifier (same namespace style as
    ``Finding.code``); ``exit_code`` is the CLI exit status (design section 13.1).
    Subclasses set both as class attributes; ``code`` may be overridden per instance.
    """

    code: str = "ERROR"
    exit_code: int = 1

    def __init__(
        self,
        message: str = "",
        *,
        code: str | None = None,
        refs: Sequence[str] = (),
    ) -> None:
        super().__init__(message)
        self.message = message
        self.refs: list[str] = list(refs)
        if code is not None:
            self.code = code

    def __str__(self) -> str:
        return self.message


class LabParseError(EveLabError):
    """The .unl file is not well-formed or lacks required structure."""

    code = "LAB_PARSE"


class UnsupportedLayout(EveLabError):
    """The raw span index and the ET view disagree: lab is read-only."""

    code = "UNSUPPORTED_LAYOUT"


class PreconditionError(EveLabError):
    """Dirty tree, running nodes, sha drift, lock held, etc."""

    code = "PRECONDITION"
    exit_code = 4


class BlockedError(EveLabError):
    """The plan has blockers (e.g. an edit hits protected inventory)."""

    code = "BLOCKED"
    exit_code = 2


class ConflictError(EveLabError):
    """Overlapping or stale edits."""

    code = "CONFLICT"
    exit_code = 2


class ValidationError(EveLabError):
    """Post-write validation failed (the lab was rolled back)."""

    code = "VALIDATION"
    exit_code = 5
