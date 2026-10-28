"""eve-localize errors: the shared hierarchy from :mod:`evelab.common.errors`.

``LocalizeError`` is the base class every eve-localize failure derives from. It is
the shared :class:`~evelab.common.errors.EveLabError` itself, not a subclass: the
common modules (``unl``, ``codec``, ``tomlw`` ...) raise the shared classes, and
``except LocalizeError`` must keep catching those too.
"""

from evelab.common.errors import (
    BlockedError,
    ConflictError,
    EveLabError,
    LabParseError,
    PreconditionError,
    UnsupportedLayout,
    ValidationError,
)

LocalizeError = EveLabError

__all__ = [
    "BlockedError",
    "ConflictError",
    "EveLabError",
    "LabParseError",
    "LocalizeError",
    "PreconditionError",
    "UnsupportedLayout",
    "ValidationError",
]
