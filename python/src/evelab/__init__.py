"""evelab: Python tooling for the EVE-NG lab repository.

* :mod:`evelab.common`: tool-agnostic building blocks (``.unl`` parsing, text and
  TOML helpers, EVE host probes); nothing in there knows about any one tool.
* :mod:`evelab.localize`: eve-localize, which relocates labs to a new site.

New tools get their own subpackage next to ``localize`` and may import ``common``.
"""

__version__ = "0.1.0"
