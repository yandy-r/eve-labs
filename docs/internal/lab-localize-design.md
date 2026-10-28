# eve-localize: final design and implementation plan

Status: approved design, ready for implementation · Owner: repo maintainers · Target: Python 3.11+ stdlib only

This document combines three candidate designs and the judges' reviews of them into one buildable design.
The baseline is **Design 2 (discovery-first, plugin-based)**, because the user asked for a tool that adapts when "other
labs and scenarios" are added. Grafted onto it:

- from **Design 1**: committed, *generated* per-lab manifests with pinned counts, tri-state matching, a
  baseline/revert workflow, CI validation and leak scan, TOML rule packs, and `site_key` bindings.
- from **Design 3**: fact confidence levels, a protected inventory, the declarative `RuleDialect`, saved plans
  checked by hash, a journal with undo, a segment/scheme matrix, the bridge roles wizard, and explicit blockers.

Every gap the judges raised is either closed or explicitly scoped out (section 15).

---

## 1. Problem, goals, non-goals

### 1.1 Problem

People who clone this repo have a different "outside world" from the author. These things differ:

- which EVE cloud bridge each segment uses (`pnet0`, `pnet2`, `nat0`, ...);
- the VLAN tags on those trunks;
- the mgmt and INET subnets, gateways, DNS, NTP and domains;
- the labels that devices repeat in their configs.

These values are spread across several places:

- the `.unl` XML (network `type` and `name`);
- base64 startup configs and configsets;
- sidecar `*_cfgs/NN_name.txt` files (Forti, F5);
- canvas textobjects.

Hand-editing is error-prone. The same digits appear everywhere as lab-internal values: `rd 2:2`, internal `Gi3.1240`,
`plsnetlab.local` vs `netlab.local`, `172.31.240.1` vs `.10`.

### 1.2 Goals

1. One interactive command, `scripts/eve-localize`, that:
   - lets the user pick one lab, several labs, or `--all`;
   - analyses each lab;
   - asks **only the questions that are relevant and feasible for that lab**;
   - rewrites every copy of each value consistently;
   - shows a reviewable plan before writing anything.
2. **Surgical edits.** Bytes outside the edited value spans stay identical. EVE quirks are preserved: stray `<objects/>`,
   attribute order, `smart="-1"`, `vlan8021ad`, `native_vlan`, `vid="1"`, single-line base64, trailing spaces, missing
   trailing newlines, UTF-8 em dashes in sidecars.
3. **Adapts to new labs with no code.** A new lab works through live discovery. A generated manifest pins it for CI.
   - A new vendor is one dialect file: mostly a `PatternRule` list, or a TOML pack with no Python at all.
   - A new scenario is one file. A new parameter kind is one registry entry.
4. **Safe and reversible.**
   - Dry-run by default; plan with diff, backup and journal.
   - Atomic writes that keep owner and mode (`www-data` on the EVE host).
   - Validation after writing, including `scripts/check-labs.py` logic.
   - Idempotent re-runs.
   - `revert` back to the repo baseline, so the user can `git pull` cleanly.
5. Runs on the EVE host as root and on Linux/macOS workstations. On Windows it degrades gracefully (section 11.9).

### 1.3 Non-goals (v1), each reported explicitly instead of done silently

| Not done in v1 | What the tool does instead |
|---|---|
| Structural config changes: untagged→tagged (new subif), tagged→untagged, DHCP→static, inserting routes or NAT | Reports a **blocker** that lists the exact lines to change by hand. A `transforms/` registry exists. One reference transform is planned as task T22 (optional wave). |
| Inventing values for devices with no config (Forti/F5 with `config="0"` and no sidecar) | Status `LABEL_ONLY`. Only bridge and label questions are asked. |
| Regenerating thumbnails | Notice: EVE regenerates them on the next save. |
| Mapping image names / docker images / templates between hosts | `scan --images` lists images missing on this host (EVE host only), for information. Out of scope because these are not network values; the fix is installing images. |
| IPv6 rewriting | IPv6 literals are **detected and reported** as "unhandled" in in-scope blobs. Nothing is silently ignored. |
| Changing EVE trunk attributes (`native_vlan`, `vlan8021ad`, interface `vid`) | Shown in the analysis. A warning appears when the user's bridge roles say the native VLAN differs (section 7.4). |
| Removing secrets from git history | `secrets` scenario: replace with a placeholder plus a printed rotation and history note. History rewrites are the maintainer's decision. |
| git clean/smudge filters, `skip-worktree` | Scoped out: they are fragile with EVE rewriting whole files. The supported workflow is `revert → git pull → apply --answers` (section 11.7). The `--out` copy mode avoids a dirty tree altogether. |

---

## 2. Concepts

| Term | Meaning |
|---|---|
| **Cloud network** | A `<network>` with `type != "bridge"` (`pnetN`, `natN`, `cloudN`, anything else). This is the **only** test for "external". Names never decide it. |
| **Store** | One place a config text lives: `startup` (`<configs>`), `cs:<name>` (one `<configset>`), `sidecar` (`<stem>*_cfgs/NN_name.txt`), `textobject:<id>`, or `xml` (network attributes). |
| **Scope** | The config scope a text belongs to: `startup` or a configset name. A sidecar has the scope it mirrors, or the node's active scope. |
| **Fact** | A typed value found at an exact span in a store, with a dialect rule id, an iface/block context, and a **confidence**. |
| **Confidence** | `PROVEN`: config on an interface traced to the cloud, directly or through L2. `CORRELATED`: IP inside a proven subnet, the same VLAN on the same switch, or an exact label token. `HEURISTIC`: name parsing, textobject proximity, corrupt-block facts. |
| **Segment** | One external L2/L3 domain. It contains: a group of cloud network ids; a role; one or more **schemes**; attachments; and a status of `CONFIGURABLE`, `DHCP`, `LABEL_ONLY`, `CARRIER` or `UNKNOWN`. |
| **Scheme** | `(tag, subnet, gateway)` as observed in a set of scopes. The backbone lab has three. |
| **Protected inventory** | Every VLAN and prefix not attributed to an external segment. An edit touching it is a **hard error**. |
| **Manifest** | The optional, committed, *generated* `<stem>.localize.toml`. It pins segments, baseline values, counts and author decisions such as scope policy, protect lists and scenarios. |
| **Site profile / answers** | The user's target values, gitignored. Keyed by **`site_key`**, a stable segment identity, plus value maps for services. |
| **Baseline** | The author's values, recorded in manifests. CI enforces that committed labs match it. `revert` targets it. |
| **Plan** | An ordered list of `Edit`s. Each has a span, the old text, the new text, provenance (question → fact → rule → evidence), category, confidence and group. |

---

## 3. Architecture

```
 .unl ──► unl.RawLab (raw bytes + span index, ET read-only cross-check)
 sidecars ─► stores (embedded / sidecar, id+name guard, mirror detection) ─► ConfigText[]
                                                     │ dialects.pick(node, text)
                                                     ▼
                         dialects.* (RuleDialect + PatternRule / TOML packs) ─► ParsedConfig (facts w/ spans)
                                                     ▼
                discover.topology ► discover.l2trace ► discover.segments ► discover.inventory
                                                     ▼
            Analysis(segments, schemes, facts, protected, findings)  ◄── manifest (pins / overrides / expect)
                                                     ▼
            scenarios.* ─► Question[]  ◄──► ui (interactive) | answers file | --yes defaults
                                                     ▼
            planner: ValueMaps (single pass) ► claims ► conflicts/blockers ► Plan
                                                     ▼
            ui.review (matrix, groups, decoded diff, explain) ► apply: preflight ► backup ► atomic write
                       ► validate (ET, counts, spans, check-labs, re-scan = 0 edits) ► journal ► state
```

All analysis is read-only and gives the same result every run. Writing is the last step and only happens when asked
for.

### 3.1 File layout (exact)

```
scripts/
  eve-localize                       # shim: sys.path.insert(0, <repo>/python/src); from evelab.localize.cli import main
python/
  pyproject.toml                     # package "evelab", ruff + black config, console script eve-localize
  src/evelab/
    __init__.py
    common/                          # tool-agnostic building blocks; never import a tool package
      errors.py                      # EveLabError, LabParseError, UnsupportedLayout, PreconditionError,
                                     #   BlockedError, ConflictError, ValidationError (each has .code: str and .exit_code: int)
      spans.py                       # Span, TextEdit
      labmodel.py                    # Interface, Node, Network (parsed-lab topology records)
      findings.py                    # Finding
      paths.py                       # REPO_ROOT, SCRIPTS_DIR
      textutil.py                    # IPv4 tokenizer, IPv6 detector, masks, VlanList, token_re,
                                     #   domain_re, html_text_regions
      codec.py                       # DecodedBlob, decode_blob, encode_blob (canonical base64 check)
      unl.py                         # RawLab: span index, ET cross-check, set_attr, replace_blob, edits->bytes
      hostenv.py                     # EVE host probes: bridges (/sys/class/net), running nodes, images, lock
      tomlw.py                       # minimal TOML writer (+ re-parse check with tomllib)
      tomlschema.py                  # TableReader: strict, path-naming TOML table reader
    localize/
      __init__.py                    # __version__, SCHEMA = 1
      errors.py                      # LocalizeError (= common EveLabError) and the shared subclasses
      model.py                       # all shared dataclasses / enums (section 4) — THE contract; re-exports the
                                     #   records that live in common (Span, TextEdit, Finding, Node, Network, Interface)
      stores.py                      # load ConfigTexts: embedded startup/configsets + sidecars; mirrors
      manifest.py                    # load/validate/generate <stem>.localize.toml
      profile.py                     # site profile + answers load/merge/save; secrets via env
      dialects/
        __init__.py                    # REGISTRY, register(), pick(), load_packs(dirs)
        base.py                        # Dialect protocol, RuleDialect, PatternRule, IfaceInfo, ParsedConfig
        blocks.py                      # tolerant block parsers: indent | fortios | brace | flat | html
        ios.py                         # IOS / IOL L3 / IOL L2 / vIOS / IOSv-L2
        iosxe.py                       # CSR1000v / C8000v (inherits ios)
        nxos.py
        asa.py
        fortios.py
        f5tmsh.py
        junos.py
        linuxsh.py                     # docker/linux startup scripts, resolv.conf heredocs
        vpcs.py
        eve_html.py                    # textobject HTML: text-node IP/CIDR/token facts only
        generic.py                     # fallback: IPv4 tokens + label tokens, HEURISTIC/CORRELATED only
        packs/                         # declarative TOML rule packs (no Python), e.g. vyos.toml later
      discover/
        __init__.py                    # analyse(lab, manifest) -> Analysis
        topology.py                    # clouds, attachments, EVE<->config iface-name mapping
        l2trace.py                     # VLAN propagation through switches / bridges, per scope
        segments.py                    # grouping, merge rules, schemes, status, outliers
        names.py                       # NameExplainer (tag / octet3 / host / netid / ambiguous / unknown)
        inventory.py                   # protected inventory + internal subnets
      scenarios/
        __init__.py                    # SCENARIOS registry, register_scenario()
        base.py                        # Scenario protocol, Question, Answers
        bridge.py                      # cloud bridge per segment (+ carrier follow, pnet text mentions)
        segment_l2.py                  # VLAN tags (+ subif/SVI rename, VLAN lists, (VLAN n) mentions)
        segment_l3.py                  # subnet / gateway / masks / split maps / host overrides
        labels.py                      # network names (+ templated suggestions, text propagation, textobjects)
        services.py                    # DNS / NTP / domain / search / SLA probe targets
        site_routes.py                 # supernet / home routes via external gateways
        bgp_upstream.py                # eBGP peer inside external subnet, peer AS, advertised prefixes
        azure_s2s.py                   # public IPsec peer as object name, PSK, APIPA, ASNs
        secrets.py                     # placeholder replacement of committed secrets
      transforms/
        __init__.py                    # TRANSFORMS registry (empty in v1; T22 adds ios_dhcp_to_static)
      planner.py                       # ValueMaps, claims, conflicts, Plan build, explain chains
      apply.py                         # preflight, backup, atomic write, validate, journal, undo, state
      ui.py                            # prompts, tables, matrix, pager, decoded diff, secret redaction
      cli.py                           # argparse, commands, lab picker, orchestration, exit codes
  tests/
    __init__.py                      # puts python/src on sys.path (no install needed)
    common/                          # test_textutil.py test_codec.py test_unl.py test_tomlw.py test_hostenv.py
    localize/
      fixtures/snippets/<dialect>/*.txt + *.facts.json
      fixtures/minilabs/*.unl        # synthetic edge-case labs
      golden/<stem>.scan.json        # discovery goldens
      golden/<stem>.answers.toml     # synthetic "site B" answers per lab
      test_stores.py
      test_dialect_contract.py test_dialect_<name>.py
      test_l2trace.py test_segments.py test_planner.py test_apply.py
      test_labs_golden.py test_roundtrip.py test_cli.py
localize/
  site.example.toml                  # generated from manifests (author baseline as an example profile)
  README.md                          # user guide
labs/**/<stem>.localize.toml         # generated manifests, committed next to each .unl that has clouds
.localize/                           # gitignored: site.toml, backups/, journal.json, state.json, plans/, lock
```

`.gitignore` additions: `/.localize/`, `*.localize.toml.draft`. Thumbnails, `Users/` and `Shared/` are unchanged.

**Layout change.** The tool was first built as `scripts/eve-localize.py` + `scripts/evelocal/` + `scripts/tests/`
(historical wording elsewhere in this document, e.g. the module names in sections 4-16, refers to that layout). It
now lives in a src-layout Python project so that more tools can be added:

- `scripts/evelocal/X.py` is `python/src/evelab/localize/X.py`, except the tool-agnostic modules (`unl`, `codec`,
  `textutil`, `tomlw`, `tomlschema`, `hostenv`, `errors`) which are in `python/src/evelab/common/`. `Span`,
  `TextEdit`, `Finding`, `Node`, `Network` and `Interface` moved to `common` too and are re-exported by `model.py`;
  `localize.errors.LocalizeError` is the common `EveLabError` itself, so `except LocalizeError` still catches the
  errors raised by common modules.
- Imports are absolute across packages (`evelab.common.unl`) and relative inside one (`from .model import Span`).
- `scripts/eve-localize` (no `.py`) is the shim and needs no install; `pip install -e python/` adds an
  `eve-localize` console script. `scripts/check-labs.py` did not move.
- Tests: `cd python && python3 -I -B -m unittest discover -s tests -t .` (`make localize-test`);
  `tests/__init__.py` puts `python/src` on `sys.path`. Lint: `ruff` + `black` configured in `python/pyproject.toml`.

### 3.2 Shared interfaces (signatures; implementors must not change them without updating this doc)

```python
# unl.py
class RawLab:
    path: Path; raw: bytes; sha256: str; lab_id: str; name: str
    @classmethod
    def read(cls, path: Path) -> "RawLab": ...           # raises LabParseError / UnsupportedLayout
    def networks(self) -> list[RawElem]: ...              # id, attrs, Span of start tag, attr value spans
    def nodes(self) -> list[RawNode]: ...                 # attrs + interfaces(id, name, network_id, vid)
    def config_blobs(self) -> list[RawBlob]: ...          # scope "startup" | "cs:<name>", node_id, Span(b64)
    def configsets(self) -> dict[str, str]: ...           # configset id -> name
    def textobjects(self) -> list[RawBlob]: ...           # id, name, type, Span(b64 <data>)
    def objects_count(self) -> int: ...                   # incl. stray <objects/>
    def attr_edit(self, elem: RawElem, attr: str, new: str) -> RawEdit: ...   # value span only, escaped
    def blob_edit(self, blob: RawBlob, new_b64: bytes) -> RawEdit: ...
def splice(raw: bytes, edits: list[RawEdit]) -> bytes: ...   # sorted, overlap -> ConflictError, expect checked

# codec.py
@dataclass
class DecodedBlob: raw_b64: bytes; text: str; encoding: Literal["utf-8","latin-1"]; canonical: bool
def decode_blob(b64: bytes) -> DecodedBlob | None: ...   # None = opaque (undecodable/binary)
def encode_blob(text: str, like: DecodedBlob) -> bytes: ...  # single-line, same encoding

# stores.py
def load_texts(lab: RawLab, nodes: dict[str, Node], manifest: Manifest | None) -> tuple[list[ConfigText], list[Finding]]
def write_sidecar(ct: ConfigText, new_text: str) -> bytes: ...   # same newline style & trailing-nl

# dialects/__init__.py
def register(cls: type[Dialect]) -> type[Dialect]: ...
def pick(node: Node | None, text: str, override: str | None = None) -> Dialect: ...
def load_packs(dirs: list[Path]) -> None: ...           # TOML packs + --plugins *.py

# discover/__init__.py
def analyse(lab: RawLab, manifest: Manifest | None, opts: AnalyseOptions) -> Analysis: ...

# scenarios/base.py
class Scenario(Protocol):
    id: str; order: int
    def applies(self, a: Analysis, m: Manifest | None) -> bool: ...
    def questions(self, a: Analysis, m: Manifest | None, prof: Profile) -> list[Question]: ...
    def plan(self, a: Analysis, ans: Answers, maps: ValueMaps) -> PlanFragment: ...

# planner.py
def build_plan(a: Analysis, ans: Answers, opts: PlanOptions) -> Plan: ...
def explain(plan: Plan, edit_id: str) -> list[str]: ...

# apply.py
def preflight(plans: list[Plan], opts: ApplyOptions) -> list[Finding]: ...
def apply_plan(plan: Plan, opts: ApplyOptions) -> RunRecord: ...     # tx per lab, rollback on failure
def undo(run_id: str | None, opts: ApplyOptions) -> list[Path]: ...
def validate_written(path: Path, plan: Plan, before: RawLab) -> list[Finding]: ...

# manifest.py
def load(path: Path) -> Manifest: ...          # strict: unknown keys/ids -> error
def find_for(lab_path: Path) -> Manifest | None: ...
def generate(a: Analysis, previous: Manifest | None = None) -> str: ...   # TOML (draft/update), T15
def check(a: Analysis, m: Manifest | None, *, localized=None, localized_params=None,
          leaks=True) -> list[Finding]: ...   # counts, baseline, coverage, leaks, unpinned (T15)

# profile.py
def load_profile(paths: list[Path]) -> Profile: ...
def save_answers(path: Path, ans: Answers, include_secrets: bool = False) -> None: ...
```

---

## 4. Data model (`model.py`)

```python
from dataclasses import dataclass, field
from enum import IntEnum
from ipaddress import IPv4Address, IPv4Network
from typing import Literal, NamedTuple

class Confidence(IntEnum):
    HEURISTIC = 1; CORRELATED = 2; PROVEN = 3

class Store(NamedTuple):
    kind: Literal["xml", "startup", "configset", "sidecar", "textobject"]
    name: str            # "startup" | configset name | sidecar relpath | textobject id | "xml"
    scope: str           # "startup" | "<configset name>" | "-"

@dataclass(frozen=True)
class Span: start: int; end: int

@dataclass
class Interface: id: str; name: str; network_id: str | None; vid: str
@dataclass
class Node:
    id: str; name: str; type: str; template: str; image: str
    config_attr: str     # "0" | "1" | configset id
    ifaces: list[Interface]
@dataclass
class Network:
    id: str; type: str; name: str; attrs: dict[str, str]
    @property
    def is_cloud(self) -> bool: return self.type != "bridge"

@dataclass
class ConfigText:
    store: Store; node_id: str; text: str; dialect: str
    blob: "DecodedBlob | None"        # embedded
    path: Path | None                 # sidecar
    mirror_of: tuple[str, str] | None = None   # (scope, node_id) when byte-identical to an embedded blob
    opaque: bool = False

FactKind = str   # extendable; registered kinds below (see section 13.3)
CORE_FACT_KINDS = {
    "ip_host", "ip_gateway", "ip_route_dst", "mask", "dhcp", "vlan_tag", "vlan_list", "vlan_def",
    "vlan_name", "subif_name", "svi_name", "label_ref", "cloud_ref", "vlan_mention",
    "dns_server", "domain", "search_list", "ntp_server", "probe_target", "peer_ip", "asn",
    "router_id", "secret", "ipv6_literal",
}

@dataclass
class Fact:
    id: str                      # sha1(store, node, start, kind)[:12], stable
    kind: FactKind; value: str
    store: Store; node_id: str | None; span: Span; line: int
    rule: str                    # "iosxe.encap_dot1q"
    iface: str | None            # canonical iface key of the enclosing block ("gi16.2"); None = no/orphan block
    parent: str | None           # physical parent iface key for subifs / Forti vlan ifaces
    mask_span: Span | None = None; mask_form: Literal["dotted", "prefix", "netmask", "none"] = "none"
    list_value: "VlanList | None" = None
    group: str | None = None     # tokens that must change together (subif name + encap)
    segment: str | None = None   # set by attribution
    confidence: Confidence = Confidence.HEURISTIC
    evidence: str = ""           # path / reason ("mgmt-80 e0/0 trunk(ALL) -> e0/2 access 2 -> mgmt0")
    orphan: bool = False         # inside a corrupt/truncated block
    flags: frozenset[str] = frozenset()   # {"uncabled", "cosmetic", "outlier", "secret"}

Tag = int | Literal["untagged", "unknown"]

NameClass = Literal["tag", "octet3", "host", "netid", "ambiguous", "unknown"]

@dataclass(frozen=True)
class NameToken:                 # one digit run of a cloud network name (section 7.4)
    text: str                    # digits as written ("0203")
    span: Span                   # offsets inside the network name
    kind: NameClass
    value: int | None = None

@dataclass
class Scheme:
    tag: Tag; subnet: IPv4Network | None; gateway: IPv4Address | None
    scopes: set[str]; members: list[str]; outliers: list[str]

@dataclass
class Attachment:
    node_id: str; iface: str; network_id: str; scope: str
    path: list[str]; direct: bool; arrives: Literal["untagged", "tagged"]

@dataclass
class Segment:
    key: str                     # manifest key or derived ("MGMT-203", "cloud-22")
    site_key: str                # profile identity ("site.mgmt_a" or "<labstem>.<key>")
    role: str | None             # mgmt|inet|oob|trunk|nat|wan|None
    network_ids: list[str]; cloud_types: set[str]; labels: dict[str, str]   # net id -> name
    attachments: list[Attachment]; schemes: list[Scheme]
    status: Literal["CONFIGURABLE", "DHCP", "LABEL_ONLY", "CARRIER", "UNKNOWN"]
    carries: list[str] = field(default_factory=list)  # CARRIER: segment keys it carries
    name_hints: dict[str, list["NameToken"]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

@dataclass
class Finding:
    code: str                    # e.g. "STRUCTURAL_TAGGING", "LEAK", "UNCONFIGURED", "IPV6_UNHANDLED"
    severity: Literal["info", "warn", "conflict", "blocker", "error"]
    msg: str; refs: list[str] = field(default_factory=list)

@dataclass
class Analysis:
    lab: "RawLab"; nodes: dict[str, Node]; networks: dict[str, Network]
    texts: list[ConfigText]; facts: dict[str, Fact]; segments: list[Segment]
    protected_vlans: dict[str, set[int]]          # scope -> vlans
    protected_prefixes: list[IPv4Network]
    active_scope: dict[str, str]                  # node_id -> scope
    findings: list[Finding]; pinned: bool         # manifest present and consistent

@dataclass
class TextEdit: start: int; end: int; old: str; new: str
@dataclass
class Edit:
    id: str; file: Path; target: Literal["xml_attr", "blob", "sidecar", "textobject"]
    store: Store; node_id: str | None; text_edit: TextEdit
    category: str                # cloud|label|vlan|ip|mask|gateway|dns|domain|ntp|route|cosmetic|secret|derived
    group: str                   # review toggle group, e.g. "MGMT-203/vlan", "cosmetic/pnet-text"
    confidence: Confidence; secret: bool
    provenance: list[str]        # [question id, fact id(s), rule id, evidence]

@dataclass
class Plan:
    schema: int; lab: Path; lab_id: str
    base_sha256: dict[str, str]  # every file touched (relpath -> sha)
    answers_digest: str; edits: list[Edit]; enabled_groups: set[str]
    findings: list[Finding]
    @property
    def blocked(self) -> bool: return any(f.severity in ("conflict", "blocker", "error") for f in self.findings)
```

**Resolutions applied when `model.py` was written (T1)**

- `Span` is defined only in `model.py` (section 3.1 listed it under `textutil.py` too). `textutil.py` re-exports it.
- `NameToken` was referenced by `Segment.name_hints` but never defined; it is defined above (frozen dataclass, section 7.4
  classes).
- `DecodedBlob` (`codec.py`), `VlanList` (`textutil.py`) and `RawLab` (`unl.py`) are imported only under
  `TYPE_CHECKING` (no runtime import cycle); `model.py` uses `from __future__ import annotations` and `from pathlib
  import Path`.
- `CORE_FACT_KINDS` stays a plain mutable `set[str]` so dialect packs/plugins may register extra kinds (section 13.3).
- Every error in `errors.py` has `.code: str` (stable upper-case id, overridable per instance via `code=`) and
  `.exit_code: int` (section 13.1 table: `LocalizeError`/`LabParseError`/`UnsupportedLayout` 1,
  `BlockedError`/`ConflictError` 2, `PreconditionError` 4, `ValidationError` 5). Constructor:
  `LocalizeError(message="", *, code=None, refs=())`.
- Only `Span`, `NameToken` are frozen. Everything else is a plain mutable dataclass exactly as listed (`Fact.segment`,
  `Fact.confidence` etc. are set during attribution).
- `__pycache__/` is not yet in `.gitignore`; T22 adds it with the other entries.

**Resolutions applied when `unl.py` / `codec.py` were written (T3)** — all additive to section 3.2

- `RawLab.read(path, *, strict=False)`: malformed XML / wrong root → `LabParseError`. An ET cross-check mismatch does
  **not** raise (scan must still work): the lab gets `read_only=True` and `layout_issues: list[str]`; `attr_edit` and
  `blob_edit` then raise `UnsupportedLayout`. `strict=True` raises `UnsupportedLayout` at read time instead.
  `verify_against_etree() -> list[str]` returns the problems (empty = ok).
- Added `RawLab.from_bytes(raw, path=None)` (re-read freshly written bytes), `node_models()`/`network_models()` (shared
  model objects keyed by id), `skip_regions() -> list[tuple[str, Span]]` (`description`, `tasks`, `lineobjects`).
- Shapes (all in `unl.py`): `RawAttr(name, value, span, quote)`; `RawElem(tag, span, attrs: Mapping[str, RawAttr])` with
  `.id`, `.get(name, default="")`, `.values()`; `RawIface(elem)`; `RawNode(elem, ifaces)` with `.to_model()`;
  `RawBlob(kind, scope, id, node_id, name, type, configset_id, span, b64, elem, self_closing)`
  (config: scope `"startup"` | `"cs:<name>"`; textobject: scope `"-"`, `node_id=None`);
  `RawEdit(start, end, old: bytes, new: bytes)`. All offsets are byte offsets.
- `splice()` raises `ConflictError` (`code` default `CONFLICT` for overlaps, `STALE_EDIT`, `BAD_SPAN`); two
  insertions at one offset count as an overlap. `verify_outside_spans(before, after, edits)` implements the slice
  comparison of section 12.3 step 3.
- `attr_edit` escapes `& < >` and the active quote char (`>` as well as the section 5.1 list, always legal) and keeps
  the original bytes when the new value equals the current decoded value. Label check failures raise
  `LocalizeError(code="BAD_LABEL")`; `label_warnings()` reports the soft 32-character limit. A missing attribute is
  `NO_SUCH_ATTR`.
- `codec.py` adds `encode_text(text, encoding)` (no shortcut), `apply_text_edits(text, edits)` and
  `edit_blob(like, edits)`. `encode_blob` returns `like.raw_b64` untouched for unchanged text and raises
  `LocalizeError(code="NONCANONICAL_BLOB")` for changed text on a non-canonical blob. A blob that is valid base64 of
  text such as `ff` (lab1 VPC, `ZmY=`) decodes as text; only invalid base64, NUL bytes or >5 % stray control bytes are
  opaque (`decode_blob` → `None`). ASCII whitespace inside a blob is tolerated and makes it non-canonical.
- Self-closing `<config id="N"/>` is indexed (empty span, `self_closing=True`) but cannot be edited in place.

---

## 5. Reading and writing `.unl` without corrupting it

### 5.1 RawLab (`unl.py`)

- `raw` is the exact file bytes. `ET.fromstring(raw)` builds the semantic model and is **never used to write**.
- A span index is built with anchored regexes over the raw bytes:
  - each `<network ...>` start tag, and the value spans of its `type` and `name` attributes;
  - inside the first `<objects>` element that has children: `<configs>` → `<config id="N">B64</config>`;
  - each `<configset id=".." name="..">`, and the `<config id>` children inside it;
  - `<textobject id=..>…<data>B64</data>`.
- `<tasks>`, `<description>` and `<lineobjects>` are recorded as regions to skip and are never decoded. That covers the
  1.6 MB PDF in `lab1-ei-v01`. Stray empty `<objects/>` elements are counted and never touched.
- `verify_against_etree()`: the ids and counts of networks, nodes, interfaces, configs per configset and textobjects
  must equal the ET view. On mismatch → `UnsupportedLayout`: the lab becomes **read-only** (scan works, apply is
  refused).
- `attr_edit()`: the new value is escaped (`&amp; &lt; &quot;`) and must pass the label character check (printable, no
  control characters, at most 64 chars, warning above 32).
- `splice()`: edits are sorted by start offset, overlaps raise `ConflictError`, the expected old bytes are checked at
  each span, and edits are applied from the end of the file backwards.

### 5.2 Blob codec (`codec.py`)

- base64-decode, then UTF-8 decode. If UTF-8 fails, fall back to latin-1 so bytes round-trip exactly.
- `canonical = b64encode(decoded_bytes) == raw_b64`. All current blobs are canonical: single line, no wrapping.
- A **non-canonical** blob is read, but any edit to it is `blocker NONCANONICAL_BLOB`.
- An undecodable or binary blob is `opaque`. It produces no facts and an info finding. Examples: the VPC config that is
  literally `ff`, and nodes with `config="1"` but no blob.
- Edits are span splices inside the decoded text. Leading `\n` (ASA), trailing spaces, missing trailing newline, `^C`
  banners, LF line endings and text after `end` are all preserved automatically.
- **Blobs with no edits are never re-encoded.** This applies especially to SVG textobjects.

### 5.3 Sidecars (`stores.py`)

- Directory resolution, in order:
  1. the manifest's `sidecar_dirs`;
  2. `<parent>/<stem>_cfgs`;
  3. `<parent>/<stem>*_cfgs`. This matches `vxlan_evpn_multi-site_with_backbone_dmvpn_cfgs`.
- If more than one directory matches and no manifest entry exists → `blocker SIDECAR_AMBIGUOUS`.
- File mapping: `^(\d+)_(.+)\.txt$`. The file is accepted **only if NN is a node id and `name == nodes[NN].name`**. On a
  mismatch the file is skipped with `warn SIDECAR_MISMATCH`; a manifest `[sidecar_map]` entry can force a mapping.
  This guard matters because ids 7/8/10/20/41 exist in both the sdwan and backbone labs. Sidecars are **never shared
  across labs**.
- Files are read as bytes and decoded as UTF-8 with `surrogateescape`. Newline style (LF/CRLF) and the trailing-newline
  state are recorded and written back the same way.
- Dialect comes from the node's template first, then content sniffing (`config system` → fortios, `tmsh ` → f5tmsh).
- **Mirror detection**: if a sidecar is byte-identical to the node's decoded blob in some scope, it is marked
  `mirror_of=(scope, node)`. The backbone `_dmvpn_cfgs` mirror `vxlan-dmvpn-backbone`, or `startup` for 11 docker
  nodes.
  - The same TextEdits are applied to both copies, and the results must still be identical, otherwise the lab aborts.
  - If they already differed before editing, they are treated as independent stores and an info finding is shown.

**Resolutions applied when `stores.py` was written (T8)** — additive to section 3.2

- `load_texts(lab, nodes=None, manifest=None, *, textobjects=True)`: `nodes` defaults to `lab.node_models()`. Order:
  embedded blobs (document order), textobjects, sidecars (sorted by path).
- Stores: startup `Store("startup", "startup", "startup")`; configset `Store("configset", <name>, <name>)`; textobject
  `Store("textobject", <id>, "-")` with `node_id=""` and dialect `eve_html` (or `generic` if not registered); sidecar
  `Store("sidecar", <path relative to the lab dir, POSIX>, <mirrored scope or node's active scope>)`.
- `mirror_of = (scope, node_id)` uses the **Store scope** form (`"startup"` or the configset name, not `cs:<name>`).
  Several matching scopes: active scope, then `canonical_scope`, then `startup`, then document order. Helpers
  `mirror_source(texts, ct)` and `mirrors_agree(a, b)` serve the planner's equality assertion.
- `<stem>*_cfgs` candidates that are the exact `_cfgs` dir of another lab next to this one are excluded. Under
  `SIDECAR_AMBIGUOUS` no sidecar is loaded. `[sidecar_map]` keys are a file name or a lab-relative path (a path may
  point outside the resolved dirs). Non-`NN_name.txt` files are ignored silently.
- Finding codes: `SIDECAR_AMBIGUOUS` (blocker), `SIDECAR_MISMATCH`, `SIDECAR_DIR_MISSING`, `SIDECAR_DUPLICATE`
  (warn), `SIDECAR_INDEPENDENT`, `OPAQUE_BLOB`, `MISSING_BLOB` (`config="1"` with no startup blob), `ORPHAN_CONFIG`
  (info), `UNKNOWN_DIALECT` (error; manifest dialect override not registered, falls back to detection).
- Opaque texts produce no facts: undecodable/binary (`text=""`, `blob=None`), empty or self-closing blobs, and
  decodable garbage (`is_garbage_text`: one short token with no whitespace/`.`/`:`, e.g. `ff`; `blob` and `text` kept).
- Sidecar text is not newline-normalised (dialects see `\r\n`). `write_sidecar` converts newlines to the original
  style (`lf`/`crlf`; `mixed` untouched) and restores the trailing-newline state. Dialect pick failures (registry
  without `generic`) fall back to the name `"generic"`.

---

## 6. Dialects

### 6.1 Contract (`dialects/base.py`)

```python
@dataclass(frozen=True)
class PatternRule:
    id: str                         # "iosxe.encap_dot1q"
    pattern: str                    # Python regex, named groups: v (value) [, mask, parent, list, ...]
    kind: FactKind
    block: str | None = None        # "interface" | "vlan" | "vrf" | "system dns" | "edit:<cfg>" | None=top/any
    l2: bool = False                # contributes to l2_ports()
    list_style: Literal["nxos", "ios", "space", "brace"] | None = None
    anchored_keywords: tuple[str, ...] = ()   # documentation + negative-test hints
    negative: tuple[str, ...] = ()  # example lines that must NOT match (contract-tested)

class Dialect(Protocol):
    name: str
    templates: tuple[str, ...]      # fnmatch on node.template / node.image
    sniff: tuple[str, ...]          # content regexes
    block_style: Literal["indent", "fortios", "brace", "flat", "html"]
    mask_form: Literal["dotted", "prefix", "mixed"]
    def score(self, node: Node | None, text: str) -> int: ...          # 0..100
    def iface_key(self, name: str) -> str: ...                          # "GigabitEthernet16.2"/"Gi16.2" -> "gi16.2"
    def eve_to_config(self, eve_name: str) -> list[str]: ...           # "Gi16" -> ["GigabitEthernet16"]
    def parse(self, ct: ConfigText) -> ParsedConfig: ...
    def render(self, fact: Fact, new: str, ctx: RenderCtx) -> list[TextEdit]: ...
    def secret_spans(self, text: str) -> list[Span]: ...

class RuleDialect:                  # default implementation: 90% of vendors only declare data
    rules: tuple[PatternRule, ...]; secret_rules: tuple[str, ...]; iface_aliases: dict[str, str]
    # parse(): blocks.split(text, block_style) -> for each rule: finditer within allowed blocks -> Fact
    # render(): replace value span; list facts via VlanList; mask facts via textutil.mask_render(form)

@dataclass
class IfaceInfo:
    key: str; name: str; parent: str | None; name_span: Span | None
    mode: Literal["routed", "access", "trunk", "unknown"]
    access_vlan: int | None; trunk_vlans: "VlanList | None"   # None = ALL (no allowed list)
    native_vlan: int | None; tag: int | None; dhcp: bool; orphan: bool

@dataclass
class ParsedConfig:
    dialect: str; facts: list[Fact]; ifaces: dict[str, IfaceInfo]
    vlan_db: set[int]                # explicit `vlan N` defs ∪ implicit (access/allowed/SVI) VLANs
    is_switch: bool; notes: list[str]
```

Dialect selection uses template, image and content only, **never the node name**. For example, R2 runs an L2 image and
ISP-RTR9 has `hostname ISP-RTR1`. A manifest `[nodes."N"] dialect = "..."` always wins. Unknown templates get
`generic`: IPv4 tokens in proven subnets plus label tokens, no tag edits, and a finding suggesting a new dialect.

### 6.2 Block parsers (`blocks.py`)

- `indent` (ios/iosxe/nxos/asa):
  - A block starts at `^interface (\S+)\s*$`, `^vlan (\S+)`, `^vrf context (\S+)`, `^router bgp`, and similar, and ends
    at the next column-0 line.
  - Spliced syslog lines (`^\*\w{3} +\d+ \d\d:\d\d:\d\d\.\d+: %`) are skipped.
  - A truncated header (`interface GigabitEthernet` with no number) opens an **orphan** block. Facts in it get
    `iface=None, orphan=True` and at most CORRELATED confidence.
  - Text after `end` is ignored.
- `fortios`: a `config X` / `edit "y"` / `next` / `end` stack. Block ids look like `system interface/oob-mgmt`, and the
  parent comes from `set interface "port8"`.
- `brace` (junos): a brace-depth path such as `interfaces/fxp0/unit 0/family inet`.
- `flat` (linuxsh, f5tmsh, vpcs): no blocks. Heredoc regions (`cat << EOF > /etc/resolv.conf` … `EOF`) are tagged.
- `html`: only text between `>` and `<` is examined. Tag interiors (attributes, `style`, SVG geometry) never are.

### 6.3 Tag-bearing syntax: the only places a VLAN number can change

| dialect | syntax (rule ids) |
|---|---|
| ios / iosxe | `interface X.N` (subif_name), `encapsulation dot1[Qq] N`, `switchport access vlan N`, `switchport trunk allowed vlan [add] LIST`, `switchport trunk native vlan N`, top-level `vlan N` / `vlan LIST`, `interface VlanN` |
| nxos | as ios + `vlan 1,100-101,201,…` range lists, lowercase `encapsulation dot1q N` |
| asa | `interface X.N` + ` vlan N` |
| fortios | `set vlanid N` inside `edit "<if>"` (parent from `set interface`) |
| junos | `vlan-id N;`, `unit N { vlan-id N; }` |
| linuxsh | `ip link add link P name P.N type vlan id N` |
| f5tmsh | `create net vlan NAME tag N` |

These lines never produce a tag fact and are protected: `rd 2:2`, `set ike-version 2`, `edit 2`,
`set community 204:204`, `members 1 2`, CSS `203px`, and ISIS `net 49.0000…`. Each one appears as a `negative`
example on the relevant rules.

### 6.4 Services, anchored keywords only

- DNS:
  - `ip name-server [vrf X] IP…` (and NX-OS under `vrf context`)
  - resolv.conf `nameserver IP`
  - Forti `config system dns` → `set primary|secondary IP`
  - F5 `name-servers replace-all-with { … }`
  - Junos `name-server { IP …; }`
- Domain:
  - `ip domain-name X`, `ip domain name X`
  - Junos `domain-name X;` / `domain-search X;`
  - resolv.conf `search a b`
  - F5 `search replace-all-with { … }`
  - the F5 FQDN hostname suffix
- NTP:
  - `ntp server X`
  - F5 `ntp servers replace-all-with { … }`
  - Forti `config system ntp` → `set server`
  - Junos `ntp { server X; }`
- Probe targets: Forti health-check `set server "a" "b"`. This is kind `probe_target` and never counts as DNS.
- The NX-OS `vlan 100` / `name servers` pair is a `vlan_name`. It never matches a DNS rule.

### 6.5 IPv4 tokens (`textutil.py`)

```python
IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]|\.\d)")
```

Each match is validated with `ipaddress`. The pattern never matches `172.31.240.1` inside `172.31.240.10`, cert hex
(`01010105`), OIDs or ISIS NETs. When a mask follows the address it is captured: ` 255.255.255.0`, `/24`,
` netmask M`. `domain_re(d)` is `(?<![\w-])` + escaped d + `(?![\w-])`. A preceding `.` is allowed so FQDN suffixes
match, so `plsnetlab.local` never matches `netlab.local`.

**Resolutions applied when `textutil.py` and `dialects/` were written (T2, T5)**

- `IPV4_RE` guard is `(?!\w|\.\w)`: a sentence-final period still matches; `1.2.3.4.5`, `10.1.1.1.example.com` and
  `.10` vs `.1` do not. `domain_re` uses `(?![\w-]|\.[\w-])` and is case-insensitive, so `netlab.local.example` is a
  different domain. `find_ipv4` absorbs an ACL wildcard (`0.0.0.255`) following an address as a `wildcard` mask.
- `RenderCtx(text, new_prefix=None)` is defined in `dialects/base.py`. `render` verifies `fact.span` still holds the old
  value (else `ConflictError(code="STALE_FACT")`), returns `[]` for a no-op, validates IPv4/number/list values
  (`LocalizeError(code="BAD_VALUE")`), and rewrites the adjacent mask in its own form when `new_prefix` differs.
- `PatternRule` gained optional `role` (`access_vlan|trunk_allowed|native_vlan|encap_tag|mode_access|mode_trunk`; feeds
  `IfaceInfo`, inferred from `kind`+`l2` when omitted; `kind=""` = role only, no fact) and `flags` (copied to
  `Fact.flags`). Patterns run line by line; `IPV4`/`MASK` placeholders; groups `v mask parent list many add kw`;
  `block` may also be `"top"`, a trailing-`*` fnmatch or a prefix (`heredoc` matches `heredoc:/etc/resolv.conf`).
- `RuleDialect` parse defaults: facts get `Confidence.PROVEN` (`default_confidence`; orphans at most CORRELATED,
  `iface=None`; ipv6 literals HEURISTIC); `group="subif:<iface>"` ties subif/SVI names to the tag facts of the same
  interface; orphan interface blocks appear in `ParsedConfig.ifaces` under the key `orphan:<header line>` with
  `orphan=True`; `secret` facts come from `secret_rules` group `s`; `ipv6_literal` facts from `textutil.find_ipv6`.
- `REGISTRY` holds shared **instances**. `register` rejects a different class under an existing name
  (`DIALECT_DUPLICATE`). Built-in modules and `packs/*.toml` load lazily (`load_builtin()`, called by `pick`/`get`).
  `pick` never uses the `generic` dialect in the scoring (it is the fallback only).
- Contract harness: `tests/localize/test_dialect_contract.py` (`DialectContractMixin`, `check_snippet`, `check_static`,
  `skeleton`); it auto-generates `Contract_<dialect>` tests for every registered dialect with
  `fixtures/snippets/<dialect>/*.txt` + `*.facts.json`.


**Resolutions applied when `asa.py`, `fortios.py` and `f5tmsh.py` were written (T10)** — additive, no contract change

- New helper module `dialects/_common.py` (not a dialect; `load_builtin` does not list it):
  - `ContextRule(id, context, token, kind, block, flags, negative)` + `ContextRulesMixin`: one fact per `token` match
    inside the `ctx` group of a line-level `context` regex (a `PatternRule` yields one value per match). Used for
    label words, `pnetN`, `(VLAN n)`, Forti health-check servers, F5 `search`/`ntp servers` lists.
  - `label_context_rules(prefix, contexts)` builds `label_ref` + `cloud_ref` + `vlan_mention` rules, all flagged
    `cosmetic`. A `label_ref` is one **label-like word** (>= 5 chars, has a digit or hyphen, not all digits, not part of
    an IP/FQDN), not the whole description: the planner replaces a fact whose value equals an old label, so spans never
    overlap. `pnet0-trunk` gives `cloud_ref "pnet0"` and no label word.
  - `HostnameServiceMixin`: `dns_server` / `ntp_server` / `probe_target` facts accept IPv4 **or** a host name on
    render (F5 `pool.ntp.org`); IPv4-looking values are validated strictly.
  - `StanzaDeleteMixin`: the stanza deletion support flag is `supports_stanza_delete = True` plus
    `stanza_span(fact, text) -> Span | None` and `delete_stanza(fact, ctx) -> [TextEdit]` (one edit with `new=""`,
    whole lines incl. terminator; stale facts refused; `LocalizeError(code="NO_STANZA")` outside a deletable stanza).
    Callers test `getattr(dialect, "supports_stanza_delete", False)`. Supported: Forti `config router static`
    `edit N … next` (via its `set dst` or `set gateway` fact), ASA `route …` line, and F5 single-line
    `net route` / `sys management-route` (F5 added: one command per line, as trivial as ASA).
- ASA: IPsec peers used as object names (`tunnel-group`, `group-policy`, `default-group-policy`,
  `tunnel-group-map default-group`) are `peer_ip` facts with flag `object_name` (only `azure_s2s` claims them);
  `tunnel destination` / BGP `neighbor` are plain `peer_ip`; `standby` addresses are `ip_host` (`asa.ip_standby`);
  the default route gives only an `ip_gateway` (no `0.0.0.0` dst fact); `Cryptochecksum:` adds a `ParsedConfig.notes`
  entry. Extra indent block starts: `dns server-group`, `tunnel-group`, `group-policy`. `priority = 10`.
- FortiOS: BGP `edit "IP"` under `config neighbor` = `peer_ip`, `set as` / `set remote-as` = `asn`; health-check
  `set server "a" "b"` = `probe_target` (IPv4 or host names); `set mode dhcp` = `dhcp`. Not facts (leak scan only):
  `config firewall address` subnets, `set exchange-ip-addr4`, `set source`, `location-id`.
- F5: one `IfaceInfo` per `net vlan` (key = VLAN name, `parent` = first member such as `1.1`, `tag` only for a tagged
  member) plus `mgmt`; self-IP and VLAN-name facts carry that `iface`/`parent`; `vlan_name` facts of one VLAN share
  `group="f5vlan:<key>"`; `eve_to_config("E1.1") == ["1.1"]`, `"Mgmt"` -> `["mgmt"]`.

**Resolutions applied when `junos.py`, `linuxsh.py`, `vpcs.py`, `eve_html.py` and `generic.py` were written (T11)** —
additive, no contract change

- Label / `pnetN` / `VLAN n` tokens reuse T10's `_common` (`ContextRule`, `label_context_rules`, `LABEL_TOKEN`), so all
  dialects agree on what a label word is. New helper `generic.attach_iface_blocks(layout, resolver)` synthesises
  `interface` blocks where the syntax has none (shell `dev eth0`, VPCS `eth0`, Junos set style).
- Junos: brace blocks `interfaces/<ifd>` and `.../unit N` are re-kinded `interface`; iface keys are `<ifd>` and
  `<ifd>.<N>` (`fxp0.0`, parent `fxp0`). `IfaceInfo.tag` = unit `vlan-id` (None = untagged); an untagged routed unit
  marks its physical iface `routed` (+`dhcp`), so the L2 trace treats `fxp0` as a routed untagged endpoint while the
  facts keep `iface="fxp0.0"`. `subif_name` (value = the unit number only) exists only for units with a `vlan-id`.
  Static routes give `ip_route_dst` (incl. `0.0.0.0/0`) + `ip_gateway`; `vlans { X { vlan-id N; } }` = `vlan_def`.
  Set style is supported line by line (no `subif_name`). Not handled: `interface-mode`/`vlan members`, `vlan-tags`.
- linuxsh: facts as in the module docstring; `/etc/hosts` heredoc/echo entries are `ip_host` (iface None);
  `/etc/network/interfaces` `netmask` lines are `mask` facts; `ip link add ... type vlan id N` gives `subif_name`
  (whole link name) + `vlan_tag` (role `encap_tag`); `vconfig`/nmcli vlan give `vlan_tag` only.
- eve_html: `ip_host` for every IPv4 text-node token (CIDR network addresses included) + cosmetic label/cloud/vlan
  tokens; all HEURISTIC (discovery correlates). `score` is 95 for HTML fragments, so stores may also just `pick`.
- generic: HEURISTIC `ip_host` + cosmetic `label_ref`/`cloud_ref`; no `vlan_mention`, never tags; `score` is 0.

**Resolutions applied when `ios.py`, `iosxe.py` and `nxos.py` were written (T9)**

- **New fact kind `log_server`** (syslog targets: IOS `logging host A` / `logging A`, NX-OS `logging server A`) added to
  `model.CORE_FACT_KINDS` (one additive entry); `test_model` now checks a lower bound (packs may register kinds).
  `base.IPV4_KINDS` is frozen, so the Cisco dialects validate `log_server` values as IPv4 in their own `render`.
- Static routes: the default-route next hop (`ip route [vrf X] 0.0.0.0 0.0.0.0 [IF] GW`, NX-OS `ip route 0.0.0.0/0
  GW` at top level or in `vrf context`) and `ip default-gateway` are `ip_gateway` facts **without** flags; a
  non-default route gives `ip_route_dst` (with its mask) plus an `ip_gateway` with flag **`nexthop`**, so gateway
  consensus (7.3) must ignore `nexthop` facts. BGP `network A [mask M]` / `network A/len` is `ip_route_dst`.
- Other IPv4 kinds: HSRP/VRRP VIPs (`standby N ip A`, NX-OS `hsrp N` / `ip A`) are `ip_host` without a mask;
  BGP `neighbor A ...` (every line, incl. `activate`) and `tunnel destination A` are `peer_ip`; `router bgp N`,
  `neighbor X remote-as N`, NX-OS / peer-template `remote-as N` are `asn`; `[bgp|eigrp] router-id A` is `router_id`.
  Not facts (left to the literal/leak scan): `ip helper-address`, `ip host`, prefix-lists, ACLs, OSPF/EIGRP
  `network` with wildcards, NHRP maps, `ip pim rp-address`, `peer-keepalive`.
- Descriptions (cosmetic): any `pnetN` = `cloud_ref`; `description to pnetN: <label>` gives `label_ref` = the first
  token after the colon (no overlap with other facts); `VLAN N` = `vlan_mention`. Same idea as T10's label words, but
  without `_common.py` (the Cisco descriptions in the labs only use the `to pnetN: LABEL` form).
  *Superseded by the review fixes (labels), see 10.4:* IOS / IOS-XE descriptions are not limited to that form
  (c8kv `description EVE-INET-201 (ISP1)`), so `ios_context_rules(prefix)` makes every `_common.LABEL_TOKEN` word of
  a `description` a `label_ref` (`<prefix>.desc_label`, a `ContextRule`; `IOS` mixes in `ContextRulesMixin`). NX-OS
  keeps the `to pnetN:` rule.
- `banner <kind> ^C ... ^C` regions are masked (`Line.skip="banner"`, blocks opened inside them dropped) by
  `CiscoDialect._layout` (`ios.mask_banners`); an unterminated banner is not masked.
- `iosxe.IOSXE` subclasses `ios.IOS` (selection data + rule ids `iosxe.*`, `priority = 1`); `ios_rules(prefix)`
  builds the shared table. `trunk allowed vlan remove|except` and QinQ `second-dot1q` lines are deliberately not
  matched (no tag fact; listed as gaps).
- Iface keys: ios `Ethernet0/1` -> `et0/1`, `GigabitEthernet16.2` -> `gi16.2`, `Vlan203` -> `vl203`; nxos
  `Ethernet1/6` -> `eth1/6`, `loopback0` -> `lo0`, `Vlan3101` -> `vl3101`, `mgmt0`. `eve_to_config`: `e0/1` ->
  `Ethernet0/1`, `Gi16` -> `GigabitEthernet16`, `E1/6` -> `Ethernet1/6`, `Mgmt0` -> `mgmt0`.
- Snippets (`fixtures/snippets/{ios,iosxe,nxos}`) are trimmed real configs; each `*.facts.json` has a `source` key
  (lab, scope, node, line ranges). Syntax absent from the labs (`allowed vlan add|all|none`, native VLAN,
  `default-gateway`, `logging`, `name-server`, `domain-list`, non-default routes) lives in `*synthetic_extras*`
  snippets after a `! synthetic` marker line.

---

## 7. Discovery algorithm (`discover/`)

### 7.1 Topology

1. `clouds = [n for n in networks if n.type != "bridge"]`. If empty → status **NONE**: "nothing to localize", zero
   questions, zero diff.
2. Attachments: every `(node, iface)` whose `network_id` is a cloud. EVE names are mapped to config names with
   `dialect.eve_to_config()`: `Gi16→GigabitEthernet16`, `e0/1→Ethernet0/1`, `E1/6→Ethernet1/6`, `fxp0`, `port8`, F5
   `Mgmt`.
3. Active scope per node: `config_attr` that equals a configset id → that configset. If the node has no blob in that
   configset → `startup` (EVE behaviour). Nodes with `config="0"` get a notice: "embedded config not pushed at boot".

### 7.2 L2 trace (`l2trace.py`), run once per scope

State: `(node, iface_key, incoming: untagged | tag N, cloud_net_ids)`, kept in a visited set, BFS depth at most 6.

- **Routed endpoint** (`is_switch=False`):
  - A routed physical iface with addresses or DHCP → attachment arrives untagged.
  - Each subif or Forti VLAN iface **whose parent is the attached iface** → arrives tagged with N. Only the attached
    parent counts, so ISP-RTR9 `Gi3.1240` on bridge net 14 is never reached.
  - Nothing configured → `unconfigured`.
- **Switch port** (`is_switch=True`):
  - access `v` → carrier untagged maps to switch VLAN `v`.
  - trunk with an allowed list → those VLANs.
  - trunk with **no allowed list → ALL VLANs in `vlan_db`**. `vlan_db` includes VLANs created *implicitly* by
    `switchport access vlan`, allowed lists and SVIs. This fixes the backbone dmvpn-backbone case, where mgmt-79..82 have
    `access vlan 203` but no `vlan 203` line.
  - Propagation to every other port carrying `v`: an access port → its bridge peer receives untagged; a trunk port → its
    peer receives tagged `v`; an SVI `Vlan v` with addresses → attachment on the switch itself.
- Bridge networks are crossed to every peer interface.
- **Switch VLAN-domain rule**: once switch VLAN `v` is proven to equal carrier tag `v`, every tag fact for `v` *on that
  switch* is attributed to the segment as CORRELATED. That includes the `vlan v` definition, the uncabled ports
  (mgmt-79 e0/3, e1/1, e1/2; mgmt-81 e1/0) flagged `uncabled`, and the vlan name. Routed devices never get this rule.
- **Orphan attribution**: an orphan tag fact (b1-sw1 `allowed vlan 203` after a broken header) is attributed
  CORRELATED only if the same node and scope has a non-orphan fact for the same VLAN already attributed (b1-sw1
  `interface Vlan203` with an address in the segment). Otherwise it is reported `UNATTRIBUTED_TAG` and left alone.
- Descriptions are never used to infer links. Only topology counts.

### 7.3 Segments (`segments.py`)

1. **Seed**: one candidate per `(type, name)` group of cloud networks, keyed by ids. A trunk-only carrier (EVE-TRUNK,
   `trunk`, `203-19` uplinks) becomes a CARRIER with one sub-unit per VLAN it carries.
2. **Merge** when one of these holds:
   - (a) the manifest says so;
   - (b) PROVEN endpoints show the same subnet *and* the same tag in the same scope (sdwan EVE-MGMT-203 direct with
     EVE-TRUNK:2; junos `mgmt` with `mgmt58`);
   - (c) a switch `vlan v` / `name X` where X equals another unit's network name (sdwan `vlan 3` /
     `name EVE-MGMT-204`);
   - (d) no configured endpoint on either side, and the same `(type, name)` (backbone `INET-201` nets 25 and 78).

   Never merge when subnets conflict. A weaker **hint** never merges automatically: the NameExplainer finds a number
   equal to a carrier tag (`204-31` with `trunk:204`, `out-255` with `trunk:255`). It becomes a yes/no question unless
   the manifest confirms it.
3. **Schemes per scope**:
   - **Tag** comes from a subif on the attached parent, Forti `vlanid` on the attached port, or the switch access/allowed
     VLAN toward the endpoint. If none → `untagged`. If the cloud-facing iface has no config → `unknown`.
   - **Subnet** is the consensus of `ip_network(ip/len, strict=False)` over member hosts. The broadest consistent prefix
     wins, so junos `10.100.240.0/20` stays one subnet and is not split into two /24s.
   - **Gateway** is the consensus of default-route next-hops inside the subnet: Cisco VRF defaults, NX-OS
     `vrf context management`, Junos `next-hop`, F5 `management-route`, Forti `set gateway` under the segment device, and
     ASA `route <nameif> 0 0 GW`.
   - Scopes with identical tuples merge into one scheme. Minority facts become **outliers**, excluded by default:
     c8kv-74 10.100.105.74 in vxlan-vpc, bb-rr84 duplicating .83, bb-rtr66 .66/.26.
4. **Correlation pass**: any IPv4 fact anywhere in the lab inside a scheme subnet → CORRELATED member. That covers
   `set remote-gw`, `set router-id`, BGP neighbors, ASA `route … GW` and textobject IPs in text nodes. Supernet routes
   (`10.100.0.0/16`) are not members; they become `ip_route_dst` facts for `site_routes`.
5. **Status**:
   - `CONFIGURABLE`: some scheme has a known tag or subnet.
   - `DHCP`: only `ip address dhcp` (nexus Gi4, lab1 R27, backbone c8kv-30 Gi15).
   - `LABEL_ONLY`: attached, no config.
   - `CARRIER`
   - `UNKNOWN`
6. **Key**:
   - the manifest key if present;
   - otherwise the normalized majority label (`EVE-` stripped, upper-cased) when it contains a letter;
   - otherwise `cloud-<lowest net id>`.

   `site_key` comes from the manifest, otherwise `<labstem>.<key>`.

### 7.4 NameExplainer (`names.py`)

Each digit run in a cloud network name is classified against the segment:

- `tag` (`INET-1240`);
- `octet3` (`mgmt-104`, `EVE-MGMT-203`);
- `host` (`203-67` → .67; `mgmt-203_111_121`);
- `netid` (`mgmt58`);
- `ambiguous` (`EVE-INET-201` is both tag and octet3);
- `unknown`.

The classification drives *suggested* label templates (`EVE-MGMT-{octet3}`, `{octet3}-{host}`, `INET-{tag}`). It is
never used as a value. `discover --write` records it in the manifest as `label_template`.

### 7.5 Protected inventory (`inventory.py`)

- Every VLAN and every prefix (from ip/len facts) not attributed to an external segment, per scope.
- Plus the manifest `protect = [...]`.
- Plus platform-reserved VLANs: IOS 1002-1005 when IOS/IOL carries the segment; NX-OS 3968-4094 when NX-OS does.

Used for:

- hard-blocking edits whose span is a protected fact;
- collision checks on new tags and subnets;
- the "protected look-alikes" list in the plan ("1240 appears 8× on internal links: untouched").

**Resolutions applied during review fixes (integration)**: an `ip_host` fact whose value is the network address of its
own mask (prefix shorter than /31, e.g. a manifest rule capturing `set dst 10.100.0.0 255.255.0.0`) is a route or ACL
reference, not an interface, and no longer adds a protected prefix. Without this the sdwan rule
`sdwan.fgt_provider_route` (per-provider hub routes after lab rework 32d9b62) protected `10.100.0.0/16`, which would
have fenced off every `10.100.x` answer and service value.

### 7.6 Findings produced by discovery

| code | example |
|---|---|
| `UNCONFIGURED` | Junos FortiGate port8, backbone Forti/F5 |
| `DHCP_UPLINK` | nexus, lab1, backbone out-255 |
| `STRUCTURAL_*` | listed when relevant to the user's answers |
| `OUTLIER` | c8kv-74, bb-rr84 |
| `CORRUPT_CONFIG_REGION` | backbone viosl2 syslog splices |
| `UNATTRIBUTED_LITERAL` | 172.21.255.30, 10.100.51.11 when not otherwise claimed |
| `IPV6_UNHANDLED` | |
| `CONFIG_NOT_PUSHED` | `config="0"` |
| `SECRET_COMMITTED` | Azure PSK |
| `TRUNK_ATTRS` | `native_vlan="1"` on EVE-TRUNK |

---

**Resolutions applied when `discover/` was written (T13/T14)** — additive

- `AnalyseOptions` lives in `discover/__init__.py` (not `model.py`): `include_outliers`, `textobjects`, `max_depth` (6),
  `canonical_scope`. `discover(lab, manifest, opts) -> Discovery(analysis, topology, index, traces, build)` exposes the
  intermediate results; `analyse()` returns `.analysis` only.
- Scope view: a node uses its configset blob, else its startup blob; mirror sidecars are never traced (their facts copy
  the attribution of the blob they mirror, matched by kind + span); independent sidecars stand in for a missing blob.
  Every scope (`startup` + each configset) is traced.
- The trace starts each cloud port with "any" (untagged + every tag). `Endpoint.tag` is the tag **on the cloud wire**.
- **Carrier** = every network of the `(type, name)` group is a switch trunk port and the group carries **two or more**
  VLANs in some scope (a trunk carrying one VLAN, e.g. sdwan `b1-sw1 Gi3/3`, is a tagged segment). Carrier sub-units are
  keyed by `(cloud type, wire tag)` across all carrier groups (one `pnet0` bridge = one VLAN space) and named
  `<label>:<tag>` (aliases `trunk:204`, `203-19:204`); sub-units ending at the same node interface in different scopes are
  one unit (backbone `1102` in startup = `204` in the dmvpn configset). A sub-unit that merges with nothing becomes a
  segment with no networks, keyed `<carrier key>-<tags>` (`TRUNK-204-1102`); carrier groups carrying a common segment
  merge into one CARRIER segment (backbone `trunk` + `203-19`).
- Schemes: per-scope consensus `(tag, subnet, gateway)`; an endpoint that does not fit its scope's tuple joins another
  scheme it fits (its scope is added to that scheme), else it is an outlier; one address on two nodes of a scheme makes
  the later node's endpoint an outlier (bb-rr84). Scheme order: canonical scope (option, manifest, else the scope most
  nodes boot from) first, then member count. Outlier facts get `segment` + flag `outlier`, CORRELATED at most.
- Status: CONFIGURABLE if an endpoint is addressed or a scheme has an int tag / subnet; DHCP if every configured
  endpoint is DHCP; LABEL_ONLY if attached but unconfigured; UNKNOWN otherwise (e.g. a VLAN reaching only uncabled ports).
- Correlation pass kinds: `ip_host`, `ip_gateway`, `peer_ip`, `router_id` (service kinds are left to `services`,
  `ip_route_dst` to `site_routes`). An SVI address in a segment attributes the SVI name and, on a switch, the
  VLAN-domain facts of that VLAN (handles backbone `b2-sw1` truncated `interface GigabitEthernet3` block) plus orphan
  tags of that VLAN. `vlan_list` facts naming several VLANs are attributed to the first external segment; the planner
  must map them with `VlanList.replace`; their other VLANs stay in `protected_vlans`.
- `UNCONFIGURED` is reported only for cloud ports configured in no scope. Extra findings: `MERGE_HINT` also when a
  LABEL_ONLY segment's attached nodes have addresses in another segment (backbone `mgmt-203_111_121` → MGMT),
  `MERGE_UNKNOWN_UNIT`, `MANIFEST_STALE`, `MANIFEST_SCOPE`, `NO_CLOUDS`, `TRACE_DEPTH`, `PARSE_FAILED`.
- Segment roles are guessed from labels (`MGMT/OOB` → mgmt, `INET/INTERNET/ISP/WAN/OUT` → inet, `nat*` type → nat,
  carrier → trunk) unless pinned. Name hints: `NameExplainer` (`discover/names.py`) also offers `suggest_template()`
  (`None` when ambiguous; repeated classes are numbered `{host1}`, `{host2}`) and `render_template()`.

## 8. Manifests (generated, committed, optional)

### 8.1 Role

Discovery is enough to *use* a lab. A manifest adds three things:

1. **Pinning for CI.** `expect` counts per segment and param, plus the baseline values. `make localize-check` fails
   when the lab changes in a way discovery attributes differently. Example: someone adds a node with a mgmt IP that no
   dialect understands; the leak scan reports it.
2. **Author decisions discovery cannot prove**:
   - `site_key` bindings across labs;
   - confirmed hint merges;
   - canonical scope and legacy policy;
   - outliers and ignores;
   - protect lists;
   - label textobjects;
   - generic labels;
   - scenario enablement;
   - dialect overrides.
3. **Baseline for `revert`** and for the "committed labs must be at baseline" CI check.

Manifests are **generated** by `eve-localize discover LAB --write` (first time: `.draft`, reviewed, then renamed)
and refreshed by `discover LAB --update`. Update keeps the author decisions and rewrites the counts and values, so
upkeep is regenerate + review the diff, never hand-counting. Without a manifest a lab is **unpinned**:

- It works interactively. PROVEN + CORRELATED edits are applied after the user confirms the segment matrix.
- Non-interactive runs require `--allow-unpinned`.
- `localize-check` lists it as `unpinned` (warning; error under `--strict`).

Labs with no clouds need no manifest.

**Tri-state rule (from Design 1).** Each planned edit's span must hold either the **current value** or the **target
value** (already applied: skip). Anything else is drift and aborts that lab. With a manifest, the discovered count for
each `expect` must equal it at the baseline, or equal it at the current localized state as recorded in `state.json`.

### 8.2 Schema

```toml
schema = 1
lab = "vxlan_evpn_multi-site_sdwan_only.unl"   # relative to this file
lab_id = "2fd99c11-2334-45b3-ac61-ee23ab5c9d38" # mismatch -> manifest ignored + error in check
generated = "eve-localize 1.0 discover --update" # informational
sidecar_dirs = ["vxlan_evpn_multi-site_sdwan_only_cfgs"]
canonical_scope = "sdwan-vxlan-evpn"           # default active scope
protect = ["10.200.0.0/16", "169.0.0.0/8"]     # added to the computed protected inventory
generic_labels = []                            # labels never propagated into text (plus built-ins)
subif_policy = "rename"                        # rename | keep-name

[nodes."29"]                                   # optional per-node overrides
dialect = "f5tmsh"

[sidecar_map]                                  # optional forced mappings "file" = "node id"

[[segment]]
key = "MGMT-203"
site_key = "site.mgmt_a"                       # shared identity across labs (author-declared)
role = "mgmt"
networks = ["74", "76", "91", "54", "55", "165"]
label_template = "EVE-MGMT-{octet3}"           # suggestion only
  [segment.baseline]                           # canonical scheme values at repo baseline
  label = "EVE-MGMT-203"; vlan = 2; subnet = "10.100.203.0/24"; gateway = "10.100.203.1"
  [segment.expect]                             # counts per param at baseline (generated)
  vlan = 41; subnet = 92; gateway = 18; label = 30

[[segment]]
key = "TRUNK"
role = "trunk"
networks = ["132", "137", "140", "152"]
carries = ["MGMT-203", "MGMT-204"]

[[merge]]                                      # confirmed hint-level merges
units = ["204-31", "trunk:204"]

[[legacy]]                                     # other schemes on the same clouds (backbone)
segment = "MGMT"; scopes = ["startup", "vxlan-vpc", "vxlan-no-vpc"]; policy = "leave"   # leave|ask|same
baseline = { vlan = 1103, subnet = "10.100.103.0/24", gateway = "10.100.103.1" }

[[outlier]]
scope = "vxlan-vpc"; node = "74"; note = "10.100.105.74 (pre-existing)"

[[label_value]]                                # textobject values that no config proves
textobject = "21"; segment = "INTERNET"; fields = { subnet = "192.168.13.0/24", gateway = "192.168.13.1" }

[scenarios.azure_s2s]
enabled = true; node = "1"

[[param]]                                      # lab-wide site params (services etc.) baseline + counts
key = "dns_public"; kind = "ipv4_list"; site_key = "site.dns_public"
baseline = ["1.1.1.1", "1.0.0.1"]; expect = 46

[[rule]]                                       # manifest-local declarative rule (rare one-offs)
id = "lab.forti_alias_pnet"; dialects = ["fortios"]; kind = "cloud_ref"
pattern = 'set alias "(?P<v>pnet\d+)-trunk"'
```

`expect` numbers in the examples are placeholders. The real values always come from `discover --write`.

### 8.3 The real labs

| lab | manifest? | key content |
|---|---|---|
| `ccie_sec_v6_practice_lab`, `cisco_nexus_9000v_vxlan_bgp_evpn_concept_lab` | none (no clouds) | — |
| `ccie_enterprise_infrastructure_practice_lab` | yes (small) | segment `SDWAN-CTRL` net 22, `site_key="site.sdwan_ctrl"`, `generic_labels=["Net"]`, status LABEL_ONLY |
| `cisco_nexus_9000v_vpc_concept_lab` | yes | segment `INTERNET` net 6 (DHCP); `label_value` textobject 21 (subnet/gw) and 3 (dns 8.8.8.8); `generic_labels=["Internet"]`; `protect=["10.1.1.0/29","192.168.100.0/24"]` |
| `lab1-ei-v01` | yes | segment `INTERNET` net 58 nat0 (DHCP); param `ntp_upstream` 34.202.215.187 (group advanced); `generic_labels=["Internet"]`; `protect` = simulated internet + 10/8, 172.16/16 |
| `azure_asa_vpn` | yes | segments `INET-105` (net 1) and `MGMT-104` (net 3), separate site_keys; `site_routes` baseline `["10.25.0.0/16","10.100.0.0/16"]`; `scenarios.azure_s2s` enabled on node 1; protect `169.254.0.0/30`, `169.254.100.0/30`, `192.168.100.0/24`, `192.168.200.0/24` |
| `vxlan_evpn_multi-site_sdwan_only` | yes | MGMT-203, MGMT-204, INET-201, INET-202, TRUNK (carrier); params dns_public, sla_targets (advanced), domain, domain_campus, search_extra, ntp, mgmt_routes |
| `vxlan_evpn_multi-site_with_backbone` | yes | `canonical_scope="vxlan-dmvpn-backbone"`; MGMT (S1 baseline tag 203 / 172.21.203.0/24 / gw .254, `label_template="{octet3}-{host}"`); `[[legacy]]` S2 (1103/10.100.103.0/24, scopes startup+vxlan-no-vpc) and S3 (vxlan-vpc, untagged c8kv) with `policy="leave"`; TRUNK carrier (132,137,140,152); `[[merge]]` FW-MGMT-204 = 204-31..71 + trunk:204; INET-201 (25,78), INET-202 (44,117) LABEL_ONLY; OUT-255 (166) DHCP + merge trunk:255; outliers c8kv-74, bb-rr84; param dns_corp 172.21.255.12/.13 |
| `vxlan_evpn_multi-site_junos` | yes | MGMT (5,13,24,58,76; /20, gw 10.100.255.254); INET-1240 (72, pnet2), INET-1242 (62, pnet2); `scenarios.bgp_upstream` nodes 9,18 peer_group HOME; protect `172.31.255.0/24`, `10.0.0.0/30`, `10.0.1.0/30`, `169.0.0.0/8`; params dns_mgmt 10.100.51.11, domain_campus, domain, dns_public |

Example (junos, abridged):

```toml
schema = 1
lab = "vxlan_evpn_multi-site_junos.unl"
lab_id = "66a315e7-90d2-492f-bb7c-9d6b395e5f8d"
protect = ["172.31.255.0/24", "10.0.0.0/30", "10.0.1.0/30", "169.0.0.0/8"]
generic_labels = ["mgmt", "mgmt58"]

[[segment]]
key = "MGMT"; site_key = "junos.mgmt"; role = "mgmt"; networks = ["5", "13", "24", "58", "76"]
  [segment.baseline]
  subnet = "10.100.240.0/20"; gateway = "10.100.255.254"
  [segment.expect]
  subnet = 16; gateway = 16

[[segment]]
key = "INET-1240"; site_key = "junos.inet_a"; role = "inet"; networks = ["72"]; label_template = "INET-{tag}"
  [segment.baseline]
  label = "INET-1240"; vlan = 1240; subnet = "172.31.240.0/24"
  [segment.expect]
  vlan = 2; subnet = 4        # Gi2.1240 header + encap; .10 x2 (addr, router-id), .1 x2 (neighbor lines)

[scenarios.bgp_upstream]
enabled = true; nodes = ["9", "18"]; peer_group = "HOME"
baseline = { peer_as = 65299, local_as = 65300, prefixes = ["172.31.255.0/24", "192.168.64.0/18", "192.168.128.0/17"] }

[[param]]
key = "dns_mgmt"; kind = "ipv4_list"; site_key = "site.dns_mgmt"; baseline = ["10.100.51.11"]; expect = 16
```

**Resolutions applied when `tomlw.py`, `manifest.py` and `profile.py` were written (T4)**

- The examples above use `;` for brevity; real files use one key per line (valid TOML). `Manifest`, `Profile` and `Answers`
  are not in `model.py`: `Manifest` and its row types live in `manifest.py`; `Profile` lives in `profile.py` and
  `Answers` is an alias of `Profile` (one file format for profile and answers).
- New helper module `tomlschema.py` (`TableReader`): strict typed reads, unknown key -> error with a "did you mean"
  hint. Shared by manifest and profile. `tomlw.py` also exposes `TomlValue`.
- Manifest keys beyond the 8.2 sketch: `[[segment]].status` (pinned `CONFIGURABLE|DHCP|LABEL_ONLY|CARRIER|UNKNOWN`,
  used by the real labs); `[[param]].group` (`basic|advanced`); `[scenarios.<id>].enabled` defaults to true, every other
  key is a scenario option kept verbatim; `[[rule]]` also takes `block`, `negative`, `l2` (the `PatternRule` fields).
  `segment.expect` / `baseline` keys are limited to `label, vlan, subnet, gateway` (`manifest.SEGMENT_PARAMS`).
- Strict checks: unknown keys, `carries` / `legacy.segment` / `label_value.segment` naming a missing segment, duplicate
  segment keys or `[[param]]` keys or `[[rule]]` ids, a network id in two segments, `lab_id` not a UUID, a gateway
  outside its subnet. Param kinds, scenario ids and fact kinds are not checked against registries (T16/T5); they only
  need to be identifiers.
- `find_for()` returns `None` when no `<stem>.localize.toml` exists or its `lab_id` differs from the lab's (read from the
  root `<lab id=...>` element; `check` detects the mismatch by calling `load()` itself). A manifest whose `lab` does not
  name that lab file, or an invalid manifest, raises `ManifestError`. `.localize.toml.draft` is never loaded.
- Profile keys beyond the 9 sketch: segment answers also take `hosts` (old ip -> new ip) and `skip`; `[labs."<id>"]`
  holds `segments` (keyed by segment **key**) and `scenarios`. `[map.<kind>]` accepts any identifier kind. Bridge names
  must be built-in (`pnetN|natN|cloudN`) or declared in `[bridges]`, checked after merging.
- `load_profile(paths)`: files merge in order, later wins; tables merge key by key, scalars and arrays replace (so
  `site_routes."k" = []` clears). `[]` yields an empty profile; a missing path is an error (the CLI filters the default).
- Secrets: `SecretRef(env, value)`; `save_answers` writes `{ env = ... }` references only. Inline values are written
  only with `include_secrets=True`, and then the file is created with mode 0600.

**Resolutions applied when `manifest.generate()` / `check()` were written (T15)** — additive

- Signatures widened compatibly: `generate(a, previous=None)`; `check(a, m: Manifest | None, *, localized=None,
  localized_params=None, leaks=True)`. `m=None` returns `UNPINNED` (warn) when the lab has clouds, else nothing.
  `localized` (segment key -> `Baseline`) / `localized_params` (param key -> values) carry the current localized values
  from `state.json`; those are then expected instead of the baseline (tri-state rule of 8.1). `a` must come from
  `analyse(lab, m)`.
- New public helpers in `manifest.py`: `build_manifest(a, previous)` (the `Manifest` object `generate` serialises),
  `discovered_baseline(seg)`, `segment_counts(a, key, values)`, `param_count(a, p, values=None)`,
  `param_fact_kinds(p)`, `leak_scan(a, m=None, ...)`, `unpinned(a)`.
- Counting rules (shared by generate and check; facts flagged `outlier` never count): `vlan` = tag-bearing facts
  (`vlan_tag`, `vlan_list`, `vlan_def`, `subif_name`, `svi_name`) of the segment naming the VLAN; `subnet` = IPv4-valued
  facts of the segment inside the subnet **except** those equal to the gateway; `gateway` = facts of the segment equal
  to it; `label` = segment networks named exactly the label + all `label_ref` facts with that value. A `[[param]]`
  counts facts of `param_fact_kinds(p)` (its kind if that is a fact kind; else words of its key: `dns*` -> dns_server,
  `ntp*`, `sla`/`probe` -> probe_target, `log`/`syslog`, `domain`/`search` -> domain+search_list, `route*` ->
  ip_route_dst, `peer*`, `asn`; else by param kind `ipv4_list|host_list|domain|domain_list|prefix_list`) whose value is a
  baseline value (CIDR compare for routes, case-insensitive domains).
- Draft (`previous=None`): every discovered segment that has cloud networks (carried-only segments such as
  `TRUNK-204-1102` cannot be manifest segments; they and `MERGE_HINT` / `OUTLIER` findings are listed as header
  comments), explicit derived `site_key`, guessed role, suggested `label_template`, baseline = canonical scheme + most
  common label, `canonical_scope` (majority active scope) only when the lab has configsets, one `[[legacy]]` per
  non-canonical scheme (`policy = "leave"`), and draft `[[param]]` rows from service facts not inside protected
  prefixes: `dns` (ipv4_list), `ntp` / `syslog` / `sla_targets` (host_list), one `domain`, `domain_2`, ... per distinct
  domain (kind `domain`); `site_key = "site.<key>"`. Status is never pinned by a draft.
- Update (`previous` given): author decisions are kept verbatim (segment site_key/role/status/label_template/carries,
  merges, legacy scopes+policy, outliers, protect, generic_labels, subif_policy, nodes, sidecar_map, label_values,
  scenarios, rules, params' key/kind/site_key/group/values); networks, baselines (incl. legacy baselines, matched to the
  non-canonical scheme of their scopes), sidecar_dirs and all counts are refreshed; segments no longer discovered are
  dropped (header note); service values no param covers are appended as new params. The generated text is re-parsed
  with `parse()` before it is returned. Update on a localized lab would record localized values: the CLI must refuse
  or use `--baseline-from-answers`.
- `check` codes: errors `MANIFEST_LAB_ID`, `MANIFEST_LAB`, `MANIFEST_COVERAGE` (cloud in no segment, segment network
  not a cloud, segment not discovered), `COUNT_MISMATCH`, `NOT_AT_BASELINE` (canonical scheme or legacy scheme);
  warnings `MANIFEST_EXPECT` (expect key without baseline value), `PARAM_MISSING`, `LEAK`, `UNPINNED`.
- Leak scan: IPv4 tokens (all readable configs, sidecars, textobjects) inside a segment's baseline subnet (canonical
  scheme when unpinned) not covered by a fact of that segment or of a param, plus occurrences of param baseline values
  (IPv4, domains) not covered by a param or segment fact; one `LEAK` finding per (segment|params, store, node) with up
  to 5 examples and line numbers. On the real labs a fresh draft checks clean except real `LEAK`s (sdwan c8kv-75 NAT
  statics / ACL wildcards / route-map next hops and a FortiGate comment naming `10.100.201.31`) which T20 must resolve
  (rule, protect or accepted warning). VLAN-number and label leaks are not scanned.

**Resolutions applied when the real-lab manifests and repo wiring were written (T20, T22)** — additive

- Manifest `[[rule]]` tables are now applied (they were parsed but unused): `discover.manifest_rules(m, findings)`
  turns them into `PatternRule`s per dialect (`dialects = []` = every dialect, key `"*"`); `ConfigIndex(topo, texts,
  extra_rules)` parses with `topology.with_rules(dialect, rules)`, an unregistered subclass copy of the dialect with the
  extra rules appended (rendering does not depend on rules). Invalid rules are dropped with a `MANIFEST_RULE` error
  finding. Without a manifest nothing changes. The sdwan manifest uses five rules (c8kv-75/77 static NAT globals, PBR
  ACL networks and `set ip next-hop`, the FortiGate header comment) to resolve its `LEAK`s; the ACL wildcard
  `0.0.0.255` was not rewritten (fine for /24 targets, a known gap otherwise). *Resolved during review fixes
  (l3-validation)*: the rule captures `(?P<wildcard>IPV4)` and the wildcard follows the new prefix (section 11.3).
- `site_key` policy: keys are shared across labs only when every baseline value (including the label) agrees, so that
  `localize/site.example.toml` (first lab per key wins) replays as a no-op on every lab. The real labs have no such
  pair (sdwan `EVE-INET-201` vs backbone `INET-201` etc.), so the sdwan segments use `site.*` keys and the other labs
  lab-scoped keys (`backbone.*`, `junos.*`, `azure.*`, `nexus_vpc.internet`); lab1's nat0 segment is `site.nat`,
  ccie EI is `site.sdwan_ctrl`.
- `[[merge]]` units of a manifest-pinned group are named after the first network's label (backbone FW-MGMT-204:
  `["204-51", "trunk:204"]`), not the segment key. `[[segment]].baseline.label` must equal
  `scenarios.base.primary_label` (most common name, ties: lowest network id); `discover --update` picks a different
  tie-break, so the backbone FW-MGMT-204 baseline label was set to `204-31` by hand after the update.
- Site routes are recorded as `[[param]] kind = "prefix_list"` named `mgmt_routes` (counts `ip_route_dst`);
  `[[label_value]]` rows (nexus textobjects 21 and 3) are informational only.
- Known CLI gap: `discover --all --update` stops at the first lab without a manifest (no-cloud labs); run it per lab.
- Makefile: `test: check-labs localize-test localize-check`; `localize-check` runs `check --all --strict`;
  `localize-test` uses `python3 -I -B` (no bytecode); `.gitignore` adds `/.localize/`, `*.localize.toml.draft`,
  `__pycache__/`. The lint bundle covers `python/` (`ruff check .` /
  `black --check .` from the repo root pick up `python/pyproject.toml`; no excludes apply).

**Resolutions applied during review fixes (bridges)**

- `[segment.baseline]` has an optional `bridge` (the cloud `type` of the segment's networks; written by
  `discover --write/--update` only when every network has the same type, so CARRIER trunks get one too). `revert`
  uses it like the other baseline keys (manifest wins over `state.json`), so a lab whose bridge was localized can be
  reverted without `.localize/state.json`. `check` reports `NOT_AT_BASELINE` when a network of the segment has
  another type, unless `state.json` records that bridge as the localized value (tri-state rule). `bridge` is not an
  `expect` key (`SEGMENT_PARAMS` is unchanged). The 7 committed manifests carry the bridge baselines.

---

## 9. Site profile and answers

`.localize/site.toml` is gitignored. `--answers FILE` / `--profile FILE` read it, and `--save-answers FILE` writes it
through `tomlw`, followed by a re-parse check. Segment answers are keyed by **`site_key`**, which survives localization
because segments are identified by network ids, not values. Services are keyed by **old value**, because they are
plain values. Resolution order for each answer:

1. CLI / interactive answer;
2. `[labs."<lab_id>"]` override;
3. `[segments."<site_key>"]`;
4. a value-map match (`[map.*]` by current value);
5. a role default;
6. keep the current value.

```toml
schema = 1
site = "alice-homelab"

[bridges.pnet0]  roles = ["mgmt"];          mode = "untagged-only"; native_vlan = 1
[bridges.pnet1]  roles = ["mgmt", "trunk"]; mode = "trunk"
[bridges.pnet3]  roles = ["inet"];          mode = "trunk"
[bridges.nat0]   roles = ["nat"];           mode = "untagged-only"

[roles]                                   # defaults when a segment has no explicit answer
mgmt = "pnet1"; inet = "pnet3"; trunk = "pnet1"; oob = "pnet1"; nat = "nat0"

[segments."site.mgmt_a"]                  # sdwan EVE-MGMT-203 (author binds same real net elsewhere)
bridge = "pnet1"; vlan = 20; subnet = "192.168.20.0/24"; gateway = "192.168.20.254"; label = "LAB-MGMT-20"
reserved = ["192.168.20.1-192.168.20.10"] # site addresses in use / DHCP pool -> collision warnings
[segments."site.mgmt_b"]
vlan = 30; subnet = "192.168.30.0/24"
[segments."site.inet_a"]
bridge = "pnet3"; vlan = 301; subnet = "198.51.100.0/24"; dhcp_pool = "198.51.100.100-198.51.100.200"
[segments."junos.mgmt"]
subnet = "192.168.48.0/24"
split = { "10.100.241.0/24" = "192.168.48.0/25", "10.100.243.0/24" = "192.168.48.128/25" }  # split map

[map.dns]
"1.1.1.1" = "9.9.9.9"; "1.0.0.1" = "149.112.112.112"; "10.100.51.11" = "192.168.1.53"
[map.domain]
"netlab.local" = "lab.alice.net"; "plsnetlab.local" = "campus.alice.net"; "yandy.dev" = ""  # "" = drop from lists
[map.ntp]
"pool.ntp.org" = "time.alice.net"
[site_routes]
"site.mgmt_b" = ["192.168.0.0/16"]        # replace list (or [] = remove where dialect supports deletion)

[scenarios.azure_s2s]
enabled = false

[secrets]
"azure_s2s.psk" = { env = "AZURE_PSK" }   # never stored inline unless --save-secrets

[policy]
cosmetic_text = true          # descriptions/aliases/comments/(VLAN n) follow labels & tags (default true)
include_heuristic = false
legacy_scopes = "leave"       # leave | ask | same
subif_policy = "rename"

[labs."0ca56f43-8e11-44ca-a007-a6dce53df987".segments."INET-105"]
bridge = "pnet3"
```

`localize/site.example.toml` is **generated** by `eve-localize profile --example`. It is built from all manifests
and filled with the author's baseline values, and a CI check ensures it is current.

---

## 10. Questions and interaction

### 10.1 Question model

```python
@dataclass
class Question:
    id: str               # "<site_key>/<kind>[@scope]" or "<lab_stem>/<param>" — stable, used in answers files
    group: Literal["A Clouds", "B VLAN tags", "C Addressing", "D Labels", "E Services",
                   "F Site routes", "G Scenarios", "H Secrets", "S Scope"]
    kind: str             # registered ParamKind (section 13.3)
    prompt: str; current: str | None; default: str | None; default_source: str
    choices: list[str] | None
    validate: Callable[[str, "Answers"], str | None]
    depends_on: list[str]; evidence: list[str]      # fact ids, shown with "?"
    affects: int                                    # edit count it would drive
```

### 10.2 Relevance rules (questions follow facts)

| Question | Asked only if |
|---|---|
| bridge | once per **segment** (not per pnet type). CARRIER defaults to the bridge of the segments it carries. Choices are annotated from `hostenv` (exists/up) and the profile roles. Moving a tagged segment to another trunk bridge keeps its tag. Moving it to a bridge marked `untagged-only` is a **blocker** (structural). |
| merge | a hint-level link exists and the manifest has not confirmed it |
| tag | the scheme tag is numeric and PROVEN tag facts exist; never for untagged/unknown; never for internal-only tags (junos 1241/1243) |
| subnet / gateway | the scheme has a subnet from PROVEN facts. DHCP and LABEL_ONLY segments get no subnet question, but a status note. Label-only subnets (nexus textobject 21) are asked as "documentation only". |
| split / host map | only when the new prefix cannot hold every baseline host offset |
| label | the segment has cloud networks. A suggestion comes from `label_template`. Text propagation follows the distinctiveness rule (10.4). |
| scope / legacy | the segment has legacy schemes (backbone). Default `leave`. |
| dns / domain / ntp / probe | a ServiceFact exists in an in-scope store. One question per distinct value, with counts per dialect and store. |
| site routes | supernet `ip_route_dst` facts exist via a segment gateway |
| scenario groups | `applies()`: manifest-enabled or signature detected. A yes/no gate, default no. |
| secrets | a `SECRET_COMMITTED` finding exists (optional placeholder replacement) |

**Validators:**

- **bridge**: matches `^(pnet\d+|nat\d+|cloud\d+)$`, extendable through profile `[bridges]`. A tagged segment on `nat*`
  is a blocker.
- **vlan**: 1-4094; not in the protected set of any scope sharing the bridge; not platform-reserved; unique per target
  bridge; the target subif or SVI name must not already exist on that node.
- **cidr**: must be valid. Offsets must fit, or a split/host map is offered. Overlap with the protected inventory or
  with another segment is a conflict. Mapped hosts landing in the profile's `reserved` or `dhcp_pool` → warning.
- **gateway**: inside the subnet; not the network or broadcast address; not equal to a mapped host.
- **label**: character set and length (section 5.1).
- **domain**: RFC 1123.
- **asn**: 1-4294967295.

**Resolutions applied during review fixes (bridges)**

- **Carrier vs carried bridges** (`CARRIER_SPLIT`): after the bridges are resolved, every CARRIER is compared with the
  final bridge of each carried segment that has cloud networks (carried-only segments without networks are ignored,
  also by the carrier-follow default). Nothing is reported unless one of them moves. Carried segments going to
  several bridges while the carrier has no explicit answer is a **conflict** (the tool cannot pick the bridge the trunk
  follows; answer `<carrier site_key>/bridge` or put the carried segments on one bridge). An explicit carrier answer
  that differs from a carried segment's bridge (or explicit answers with split carried segments) is a **warning**,
  not a blocker: separate host bridges may be joined outside EVE, and `--strict` fails on it. The carrier's bridge
  question is asked after the carried segments; its default follows their answers, or shows
  `keep (carried segments split)` plus a note naming the split.
- **Host bridge state**: `BridgeInfo.state` is `missing`, `down` (admin down), `no-carrier` (IFF_UP but operstate
  `down`/`lowerlayerdown`, i.e. `<NO-CARRIER,...,UP> state DOWN`) or `up`; `carrier` is read from sysfs. The bridge
  prompt lists the cloud bridges present on the host after the profile choices. On an EVE host (any `pnetN` in
  sysfs) the plan warns `BRIDGE_NOT_ON_HOST` / `BRIDGE_NO_CARRIER` for target bridges that are missing or have no
  link; elsewhere (a laptop preparing a profile) any name is accepted silently.

**Resolutions applied during review fixes (services-maps)**

- **dns / domain / ntp / probe** questions skip IPv4 values inside the protected inventory (`protected_prefixes`:
  unattributed interface/loopback networks plus the manifest `protect` list), e.g. the sdwan hub loopback
  `10.200.255.251` used as the HUB_HC probe, or lab1's internal `10.x` resolvers. A `[map.<kind>]` entry for such a value
  (answers file or profile) is not rendered: `SERVICE_INTERNAL` warning, left unchanged. It is a warning, not a blocker,
  because profile maps are shared by every lab.
- **domain** (RFC 1123 2.1): a value whose last label is all digits (`9.9.9.9`) is refused at the prompt, and a
  `[map.domain]` profile entry holding one is dropped with a `BAD_VALUE` warning.
- **dns / ntp / probe** host names are accepted at the prompt only when every targeted fact's dialect renders host
  names (`HostnameServiceMixin`: FortiOS, F5); otherwise the prompt requires IPv4 (no more silent `BAD_VALUE` drop
  after the questions).
- **azure_s2s**: `local_asn` must differ from the answered-or-discovered `azure_asn` and vice versa (prompt validator,
  plus an `AZURE_ASN_EQUAL` blocker in `plan()`); `azure_asn` also refuses Azure-reserved ASNs except Azure's default
  65515. A non-public `peer_ip` is accepted (in-lab simulated gateway) with an `AZURE_PEER_PRIVATE` warning.
- **secrets**: `psk` is offered only when cleartext PSKs exist; the history note names the Azure VPN gateway only when
  the `azure_s2s` scenario applies, otherwise "rotate it wherever it is used".
- Lab picker: a range (`2-4`) skips non-selectable labs; a single explicit number still errors. After `a` the review
  prints that the plan is queued and written after the last lab (`q` still writes nothing).

**Resolutions applied during review fixes (l3-validation)**

- **Answered values are validated**: a question the profile, `.localize/site.toml` or a TOML `--answers` file already
  decides is not prompted in non-interactive / `--yes` mode, but its value (the question default) still runs through
  the parameter kind and question validators (`cli._check_answered`). A failure is `BAD_ANSWER` (exit 1), exactly like
  a typed or JSON answer. In interactive mode the answered value is the prompt default, which `Enter` validates too.
- **gateway** also refuses the new address of any non-gateway baseline host (host overrides > split pieces > answered
  subnet offset; an unanswered subnet keeps hosts in place), at the prompt and for answered values.
- **gateway default** after a subnet change: same offset when it fits; else the same distance from the top of the
  new subnet (`10.100.255.254` in a /20 -> `.254` in a /24, `same offset from top`); else the last or first usable host
  by the side the old gateway sat on. Never the old gateway. A /31 or /32 gets no default (`required`).
- **cidr** checks overlap against every other segment's **answered** subnet (where it will live), not only the ones
  whose baseline it touches; a skipped segment counts with its baseline.
- **split** has a real validator: the pairs must parse, every OLD must overlap the baseline subnet, a piece outside
  the answered subnet must not overlap another segment, and every baseline host must end up mapped (the gateway
  counts as mapped once a gateway is answered; host overrides count). The question note lists all unmapped hosts
  grouped by /24.
- **Blocked plan, interactive**: when the plan has conflicts/blockers naming segments, the tool asks
  `Revise the answers for <segments>?` (default yes) and re-asks only those segments' questions, after clearing the
  answer fields the finding invalidates (`SUBNET_OVERLAP`: subnet/gateway/split/hosts, `SPLIT_REQUIRED`: split/hosts,
  `GATEWAY_INVALID`: gateway, `VLAN_DUPLICATE`: vlan). Declining keeps the old behaviour (not applied, exit 2).

### 10.3 Prompt keys

`Enter` accepts the default. `k` keeps the current value. `s` skips the segment. `?` shows evidence. `b` goes back.
`q` quits without writing. Secrets are read with `getpass`. With `NO_COLOR` set, or when output is not a TTY, the
output is plain text.

### 10.4 Label text propagation (distinctiveness rule)

Old labels are propagated into device text only when **all** of these hold:

- the label contains a digit or a hyphen;
- it is at least 5 characters long;
- it is not a prefix of internal bridge names (`Net-`);
- it is not in the built-in generic set (`Internet`, `Net`, `mgmt`, `trunk`, `out`) or the manifest `generic_labels`.

Otherwise only the XML `name` changes. This protects `INTERNET-ONLY`, `fd-to-internet`, `Internet Cloud` and the
`Net-*` bridges.

**Resolutions applied during review fixes (labels)**

- *Label validation.* `labels.label_error()` is the hard rule for every segment label (question validator, so the
  answers-file and profile paths too, and again in the plan as `BAD_LABEL` error): non-empty, no surrounding blanks,
  none of `< > & "` or control characters, plus `unl.check_label` (printable, at most 64). Field limits of the device
  texts a label reaches go through an extensible dialect hook `label_problem(fact, new, text) -> str | None`, checked
  per `label_ref` / `vlan_name` fact (`labels.text_label_problem`): FortiOS `alias` at most 25 characters
  (`description` 255, `comment(s)` 1023, no `"`); Cisco (`CiscoDialect`: IOS, IOS-XE, NX-OS) `vlan N / name` at most
  32 characters without blanks. A dialect without the hook has no extra limit.
- *Reversible propagation.* The new label must itself be findable again: text references follow only when the new
  label is one `_common.LABEL_TOKEN` and distinctive (`labels.text_safe`); otherwise the planner emits one
  `LABEL_TEXT_KEPT` warning and only the network names change (`MGMTX`, `Mgmt B`), so `revert` stays byte-identical.
  The labels an apply actually wrote into text are recorded in `state.json` as `baseline_text_labels`
  (`{label now in text: original label}`, composed over runs); the CLI passes their keys as
  `PlanOptions.written_labels`, and a written label follows a rename even when it fails the distinctiveness rule.
- *Template-derived labels.* An unanswered label is renamed when a template that reproduces the network's current
  name with the current values renders differently with the answered tag / subnet (`labels.derive(strict=True)`),
  network by network: manifest `label_template` first, then the NameExplainer suggestion, where a digit run that is
  both tag and third octet ("ambiguous") takes the kind the manifest template uses (`mgmt-203` ->
  `mgmt-{octet3}` beside `{octet3}-{host}`). This is exactly the question default, so `plan` without `--yes` and
  `apply --yes` agree, a `{netid}`/`{host}`-only template never fires on a VLAN/subnet change, and a generic name
  (`mgmt`) is never re-templated. A label answer equal to that default also renames per network; any other label
  answer goes to every network named like the primary label, as before.

### 10.5 Example transcript: sdwan lab

```
$ ./scripts/eve-localize --lab sdwan
Profile: .localize/site.toml (3 segment answers, 6 value maps) · host: EVE (bridges: pnet0 up, pnet1 up, nat0 up)

Lab: labs/datacenter/cisco/vxlan_evpn_multi-site_sdwan_only.unl  [pinned: manifest OK, 0 drift]
Stores: startup (61 blobs) · configset sdwan-vxlan-evpn (49) · sidecar _cfgs (9 files)

Segment   Nets                  Cloud  Tag  Subnet            GW  Endpoints               Status
MGMT-203  74,76,91,54,55,165    pnet0  2    10.100.203.0/24   .1  38 (15 via IOL mgmt-*)  CONFIGURABLE
MGMT-204  139,141,83,60,148     pnet0  3    10.100.204.0/24   .1  7 (2 via IOL trunk)     CONFIGURABLE
INET-201  25                    pnet0  201  10.100.201.0/24   .1  5 + 2 via BGW E1/6->E1/3 CONFIGURABLE
INET-202  44                    pnet0  202  10.100.202.0/24   .1  5 + 2 via BGW           CONFIGURABLE
TRUNK     132,137,140,152       pnet0  all  -                 -   4 IOL uplinks           CARRIER (2,3)
Notes: Forti/F5 configs are sidecar-only (EVE never pushes them; re-paste after localizing).
       EVE-TRUNK has native_vlan="1" (kept).  Protected look-alikes: rd 2:2 (10x), set ike-version 2 (14x).

[A Clouds]
 1/5 MGMT-203 bridge [pnet1 from site.mgmt_a] (?=evidence): ⏎
 2/5 MGMT-204 bridge [pnet1 role oob]: ⏎
 3/5 INET-201 bridge [pnet3 from site.inet_a]: ⏎
 4/5 INET-202 bridge [pnet0 keep]: pnet3
 5/5 TRUNK (carries MGMT-203, MGMT-204) bridge [pnet1 follows carried]: ⏎
[B VLAN tags]  (internal VLANs 1,100,101,200,501,502,3101 are reserved)
 MGMT-203 tag 2 [20 from site.mgmt_a] — 41 spans: dot1Q x18, IOL access x15, vlan def x4, b1/b2 trunk+SVI: ⏎
   Sub-interfaces Gi16.2 / Gi3/3.2 / Vlan2 follow the tag (policy rename) [Y/n]: ⏎
 MGMT-204 tag 3 [30]: ⏎
 INET-201 tag 201 [301]: ⏎
 INET-202 tag 202 [keep]: 302
[C Addressing]
 MGMT-203 subnet 10.100.203.0/24 [192.168.20.0/24]: ⏎   gateway 10.100.203.1 [192.168.20.254]: ⏎
   warn: mapped host 192.168.20.11..23 ok; none inside reserved 192.168.20.1-10
 MGMT-204 subnet [192.168.30.0/24]: ⏎   gateway [192.168.30.1 same offset]: ⏎
   note: dc1/dc2-svc-fgt1 BGP router-id derives from mgmt IP (10.100.204.69 -> 192.168.30.69)
 INET-201 subnet [198.51.100.0/24]: ⏎   gateway [198.51.100.1]: ⏎
   warn: hosts .31,.41,.51,.61,.71 outside dhcp_pool 198.51.100.100-200 ✓
 INET-202 subnet 10.100.202.0/24 [keep]: 203.0.113.0/24   gateway [203.0.113.1]: ⏎
[D Labels]
 EVE-MGMT-203 -> [LAB-MGMT-20] (6 networks, 30 text refs: vlan names, descriptions, sidecar headers): ⏎
 EVE-MGMT-204 -> [EVE-MGMT-30 from template EVE-MGMT-{octet3}]: ⏎
 EVE-INET-201 -> ('201' is both tag and octet3; template follows?) [t]ag/[o]ctet/[k]eep: t   => EVE-INET-301
 EVE-INET-202 -> [EVE-INET-302]: ⏎
 'pnet0' in descriptions/aliases follows bridges? 26 refs; alias "pnet0-trunk" spans MGMT-204+INET (now
   pnet1/pnet3) -> ambiguous, skipped [Y/n]: ⏎
[E Services]
 DNS 1.1.1.1 -> [9.9.9.9] (docker x24, Forti x7, F5 x2): ⏎      DNS 1.0.0.1 -> [149.112.112.112]: ⏎
 SLA probe targets "1.1.1.1" "8.8.8.8" (Forti spokes x3) [keep]: ⏎
 domain netlab.local -> [lab.alice.net] (~120 refs; plsnetlab.local is separate): ⏎
 domain plsnetlab.local -> [campus.alice.net]: ⏎     search yandy.dev -> [drop]: ⏎
 NTP pool.ntp.org (F5 x2) -> [time.alice.net]: ⏎
[F Site routes] via MGMT-204 gw: 10.100.0.0/16, 10.25.0.0/21, 192.168.0.0/24 (7 Forti files)
 [k]eep / [r]eplace list / [d]elete: r  -> list: 192.168.0.0/16

Plan: 3 files, 612 edits (PROVEN 431, CORRELATED 158, cosmetic 23) · 0 conflicts · 0 blockers · 2 warnings
  .unl  xml_attr 34 · startup 251 · cs:sdwan-vxlan-evpn 233        sidecar 9 files 94
[r]eview groups  [d]iff  [x] explain  [s]ave plan  [a]pply  [q]uit: d c8kv-75
--- vxlan_evpn_multi-site_sdwan_only.unl :: cs:sdwan-vxlan-evpn :: node 75 c8kv-75
-interface GigabitEthernet16.2
+interface GigabitEthernet16.20
- encapsulation dot1Q 2
+ encapsulation dot1Q 20
- ip address 10.100.203.75 255.255.255.0
+ ip address 192.168.20.75 255.255.255.0
...
: a
Preflight: git clean ✓  running nodes: none (tmp dir present: nodes not wiped) ✓  lock ✓
Backup .localize/backups/20261027T101500Z/ · writing 10 files · validating ✓ (re-scan: 0 edits)
Run 20261027T101500Z journaled.  Next: wipe affected nodes in EVE; re-paste sidecar configs to Forti/F5;
close and reopen the lab in the UI only after this run (EVE overwrites the file on save).
Suggested commit (if you keep it local): chore(labs): localize sdwan lab for alice-homelab
```

### 10.6 Example transcript: lab with no externals

```
$ ./scripts/eve-localize --lab ccie_sec
Lab: labs/ccie/ccie_sec_v6_practice_lab.unl
Nothing to localize: all 45 networks are internal bridges (no pnet/nat/cloud). No changes.
$ echo $?
0
```

With `--all`, labs like this appear as one line in the picker (status `nothing to localize`) and are skipped
automatically.

---

## 11. Rewrite strategy

### 11.1 Single pass, claims, precedence

The planner builds `ValueMaps` from the answers:

```python
@dataclass
class ValueMaps:
    bridges: dict[str, str]                       # segment key -> new bridge (applied to its network ids)
    labels: dict[str, str]                        # network id -> new name ; text_labels: old -> new (distinctive only)
    text_labels: dict[str, str]
    tags: dict[tuple[str, int], int]              # (segment key, old tag) -> new tag
    subnets: dict[str, list["SubnetMap"]]         # segment key -> maps (split maps = several entries)
    exact_ips: dict[IPv4Address, IPv4Address]     # gateways, peers, explicit host overrides
    services: dict[tuple[str, str], str]          # (kind, old) -> new
    asns: dict[tuple[str, int], int]
    routes: dict[str, list[IPv4Network] | None]   # segment key -> replacement list (None = keep)
    secrets: dict[str, str]
```

- Each scenario maps facts to `Edit`s through `dialect.render`.
- **Claims**: each span is claimed once. Precedence: `exact_ips` > gateway > subnet offset; scenario-exact
  (peer, ASN) > membership. Identical edits on the same span are deduplicated. Different replacements on the same span
  → `conflict`.
- All edits apply **in one pass** from the original text, so swaps (tag 2→3 and 3→2, subnet A↔B) cannot chain. This
  is tested.
- Protected facts are never claimable: a hard error naming the rule.
- The plan only contains PROVEN and CORRELATED facts, plus cosmetic groups when `policy.cosmetic_text` is on.
  HEURISTIC edit groups are off unless `--include-heuristic` is given or they are toggled in review.

### 11.2 Per location

| Location | Rule |
|---|---|
| **Network `type`** | `attr_edit` on each network id of the segment. No attributes are added, removed or reordered. `smart`, `vlan8021ad` and `native_vlan` are preserved. |
| **Network `name`** | By id, only on the segment's cloud networks whose current name equals the old label or matches the template. Bridges are never renamed (`Net-mgmt-203iface_*`, bridge 64 `Net`). Templated renames keep host suffixes (`203-67` → `20-67`). |
| **Interface `vid`** | Never changed (always 1). |
| **Startup configs / configsets** | Every `ConfigText` is parsed and rewritten **independently** with the same ValueMaps, so all stores stay consistent. Legacy-scheme scopes are handled per the `legacy_scopes` policy (default `leave`, with a warning listing them). Re-encoding goes through `encode_blob(like=original)`. |
| **Sidecar files** | The same treatment as configs. Written back with the original newline style and trailing newline. Mirrors get identical edits, followed by an equality assertion. |
| **Textobject HTML** | Only through `label_value` facts (manifest) or `eve_html` text-node facts. Exact IP, CIDR or label tokens that equal proven old values are matched in text nodes only. The decoded HTML is spliced and re-encoded. `<br>`, trailing spaces and CSS are untouched. Unchanged textobjects keep their exact bytes. |
| **`<description>` / `<task>`** | Never decoded or edited. If a manifest declares `scan_description = true`, exact proven old values found there are reported as `LEAK` warnings only. Tasks can hold MB-sized PDFs. |
| **`<lab id/name/author>`** | Never edited, except in `--out` copy mode, which sets a new `uuid4` id and an optional name suffix. |

### 11.3 Per value class and dialect

**VLAN tags**: only tag-bearing facts (6.3) attributed to the segment.

- `subif_policy=rename`, when the suffix equals the old tag: the header `interface X.2` becomes `X.20`, plus every
  whole-token reference to `X.2` or its abbreviation (`Gi16.2`) **in the same config**. The same applies to
  `interface VlanN`. If the target name already exists → conflict.
- After that, the leak scan searches **all other configs and sidecars** for `<node-name>: <old ifname>` and bare old
  iface tokens, for example a peer description "to c8kv-75: Gi16.2". These are rewritten when the pattern is
  `to <node>: <ifname>` and the node and iface resolve exactly (CORRELATED, cosmetic group). Otherwise they are listed
  as warnings.
- VLAN lists (`1,100-101,201,501-502,3101`) are handled with `VlanList.replace().render(style)`. Ranges are split only
  when needed, with a warning. Duplicates are never created; a collision is a conflict.
- `vlan N` definition + `name X`: the id changes with the tag; the name text follows the label rules.
- Free-text `(VLAN 3)`, `(802.1Q trunk, VLAN 3)` and `VLAN 2) arrives untagged`: rewritten only on lines (or `#`
  comment lines) that also contain the segment's old or new label. Cosmetic group, on by default.

**IPv4**:

- `SubnetMap.map_host(ip) = new.network_address + (ip - old.network_address)`. Each split-map entry covers its own
  sub-range. `host_overrides` win.
- The mask token adjacent to a rewritten IP is rewritten **in its own form** (`255.255.255.0`, `/24`, `netmask M`),
  and only if the prefix length changed.
- *Resolution applied during review fixes (l3-validation)*: an ACL wildcard is a mask form too (`mask_form =
  "wildcard"`). A rule captures it with `(?P<mask>MASK)` (a contiguous non-netmask quad such as `0.0.0.255` is
  classified `wildcard`) or with `(?P<wildcard>IPV4)` (always read as a host mask, so `0.0.0.0` is /32). It is
  rewritten as a wildcard (`0.0.1.255` for /23) **only** when it equals the segment's old prefix (the ACL matches the
  whole segment); host matches and wider summaries keep their width (no split-delta adjustment). Wildcard facts never
  feed subnet discovery (`host_network`). The sdwan rule `sdwan.acl_any_to_net` captured its wildcard this way, which
  closes the T20 "known gap" below.
- *Resolution applied during review fixes (integration)*: lab rework 32d9b62 (per-provider VRFs on the CSRv) removed
  the sdwan PBR ACL and `set ip next-hop`, so `sdwan.acl_any_to_net` and `sdwan.pbr_next_hop` were dropped from the
  manifest. `sdwan.nat_static_global` now accepts a trailing `vrf <name>`, and the FortiGate hub rules became
  `sdwan.fgt_nat_note_a/_b` (header comment), `sdwan.fgt_lo_alias_nat` (loopback alias `(NAT a.b.c.d)`) and
  `sdwan.fgt_provider_route` (`set dst` + mask, so the per-provider /24 routes follow a subnet or prefix change). The
  wildcard regression test injects the ACL into a temp copy.
- Supernets are never prefix-replaced. They belong to `site_routes`: replace the list, or delete whole stanzas only
  where the dialect supports it (Forti `edit N … next`, ASA single-line `route`). Otherwise it is a blocker.
- Free-text host references that are not dotted quads (sidecar "reserve .31 on EVE-INET-202", ".51/.61/.71"):
  - Under offset-preserving maps where the last octet is unchanged, they need no change. The tool checks this.
  - Under split, host or override maps, each `\.\d{1,3}\b` token on a line containing the segment label is rewritten
    if it equals a mapped host's old last octet within that segment (cosmetic group).
  - Otherwise it is listed as a warning.

**Labels**: `text_labels` replace whole tokens inside description, vlan-name, alias, comment and sidecar `#` contexts
only. Ambiguous `cloud_ref` aliases are skipped: one alias spanning segments that now go to different bridges, such as
Forti `pnet0-trunk`.

**Services**: only the anchored spans. List-aware removal (`"" = drop`) applies inside search lists, never inside
`domain-name`.

**Per-dialect specifics:**

| dialect | specifics |
|---|---|
| ios / iosxe / iol | `ip domain-name` vs `ip domain name` kept as is; dotted masks; VRF defaults; uncabled ports per the VLAN-domain rule |
| nxos | `/len` masks, 2-space indent, lowercase `dot1q` internal subifs are protected, range lists |
| asa | trailing-space `ip address … MASK `; `route <nameif> NET MASK GW 1`; object names that are IPs (`tunnel-group 172.173.204.134`) are only changed by `azure_s2s` exact claims; `Cryptochecksum:` goes stale (info) |
| fortios | `set vlanid`, `set ip A M`, `set gateway`, `set remote-gw`, `set router-id`, quoted alias, description and comments; static route stanza deletion supported |
| f5tmsh | `management-ip A/len`, `management-route default gateway`, `replace-all-with { … }` lists |
| junos | `address A/len;`, `next-hop X;`, `name-server { X routing-instance …; }`, no trailing newline kept |
| linuxsh | `ip addr add A/len`, `ifconfig eth0 A netmask M`, `route add default gw G`, resolv.conf heredoc |
| eve_html | text-node tokens only |
| generic | proven-subnet IPv4 + distinctive label tokens, CORRELATED; never tags |

**Resolutions applied when the core scenarios and the planner were written (T16, T18)**

- `ValueMaps` and `SubnetMap` live in `scenarios/base.py` (re-exported by `planner.py`) so scenario modules can import
  them without an import cycle. Additive fields: `gateways` / `seg_exact` (per-segment gateway and host-override maps),
  `primary` (canonical old subnet -> answered subnet, drives mask decisions), `old_labels`, `legacy_scopes`, `skipped`,
  `lab_id`, `manifest`, `include_outliers`, `subif_policy`, `cosmetic_text`. `services` keys are
  `(profile map kind, old)` exactly as in `[map.<kind>]`; `routes` is keyed by segment key.
- `PlanFragment` = `claims: list[Claim]`, `findings`, `notes`. A `Claim` is a proposed span replacement in one store
  text (xml claims carry the byte span of the attribute value) with category, group, confidence, priority
  (`PRIO_MEMBERSHIP` 10 < `PRIO_GATEWAY` 20 < `PRIO_EXACT` 30 < `PRIO_SCENARIO_EXACT` 40), provenance and `exact`
  (bypasses the protected-fact check for scenario-exact claims). The planner converts claims to `Edit`s following the
  apply offset contract (CRLF sidecar offsets are shifted to the LF-only view of `apply.sidecar_decode`).
- `Question` gained optional `scenario`, `segment`, `apply` (setter storing the parsed answer in `Answers`) and `notes`;
  `apply_answer(ans, q, raw)` validates (ParamKind + question validator), parses and stores. Segment answers go to
  `[segments."<site_key>"]`; the legacy choice goes to `[scenarios.scopes]` options keyed by site key.
- Optional scenario extras honoured by the planner: `gated` (G-group yes/no: runs only when
  `ans.scenario_enabled(id)` is true or `PlanOptions.enable_scenarios` names it) and `contribute(a, ans, maps)` (adds map
  entries before any scenario plans). `scenarios.load_builtin()` imports the nine built-in modules (missing ones are
  skipped); `ordered()` sorts by `order` (bridge 10, segment_l2 20, segment_l3 30, labels 40).
- Answers are taken literally: unanswered = keep. Question defaults (role bridge, carrier follow, same-offset gateway,
  templated label) are what the CLI stores with `--yes`. *Review fix (labels):* the templated label is derived by
  the planner itself when the label is unanswered (10.4 resolutions), so it no longer depends on `--yes`. Exception: when no bridge answer exists the planner applies
  the role default and the carrier-follow rule itself (section 9 steps 4-5).
- A VLAN answer for an untagged segment is a `TAG_NOT_APPLICABLE` warning (ignored), not a blocker, so one shared
  `site_key` can be bound in labs that tag it and labs that do not.
- Edit groups: `<segment>/<cloud|vlan|ip|gateway|derived|textobject|label>`, `cosmetic/<pnet-text|label-text|vlan-text>`,
  HEURISTIC claims get the suffix `:heuristic` (off unless `include_heuristic`), `outliers/*` are never enabled by
  default. `Edit.provenance` = `[question id, comma-joined fact ids, rule, evidence, "scenario:<id>"]`.
- Plan findings = planner/scenario findings + analysis findings of severity conflict/blocker/error. Codes:
  `VLAN_PROTECTED` (blocker), `VLAN_DUPLICATE`, `SUBNET_OVERLAP`, `GATEWAY_INVALID`, `CLAIM_CONFLICT`, `CLAIM_OVERLAP`,
  `SUBIF_EXISTS`, `VLAN_COLLISION` (conflict), `STRUCTURAL_TAGGING`, `SPLIT_REQUIRED`, `READ_ONLY_LAB` (blocker),
  `PROTECTED_EDIT`, `STALE_CLAIM`, `BAD_BRIDGE`, `BAD_LABEL` (error), `LEGACY_LEFT`, `HOST_RESERVED`, `LABEL_AMBIGUOUS`
  (warn), `AMBIGUOUS_CLOUD_REF`, `F5_VLAN_NAME` (info).
- Plan JSON (`planner.plan_to_dict` / `dumps_plan` / `loads_plan`): secret edit text is redacted unless
  `include_secrets`; loading a redacted plan disables those groups (`SECRET_REDACTED`).
- Gaps: cross-config `to <node>: <ifname>` references to renamed subifs are not rewritten or reported; free-text
  `.31`-style host references under split/host maps are not rewritten; Junos unit renames are not done (only the
  `vlan-id`); F5 `net vlan` names equal to an old label are kept (info).

---

## 12. Safety

### 12.1 Preflight (`apply.preflight`)

- Python ≥ 3.11. The repo root is found with `git rev-parse` (optional; the tool also works outside git).
- **Git state**: if a target file is dirty → warning. With `--require-clean` → precondition failure. A file that is
  dirty *because of a previous localization recorded in `state.json`* counts as clean.
- **Running nodes** (`hostenv.running_nodes(lab_id)`): scan `/proc/*/cmdline` for qemu, iol, dynamips or vpcs
  processes, and `docker ps` labels/names, that reference the lab UUID or its `/opt/unetlab/tmp/<pod>/<uuid>/` path.
  Live processes → blocker, unless `--force-running`. A leftover `/opt/unetlab/tmp/*/<uuid>/` directory with **no live
  process** → info "nodes not wiped". This fixes the false positive verified on the sdwan lab.
- **Open in the web UI** cannot be detected reliably (EVE Pro session state is not a stable interface). Mitigations:
  - a pre-apply warning;
  - a post-apply reminder;
  - `eve-localize check --lab X`, which re-scans and reports **"reverted by EVE?"** when `state.json` says the lab
    was localized but discovery finds baseline values;
  - `--out` copy mode avoids the race entirely.
- **Plan freshness**: every file's sha256 must equal `plan.base_sha256`, otherwise a blocker. This covers
  `apply --plan plan.json`.
- **Lock**: `fcntl.flock` on `.localize/lock`. Where fcntl is unavailable, an `O_CREAT|O_EXCL` lockfile with the PID.

### 12.2 Transaction (per lab)

1. Back up every touched file (`.unl` and sidecars) with `shutil.copy2` to
   `.localize/backups/<run-id>/<relpath>`, recording mode, uid and gid.
2. For each file: write a temp file in the same directory, `fsync`, `os.chmod(orig_mode)`, and `os.chown(orig_uid,
   orig_gid)` when euid is 0. If not root and the owner differs → warning plus a `make fix-perms` hint. Skipped on
   Windows.
3. Validate the temps (12.3) **before** `os.replace`. If any lab file fails, nothing is replaced for that lab.
4. `os.replace` all temps, then `fsync` the directory.
5. Append to `.localize/journal.json`: `{run_id, ts, user, host, labs: {lab_id: {files: {path: {before_sha,
   after_sha, mode, uid, gid}}, answers_digest, plan_digest}}}`. Update `.localize/state.json`:
   `{lab_id: {localized: true, site_keys: {...}, values: {...}, after_sha}}`.
6. With `--all`, each lab is its own transaction. The summary lists exactly which labs were localized, skipped, failed
   (rolled back) or untouched. `--continue-on-error` controls whether a failure stops the run.

**Resolutions applied during review fixes (apply-safety)**

- After validation, and again right before each `os.replace`, every target is re-hashed against the bytes the changes
  were built from (a created copy must still not exist). A mismatch (an EVE save during the seconds validation takes)
  stops the lab with `SHA_DRIFT` (exit 4): nothing written, or what was already replaced is rolled back. Backups are
  written from those verified bytes, so a backup always matches the journal's `before_sha`.
- Rollback restores a file only while it still holds the bytes this run wrote; otherwise `ROLLBACK_FAILED` names the
  backup. Ctrl-C during the replace step rolls the lab back before re-raising.
- `undo` also checks, before writing anything, that each backup's sha equals `before_sha` (`UNDO_REFUSED`).
- Step 5 is per lab: `journal.json` (the run's entry, created on the first committed lab) and `state.json` are
  rewritten as each lab commits, so a run interrupted on lab N leaves labs 1..N-1 journaled and undoable.
- A new `state.json` entry starts from the previous one, so `baseline`, `baseline_maps` and `baseline_split` survive
  an apply whose caller did not recompute them. `apply --plan` (no answers) records `values` from the bytes the plan
  writes and the baseline from the file before it (or the recorded one). A localized entry without a baseline (old
  state) is treated as "baseline unknown": a later apply does not record localized values as the baseline, and
  `revert` warns and exits 1 instead of reporting "already at baseline".
- `--state-dir` / `--backup-dir` are resolved to absolute paths, so the journal's backup paths work from any cwd.
- The Python >= 3.11 check moved to `scripts/eve-localize`, before any `evelocal` import (3.10 failed earlier with
  an ImportError, so the preflight check was unreachable).

### 12.3 Validation after write (rollback on failure)

1. `ET.fromstring` parses; root is `<lab>`; `id` is unchanged (or is the new uuid in `--out` mode).
2. Ids and counts of networks, nodes, interfaces, configs per configset, textobjects and `<objects>` elements are
   unchanged.
3. **Bytes outside the planned spans are identical.** This is computed directly from the sorted span list with
   slice comparisons, not difflib, so it stays fast on the 2.7 MB `lab1-ei-v01.unl`.
4. Every edited blob decodes, is canonical, and has the same encoding and trailing-newline state.
5. Mirror pairs are still byte-equal.
6. `check-labs` logic runs on the result. It is loaded with
   `importlib.util.spec_from_file_location("check_labs", scripts/check-labs.py)` because the filename contains a hyphen.
   It is called with the repo's tracked labs plus the new file, which matters for id uniqueness in `--out` mode.
7. **Re-scan idempotency**: `analyse()` on the new bytes, then `build_plan` with the same answers → **zero edits**. The
   segment schemes must equal the requested targets. Any residual edit means a bug, and the lab is rolled back.

**Resolutions applied during review fixes (services-maps)**: `[map.<kind>]` entries are keyed by the old value, so
re-planning with the same map after a swap (`1.1.1.1 = 1.0.0.1`, `1.0.0.1 = 1.1.1.1`) or a chain (`netlab.local =
lab`, `yandy.dev = netlab.local`) would rewrite the written targets again. The re-scan therefore uses
`cli.rescan_answers(ans)`: map entries whose key is also a target of the same map are dropped; the rest still catch a
value the write left behind. Segment swaps were never affected (keyed by site_key).

### 12.4 Idempotency, re-runs, revert, undo

- Plans are computed from **current** values, which discovery reads from the file, to target values. Tri-state
  matching skips spans that already hold the target and aborts on drift. Running the same answers twice gives
  "0 edits".
- **Re-localizing** an already localized lab (for example a second site change) works: segments are identified by
  network id and site_key, not by value.
- **`revert`** targets the manifest baselines, including legacy schemes. It works without backups.
- **`undo [RUN]`** restores backups only if each file's current sha equals the journal's `after_sha`. If EVE re-saved
  the file in the meantime, it refuses and suggests `git restore` or `revert`.
- Reversibility is a tested property (section 14): localize → revert gives byte-identical files.

### 12.5 Upstream sync workflow (gap closure)

```
./scripts/eve-localize revert --all --yes      # back to repo baseline (state.json cleared)
git pull --ff-only
./scripts/eve-localize apply --all --answers .localize/site.toml --yes
```

`make localize-sync` prints these steps without running git. CI (`localize-check`) enforces that committed labs are at
baseline, so contributors can't accidentally push localized values. Run `revert` before contributing a lab back. A lab
that a cloner created *with their own site values* can be "baselined" with
`discover --write --baseline-from-answers`, which maps their values back to the repo's site_keys when they choose to.

### 12.6 Copy mode (`--out DIR`)

Writes localized copies (`.unl` plus sidecar dir) under `DIR`, for example `Users/<name>/` or any path, with a new
`uuid4` lab id. The repo working tree stays clean, `git pull` never conflicts, and the EVE save race on the original is
irrelevant. It needs a re-run after upstream changes, which is idempotent.

**Resolutions applied during review fixes (apply-safety)**

- `OUT_IS_SOURCE` (blocker): `DIR` is the lab's own directory, or a copy would land on one of its source files.
- An existing lab at the destination gets the in-place running-node check for *its* id (`RUNNING_NODES`, unless
  `--force-running`) plus an `EVE_SAVE_RACE` warning.
- The destination's id is reused on re-runs only when it is not the source's id, not another tracked lab's id, and not
  an id this run already gave another copy; otherwise a new `uuid4` is minted with a `DEST_ID_DUPLICATE` warning (a
  plain `cp` of the lab into `DIR` used to fail check-labs with a duplicate id).
- Copies are still flattened to `DIR/<basename>`; two labs of one run that map to the same destination file refuse the
  whole run with `DEST_COLLISION` (exit 4, nothing written). Apply them with different `--out` directories.

**Resolutions applied during review fixes (bridges)**

- New copies take the source file's mode **and owner/group** (chown only when running as root, as for in-place
  writes); directories created under `DIR` (including `DIR` itself) get the source file's owner too, so EVE
  (`www-data`) can save a copy written by root into `Users/<name>/`. `--fix-perms` now also works in copy mode: it
  runs `scripts/fix-lab-permissions.sh DIR` on the `--out` tree only (never the whole repo).

### 12.7 Secrets

- Secret spans are redacted (`****`) in prompts, diffs, plans (stored as `sha256:` digests), JSON, logs and evidence.
  `--show-secrets` unmasks them.
- New secrets are read with `getpass` or `{env=...}`. They are never written to answers unless `--save-secrets` is
  given, with a warning.
- The `secrets` scenario offers to replace committed real secrets (the Azure PSK) with `CHANGE-ME-<name>`. It prints:
  "the old value remains in git history; rotate it at the provider (Azure VPN gateway)".
  (Review fixes, services-maps: that wording is used only when the `azure_s2s` scenario applies; other labs get "rotate
  it wherever it is used", and `psk` is offered only when cleartext PSKs exist.)

**Resolutions applied when `apply.py` was written (T12)** — additive to section 3.2

- Edit offsets (contract for T18): `xml_attr` → `text_edit.start/end` are **byte** offsets of the attribute *value*
  span (`RawAttr.span`) in the `.unl`, `old`/`new` are decoded values (apply escapes via `RawLab.attr_edit`; a
  mismatching `old` is `STALE_EDIT`). `blob` (`store.kind` `startup`/`configset`, located by scope + `node_id`) and
  `textobject` (`store.name` = textobject id) → offsets into `DecodedBlob.text`. `sidecar` → offsets into
  `apply.sidecar_decode(bytes)[0]`: UTF-8 + surrogateescape, and a file whose every LF is CRLF is presented LF-only and
  written back CRLF (T8's `ConfigText.text` for sidecars must use the same function).
- Only edits with `group in plan.enabled_groups` are applied (empty set = nothing). `Edit.file` and `base_sha256` keys
  may be absolute or relative to the lab's directory (fallback `repo_root`).
- `ApplyOptions` (in `apply.py`): `state_dir`, `backup_dir`, `repo_root`, `no_backup`, `require_clean`,
  `force_running`, `out_dir`, `new_lab_id`, `continue_on_error`, `rescan`, `check_labs`, `check_labs_script`,
  `check_labs_peers` (None = git-tracked labs), `mark_localized` (False for `revert`: clears the state entry),
  `state_extra` (`{lab_id: {site_keys, values, ...}}` merged into `state.json`), host-probe roots (`proc`, `tmp_root`,
  `docker_names`), `use_fcntl`, `run_id`, `clock`, `user`, `host`.
- Added `apply_plans(plans, opts) -> RunRecord` (one run id, one journal entry, per-lab transactions);
  `apply_plan(plan)` = `apply_plans([plan])`. `RunRecord(run_id, ts, labs: list[LabResult], journaled, mode)` with
  `.ok`, `.exit_code` (5 > 4 > 2 > 1), `.findings`, `by_status()`; `LabResult.status` is `localized | unchanged |
  skipped (preflight) | failed (nothing replaced or rolled back) | untouched`.
- Re-scan hook: `rescan(staged_lab_path, plan) -> Sequence[Edit] | int`; it receives a **staged full copy** (new
  `.unl` + the lab's sidecar dirs in a temp dir) because validation runs before `os.replace`. It may raise
  `ValidationError` for scheme mismatches. `check-labs` also runs on the staged copy plus peers (the original lab is
  dropped from peers in place, kept in `--out` mode).
- `validate_written(path, plan, before, *, changes=None, expect_lab_id=None, peers=(), check_labs_script=...)` covers
  12.3 steps 1-4 and 6; mirrors (5, sidecar files `NN_name.txt` byte-equal to a blob payload of node NN, in the lab's
  `<stem>_cfgs`/single `<stem>*_cfgs` dir or dirs of touched sidecars) and re-scan (7) run inside `apply_plans`.
- Copy mode reuses the id of an existing destination lab (idempotent re-runs), else `uuid4`; copies the lab's
  sidecar dirs whole; is journaled (`mode: "out"`, undo deletes created files) but never touches `state.json`.
- Journal `{schema, runs: [{run_id, ts, user, host, mode, labs: {lab_id: {lab, source, mode, files: {abs path:
  {before_sha, after_sha, mode, uid, gid, backup, created}}, answers_digest, plan_digest, edits, prev_state}}, undone?}]}`;
  undo restores `prev_state`. `state.json` entries also carry `files: {abs path: after_sha}` (used by the git-dirty
  check) and `run_id`. Preflight adds `EVE_SAVE_RACE` (warn, in place only) and `OWNER_DIFFERS` (warn, non-root).

**Resolutions applied when the extra scenarios were written (T17)** — additive, no contract change

- New helper module `scenarios/extra_common.py` (not a scenario): per-lab option storage in
  `[labs."<lab_id>".scenarios.<id>]` (read merged over the global `[scenarios.<id>]`), the "G Scenarios" gate question
  (`<id>/enabled`, bool, default no) and fact helpers.
- `services`: question ids `services/<kind>:<old>` with kinds `dns|ntp|domain|probe` = the `[map.<kind>]` keys (search
  entries share `map.domain`). `""` drops only from search lists (token + one blank run); refused with
  `SERVICE_DROP_REFUSED` for `domain-name`, servers, probes and the last entry of a list. Claims use `PRIO_EXACT`.
- `site_routes`: new param kind `site_routes` (`keep` -> None, `delete` -> `[]`, else a list). Site route = `ip_route_dst`
  with a mask whose next hop on the same line / deletable stanza is a segment gateway; default routes, routes inside a
  segment subnet and `/32` routes to a `peer_ip` are excluded. Routes in both lists stay; the rest are paired in address
  order and rewritten (dst + mask in its own form), surplus old routes are deleted (stanza deletion, else blocker
  `ROUTE_DELETE_UNSUPPORTED`), surplus new ones give `ROUTES_NOT_ADDED` (warn; no stanza synthesis). Claims are
  `exact` (route dsts are protected facts).
- `bgp_upstream` (gated, IOS-family syntax only): options `peers = {old = new}` (per peer, also added to
  `ValueMaps.seg_exact` through `contribute`), `peer_as`, `local_as` (lab-wide; `set community` of the outbound route-map
  recomputed for `L:NN` and `L*65536+NN`), `prefixes` (prefix-list entries of the outbound route-map; same keep/pair/delete
  rule, whole-line deletion; `PREFIX_INTERNAL` warning on overlap with the protected inventory). `l2lab` minilab matches.
- `azure_s2s` (gated): options `peer_ip`, `tunnel_ip` (APIPA 169.254.21.0-169.254.22.255, rest of the /30 by offset),
  `azure_bgp_ip`, `local_asn` (Azure-reserved ASNs refused; lab-wide), `azure_asn`; PSK in `[secrets."azure_s2s.psk"]`
  (claims flagged secret; only the PSKs inside `tunnel-group <peer> ipsec-attributes`). Answers are targets (equal =
  no-op). "Public" = not RFC 1918/CGNAT/APIPA/loopback/multicast, so documentation addresses keep the lab detectable
  after localization without a manifest.
- `secrets`: option `placeholders = none|psk|all` (group "H Secrets"); `CHANGE-ME-<psk|enable|user|snmp|key|secret>`;
  hashed/encrypted values (type 5/7/8/9, `encrypted`, `pbkdf2`, `ENC`, `$..$`) and user-chosen secret values are never
  replaced; scenario-exact `azure_s2s` PSKs win by priority. Findings never contain secret values.

---

## 13. CLI and Makefile

### 13.1 Commands

```
scripts/eve-localize [COMMAND] [LAB ...] [options]

Commands (default: run = interactive picker -> questions -> review -> apply)
  run              interactive full flow
  scan             analysis only: segment/scheme matrix, findings          (alias: --list for summary table)
  plan             build plan + diff; never writes (alias: --dry-run on run)
  apply            build (or --plan FILE) and apply
  revert           apply manifest baselines as targets
  undo [RUN]       restore a journaled run's backups (sha-guarded)
  runs             list journal entries
  check            CI: manifests vs discovery (counts, baseline, coverage, leaks, unpinned), example profile
                   freshness, "reverted by EVE?" detection          (alias: --check)
  discover LAB     print draft manifest; --write -> <stem>.localize.toml.draft; --update refreshes counts/values
  explain LAB      full fact dump with confidence, evidence, protected look-alikes
  profile          --wizard (bridges/roles from host) | --example (regenerate localize/site.example.toml)

Selection
  LAB ... | --lab PATH|SUBSTRING (repeatable)   --all (git ls-files '*.unl', fallback rglob)

Inputs
  --profile FILE / --answers FILE   (default .localize/site.toml)    --save-answers FILE   --save-secrets
  --plan FILE (apply a saved plan, sha-verified)                      --save-plan FILE
  --plugins DIR (extra dialects/scenarios/packs; repeatable)

Behaviour
  --dry-run            never write (default when stdin is not a TTY and no --yes)
  --yes                accept defaults for unanswered questions and skip final confirmation
  --non-interactive    never prompt; unanswered = keep (exit 3 with --strict)
  --strict             unanswered questions / unpinned labs / warnings in check -> failure
  --allow-unpinned     permit non-interactive apply on labs without manifest
  --scope NAME[,..]    restrict scopes (startup, configset names, sidecar)
  --legacy {leave,ask,same}   --include-heuristic   --include-outliers   --no-cosmetic
  --out DIR            copy mode (new lab uuid)
  --continue-on-error  (--all)

Safety
  --require-clean   --force-running   --backup-dir DIR (default .localize/backups)   --no-backup (needs clean git)
  --fix-perms (run scripts/fix-lab-permissions.sh after apply on EVE host)   --show-secrets

Output
  --diff {none,summary,decoded,raw}   --json   --no-color (NO_COLOR honoured)   -v / -q
```

`--json` on `scan` emits the question schema (ids, kinds, choices, current values, defaults). Wrappers (Ansible, a
future web UI) can fill an answers file from it and replay with `--answers --non-interactive`.

Exit codes:

| code | meaning |
|---|---|
| 0 | ok, or nothing to do |
| 1 | error |
| 2 | conflicts or blockers |
| 3 | unanswered under `--strict` |
| 4 | precondition failed (dirty / running / sha drift / lock) |
| 5 | validation failed (rolled back) |

**Resolutions applied when `cli.py` was written (T19)** — additive, no contract change

- Command aliases: `localize` = `run`, `list` = `scan` (and `--list` → `scan --list`), `localize-check` = `check`
  (and `--check`). The command must be the first non-option token; anything else is a LAB. `main(argv, runtime)` takes
  an optional `cli.Runtime` (streams, env, forced interactivity, `getpass_fn`, fake `proc`/`tmp_root`/`docker_names`/
  `sys_net`, `check_labs_peers`) so tests never probe the real host. `--root DIR` (default: git top of cwd, else the
  repo of the script) selects the tree; the hidden `--state-dir` overrides `<root>/.localize`.
- `--answers FILE.json`: `{"answers": {"<question id>": value}}`, a plain `{id: value}` object, or a `scan --json`
  document with `"answer"` filled per question (the question-schema round trip). JSON answers are applied through
  `scenarios.apply_answer` while the questions are walked (so dependent defaults are recomputed); an invalid value is
  `BAD_ANSWER` (exit 1). TOML files go to `profile.load_profile`; `.localize/site.toml` is used only when no
  `--profile`/`--answers` is given and it exists.
- Question loop: questions are re-collected after every answer. A question is *answered* when its `default_source`
  starts with `from `, `map.`, `scenarios.` or `site_routes.` (gates: `ans.scenario_enabled()` is not None). Non-
  interactive runs skip answered questions; `--yes` stores a default only when it differs from `current`; keep mode
  records unanswered ones (`--strict` → exit 3). Interactive runs ask everything (defaults from the profile); `k` on a
  profile-answered question stores the current value (overrides the profile), `s` sets `SegmentAnswer.skip`, `b`
  restores the answers snapshot of the previous question. Gated questions are hidden while their gate is not yes;
  `secret` questions use `getpass`, `bool` ones a y/N prompt. With several labs (`--all`, repeated `--lab`) one
  `Answers` object is carried from lab to lab.
- Writing: `run` without a TTY and without `--yes` is a dry run; `apply`/`revert` write non-interactively (the command
  is the consent). Interactive runs end with the review menu (`r` toggle groups, `d [filter]` decoded diff, `x ID`
  explain, `s FILE` save plan, `a` apply, `n` skip lab, `q` quit); accepted plans of all labs are applied as one
  `apply_plans` run with the re-scan hook = analyse + build_plan with the same answers (lab overrides copied to the
  new id in `--out` mode). Unpinned labs: interactive runs confirm the matrix; non-interactive writes need
  `--allow-unpinned` (else exit 4); `--strict` without `--allow-unpinned` refuses the lab (exit 1).
- `state.json` extras written by the CLI: `values` (target bridge/vlan/subnet/gateway/label per segment key),
  `baseline` (values before the *first* localization, with `networks`), `baseline_maps` (service maps composed from the
  original values), `site_keys`. `revert` builds answers as `[labs."<id>".segments."<key>"]` overrides from
  `baseline` (matched by network id, so relabelled unpinned segments are found) overlaid by manifest baselines, plus
  inverse `baseline_maps`; with neither it skips the lab. `check` feeds `values`/`baseline_maps` to `manifest.check`
  as `localized`/`localized_params`, reports `REVERTED_BY_EVE` (warn) when the lab is back at baseline although
  state says localized, and `STALE_EXAMPLE` (error) when `localize/site.example.toml` differs from `profile --example`
  output (segments by `site_key` from manifest baselines + current bridge; `[map.dns|ntp|domain|probe]` identity
  entries from params `dns*`/`ntp*`/`domain*`/`sla*`).
- `--scope a,b`: blob/textobject edits by store scope or configset name, sidecar edits by `sidecar`, `.unl` attribute
  edits by `startup` or `xml`. Restricting scopes that sidecars mirror makes the mirror check fail (rollback, exit 5).
- Not implemented (gaps): `discover --baseline-from-answers`, `scan --images`, `--check-host`, the label
  `[t]ag/[o]ctet` choice prompt, `--save-plan` with several labs (single lab only), `--diff` in the picker. Findings
  are folded per code (2 shown + "... and N more") unless `-v`.

### 13.2 Makefile (outside the ycc managed block)

```make
.PHONY: localize localize-check localize-test localize-sync
localize:        ; ./scripts/eve-localize
localize-check:  ; ./scripts/eve-localize check --all
localize-test:   ; cd python && python3 -I -B -m unittest discover -s tests -t .
localize-sync:   ; @echo "1) ./scripts/eve-localize revert --all --yes  2) git pull --ff-only  3) ./scripts/eve-localize apply --all --answers .localize/site.toml --yes"
test: check-labs localize-test localize-check
```

### 13.3 Extension guide

**Onboard a new lab (no code)**

1. Build the lab in EVE and commit the `.unl` (plus `<stem>_cfgs/NN_<nodename>.txt` sidecars, named exactly like the
   node).
2. `./scripts/eve-localize scan --lab new` and check the matrix and findings.
3. `discover --lab new --write`, then review `new.localize.toml.draft`:
   - set `site_key`s (reuse `site.*` keys only when it is truly the same real network);
   - confirm merges;
   - set protect, generic_labels and scenarios.
4. Rename it to `new.localize.toml`. Run `make localize-check` and `profile --example`.
5. Add `python/tests/localize/golden/new.answers.toml`, then `UPDATE_GOLDEN=1 make localize-test` (writes
   `golden/new.scan.json`). No test list is edited: the suites derive the lab lists from the tree
   (`tests/localize/labfiles.py`: tracked `labs/**/*.unl`, split by "has cloud networks"); a lab without golden files is
   skipped with a message naming them.
6. Commit with `feat(labs): add <lab> with localize manifest`.

After later edits in EVE: `discover --lab new --update`, review the diff, commit.

**Add a vendor dialect**

The usual case is a `RuleDialect` with data only, about 20 lines:

```python
# python/src/evelab/localize/dialects/eos.py
from .base import RuleDialect, PatternRule
from . import register

@register
class EOS(RuleDialect):
    name = "eos"; templates = ("veos*", "ceos*"); sniff = (r"^! device: .* EOS",)
    block_style = "indent"; mask_form = "prefix"
    iface_aliases = {"Et": "Ethernet", "Ma": "Management"}
    rules = (
        PatternRule("eos.encap", r"^\s+encapsulation dot1q vlan (?P<v>\d+)$", "vlan_tag", block="interface",
                    negative=("   rd 2:2",)),
        PatternRule("eos.ip", r"^\s+ip address (?P<v>IPV4)(?P<mask>/\d+)$", "ip_host", block="interface"),
        PatternRule("eos.access", r"^\s+switchport access vlan (?P<v>\d+)$", "vlan_tag", block="interface", l2=True),
        PatternRule("eos.ns", r"^ip name-server vrf \S+ (?P<v>IPV4)$", "dns_server"),
    )
    secret_rules = (r"^username \S+ .*secret (?:\d )?(?P<s>\S+)",)
```

(`IPV4` inside patterns is expanded by `RuleDialect` to the boundary-aware token.)

- The module is imported automatically: `load_builtin()` imports every non-private module of `dialects/` except the
  helpers in `HELPER_MODULES` (`base`, `blocks`); `BUILTIN_MODULES` is computed, not hand-kept.
- **Zero-Python alternative**: `python/src/evelab/localize/dialects/packs/eos.toml` with `dialect`, `templates`, `block_style`,
  `mask_form` and `[[rule]]` tables carrying the same fields. Packs are loaded automatically. Out-of-tree packs and
  Python files load with `--plugins DIR` or `$EVE_LOCALIZE_PLUGINS` (`os.pathsep`-separated).
- Add `fixtures/snippets/eos/*.txt` plus `*.facts.json`. `test_dialect_contract.py` automatically runs every registered
  dialect and checks:
  - a no-op render is byte-identical;
  - render followed by extract yields the new value;
  - the inverse render restores the original bytes;
  - none of the `negative` lines match.
- Subclass and override `parse()`/`render()` only for unusual syntax, the way `junos.py` does for braces.

**Add a scenario**

`python/src/evelab/localize/scenarios/syslog.py` with `@register_scenario` implementing `applies` / `questions` / `plan` (the
module is auto-imported like dialects; helpers: `scenarios.HELPER_MODULES`). Add `PatternRule`s with the new fact kind to
the relevant dialects.

**Add a parameter kind**

Register it in `scenarios/base.py`:

```python
PARAM_KINDS["mac"] = ParamKind(
    name="mac",
    parse=lambda s: s.lower(),
    validate=validate_mac,                     # (value, answers) -> str | None
    fact_kinds={"mac_addr"},                   # documentation only
)
```

Then add the fact kind to the dialect rules that produce it, and a question in an existing or new scenario: the
scenario's `plan()` produces the edits through `render_fact()` / `Dialect.render` (a `ParamKind` never renders). The
profile, answers, plan JSON and review pick the kind up automatically (the kind name is the serialisation key).

**Add a structural transform (later)**

`transforms/<name>.py`, for example `ios_dhcp_to_static` (T22):

- `applies(finding) -> bool`
- `questions()`
- `plan() -> list[Edit]` (insertions are TextEdits with `start == end`)

When registered, the matching blocker becomes an opt-in edit group (`--allow-structural`), always shown in a separate
review section.

**Add a cloud kind**: extend profile `[bridges]`, or `hostenv.BRIDGE_PATTERNS`.

**Resolutions applied during review fixes (cli-extensibility)**

- Built-in dialect and scenario modules are auto-discovered (`pkgutil.iter_modules` over the package directory, minus
  private `_x` modules and `HELPER_MODULES`); the hand-kept `BUILTIN_MODULES` tuples are gone (#29).
- `ParamKind.render` is reserved and never called; edits always come from `Dialect.render` via `render_fact()` (#30).
- Registration clashes are errors: a pack class's identity includes its source file, so two pack files declaring one
  dialect raise `DIALECT_DUPLICATE` (re-loading the same file stays quiet, #31); `register_scenario` raises
  `SCENARIO_DUPLICATE` for a different class under an existing id unless `override=True` (#32). The CLI loads the
  built-ins before `--plugins`, so a clash is reported against the plugin file, deterministically.
- Plugin persistence (#27): `dialects.PLUGIN_SOURCES` maps plugin-registered dialects to their file; `apply` records
  the ones a lab's texts used in `state.json` (`plugin_dialects`), and loading that lab without them (revert, check,
  plan, apply) fails with `UNKNOWN_DIALECT` naming the `--plugins` dirs. `$EVE_LOCALIZE_PLUGINS` gives a persistent
  plugin path (e.g. for `make test`). Recorded plugin dirs are never auto-loaded: running code because `state.json`
  names it would be a surprise.
- An exception in a scenario's `applies()` becomes a `SCENARIO_FAILED` error finding on the analysis (scan JSON, plan,
  blocks apply) instead of silently dropping the scenario; an unknown dialect name falls back to `generic` with an
  `UNKNOWN_DIALECT` warning (#32, #39).
- Manifest `[[rule]]` tables also apply to canvas textobjects (`ConfigIndex.dialect_for`, #40).
- Answers (#36): a JSON answer id matching no question of the selected labs is a warning with close matches,
  `BAD_ANSWER` (exit 1, nothing written) under `--strict`; ids whose prefix belongs to another lab of the repository
  are ignored on `--lab` runs; a TOML `[segments."KEY"]` no lab or manifest knows is a warning.
- `--lab PATH` is resolved against `--root` first and must lie under it (`LAB_OUTSIDE_ROOT`, #37).
- The example profile takes a segment's bridge from the manifest baseline, then the `state.json` baseline, never the
  localized lab, so `check --all` stays green after a bridge localization (#35).
- Review menu (#25): `i [filter]` lists edits with ids, `x` accepts a unique id prefix, XML attribute diffs name the
  network and attribute.
- Performance (#38): `check --all` reuses the analyses for the example-profile check (each lab analysed once), and
  `RuleDialect.parse` memoises the applicable `(rule, regex, role)` list per tuple of enclosing block kinds instead of
  evaluating every rule's block filter on every line. A lab is analysed several times per run (load, apply staging and
  validation, rescan, revert), so three bounded process-level memo caches skip repeated work on identical input:
  `topology.cached_parse` (dialect, rules, store, node, text; a hit returns fresh copies of the facts and interfaces
  because attribution mutates them), `dialects.pick` (registry contents, node scalars, text) and `unl._tokenize` (raw
  bytes; the element tree is never mutated). `localize-test` went from about 150 s to about 70 s with more tests.

---

## 14. Test plan (stdlib `unittest`, `make localize-test`)

1. **textutil**:
   - IPv4 boundaries: `.1` vs `.10`, cert hex `01010105`, `49.0000`, IPs followed by masks.
   - IPv6 detection.
   - VlanList parse/render/replace/collision on `1,100-101,201,501-502,3101`.
   - Mask conversions.
   - Domain tokens: `netlab.local` vs `plsnetlab.local` vs `dc1-f5-1.netlab.local`.
   - HTML text-node regions skip `style`/SVG.
2. **codec / unl**:
   - For **every real lab**: decode→encode of every blob is byte-identical.
   - `verify_against_etree` passes.
   - The empty plan writes byte-identical files.
   - Stray `<objects/>` counts are preserved.
3. **Minilab fixtures** (synthetic `.unl`):
   - no `<configs>`;
   - garbage blob `ff`;
   - `config="1"` without a blob;
   - non-canonical base64 (blocked);
   - duplicate names (`Net` cloud and bridge);
   - a name containing `&`;
   - CRLF sidecar;
   - missing sidecar;
   - mismatched sidecar name (skipped);
   - two sidecar dirs (ambiguous);
   - an unknown layout element (read-only).
4. **Dialect contract and snippets**, taken from the real labs. Positive and negative cases include:
   - `rd 2:2`, `set ike-version 2`, `name servers`, `set community 204:204`, `rd 203:203`;
   - spliced syslog → orphan;
   - Forti vlanid parent;
   - Junos `/20`;
   - linux heredoc;
   - F5 tmsh;
   - ASA trailing space and leading newline.
5. **l2trace / segments** (minilabs):
   - direct subif;
   - IOL access → mgmt0;
   - trunk with no allowed list and **implicit VLAN only** (backbone case);
   - NX-OS L2 pass-through to a Forti vlanid;
   - internal subif reusing an external tag (junos Gi3.1240 untouched);
   - uncabled port;
   - orphan attribution;
   - loop termination;
   - merge rules a–d;
   - hint not merged without confirmation;
   - /20 kept whole;
   - outliers.
6. **Planner**:
   - claims precedence;
   - **swap test** (tag 2↔3, subnet A↔B) has no chaining;
   - protected hard block;
   - conflicts: new tag 3101, subif target exists, overlap, offset doesn't fit → split map;
   - tagged segment → untagged-only bridge blocker;
   - ambiguous alias skipped;
   - generic label not propagated.
7. **Golden discovery**: `scan --json` for all 9 labs is compared with `golden/<stem>.scan.json` (segments, schemes,
   status, question ids, protected look-alikes). `UPDATE_GOLDEN=1` regenerates.
8. **Golden round-trip (core acceptance)**, for each lab with clouds, on a temp copy:
   - apply `golden/<stem>.answers.toml` (site B: every bridge, tag, subnet (including prefix-length changes and the
     junos split map), gateway, label and service changed to non-colliding values);
   - assert: only planned spans changed; ET counts are equal; check-labs passes; re-scan gives 0 edits; the protected
     inventory counts are unchanged (10.1.1.x, 169.x, 10.200.x, 172.31.255.x, VLAN 100/3101, Gi3.1240, `rd 2:2`);
   - `revert` → **byte-identical to the original** `.unl` and sidecars;
   - applying site B a second time → 0 edits.
9. **Apply / safety**:
   - owner and mode preserved (real chown as root; mocked otherwise);
   - rollback on an injected validation failure;
   - sha drift refused;
   - undo refuses after a simulated EVE save;
   - running-node detection with a fake `/proc` tree;
   - leftover tmp dir → info only;
   - lock contention.
10. **CLI**:
    - scripted stdin through the full flow;
    - `--non-interactive --strict` exits 3;
    - `--json` question schema round-trips through `--answers`;
    - `--out` produces a new unique lab id that passes check-labs;
    - no-externals lab exits 0 with no writes.
11. **check**: a manifest whose counts are stale fails; a lab with an injected unattributed old value is reported as
    `LEAK`; an unpinned lab gives a warning (error under `--strict`); a stale `site.example.toml` fails.
12. **Lint**: ruff + black through `make lint` on `python/` (config in `python/pyproject.toml`).


**Resolutions applied when the goldens were written (T21)**

- Goldens live in `python/tests/localize/golden/`: `<stem>.scan.json` = the `scan --json` lab entry plus
  `protected` (`vlans` per scope as a VLAN-list string, `prefixes`, per-segment `lookalikes`), computed on a temp tree
  holding the labs, sidecars and committed manifests, with fake host probes (`/sys/class/net` offers
  pnet0/2/4/5/6, nat0/1). `<stem>.answers.toml` = site-B profile keyed by the manifest site keys (no-cloud labs carry a
  trivial `[map.dns]` only). Helpers: `tests/localize/goldlib.py` (Tree, golden_docs, protected_doc),
  `tests/localize/realtexts.py` (decoded real configs via unl + codec; replaces the old `/tmp/an` dumps).
- Site B changes segments and service maps only; scenario answers (site_routes, bgp_upstream, azure_s2s, secrets)
  stay at their defaults because `revert` restores segments + service maps only.
- "Only planned spans changed" is asserted by the apply engine's own validation; the test adds ET element counts,
  check-labs, `check`, unchanged segment keys and protected inventory, no `LEAK`, no baseline-subnet token, no mapped
  service value and no replaced label left.
- Fixes exposed by the round-trip: `cli.localized_from_state` maps each param through its own map kind (dns vs
  probe for the same old IP); `state.json` records `baseline_split` (`{segment: {current subnet: original}}`) and
  `revert` answers it as a split map, so a split (junos /20 -> /24) reverts exactly; `planner.build_value_maps`
  ignores split entries outside every discovered subnet (stale on a re-run: was a `SPLIT_REQUIRED` blocker);
  `planner._validate_maps` reports a new VLAN equal to the manifest baseline VLAN as `VLAN_PROTECTED` info instead of
  a blocker (revert of junos 1250 -> 1240, which coexists with the internal Gi3.1240 by design);
  `discover.segments._merge` also resolves `[[merge]]` unit names by the manifest baseline label of a pinned group /
  carrier (`trunk:204` after `trunk` was relabelled), so a relabelled lab keeps its segment structure.

---

## 15. Edge cases and gap closure

| # | Pitfall / gap | Handling |
|---|---|---|
| 1 | Labs with no clouds (ccie_sec, vxlan concept) | NONE status, "nothing to localize", exit 0, zero diff (10.6) |
| 2 | Name-based external detection (`R-ISP`, `ISP1`, `Internet Cloud`) | external ⇔ `type != "bridge"` only |
| 3 | Duplicate names (`Net` cloud + bridge 64; `EVE-MGMT-203`×6; `mgmt-203`×9; `INET-201`×2; textobject names) | everything keyed by id; renames by segment → ids; bridges never renamed |
| 4 | Bridge names containing external text (`Net-mgmt-203iface_*`, `Net-R14iface_16`) | bridges excluded from rename, hints and text propagation |
| 5 | Number in name ≠ tag (`EVE-MGMT-203`=tag 2; `mgmt-104`; `mgmt58`; `203-67`) | NameExplainer classes; display and suggestion only; ambiguous → ask |
| 6 | Untagged segments (azure, nexus, lab1, junos mgmt) | no tag question; tagging request → STRUCTURAL blocker with exact lines |
| 7 | DHCP uplinks | DHCP status; bridge question plus "target must provide DHCP"; no subnet question; T22 transform later |
| 8 | Attached nodes with no config (Forti/F5 in junos/backbone, ccie EI controllers) | LABEL_ONLY; bridge and label only; never borrow values from sibling labs |
| 9 | Values only in a textobject (nexus 21/3) | manifest `label_value`; documentation-only prompt; text-node splice |
| 10 | SVG/CSS numbers in textobjects | html text nodes only; unchanged blobs not re-encoded |
| 11 | Small tags colliding (`rd 2:2`, `edit 2`, `ike-version 2`, `community 204:204`, `rd 203:203`) | tag-bearing syntax only + protected inventory + negative tests |
| 12 | External tag reused internally (junos Gi3/Gi5 `.1240`) | attached-parent scoping; protected look-alikes listed |
| 13 | Internal-only tags (1241/1243) | no question; protected |
| 14 | Subif/SVI number = tag | `subif_policy` rename with in-config refs; cross-config refs via `to <node>: <if>` pattern or warning |
| 15 | NX-OS VLAN range lists | VlanList, style-preserving, collision checks |
| 16 | L2 pass-through (BGW, IOL access to mgmt0/F5) | l2trace, PROVEN |
| 17 | IOL trunk without allowed list; **implicit VLANs** (backbone dmvpn) | trunk = ALL of `vlan_db` including implicit VLANs |
| 18 | Uncabled configured ports | switch VLAN-domain rule, CORRELATED, `uncabled` badge |
| 19 | Startup vs configset disagree; nodes absent from configset | per-scope trace and schemes; each store edited independently; startup fallback |
| 20 | Multiple schemes (backbone S1/S2/S3) | scheme matrix; canonical scope; legacy policy default `leave` (warning lists untouched scopes) |
| 21 | Outliers / pre-existing bugs | excluded by default, `--include-outliers`; never "fixed" |
| 22 | Sidecar dir ≠ stem; ambiguous dirs | `<stem>*_cfgs`; manifest `sidecar_dirs`; ambiguity = blocker |
| 23 | Sidecar id reused in another lab / name mismatch | id **and** name guard; skip with warning; `[sidecar_map]` override |
| 24 | Sidecar mirrors | mirror detection, replicated edits, equality assertion |
| 25 | Sidecar-only values (Forti/F5) | sidecars are first-class stores; post-apply "re-paste to devices" note |
| 26 | UTF-8 em dash, CRLF/LF, trailing spaces, leading/missing newline, `^C`, text after `end` | byte-exact span splices; newline style recorded |
| 27 | Non-canonical base64 | read-only blob; edits blocked |
| 28 | Stray `<objects/>`, huge task PDF, attribute order | ET read-only; raw splicing; skip regions; outside-span byte check |
| 29 | Garbage or empty blobs | opaque; info finding |
| 30 | Spliced syslog / truncated headers | tolerant blocks; orphan facts CORRELATED by value; badge |
| 31 | Node name ≠ role/hostname | dialect from template/image/content; config by node id |
| 32 | IP prefix substrings, cert hex | boundary tokenizer + `ipaddress` validation |
| 33 | Mask forms, prefix change | adjacent mask token rewritten in its own form |
| 34 | Supernet / home routes | `site_routes` list question; deletion only where the dialect supports it |
| 35 | /20 as two /24s (junos) | broadest prefix; offset map; **split map** or host overrides when it doesn't fit |
| 36 | Gateway .1 vs .254 | separate question, default same offset |
| 37 | Same host octet across segments | maps per segment subnet, never by last octet |
| 38 | Router-id / peers derived from external IPs | CORRELATED members rewritten, listed as "derived" |
| 39 | Two segments on one untagged pnet (azure) | bridge question per segment; warning if they stay shared with different subnets |
| 40 | Moving one segment off a shared trunk (sdwan INET) | allowed with the tag unchanged; untagged-only target = blocker |
| 41 | Domain substrings; three domain syntaxes | anchored rules + `domain_re`; one question per domain |
| 42 | `name servers` VLAN name | anchored DNS keywords only |
| 43 | Public-looking internal IPs; 1.1.1.0/30 labels | only proven-subnet members or anchored services; protected inventory |
| 44 | 169.254 APIPA external vs internal | `azure_s2s` scoped to Tunnel1 /30 + its routes; others protected |
| 45 | Peer IP used as object name | `azure_s2s` exact claim, ASAv-1 only |
| 46 | Committed real secret | redacted; placeholder option; rotation + history note |
| 47 | Cryptochecksum, timestamps, UDI, PKI, call-home | no rule matches; info for the checksum |
| 48 | Upstream eBGP instead of a default route | `bgp_upstream` scenario (peer IP, AS, prefixes; community recomputed if the local AS changes) |
| 49 | Internal prefix exported upstream (172.31.255.0/24) | overlap warning; advanced question |
| 50 | Generic labels vs policy names (`INTERNET-ONLY`) | distinctiveness rule: XML name only |
| 51 | `pnet0` in text; alias across segments | cosmetic cloud_ref group; ambiguous aliases skipped |
| 52 | `(VLAN 3)`, "reserve .31" free text | label-line-scoped cosmetic edits; under non-offset maps rewritten or warned |
| 53 | Cross-config references to renamed subifs | `to <node>: <if>` rewrite or `LEAK` warning |
| 54 | Collision with addresses in use at the target site / DHCP pools | profile `reserved` / `dhcp_pool` per segment → warnings |
| 55 | Lab-internal overlap with target subnets (lab1 172.16/16, 10/8 deny lists) | protected inventory → conflict, or warning for prefix-list-only |
| 56 | Running lab | process-based detection; leftover tmp dir = info "not wiped" |
| 57 | Lab open in UI (EVE overwrites on save) | warnings; `check` detects "reverted by EVE?"; `--out` copy mode |
| 58 | `config="0"` / active configset mismatch | notice per node; next-steps list wipes; `scan` shows which scope each node boots from (pointers not auto-changed: EVE UI decision) |
| 59 | Thumbnails stale | notice |
| 60 | Ownership `www-data`, mode | chmod/chown to the original on the temp file; `--fix-perms` |
| 61 | Re-runs, partial localization | current→target planning; tri-state; 0-edit re-plan |
| 62 | File changed between plan and apply | sha precondition blocker |
| 63 | Unique `<lab id>` | never edited in place; `--out` makes a uuid4; check-labs over the repo |
| 64 | `git pull` after localizing; contributing back | `revert → pull → apply`; CI enforces baseline; `--out` alternative |
| 65 | Cross-lab "same real network" vs "same name" | explicit `site_key` bindings in manifests; value-match suggestions are never auto-applied |
| 66 | Cloner's own new labs (values ≠ author baseline) | discovery works on any values; `discover --baseline-from-answers` |
| 67 | Unknown future vendor | generic dialect (CORRELATED IPv4 + label tokens, no tags) + finding; add a rule pack |
| 68 | Unknown future EVE XML layout | ET cross-check → read-only |
| 69 | IPv6 literals | `IPV6_UNHANDLED` findings; not rewritten |
| 70 | EVE trunk attrs (`native_vlan`, `vlan8021ad`) | displayed; warning if profile `bridges.*.native_vlan` differs; not edited |
| 71 | Platform VLAN limits | IOS/NX-OS reserved ranges validated; Forti/Junos/F5 at 1-4094; host bridge VLAN filtering not checkable → `--check-host` info (`bridge vlan show` if present) |
| 72 | Image / template availability | out of scope; `scan --images` lists missing images on the EVE host |
| 73 | Windows / non-POSIX | O_EXCL lock fallback; chown/sys probes skipped; paths via pathlib |
| 74 | Machine-readable prompting | `scan --json` question schema + `--answers --non-interactive` |
| 75 | Sidecar node-id drift after re-adding nodes | id+name guard reports a mismatch; `[sidecar_map]` in the manifest re-maps |

---

## 16. Implementation tasks (ordered, parallelizable)

Rules for implementors:

- `model.py`, `errors.py` and section 3.2 are the frozen contract. Changing them requires updating this doc in the same
  PR.
- Each task owns only its listed files plus its tests.
- Stdlib only. ruff + black. Python 3.11.
- Every task ships unit tests under `python/tests/localize/`.

| ID | Task | Owns | Depends on | Notes |
|---|---|---|---|---|
| **T1** | Contracts | `evelocal/__init__.py` (now `evelab/localize/`), `errors.py`, `model.py`, `eve-localize` shim, `python/tests/localize/__init__.py` | — | Exactly as in section 4. Small, done first. |
| **T2** | Text utilities | `textutil.py`, `test_textutil.py` | T1 | IPv4/IPv6, masks, VlanList, token/domain regexes, HTML text regions |
| **T3** | RawLab + codec | `unl.py`, `codec.py`, `test_unl.py`, `test_codec.py`, `fixtures/minilabs/*` | T1 | span index, ET cross-check, splice, round-trip on all real labs |
| **T4** | TOML + manifest + profile | `tomlw.py`, `manifest.py` (load/validate/schema), `profile.py`, tests | T1 | `generate()`/`check()` bodies are completed in T15 |
| **T5** | Dialect framework | `dialects/__init__.py`, `dialects/base.py`, `dialects/blocks.py`, `test_dialect_contract.py` | T1, T2 | RuleDialect, PatternRule, TOML pack loader, `--plugins` loader, contract test harness |
| **T6** | UI | `ui.py`, tests | T1 | prompts, tables, pager, decoded diff, redaction |
| **T7** | Host env | `hostenv.py`, tests (fake /proc, /sys) | T1 | bridges, running nodes, tmp leftovers, images, lock helpers |
| **T8** | Stores | `stores.py`, `test_stores.py` | T3, T5 (pick) | embedded + sidecar, id+name guard, mirrors, newline style |
| **T9** | Cisco dialects | `dialects/ios.py`, `iosxe.py`, `nxos.py`, `fixtures/snippets/{ios,iosxe,nxos}` | T5 | incl. IOL L2, implicit vlan_db, orphan blocks |
| **T10** | ASA / Forti / F5 dialects | `dialects/asa.py`, `fortios.py`, `f5tmsh.py`, fixtures | T5 | Forti parent resolution, stanza deletion support flag |
| **T11** | Junos / linux / vpcs / html / generic | `dialects/junos.py`, `linuxsh.py`, `vpcs.py`, `eve_html.py`, `generic.py`, fixtures | T5 | brace parser override for Junos |
| **T12** | Apply engine | `apply.py`, `test_apply.py` | T3, T7 | preflight, backup, atomic write, owner/mode, validate (spans, counts, check-labs via importlib), journal, state, undo. Re-scan hook injected as a callable. |
| **T13** | Topology + L2 trace | `discover/topology.py`, `discover/l2trace.py`, `test_l2trace.py` | T8, T9 (minilab tests use IOS/NX-OS) | per-scope BFS, VLAN-domain rule, orphan attribution |
| **T14** | Segments + names + inventory + analyse | `discover/segments.py`, `names.py`, `inventory.py`, `discover/__init__.py`, `test_segments.py` | T13, T4 (manifest pins) | merge rules, schemes, outliers, status, correlation, protected inventory |
| **T15** | Manifest generation/check | `manifest.py` (`generate`, `check`), `test_manifest_check.py` | T14, T4 | expect counts, leak scan, baseline check, unpinned status |
| **T16** | Core scenarios | `scenarios/__init__.py`, `base.py`, `bridge.py`, `segment_l2.py`, `segment_l3.py`, `labels.py` | T14, T2 | questions + plan fragments; PARAM_KINDS registry |
| **T17** | Extra scenarios | `scenarios/services.py`, `site_routes.py`, `bgp_upstream.py`, `azure_s2s.py`, `secrets.py` | T14 (can stub-test with T16's base) | |
| **T18** | Planner | `planner.py`, `test_planner.py` | T16 (base only), T2 | ValueMaps, claims, single pass, conflicts/blockers, explain, plan JSON |
| **T19** | CLI | `cli.py`, `test_cli.py` | T6, T12, T15, T16, T17, T18 | commands, picker, `--all` carry-forward, `--json` question schema, `--out`, exit codes |
| **T20** | Real-lab manifests + example profile | `labs/**/*.localize.toml` (7 files), `localize/site.example.toml`, `localize/README.md` | T15, T19 | generated with `discover --write`, then author decisions applied per section 8.3 |
| **T21** | Goldens + round-trip | `golden/*.scan.json`, `golden/*.answers.toml`, `test_labs_golden.py`, `test_roundtrip.py` | T19, T20 | the acceptance suite (section 14, items 7-8) |
| **T22** | Repo wiring | `Makefile` (non-managed section), `.gitignore`, README/AGENTS mention | T19 | `make test` includes localize-test + localize-check |
| **T23** *(optional, later)* | First structural transform | `transforms/__init__.py`, `transforms/ios_dhcp_to_static.py` | T18 | proves the extension point (nexus ISP-CE, lab1 R27) |

**Parallel waves**

| Wave | Tasks |
|---|---|
| 0 | T1 |
| 1 | T2, T3, T4, T6, T7 (parallel); T5 starts when T2 lands |
| 2 | T8, T9, T10, T11, T12 (parallel) |
| 3 | T13, then T14 |
| 4 | T15, T16, T17, T18 (parallel; T18 needs only `scenarios/base.py` from T16, so T16 lands that file first) |
| 5 | T19 |
| 6 | T20, then T21; T22 alongside |
| 7 | T23 (optional) |

**Shared fixtures**: `fixtures/minilabs/` (from T3) is used by T8, T12, T13 and T14. Minilabs are stored as
`<stem>.unl.fixture` (never `*.unl`, because this repo is EVE's live labs tree and the web UI would list them); tests load
them through `tests/localize/labfiles.py` (`minilab_path()` / `minilab()`), which copies them and their `*_cfgs` sidecars into
a temp dir as `<stem>.unl`. Each dialect task owns its
`fixtures/snippets/<dialect>/` directory. Golden files are written only by T21.

**Definition of done (whole feature)**:

- `make test` passes: check-labs, unit tests, `localize-check --strict` over all labs.
- The golden round-trip yields byte-identical files for all 7 labs with clouds.
- The two no-cloud labs produce zero diff.
- `make lint` is clean.
