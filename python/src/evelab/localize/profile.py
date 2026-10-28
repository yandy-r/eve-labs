"""Site profile and answers files (design section 9).

One file format serves both: ``.localize/site.toml`` (the profile) and an answers
file written by ``--save-answers``. ``Answers`` is therefore an alias of
``Profile``.

Merge order (``load_profile``): files are applied in the order given, later files
win. Tables merge key by key; scalars and arrays are replaced (so
``site_routes."x" = []`` really clears a list). The CLI passes
``[site.toml, --profile FILE, --answers FILE]``.

Answer resolution order for one segment value (section 9) is: interactive answer,
``segment_answer()`` with the ``[labs."<lab_id>"]`` override on top of
``[segments."<site_key>"]``, a value-map match, ``role_bridge()``, keep. This module
supplies steps 2, 3 and 5 plus the value-map lookup; the planner owns the rest.

Secrets: ``[secrets]`` entries are ``{ env = "VAR" }`` references. The env var is
read at use time. An inline ``value`` (typed at a ``getpass`` prompt) is never
written by ``save_answers`` unless ``include_secrets`` is true, in which case the
file is created with mode 0600.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import TypeAlias

from evelab.common import tomlw
from evelab.common.tomlschema import TableReader, parse_address, parse_network
from evelab.common.tomlw import TomlValue

from .errors import LocalizeError
from .manifest import LEGACY_POLICIES, ROLES, SUBIF_POLICIES

SCHEMA = 1
BRIDGE_MODES: tuple[str, ...] = ("trunk", "untagged-only")
BUILTIN_BRIDGE = re.compile(r"(pnet\d+|nat\d+|cloud\d+)")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
_KIND = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_ENV_VAR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_HEADER = "eve-localize site answers (generated; edit freely)"


class ProfileError(LocalizeError):
    """A profile or answers file is unreadable, malformed or inconsistent."""

    code = "PROFILE"


# -- schema ---------------------------------------------------------------------


@dataclass
class BridgeProfile:
    """What the user's EVE host does with one cloud bridge (``[bridges.<name>]``)."""

    roles: list[str] = field(default_factory=list)
    mode: str = "trunk"  # "trunk" | "untagged-only"
    native_vlan: int | None = None


@dataclass
class SegmentAnswer:
    """Target values for one segment. ``None`` means "no answer given"."""

    bridge: str | None = None
    vlan: int | None = None
    subnet: IPv4Network | None = None
    gateway: IPv4Address | None = None
    label: str | None = None
    reserved: list[str] | None = None  # site addresses in use: "a-b", CIDR or single IP
    dhcp_pool: str | None = None  # "a-b" or CIDR
    split: dict[IPv4Network, IPv4Network] | None = None  # old subnet -> new subnet
    hosts: dict[IPv4Address, IPv4Address] | None = None  # explicit host overrides
    skip: bool | None = None  # the user skipped this segment (prompt key "s")

    def merged_over(self, base: SegmentAnswer) -> SegmentAnswer:
        """``self`` wins field by field; unset fields fall through to ``base``."""
        merged = SegmentAnswer()
        for name in SegmentAnswer.__dataclass_fields__:
            mine = getattr(self, name)
            setattr(merged, name, mine if mine is not None else getattr(base, name))
        return merged


@dataclass
class ScenarioAnswer:
    enabled: bool | None = None
    options: dict[str, TomlValue] = field(default_factory=dict)


@dataclass
class SecretRef:
    """A secret supplied by environment variable and/or an in-memory value."""

    env: str | None = None
    value: str | None = field(default=None, repr=False)

    def resolve(self, environ: Mapping[str, str] | None = None) -> str | None:
        """The env var wins when set and non-empty, else the inline value."""
        source = os.environ if environ is None else environ
        if self.env and (found := source.get(self.env)):
            return found
        return self.value


@dataclass
class Policy:
    cosmetic_text: bool = True
    include_heuristic: bool = False
    legacy_scopes: str = "leave"  # leave | ask | same
    subif_policy: str = "rename"  # rename | keep-name


@dataclass
class LabOverride:
    """``[labs."<lab_id>"]``: answers that apply to one lab only."""

    segments: dict[str, SegmentAnswer] = field(default_factory=dict)  # by segment key
    scenarios: dict[str, ScenarioAnswer] = field(default_factory=dict)


@dataclass
class Profile:
    schema: int = SCHEMA
    site: str = ""
    bridges: dict[str, BridgeProfile] = field(default_factory=dict)
    roles: dict[str, str] = field(default_factory=dict)  # role -> bridge name
    segments: dict[str, SegmentAnswer] = field(default_factory=dict)  # by site_key
    maps: dict[str, dict[str, str]] = field(default_factory=dict)  # [map.<kind>]
    site_routes: dict[str, list[IPv4Network]] = field(default_factory=dict)
    scenarios: dict[str, ScenarioAnswer] = field(default_factory=dict)
    secrets: dict[str, SecretRef] = field(default_factory=dict)
    policy: Policy = field(default_factory=Policy)
    labs: dict[str, LabOverride] = field(default_factory=dict)
    sources: list[Path] = field(default_factory=list, compare=False)

    def segment_answer(
        self, site_key: str, lab_id: str | None = None, segment_key: str | None = None
    ) -> SegmentAnswer:
        """Resolution steps 2 and 3: the lab override over the ``site_key`` entry."""
        base = self.segments.get(site_key, SegmentAnswer())
        if lab_id is not None and segment_key is not None:
            lab = self.labs.get(lab_id)
            if lab is not None and segment_key in lab.segments:
                return lab.segments[segment_key].merged_over(base)
        return base

    def role_bridge(self, role: str | None) -> str | None:
        """Resolution step 5: the default bridge for a segment role."""
        return None if role is None else self.roles.get(role)

    def map_value(self, kind: str, old: str) -> str | None:
        """Resolution step 4: the ``[map.<kind>]`` entry for ``old``, if any."""
        return self.maps.get(kind, {}).get(old)

    def scenario_enabled(
        self, scenario_id: str, lab_id: str | None = None
    ) -> bool | None:
        """Lab override, then global answer; ``None`` when never answered."""
        if lab_id is not None:
            lab = self.labs.get(lab_id)
            if lab is not None and scenario_id in lab.scenarios:
                answer = lab.scenarios[scenario_id].enabled
                if answer is not None:
                    return answer
        answer_global = self.scenarios.get(scenario_id)
        return None if answer_global is None else answer_global.enabled

    def secret_value(
        self, name: str, environ: Mapping[str, str] | None = None
    ) -> str | None:
        ref = self.secrets.get(name)
        return None if ref is None else ref.resolve(environ)

    def bridge_allowed(self, name: str) -> bool:
        """Built-in bridge name or declared in ``[bridges]``."""
        return bool(BUILTIN_BRIDGE.fullmatch(name)) or name in self.bridges


Answers: TypeAlias = Profile


def parse_ip_range(text: str) -> tuple[IPv4Address, IPv4Address]:
    """``"a-b"``, ``"a.b.c.d/n"`` or ``"a.b.c.d"`` -> inclusive (first, last)."""
    try:
        if "-" in text:
            first_s, last_s = (part.strip() for part in text.split("-", 1))
            first, last = IPv4Address(first_s), IPv4Address(last_s)
        elif "/" in text:
            net = IPv4Network(text, strict=True)
            first, last = net[0], net[-1]
        else:
            first = last = IPv4Address(text.strip())
    except ValueError as exc:
        raise ValueError(f"invalid address range {text!r}: {exc}") from exc
    if last < first:
        raise ValueError(f"address range {text!r} ends before it starts")
    return first, last


# -- loading ---------------------------------------------------------------------


def load_profile(paths: list[Path]) -> Profile:
    """Merge profile/answers files in order (later wins). ``[]`` gives an empty profile.

    Every file is validated on its own (unknown keys are errors); cross references
    (role/segment bridges) are checked on the merged result. A missing file is an
    error: callers decide whether a default path exists before passing it.
    """
    merged: dict[str, TomlValue] = {}
    for path in paths:
        raw = _read(Path(path))
        _build(raw, str(path), check_refs=False)
        _deep_merge(merged, raw)
    profile = _build(merged, "profile", check_refs=True)
    profile.sources = [Path(p) for p in paths]
    return profile


def load_answers(path: Path) -> Answers:
    """Load one answers file (same format as a profile)."""
    return load_profile([path])


def _read(path: Path) -> dict[str, TomlValue]:
    try:
        with path.open("rb") as handle:
            return dict(tomllib.load(handle))
    except OSError as exc:
        raise ProfileError(f"{path}: cannot read profile: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ProfileError(f"{path}: invalid TOML: {exc}") from exc


def _deep_merge(base: dict[str, TomlValue], extra: Mapping[str, TomlValue]) -> None:
    for key, value in extra.items():
        current = base.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            _deep_merge(current, value)
        elif isinstance(value, dict):
            copy: dict[str, TomlValue] = {}
            _deep_merge(copy, value)
            base[key] = copy
        else:
            base[key] = value


def _build(data: object, source: str, *, check_refs: bool) -> Profile:
    root = TableReader(data, "", ProfileError, source)
    profile = Profile(
        schema=SCHEMA,
        site=root.opt_str("site", "") or "",
    )
    schema = root.opt_int("schema", SCHEMA)
    if schema != SCHEMA:
        raise root.fail("schema", f"must be {SCHEMA}, got {schema!r}")
    profile.bridges = _bridges(root)
    profile.roles = _roles(root)
    profile.segments = _segments(root.table("segments"))
    profile.maps = _maps(root)
    profile.site_routes = _site_routes(root)
    profile.scenarios = _scenarios(root.table("scenarios"))
    profile.secrets = _secrets(root, source)
    profile.policy = _policy(root.table("policy"))
    profile.labs = _labs(root)
    root.done()
    if check_refs:
        _check_refs(profile, source)
    return profile


def _name(reader: TableReader, key: str, value: str) -> str:
    if not _NAME.fullmatch(value):
        raise reader.fail(key, f"{value!r} is not a valid name")
    return value


def _bridges(root: TableReader) -> dict[str, BridgeProfile]:
    out: dict[str, BridgeProfile] = {}
    for name, table in root.subtables("bridges").items():
        _name(root, f"bridges.{name}", name)
        mode = table.opt_str("mode", "trunk", choices=BRIDGE_MODES) or "trunk"
        out[name] = BridgeProfile(
            roles=table.str_list("roles"),
            mode=mode,
            native_vlan=table.opt_int("native_vlan", minimum=1, maximum=4094),
        )
        for role in out[name].roles:
            if role not in ROLES:
                raise table.fail("roles", f"{role!r} is not one of {list(ROLES)}")
        table.done()
    return out


def _roles(root: TableReader) -> dict[str, str]:
    out = root.str_map("roles")
    for role, bridge in out.items():
        if role not in ROLES:
            raise root.fail(f"roles.{role}", f"unknown role (valid: {list(ROLES)})")
        _name(root, f"roles.{role}", bridge)
    return out


def _segment_answer(t: TableReader) -> SegmentAnswer:
    answer = SegmentAnswer()
    bridge = t.opt_str("bridge")
    if bridge is not None:
        answer.bridge = _name(t, "bridge", bridge)
    answer.vlan = t.opt_int("vlan", minimum=1, maximum=4094)
    if (subnet := t.opt_str("subnet")) is not None:
        answer.subnet = parse_network(t, "subnet", subnet)
    if (gateway := t.opt_str("gateway")) is not None:
        answer.gateway = parse_address(t, "gateway", gateway)
    if (label := t.opt_str("label")) is not None:
        if not label or not label.isprintable() or len(label) > 64:
            raise t.fail("label", "must be 1-64 printable characters")
        answer.label = label
    if t.has("reserved"):
        answer.reserved = t.str_list("reserved")
        for entry in answer.reserved:
            _range(t, "reserved", entry)
    if (pool := t.opt_str("dhcp_pool")) is not None:
        _range(t, "dhcp_pool", pool)
        answer.dhcp_pool = pool
    if t.has("split"):
        answer.split = {
            parse_network(t, "split", old): parse_network(t, "split", new)
            for old, new in t.str_map("split").items()
        }
    if t.has("hosts"):
        answer.hosts = {
            parse_address(t, "hosts", old): parse_address(t, "hosts", new)
            for old, new in t.str_map("hosts").items()
        }
    if t.has("skip"):
        answer.skip = t.opt_bool("skip", False)
    if (
        answer.subnet is not None
        and answer.gateway is not None
        and answer.gateway not in answer.subnet
    ):
        raise t.fail("gateway", f"{answer.gateway} is outside {answer.subnet}")
    t.done()
    return answer


def _range(t: TableReader, key: str, text: str) -> None:
    try:
        parse_ip_range(text)
    except ValueError as exc:
        raise t.fail(key, str(exc)) from exc


def _segments(table: TableReader | None) -> dict[str, SegmentAnswer]:
    if table is None:
        return {}
    out = {name: _segment_answer(t) for name, t in _each(table)}
    table.done()
    return out


def _each(table: TableReader) -> list[tuple[str, TableReader]]:
    return [
        (name, table.require_table(name))
        for name in table.keys()  # noqa: SIM118 - TableReader.keys()
    ]


def _maps(root: TableReader) -> dict[str, dict[str, str]]:
    table = root.table("map")
    if table is None:
        return {}
    out: dict[str, dict[str, str]] = {}
    for kind in table.keys():  # noqa: SIM118 - TableReader.keys(), not dict.keys()
        if not _KIND.fullmatch(kind):
            raise table.fail(kind, "map kind must be an identifier")
        out[kind] = table.str_map(kind)
    table.done()
    return out


def _site_routes(root: TableReader) -> dict[str, list[IPv4Network]]:
    table = root.table("site_routes")
    if table is None:
        return {}
    out = {
        site_key: [
            parse_network(table, site_key, text) for text in table.str_list(site_key)
        ]
        for site_key in table.keys()  # noqa: SIM118 - TableReader.keys()
    }
    table.done()
    return out


def _scenarios(table: TableReader | None) -> dict[str, ScenarioAnswer]:
    if table is None:
        return {}
    out: dict[str, ScenarioAnswer] = {}
    for name, t in _each(table):
        if not _NAME.fullmatch(name):
            raise table.fail(name, "not a valid scenario id")
        enabled = t.opt_bool("enabled", True) if t.has("enabled") else None
        out[name] = ScenarioAnswer(enabled=enabled, options=t.rest())
        t.done()
    table.done()
    return out


def _secrets(root: TableReader, source: str) -> dict[str, SecretRef]:
    table = root.table("secrets")
    if table is None:
        return {}
    out: dict[str, SecretRef] = {}
    for name in table.keys():  # noqa: SIM118 - TableReader.keys(), not dict.keys()
        raw = table.raw(name)
        if isinstance(raw, str):
            out[name] = SecretRef(value=raw)
            continue
        ref = TableReader(raw, f"secrets.{name}", ProfileError, source)
        env = ref.opt_str("env")
        if env is not None and not _ENV_VAR.fullmatch(env):
            raise ref.fail("env", f"{env!r} is not a valid environment variable name")
        out[name] = SecretRef(env=env, value=ref.opt_str("value"))
        ref.done()
    table.done()
    return out


def _policy(table: TableReader | None) -> Policy:
    policy = Policy()
    if table is None:
        return policy
    policy.cosmetic_text = table.opt_bool("cosmetic_text", policy.cosmetic_text)
    policy.include_heuristic = table.opt_bool(
        "include_heuristic", policy.include_heuristic
    )
    policy.legacy_scopes = (
        table.opt_str("legacy_scopes", policy.legacy_scopes, choices=LEGACY_POLICIES)
        or policy.legacy_scopes
    )
    policy.subif_policy = (
        table.opt_str("subif_policy", policy.subif_policy, choices=SUBIF_POLICIES)
        or policy.subif_policy
    )
    table.done()
    return policy


def _labs(root: TableReader) -> dict[str, LabOverride]:
    out: dict[str, LabOverride] = {}
    for lab_id, table in root.subtables("labs").items():
        out[lab_id] = LabOverride(
            segments=_segments(table.table("segments")),
            scenarios=_scenarios(table.table("scenarios")),
        )
        table.done()
    return out


def _check_refs(profile: Profile, source: str) -> None:
    def bad(where: str, bridge: str) -> ProfileError:
        return ProfileError(
            f"{source}: {where}: bridge {bridge!r} is neither a built-in bridge "
            "(pnetN, natN, cloudN) nor declared in [bridges]"
        )

    for role, bridge in profile.roles.items():
        if not profile.bridge_allowed(bridge):
            raise bad(f"roles.{role}", bridge)
    for site_key, answer in profile.segments.items():
        if answer.bridge is not None and not profile.bridge_allowed(answer.bridge):
            raise bad(f'segments."{site_key}".bridge', answer.bridge)
    for lab_id, lab in profile.labs.items():
        for key, answer in lab.segments.items():
            if answer.bridge is not None and not profile.bridge_allowed(answer.bridge):
                raise bad(f'labs."{lab_id}".segments."{key}".bridge', answer.bridge)


# -- saving ----------------------------------------------------------------------


def _segment_dict(a: SegmentAnswer) -> dict[str, TomlValue]:
    out: dict[str, TomlValue] = {}
    if a.bridge is not None:
        out["bridge"] = a.bridge
    if a.vlan is not None:
        out["vlan"] = a.vlan
    if a.subnet is not None:
        out["subnet"] = str(a.subnet)
    if a.gateway is not None:
        out["gateway"] = str(a.gateway)
    if a.label is not None:
        out["label"] = a.label
    if a.reserved is not None:
        out["reserved"] = list(a.reserved)
    if a.dhcp_pool is not None:
        out["dhcp_pool"] = a.dhcp_pool
    if a.split is not None:
        out["split"] = {str(old): str(new) for old, new in a.split.items()}
    if a.hosts is not None:
        out["hosts"] = {str(old): str(new) for old, new in a.hosts.items()}
    if a.skip is not None:
        out["skip"] = a.skip
    return out


def _scenario_dict(a: ScenarioAnswer) -> dict[str, TomlValue]:
    out: dict[str, TomlValue] = {}
    if a.enabled is not None:
        out["enabled"] = a.enabled
    out.update(a.options)
    return out


def to_dict(profile: Profile, *, include_secrets: bool = False) -> dict[str, TomlValue]:
    """Profile as plain TOML data; inline secrets only with ``include_secrets``."""
    out: dict[str, TomlValue] = {"schema": profile.schema}
    if profile.site:
        out["site"] = profile.site
    if profile.bridges:
        bridges: dict[str, TomlValue] = {}
        for name, bridge in profile.bridges.items():
            entry: dict[str, TomlValue] = {"roles": list(bridge.roles)}
            entry["mode"] = bridge.mode
            if bridge.native_vlan is not None:
                entry["native_vlan"] = bridge.native_vlan
            bridges[name] = entry
        out["bridges"] = bridges
    if profile.roles:
        out["roles"] = dict(profile.roles)
    if profile.segments:
        out["segments"] = {k: _segment_dict(v) for k, v in profile.segments.items()}
    if profile.maps:
        out["map"] = {kind: dict(m) for kind, m in profile.maps.items()}
    if profile.site_routes:
        out["site_routes"] = {
            k: [str(n) for n in nets] for k, nets in profile.site_routes.items()
        }
    if profile.scenarios:
        out["scenarios"] = {k: _scenario_dict(v) for k, v in profile.scenarios.items()}
    secrets: dict[str, TomlValue] = {}
    for name, ref in profile.secrets.items():
        entry = {}
        if ref.env is not None:
            entry["env"] = ref.env
        if include_secrets and ref.value is not None:
            entry["value"] = ref.value
        if entry:
            secrets[name] = entry
    if secrets:
        out["secrets"] = secrets
    default = Policy()
    policy: dict[str, TomlValue] = {}
    for name in Policy.__dataclass_fields__:
        value = getattr(profile.policy, name)
        if value != getattr(default, name):
            policy[name] = value
    if policy:
        out["policy"] = policy
    if profile.labs:
        labs: dict[str, TomlValue] = {}
        for lab_id, lab in profile.labs.items():
            lab_entry: dict[str, TomlValue] = {}
            if lab.segments:
                lab_entry["segments"] = {
                    k: _segment_dict(v) for k, v in lab.segments.items()
                }
            if lab.scenarios:
                lab_entry["scenarios"] = {
                    k: _scenario_dict(v) for k, v in lab.scenarios.items()
                }
            labs[lab_id] = lab_entry
        out["labs"] = labs
    return out


def dumps(profile: Profile, *, include_secrets: bool = False) -> str:
    """TOML text for ``profile`` (re-parse verified)."""
    return tomlw.dumps(
        to_dict(profile, include_secrets=include_secrets), header=_HEADER
    )


def save_answers(path: Path, ans: Answers, include_secrets: bool = False) -> None:
    """Write ``ans`` to ``path`` through ``tomlw`` (atomic, re-parse verified).

    Secrets are written as ``{ env = "VAR" }`` references only. Inline secret values
    are dropped unless ``include_secrets`` is true; then they are written and the
    file is restricted to mode 0600.
    """
    data = to_dict(ans, include_secrets=include_secrets)
    has_inline = include_secrets and any(
        r.value is not None for r in ans.secrets.values()
    )
    tomlw.dump(Path(path), data, header=_HEADER, mode=0o600 if has_inline else None)
