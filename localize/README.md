# eve-localize: run these labs on your own EVE host

The labs in this repository were built on one EVE-NG host. Their cloud networks, VLAN tags,
management subnets, gateways, network labels, DNS/NTP servers and domains are that host's values.
`scripts/eve-localize` rewrites them for your site, both in the `.unl` files and in the
device configs inside them (startup configs, config sets, `<lab>_cfgs/` sidecars and canvas text).
It can also put everything back.

What it never does: invent topology, add or delete nodes, touch internal bridges, or change
addresses that are not on a cloud-facing segment (simulated internets, loopbacks, P2P links). Each
change is attributed to evidence (cabling, VLAN trace, config facts) and shown before it is written.

Python 3.11+ standard library only. Run it on the EVE host, as the user that owns the labs tree
(usually `root`), from the repository root.

## Quick start

```bash
cd /opt/unetlab/labs
./scripts/eve-localize scan --list          # which labs have cloud segments, pinned or not
./scripts/eve-localize                      # interactive: pick labs -> questions -> review -> apply
```

Close the lab in the EVE web UI and stop its nodes first: EVE rewrites the `.unl` on save and would
overwrite the localized file. After applying, wipe the affected nodes in EVE so they boot the new
startup configs, and re-paste sidecar configs (FortiGate, F5) into the devices.

To keep the repository clean instead, write localized copies with a new lab id somewhere else:

```bash
./scripts/eve-localize --lab sdwan --out /opt/unetlab/labs/Users/me/
```

## Files

| Path                                   | What it is                                                   |
| -------------------------------------- | ------------------------------------------------------------ |
| `labs/**/<lab>.localize.toml`          | Committed manifest: segments, baselines, counts, author pins |
| `localize/site.example.toml`           | Generated example site profile (the repository baseline)     |
| `.localize/site.toml`                  | Your answers (gitignored). Used by default when it exists    |
| `.localize/state.json`, `journal.json` | What is localized now, and every run (gitignored)            |
| `.localize/backups/<run-id>/`          | Byte copies taken before each write (gitignored)             |
| `scripts/eve-localize`                 | Shim: runs the tool straight from a checkout                 |
| `python/src/evelab/localize/`          | The tool (shared code: `python/src/evelab/common/`)          |

Labs without cloud networks need no manifest and are reported as `no clouds`.

## The interactive flow

1. **Lab picker.** Labs with cloud segments are listed with their status (`pinned` when a manifest
   matches the lab, `unpinned` otherwise).
2. **Segment matrix.** One row per external segment: clouds (`pnet0`, `nat0`, ...), tag, subnet,
   gateway, endpoint count and status. `CONFIGURABLE` segments have values to change; `DHCP` and
   `LABEL_ONLY` segments only get a bridge and a label; `CARRIER` segments are trunks.
3. **Questions.** Only questions backed by facts are asked: bridge, VLAN, subnet, gateway, label per
   segment, then services (DNS, NTP, domains, SLA probes), site routes and gated scenarios (BGP
   upstream, Azure S2S, secret placeholders). Keys at every prompt:
   - `Enter` accepts the default (from your profile, a value map, the role default or the current
     value);
   - `k` keeps the current value, `s` skips the segment, `?` shows the evidence, `b` goes back,
     `q` quits without writing.
     The bridge prompt also lists the cloud bridges present on this host with their state (`up`,
     `down`, `no-carrier`, `not on this host`); on an EVE host the plan warns
     (`BRIDGE_NOT_ON_HOST`, `BRIDGE_NO_CARRIER`) when a target bridge is missing or has no link.
     A `CARRIER` (trunk) is asked after the segments it carries and follows them by default. If they
     go to different bridges, or you put the trunk elsewhere, the plan reports `CARRIER_SPLIT`: a
     conflict while the trunk has no explicit answer, a warning once you answer it (the VLANs then
     live on several host bridges, which only works if those are joined outside EVE).
     Secrets are read with `getpass` and are never written to answer files unless you pass
     `--save-secrets`.
     Addressing answers are checked as you type: a subnet that overlaps another segment (baseline
     or already answered) is refused, the gateway default after a subnet change is always a host of
     the new subnet, and a split map must give every device a new address. If the plan still has
     conflicts or blockers that name segments, the tool asks `Revise the answers for ...?` and asks
     only those segments again, so you do not lose the other answers.
4. **Review.** A plan summary per lab, then a menu: `r` toggle edit groups, `d [filter]` decoded
   diff (XML attribute changes name the network and attribute, e.g. `[e1a2b3c4d5e6] network 3
'MGMT' type:`), `i [filter]` list the edits with their ids, `x ID` explain one edit (a unique id
   prefix is enough), `s FILE` save the plan, `a` apply, `n` skip this lab, `q` quit.
5. **Apply.** Preflight (running nodes, dirty git state, lock), backup, atomic write, validation
   (spans, counts, `check-labs`), journal. A failed validation rolls the lab back (exit 5).

Save your answers so the next run is non-interactive:

```bash
./scripts/eve-localize --save-answers .localize/site.toml
```

Start from the example profile if you prefer editing TOML: copy `localize/site.example.toml` to
`.localize/site.toml` and change only the values that differ at your site. The example holds the
repository baseline, so applying it unchanged is a no-op.

## Several labs at once: `--all`

```bash
./scripts/eve-localize --all                                   # interactive, answers carried lab to lab
./scripts/eve-localize plan --all --answers .localize/site.toml   # dry run, diff summary
./scripts/eve-localize apply --all --answers .localize/site.toml --yes
```

`--all` selects every tracked `*.unl`. One answers object is carried from lab to lab, so a segment
shared by several labs (same `site_key`) is answered once and offered as the default afterwards.
Add `--continue-on-error` to keep going past a failing lab. Unpinned labs are refused by
non-interactive writes unless you add `--allow-unpinned`.

## Replay: answers files and the question schema

Answers are keyed by **site_key** (segments) and by **old value** (services), so the same file
works for every lab and survives localization:

```toml
schema = 1
site = "my-homelab"

[segments."site.mgmt_a"]          # sdwan EVE-MGMT-203
bridge = "pnet1"
vlan = 20
subnet = "192.168.20.0/24"
gateway = "192.168.20.254"
label = "LAB-MGMT-20"

[map.dns]
"1.1.1.1" = "9.9.9.9"

[labs."2fd99c11-2334-45b3-ac61-ee23ab5c9d38".segments."INET-201"]   # one lab only
bridge = "pnet3"
```

Values from a profile, `.localize/site.toml` or a TOML answers file go through the same validators
as a typed answer, even when no prompt is shown: a gateway outside the subnet, on the network or
broadcast address, or on the new address of a device in the segment, an overlapping subnet or a
bad split map stops the run with `BAD_ANSWER` (exit 1, nothing written).

Network labels follow the same rule. A label must not be empty, must not start or end with a
blank, must not contain `< > & "` or control characters, and must be at most 64 characters long.
It must also fit every device field it is copied into. A FortiOS `set alias` holds at most 25
characters and an IOS/NX-OS `vlan N` / `name` holds at most 32 characters with no blanks.
Descriptions, aliases and comments that mention the old label only follow it when the new label
is one word of letters, digits, `_` and `-`, is at least 5 characters long, and contains a digit
or a `-` (for example `LAB-MGMT-20`). For any other label (`MGMTX`, `Mgmt B`) only the network
names change, and the plan warns `LABEL_TEXT_KEPT`. This keeps `revert` byte-identical. When you
leave the label unanswered but change the VLAN or subnet, the label follows its template
(`EVE-MGMT-203` becomes `EVE-MGMT-20`). It does so in `plan` and `apply`, with or without
`--yes`.

`[map.*]` entries may swap or chain values (`"1.1.1.1" = "1.0.0.1"` plus `"1.0.0.1" = "1.1.1.1"`):
every edit is computed from the original text. Service values inside the lab's protected ranges
(internal interface/loopback networks and the manifest `protect` list) are never asked and never
rewritten: a map entry for one is ignored with a `SERVICE_INTERNAL` warning.

For wrappers, `scan --json` prints every question (id, kind, choices, current value, default). Fill
in `"answer"` per question and replay it:

```bash
./scripts/eve-localize scan --lab sdwan --json > q.json      # edit q.json
./scripts/eve-localize apply --lab sdwan --answers q.json --non-interactive --strict
```

`--strict` makes unanswered questions fatal (exit 3). A JSON answer id that matches no question is
reported, with close matches (`did you mean azure.mgmt/subnet?`): a warning, or `BAD_ANSWER` (exit
1, nothing written) under `--strict`. Answers files are site-wide, so on a `--lab` run an id whose
prefix belongs to a segment or scenario of another lab in the repository is not reported. A TOML
`[segments."KEY"]` table that no lab and no manifest knows gets a warning. Exit codes: 0 ok, 1
error, 2 conflicts or blockers, 3 unanswered, 4 precondition failed, 5 validation failed (rolled
back).

`--lab PATH` is resolved against `--root` first. A path that resolves outside `--root` (from the
current directory, or absolute) is refused with `LAB_OUTSIDE_ROOT`, so the lab written and its
`state.json` / journal always belong to the same tree.

## Revert and undo

```bash
./scripts/eve-localize revert --all --yes   # back to the manifest baselines; works without backups
./scripts/eve-localize runs                 # journaled runs
./scripts/eve-localize undo                 # restore the last run's backups
./scripts/eve-localize undo 20261028T004326Z
```

- `revert` targets the baselines recorded in each manifest (and in `state.json`), including legacy
  schemes and each segment's cloud bridge (`[segment.baseline] bridge`), so bridges revert even
  without `.localize/state.json`. Localize then revert is expected to give byte-identical files (the test suite checks it).
- `undo` restores backups only if each file is still exactly what the run wrote. If EVE saved the
  lab in the meantime, it refuses; use `revert` or `git restore` instead.
- `apply` re-checks each file right before writing it. If EVE saved the lab while the tool was
  validating, the lab is refused with `SHA_DRIFT` (exit 4) and your EVE edit is kept; re-run.
- The journal and `state.json` are updated as each lab is written, so `undo` still works after a
  run that was interrupted part-way.
- `apply --plan FILE` records the lab's baseline like a normal apply, so `revert` can restore
  bridges afterwards. Service value maps (DNS, NTP, ...) applied from a saved plan are not
  recorded; they revert only where the manifest records the baseline value. If `state.json` has
  no baseline for a localized lab (written by an older version), `revert` warns and exits 1 -
  check `git diff` and use `git restore`.

## Upstream sync: revert, pull, re-apply

Committed labs must stay at the repository baseline (`make localize-check` enforces it), so pull
upstream changes on a baseline tree:

```bash
./scripts/eve-localize revert --all --yes
git pull --ff-only
./scripts/eve-localize apply --all --answers .localize/site.toml --yes
```

`make localize-sync` prints these steps. Re-applying is idempotent: a second run with the same
answers reports `0 edits`. Copy mode (`--out DIR`) avoids the dance entirely because the tracked
files never change. `DIR` must not be the lab's own folder (`OUT_IS_SOURCE`), copies land at
`DIR/<file name>` (two labs with the same file name in one run are refused with
`DEST_COLLISION`), and a lab already at the destination must not be running. New copies get the source lab's owner, group and mode when the tool runs as root (so EVE can
save copies under `Users/<name>/`); `--fix-perms` in copy mode runs `fix-lab-permissions.sh` on
the `--out` directory only. Always `revert` before contributing a lab change back.

## CI and checks

```bash
make localize-check   # eve-localize check --all --strict
make localize-test    # unit tests (python/tests)
make test             # check-labs + localize-test + localize-check
```

`check` compares every manifest with a fresh discovery: lab id, segment coverage, expected counts,
"at baseline" (or at the localized values recorded in `state.json`), leaks (old values no edit would
change), unpinned labs, and that `localize/site.example.toml` matches `profile --example`.
`--strict` turns warnings into failures.

## Onboarding a new lab

1. Build the lab in EVE and commit the `.unl`, plus `<stem>_cfgs/NN_<nodename>.txt` sidecars named
   exactly like the nodes.
2. `./scripts/eve-localize scan --lab new` and read the matrix and findings.
3. `./scripts/eve-localize discover --lab new --write` writes `new.localize.toml.draft` next to
   the lab. Review it:
   - set `site_key`s. Reuse an existing `site.*` key only when it is truly the same real network
     _and_ the baselines agree: the example profile is generated from the first lab that uses a key,
     and applying it must stay a no-op for every lab;
   - confirm hint merges with `[[merge]]` (`units` are cloud network names or carrier aliases such
     as `trunk:204`), pin `status` (`DHCP`, `LABEL_ONLY`), `[[outlier]]`s, `[[legacy]]` policies;
   - set `protect` (address ranges that must never change), `generic_labels`, `[scenarios.*]`,
     `[[param]]` names (`dns_public`, `domain_campus`, `mgmt_routes`, ...);
   - add `[[rule]]`s for one-off config lines no dialect reads but that hold segment values
     (`check` reports them as `LEAK`). Example from the sdwan manifest:

     ```toml
     [[rule]]
     id = "sdwan.nat_static_global"
     dialects = ["iosxe"]
     kind = "ip_host"
     pattern = '^ip nat inside source static IPV4 (?P<v>IPV4)(?: vrf \S+)?\s*$'
     ```

4. Rename it to `new.localize.toml`, run `discover --lab new --update` to fill the counts, then
   `make localize-check` and `./scripts/eve-localize profile --example`.
5. Add `python/tests/localize/golden/<stem>.answers.toml` (site B answers: change every bridge,
   VLAN, subnet, gateway and label), then run `UPDATE_GOLDEN=1 make localize-test` once to write
   `golden/<stem>.scan.json`, and `make localize-test`. No test list needs editing: the suites find
   every tracked `labs/**/*.unl` themselves and split them by "has cloud networks"
   (`tests/localize/labfiles.py`). A lab without these golden files is **skipped** with a message
   naming the files to add, so the suite stays green but the lab has no round-trip coverage until
   you add them. A lab without clouds needs no manifest, only the answers file (its round trip
   checks that nothing is written).
6. Commit: `feat(labs): add <lab> with localize manifest`.

After later edits in EVE: `discover --lab new --update` (on a reverted lab), review the diff, commit.
`--update` keeps author decisions and refreshes networks, baselines and counts; it rewrites the file,
so comments are not preserved. Check the `[segment.baseline] label` of segments whose networks have
different names: it must be the most common name, ties going to the lowest network id (the name the
label question uses), otherwise the example profile would rename a network.

## Adding a vendor dialect

The usual case is data only. Either a TOML pack (no Python), dropped into
`python/src/evelab/localize/dialects/packs/<name>.toml` (format: `dialects/packs/README.md`):

```toml
dialect = "eos"
templates = ["veos*", "ceos*"]
sniff = ['^! device: .* EOS']
block_style = "indent"
mask_form = "prefix"

[iface_aliases]
Et = "Ethernet"

[[rule]]
id = "eos.ip"
pattern = '^\s+ip address (?P<v>IPV4)(?P<mask>/\d+)$'
kind = "ip_host"
block = "interface"
```

or a `RuleDialect` subclass in `python/src/evelab/localize/dialects/<name>.py` decorated with `@register`.
Every non-private module in `dialects/` is imported automatically (only the helpers listed in
`HELPER_MODULES` are not), so no registry edit is needed. Override `parse()` / `render()` only for
unusual syntax, as `junos.py` does for braces.

Out-of-tree packs and Python files load with `--plugins DIR` (repeatable) or, persistently, with
`EVE_LOCALIZE_PLUGINS=dir1:dir2` (useful for `make test`). Two files declaring the same dialect
name, or a plugin reusing a built-in name, fail with `DIALECT_DUPLICATE`. When `apply` parses a lab
with a plugin dialect, `state.json` records it (`plugin_dialects`), and `revert`, `check`, `plan` and
`apply` refuse that lab with `UNKNOWN_DIALECT` until the plugin is loaded again. Otherwise the
values only the plugin can read would stay localized while revert reported success.

Then add `python/tests/localize/fixtures/snippets/<dialect>/*.txt` with `*.facts.json`;
`test_dialect_contract.py` runs the whole contract (no-op render is byte-identical, render then
extract gives the new value, inverse render restores the bytes, negative lines never match). A first
`facts.json` comes from:

```bash
cd python && python3 -m tests.localize.test_dialect_contract skeleton <dialect> \
  tests/localize/fixtures/snippets/<dialect>/<name>.txt
```

## Adding a scenario

A scenario turns facts into questions and edits. Create
`python/src/evelab/localize/scenarios/<name>.py` and decorate the class with `@register_scenario`. The module
is imported automatically, like dialects (helpers: `HELPER_MODULES`). A second class under an
existing id fails with `SCENARIO_DUPLICATE`; a plugin that really means to replace a built-in uses
`register_scenario(Cls, override=True)`. If `applies()` raises, the scenario is skipped and a
`SCENARIO_FAILED` error finding is reported (it blocks apply) instead of the questions silently
disappearing. It implements:

- `id`, `order` (position in the question flow; built-ins use 10-90), optional `gated = True`
  for a yes/no gate;
- `applies(a, m)`: whether the lab has the facts the scenario needs;
- `questions(a, m, prof)`: `Question`s with ids `<id>/<name>`, defaults from the profile;
- `plan(a, ans, maps)`: a `PlanFragment` of `Claim`s built with `fact_claim()` and `render_fact()`
  from `scenarios/base.py`.

If the scenario needs a new kind of fact, add the kind to `model.CORE_FACT_KINDS` and `PatternRule`s
producing it to the relevant dialects. If it needs a new answer type, register a `ParamKind` with
`register_param_kind()` (`parse` / `validate` only: its `render` field is reserved and never called,
because edits always come from `Dialect.render` via `render_fact()` in the scenario's `plan()`). Per-lab options live in the manifest (`[scenarios.<id>]`) and in answers
(`[labs."<id>".scenarios.<id>]`). Add tests under `python/tests/localize/`.

The design document (`docs/internal/lab-localize-design.md`) has the full contract.
