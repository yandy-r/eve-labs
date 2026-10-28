# eve-analyze: fit these labs to your EVE host

The labs in this repository name the images, QEMU builds and node sizes of the EVE host they were
built on. Your host probably has other versions: a different Nexus 9000v release, a newer FortiGate
build, another IOL image, less RAM. `scripts/eve-analyze` looks at what your EVE server actually
has, compares it with every lab, recommends substitutions, asks you, and rewrites the labs with
your answers.

It is the companion of [`eve-localize`](../localize/README.md), which handles the _network_ side
(cloud bridges, VLANs, subnets inside device configs). Analyze reports cloud bridges that are
missing or down on your host and tells you the `eve-localize` command that fixes them.

Python 3.11+ standard library only. Run it on the EVE host from the repository root.

## Quick start

```bash
cd /opt/unetlab/labs
./scripts/eve-analyze scan        # what this host lacks, lab by lab
./scripts/eve-analyze             # interactive: pick labs -> questions -> review -> apply + commit
```

Close the labs in the EVE web UI and stop their nodes first: EVE rewrites a `.unl` on save, and the
tool refuses to write a lab whose nodes are running.

## What it checks

| Check            | Source on the host                                     | Lab attribute  | Outcome                         |
| ---------------- | ------------------------------------------------------ | -------------- | ------------------------------- |
| QEMU images      | `/opt/unetlab/addons/qemu/<template>-*/` (with a disk) | `image`        | question                        |
| IOL images       | `/opt/unetlab/addons/iol/bin/*.bin` (L2 vs L3 family)  | `image`        | question                        |
| Dynamips images  | `/opt/unetlab/addons/dynamips/*.image`                 | `image`        | question                        |
| Docker images    | `docker images` (other tags of the same repository)    | `image`        | question                        |
| QEMU builds      | `/opt/qemu-<version>/`                                 | `qemu_version` | question                        |
| vCPUs / RAM      | `/proc/cpuinfo`, `/proc/meminfo`                       | `cpu`, `ram`   | question (only when over host)  |
| Node templates   | `/opt/unetlab/html/templates/{intel,amd}/*.yml`        | `template`     | `TEMPLATE_MISSING` warning      |
| Cloud bridges    | `/sys/class/net/pnetN`, `natN`                         | network `type` | warning + `eve-localize` hint   |
| KVM, IOL license | `/dev/kvm`, `addons/iol/bin/iourc`                     | -              | `KVM_MISSING`, `IOL_LICENSE_..` |
| Icons, total RAM | `html/images/icons/`, sum of node RAM                  | `icon`, `ram`  | info                            |

Only attribute values change. The tool never adds or removes nodes, never touches configs, and
never changes a template.

### How images are matched

EVE shows a QEMU image for a template when its folder is named `<template>-<anything>`, so only
folders with the lab node's template prefix are offered. The rest of the name splits into a
_variant_ and a _version_ (`nxosv9k-9300v-10.3.3.F` is variant `9300v`, version `10.3.3.F`;
`fortinet-FGT-v7-build2702` is variant `FGT`). Candidates are ordered same variant first, then
newest version first. Empty image folders (no `.qcow2`/`.img`/`.iso`) are ignored.

- **Image missing** on this host: a required question; the recommendation is the newest image of
  the same variant (or of another variant when that is all there is). With no image of the family
  at all you get an `IMAGE_MISSING` warning that says where to install one; for a docker image
  built from this repository it prints the `docker build` command.
- **Image present, newer one available** (QEMU and Dynamips only): an optional upgrade question
  whose default is _keep_. `--latest` makes the newest image the default.
- IOL builds and docker tags carry no comparable version, so they are offered only when the lab's
  image is missing.

One question covers every node of a lab that uses the same value, and its id is the same in every
lab (`image/qemu/nxosv9k/nxosv9k-9300v-10.3.3.F`, `qemu_version/4.1.0`, `ram/16384`), so with
several labs you answer once.

## The interactive flow

1. **Host summary and findings** for every lab (`scan` stops here).
2. **Lab picker**: labs with something to change, with a status such as `3 to fix, 1 upgrade`.
3. **Questions**: the choices are numbered; type a number or a value. `Enter` takes the
   recommendation, `k` keeps the current value, `?` shows the nodes, `q` quits without writing.
   RAM and CPU questions take any number up to what the host has.
4. **Review**: the changes per lab (`image: nxosv9k-9300v-10.3.3.F -> nxosv9k-9300v-10.5.1.F (leaf1,
leaf2)`), then `Write N change(s)?`.
5. **Write**: running-node check, a backup in `.analyze/backups/<run>/`, the edit (only the
   attribute bytes change; the file is re-parsed, compared and run through `check-labs`), an
   atomic replace that keeps the file's owner and mode, then the git commit below.

## Git: branch for clones, main for forks

| Your checkout                                                 | Where the change goes                                            |
| ------------------------------------------------------------- | ---------------------------------------------------------------- |
| `origin` is upstream (`yandy-r/eve-labs`): you cloned it      | a new local branch `analyze/<hostname>`, committed there         |
| ... and you are already on a branch other than `main`         | committed on that branch                                         |
| `origin` is any other repository (your fork, your own remote) | committed on the current branch (normally `main`)                |
| not a git checkout (downloaded archive)                       | files written with backups, nothing committed                    |
| `--no-commit`                                                 | files written, nothing committed, no branch switch               |
| `--branch NAME`                                               | committed on `NAME` (created from `HEAD` when it does not exist) |

The upstream repository can be changed with `--upstream OWNER/REPO` or `$EVE_LABS_UPSTREAM`.

The commit contains only analyze's edits: they are applied to the committed (`HEAD`) version of
each lab, so uncommitted work in the same files stays uncommitted. That matters after
`eve-localize`, whose localized labs must not be committed (`make localize-check`). A lab whose
`HEAD` version already differs in an attribute being changed is written but left uncommitted, with
a warning. Git hooks do not run for this commit.

Keeping a clone up to date then looks like this:

```bash
git checkout main && git pull --ff-only
git checkout analyze/eve2 && git merge main     # or rebase
./scripts/eve-analyze                           # new labs or images since last time
```

Run `make fix-perms` afterwards if git ran as `root` (see the main README).

## Non-interactive use

```bash
./scripts/eve-analyze plan --all --yes                  # show what --yes would change; never writes
./scripts/eve-analyze apply --all --yes                 # take every recommendation and write
./scripts/eve-analyze --save-answers .analyze/answers.toml   # remember interactive answers
./scripts/eve-analyze apply --answers .analyze/answers.toml  # replay them (e.g. after a pull)
./scripts/eve-analyze scan --json > q.json             # fill "answer" per question, then:
./scripts/eve-analyze apply --answers q.json
```

Answers files are TOML (`[answers]` table of question id to value, `keep` keeps), JSON
(`{"id": "value"}`) or a filled `scan --json`. A value that is not one of the question's choices is
refused with `BAD_ANSWER`. `apply` without `--yes` changes only what the answers say and keeps the
rest; `--strict` turns unanswered required questions into exit 3. `scan --strict` exits 2 when any
lab has something to fix, for scripted health checks of a host.

### Analysing from another machine

`scan`, `plan` and `apply` need an inventory of the EVE host. Take one on the host and use it
anywhere:

```bash
./scripts/eve-analyze inventory > host.json             # on the EVE host
./scripts/eve-analyze plan --inventory host.json        # on your laptop
```

## Files

| Path                         | What it is                                          |
| ---------------------------- | --------------------------------------------------- |
| `scripts/eve-analyze`        | Shim: runs the tool straight from a checkout        |
| `python/src/evelab/analyze/` | The tool (shared code: `python/src/evelab/common/`) |
| `.analyze/backups/<run>/`    | Byte copies taken before each write (gitignored)    |
| `.analyze/lock`              | Held while writing, so two runs never overlap       |

Exit codes: 0 ok or nothing to do, 1 error, 2 problems found (`scan --strict`), 3 unanswered
(`--strict`), 4 precondition failed (not an EVE host, running nodes, lab changed meanwhile), 5
validation failed (nothing written).
