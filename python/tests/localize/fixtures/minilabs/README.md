# Minilab fixtures

Small synthetic EVE-NG 7.2 labs used by the eve-localize tests (unl, codec, stores,
apply, l2trace, segments). They follow the attribute layout of the real labs in `labs/`
(node, interface, bridge and cloud network tags, two-space indentation, single-line
base64, trailing stray `<objects/>`). Each has a unique `<lab id>` (a uuid5 of its name)
and is well-formed (`scripts/check-labs.py` passes on a copy named `*.unl`).

**Extension.** Fixtures are stored as `<stem>.unl.fixture`, not `.unl`, because this repo
is `/opt/unetlab/labs`: EVE lists every `*.unl` in the tree and `git ls-files '*.unl'` /
check-labs would treat them as real labs. Sidecar directories (`<stem>_cfgs/NN_name.txt`)
sit next to the fixture under their normal names.

**Loading.** Use `tests/localize/labfiles.py`: `minilab_path(stem)` copies the fixture
into a fresh temp dir as `<stem>.unl` together with every `<stem>*_cfgs` directory and
returns that path (cleaned up at exit); `minilab(stem)` returns a `RawLab` of the copy;
`minilab_names()` lists all stems. Tests therefore exercise the real path and sidecar
logic and can never write into the repo.

Shared ground rules:

- node `config="1"` = embedded startup config, `config="2"` = configset id 2, `"0"` = none
- clouds: `pnet0` = management, `pnet2` = VM trunk; bridges are `Net-<node>iface_<n>`
- decoded blob contents are ordinary short IOS / FortiOS / shell text (see below)

| Minilab | What it exercises |
|---|---|
| `basic.unl.fixture` | Healthy lab with everything: IOL L3 + L2, FortiGate (sidecar), docker node; startup `<configs>` for nodes 1, 2, 4; configset `alt-scheme` (id 2) for nodes 1, 2; two textobjects (HTML text, SVG square); a `<task>`, a `<lineobject>`; a `<description>`; two cloud networks both named `EVE-MGMT-203` (ids 2 and 5) and `INET-1240` on pnet2; three `<objects>` elements (one real, two stray empty). Sidecars: `basic_cfgs/3_fw1.txt` (UTF-8 em dash, LF) and `basic_cfgs/4_srv1.txt`, byte-identical to node 4's startup blob (mirror). |
| `no_configs.unl.fixture` | No `<configs>` element at all; one textobject; nodes have `config="0"`. |
| `garbage_blob.unl.fixture` | Config 1 is literally `ff` (not base64, opaque); config 3 is base64 of binary bytes with NULs (opaque); config 4 is `ZmY=` (valid base64 of the text `ff`, canonical); config 2 is healthy. |
| `config_no_blob.unl.fixture` | Nodes with `config="1"` but: no `<config>` element (node 1), empty `<config id="2"></config>`, self-closing `<config id="3"/>` (cannot be edited in place), and one healthy config (node 4). |
| `noncanonical_b64.unl` | Config 1 is base64 wrapped at 64 columns and indented, config 2 has a trailing space, config 3 has non-zero unused bits in its last character (same decoded bytes); config 4 is canonical (control). Decodes fine, edits must be blocked. |
| `dup_names.unl.fixture` | Cloud `Net` (id 5) and bridges also named `Net` (ids 3, 6); two clouds both named `INET-201` (ids 1, 2); two textobjects both named `square1`. Everything must be keyed by id. |
| `amp_name.unl.fixture` | Escapes: lab name `A &amp; B &quot;lab&quot;`; network names `R&amp;D &quot;edge&quot; &lt;lab&gt;`, a single-quoted attribute `'it&apos;s "single" quoted'` and `Caf&#233; — &#x41;ZURE` (numeric references, em dash). |
| `crlf_sidecar.unl.fixture` | Forti nodes 2 (`fw1`) and 3 (`fw2`) with sidecars: `crlf_sidecar_cfgs/2_fw1.txt` uses CRLF line endings and a trailing CRLF, `3_fw2.txt` uses LF and has no trailing newline. |
| `missing_sidecar.unl.fixture` | Same nodes as above, but no `_cfgs` directory at all: the Forti nodes have no config anywhere. |
| `sidecar_mismatch.unl.fixture` | `sidecar_mismatch_cfgs/`: `2_fw1.txt` is accepted; `3_edge-fw.txt` has the id of node 3 but node 3 is `fw2` (skipped, `SIDECAR_MISMATCH`); `9_ghost.txt` has no node 9 (skipped); `notes.txt` does not match `NN_name.txt` (ignored). |
| `sidecar_ambiguous.unl.fixture` | No `sidecar_ambiguous_cfgs`, but two `sidecar_ambiguous_*_cfgs` directories (`_a_`, `_b_`): `SIDECAR_AMBIGUOUS` without a manifest entry. |
| `unknown_layout.unl.fixture` | Well-formed XML, but an unknown `<snapshots>` element inside `<objects>` holds a `<config id="9">` and a `<textobject id="9">` the span index does not look at. ElementTree sees them, so the lab is `read_only` (scan works, apply refused). |

Decoded blob contents (all short, ASCII except where noted):

- `RTR1` (basic/garbage/dup/...): IOL router, `ip domain name lab.example`,
  `ip name-server 10.100.51.2`, `Ethernet0/1.1240` with `encapsulation dot1Q 1240` and
  `172.31.240.11/24`, default route `172.31.240.1`, `ntp server 10.100.51.3`.
  `basic` configset `alt-scheme` carries the same text with 1241 / 172.31.241.x.
- `SW1`: IOL L2, `vlan 203`, trunk `Ethernet0/0`, access port `Ethernet0/2` in vlan 203,
  `interface Vlan203` `10.100.51.12/24`. Configset variant uses vlan 204 / 10.100.52.x.
- `SRV1`: shell script with `ip addr add 10.100.51.31/24`, default route and a
  `cat << EOF > /etc/resolv.conf` heredoc.
- `FW1` (sidecars): FortiOS `config system interface` (`port1` `10.100.51.21`) and
  `config system dns`, first line is a `# fw1 — edge firewall` comment (UTF-8 em dash).

The values are fake and exist only to be parsed; none of them are real addresses.
