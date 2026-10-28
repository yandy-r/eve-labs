# Declarative dialect packs

Every `*.toml` file in this directory is loaded automatically (by
`evelab.localize.dialects.load_builtin`) and registers one dialect. Files whose name starts
with `_` or `.` are ignored. Out-of-tree packs and Python plugins load the same way
with `eve-localize --plugins DIR`.

A pack carries the same data as a `RuleDialect` subclass, without any Python:

```toml
dialect = "eospack"                    # lower-case identifier, unique
templates = ["veos*", "ceos*"]         # fnmatch on node.template / node.image
sniff = ['^! device: .* EOS']          # content regexes (MULTILINE)
block_style = "indent"                 # indent | fortios | brace | flat | html
mask_form = "prefix"                   # dotted | prefix | mixed
secret_rules = ['^username \S+ .*secret (?:\d )?(?P<s>\S+)']   # group s = secret
fact_kinds = []                        # extra fact kinds this pack introduces
# optional: iface_block_kinds, block_parent_re, subif_re, priority

[iface_aliases]                        # abbreviation = full name
Et = "Ethernet"
Ma = "Management"

[[rule]]
id = "eos.encap"                       # unique inside the dialect
pattern = '^\s+encapsulation dot1q vlan (?P<v>\d+)$'
kind = "vlan_tag"                      # a registered fact kind
block = "interface"                    # interface | vlan | vrf | "system dns" | "edit:<cfg>" | top | omit = anywhere
role = "encap_tag"                     # optional, feeds IfaceInfo (see below)
negative = ["   rd 2:2"]               # lines that must NOT match (contract-tested)
# also: l2 = true, list_style = "ios|nxos|space|brace", anchored_keywords = [...], flags = [...]
```

Rules are matched **line by line**. In `pattern`, `IPV4` expands to the
boundary-aware IPv4 token and `MASK` to `/NN` or a dotted quad. Named groups: `v`
(the value), `mask`, `parent`, `list`, `many` (one fact per IPv4 token in the
group), and for role `trunk_allowed` also `add` / `kw`. Roles: `access_vlan`,
`trunk_allowed`, `native_vlan`, `encap_tag`, `mode_access`, `mode_trunk`; a rule with
`kind = ""` produces no fact and only sets the role.

After adding a pack, add `python/tests/localize/fixtures/snippets/<dialect>/*.txt`
and `*.facts.json`. `test_dialect_contract.py` then runs the whole contract against
it with no further test code. Generate a first `facts.json` with:

```bash
cd python && python3 -m tests.localize.test_dialect_contract skeleton <dialect> \
  tests/localize/fixtures/snippets/<dialect>/<name>.txt
```

See design section 13.3 for the full extension guide.
