# IOL images (from the CML refplat)

How to add the Cisco IOL images that ship in the CML reference platform ISO
(`refplat-*-fcs.iso`, `virl-base-images/`) to EVE. The binaries are not committed.

| CML folder                     | What it is                | EVE file name (in `/opt/unetlab/addons/iol/bin/`)      |
| ------------------------------ | ------------------------- | ------------------------------------------------------ |
| `iol-xe-17-16-01a`             | IOL XE router (L3)        | `x86_64_crb_linux-adventerprisek9-ms.17.16.01a.bin`    |
| `ioll2-xe-17-16-01a`           | IOL XE switch (L2)        | `x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.bin` |
| `iol-xe-17-16-01a-serial-4eth` | L3 with serial interfaces | not installed                                          |

## Install

IOL images go in the **IOL** addons folder, not `addons/qemu/`. EVE lists only files that end in
`.bin`, so rename the CML `.iol` file when you copy it:

```bash
src=refplat-20250616-fcs/virl-base-images/ioll2-xe-17-16-01a/x86_64_crb_linux_l2-adventerprisek9-ms.iol
dst=/opt/unetlab/addons/iol/bin/x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.bin
scp "$src" eve:"$dst"
ssh eve "/opt/unetlab/wrappers/unl_wrapper -a fixpermissions"
```

Add a node with template **Cisco IOL** and choose the image from the list. Nodes need the IOL
license file `/opt/unetlab/addons/iol/bin/iourc`, which is set up once per host and not kept in this
repository.

## The L2 image aborts on start

**Symptom:** the L2 node stops as soon as you start it. The EVE log
(`journalctl -u 'eveng_0@<lab-uuid>@<node-id>'`) shows
`Error while connecting local AF_UNIX: Connection refused /tmp/netio<uid>/<id>`. If you run the binary
by hand under a pty (`script -qc "<bin> -e 1 -s 0 -n 1024 -m 1024 98"` in a directory with
`iourc` and a `NETMAP` such as `98:0/0 101:0/0`), it prints this and dumps core:

```text
Warning: Abnormal ciscoversion string, please notify the IOU team
with the name of this branch
Warning: we parsed - NULL
```

**Cause:** at startup IOL looks up `xml.cisco.com`. The L3 image carries on whatever the answer,
but the L2 image (17.16.1a) aborts if the name resolves at all. It has to fail to resolve. Two
things make it resolve:

- an `xml.cisco.com` line in `/etc/hosts`. Older IOU guides tell you to add one, but for this
  image it causes the crash. Don't add it.
- a DNS search domain with a wildcard record. The real `xml.cisco.com` doesn't exist, so the
  resolver then tries `xml.cisco.com.<search-domain>`, and a wildcard answers it. On `eve` the
  Tailscale search domains include one with a wildcard.

**Fix on `eve`:** the L2 `.bin` is a small launcher that clears the search list for this image only.
The real binary sits beside it as a dot-file, which keeps it out of EVE's image list:

```bash
cd /opt/unetlab/addons/iol/bin
mv x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.bin .x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.real
cat > x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.bin <<'EOF'
#!/bin/sh
# IOL L2 17.16.1a aborts ("Abnormal ciscoversion string") when xml.cisco.com resolves.
# A wildcard DNS search domain makes it resolve, so clear the search list for this image.
LOCALDOMAIN=invalid exec /opt/unetlab/addons/iol/bin/.x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.real "$@"
EOF
chown root:unl x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.bin .x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.real
chmod 755 x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.bin .x86_64_crb_linux_l2-adventerprisek9-ms.17.16.01a.real
```

`LOCALDOMAIN` overrides the glibc resolver's search list, so the lookup gets the real NXDOMAIN.
To check whether a host needs this, run `getent hosts xml.cisco.com`. If it prints an address, the L2
image will abort. If it prints nothing, copy the plain `.bin` and skip the launcher.

If a host has no wildcard search domain and no `/etc/hosts` entry, it needs no launcher. The other
way to fix it is to remove the wildcard search domain from the host.
