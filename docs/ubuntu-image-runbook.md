# Runbook: build the Ubuntu server image for EVE-NG

Builds an Ubuntu server QEMU node image and installs it straight into EVE's qemu folder. Run
everything on the EVE host as root. A build takes a while and needs about 30 GB of free disk.

## 1. Clone the repo

```bash
git clone https://github.com/yandy-r/eve-labs.git
cd eve-labs
```

## 2. Install the build tools

```bash
sudo apt-get update
sudo apt-get install -y libguestfs-tools curl
```

The host also needs internet access while the image builds.

## 3. Build

Ubuntu 24.04 is the default, so no variables are needed:

```bash
sudo images/linux/build.sh server
```

For Ubuntu 26.04, set the version and its codename:

```bash
sudo UBUNTU_VERSION=26.04 UBUNTU_CODENAME=resolute images/linux/build.sh server
```

24.04 is the tested release. 26.04 uses the same script and its packages and repos resolve, but
it has not been booted in a lab yet.

Optional variables:

| Variable       | Default                    | Purpose                       |
| -------------- | -------------------------- | ----------------------------- |
| `DISK_SIZE`    | `40G`                      | Virtual disk size (thin)      |
| `BUILD_DIR`    | `/var/tmp/eve-image-build` | Scratch space (~30 GB)        |
| `EVE_QEMU_DIR` | `/opt/unetlab/addons/qemu` | Where the finished image goes |

## 4. Result

The script writes the image directly into EVE and fixes permissions with
`unl_wrapper -a fixpermissions`, so there is nothing to copy:

```text
/opt/unetlab/addons/qemu/linux-ubuntu-<version>-server/virtioa.qcow2
/opt/unetlab/addons/qemu/linux-ubuntu-<version>-server/MANIFEST.txt
```

If you built on another machine (with `EVE_QEMU_DIR` pointing somewhere local), copy the
`linux-ubuntu-<version>-server/` folder into `/opt/unetlab/addons/qemu/` on the EVE host and run:

```bash
sudo /opt/unetlab/wrappers/unl_wrapper -a fixpermissions
```

## 5. Add the node in EVE

Add a node, pick the **Linux** template, and choose `linux-ubuntu-<version>-server` as the image.
Suggested settings: 2 vCPU, 4 GB RAM, console `vnc`, NIC `virtio-net-pci`.

Log in as `admin` / `admin123`. The first NIC (`ens3`) uses DHCP; the others are left for lab config.

See [`images/linux/README.md`](../images/linux/README.md) for what's installed and for the
desktop image (`build.sh desktop`).
