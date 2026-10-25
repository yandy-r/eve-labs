# eve-labs

EVE-NG Pro lab files (`/opt/unetlab/labs` on host `eve`, EVE-NG Pro 7.2).

## Layout
- `Yandy/` – personal labs (CCIE, Datacenter, Cloud, Customers)
- `Clients/` – client labs
- `Shared/`, `Users/` – EVE default folders

## Conventions (this host)
- Cloud networks: `pnet0` = management/device access (untagged mgmt LAN 10.100.51.0/24, trunk);
  `pnet2` = VM traffic trunk for VLANs 1240-1243. `pnet1`, `pnet3`-`pnet9` are not brought up.
- Every `.unl` needs a unique `id` attribute on `<lab>` (EVE 7 rejects labs without one).
- Lab files must be owned by `www-data` so EVE can save them.
- Default device login in startup configs: `admin123`.

## Workflow
Commit from the host after changing labs in the UI:

    cd /opt/unetlab/labs && git add -A && git commit -m "..." && git push

Ignored: the code-search `index`, `.updated` marker, lock/temp files.
