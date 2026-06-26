# ndISEMig

A desktop GUI tool for backing up and migrating **Cisco ISE** (Identity Services
Engine) configuration between deployments via the ERS and OpenAPI interfaces.

Point it at a source ISE node to export its configuration to a single JSON file,
then point it at a target node to recreate those objects — handling version
differences, dependency ordering, and server-managed fields automatically.
Supports ISE **2.4 through 3.6+**.

> ⚠️ **Use at your own risk.** This tool writes configuration to live ISE
> deployments. Always test against a lab/staging node first and keep an
> independent backup of any target you import into.

## Features

- **Single-file backup** — export selected resource categories from a source ISE
  node to one portable JSON file.
- **Cross-version migration** — fields introduced in newer ISE releases are
  stripped automatically when importing into an older target (e.g. TEAP,
  TrustSec traffic steering, TACACS TLS settings).
- **Dependency-aware import** — objects are created in the correct order so that
  references (groups, ACLs, profiles, etc.) exist before the objects that use
  them.
- **Broad resource coverage** via the ERS API, including:
  - Identity groups, internal users, guest types/users, sponsor groups
  - Network device groups and network devices (NADs)
  - Endpoint groups and endpoints
  - Downloadable ACLs, allowed protocols, authorization profiles
  - TrustSec (SGTs, SGACLs, egress matrix, IP mappings)
  - TACACS+ and RADIUS profiles, command sets, external servers, sequences
  - Identity source sequences, REST ID stores, certificate profiles
  - Guest/sponsor/BYOD/hotspot portals and themes
  - Profiler profiles, ANC policies, filter-IP policies, native IPSec
- **OpenAPI resources (ISE 3.1+)** — Policy Sets, network-access and
  device-admin dictionaries/conditions, TrustSec virtual networks and VN/VLAN
  mappings, exposed through the `/api/v1` gateway.
- **CSV export** — dump individual resources to per-type CSV files for review.
- **Live log** with progress, per-item status, and one-click log saving.

## Requirements

- **Python 3.8+** (developed/tested on 3.13)
- **Tkinter** — bundled with the standard CPython installer on Windows and
  macOS. On Linux install it via your package manager (e.g.
  `sudo apt install python3-tk`).
- Python packages: [`requests`](https://pypi.org/project/requests/),
  [`urllib3`](https://pypi.org/project/urllib3/)

On the ISE side:

- **ERS API enabled** (Administration → System → Settings → ERS Settings) and an
  admin account with ERS access.
- **OpenAPI enabled** on the source/target if you want Policy Sets and other
  `/api/v1` resources (ISE 3.1+).

## Installation

```bash
git clone https://github.com/<your-username>/ndisemig.git
cd ndisemig
python -m pip install -r requirements.txt
```

## Usage

```bash
python ndisemig.py
```

1. **Connections** — enter the host, username, and password for the source and
   target ISE nodes. Tick *Enable OpenAPI* to include Policy Sets and other
   `/api/v1` resources. Test/connect to confirm reachability and version
   detection.
2. **Export** — select the resource categories to back up and save them to a
   JSON file (or export selected resources to CSV).
3. **Import** — load a backup JSON, choose the target, and recreate the objects.
   Version-gated fields are stripped automatically for the target's release.
4. **Log** — watch progress in real time and save the log for your records.

### A note on passwords

ISE cannot export hashed user passwords. Internal users created on import are
assigned a placeholder password (`ISEmigration1!`) and must be reset afterward.

## License

Released under the GNU General Public License v3.0 — see [LICENSE](LICENSE).

## Contributors

- Nathan Downes — <nd@ntwk.co.uk>

## Disclaimer

This is an independent, community tool. It is not affiliated with, endorsed by,
or supported by Cisco Systems. "Cisco" and "ISE" are trademarks of their
respective owners.
