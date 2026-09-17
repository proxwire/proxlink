# proxlink

Turn a Linux machine into a DHCP server on a chosen interface, with optional internet sharing via NAT. Built for **pen testing** (kiosks, locked-down devices), **medical and lab gear** with fixed IPs, and **quick links** to Raspberry Pi or other gear on the go—when you don't know the device's IP or subnet. *Personal link active.*

> ### Authorized use only
>
> proxlink is an offensive network tool. It runs a rogue DHCP server, can spoof DNS, transparently intercept HTTPS, and capture credentials from traffic. Use it **only** on equipment you own or have explicit written permission to test.
>
> Running this on a network you don't control is likely illegal in your jurisdiction. You are responsible for how you use it.

## Features

- **DHCP server** — Uses `dnsmasq` to hand out IPs on a configurable subnet
- **Configurable subnet** — Set network prefix (e.g. `10.0.0`, `10.16.75`) via `-p` when you know the device's network
- **VLAN support** — `-v <id>` creates a tagged subinterface (e.g. `eth2.42`) so you can reach devices on 802.1Q VLAN segments without manual setup
- **Static-IP detection** — Don't know the device's subnet? Press **`d`** while running: the script captures ARP/IP for a few seconds, infers possible static subnets, suggests `-p`, and can add **alias IPs** so you're on the same L3 without rerunning
- **Device watcher** — Always on. Uses dnsmasq's `--dhcp-script` hook to announce new connections and reconnections automatically, with an immediate `arp-scan`. Correctly handles both first-time (`add`) and returning (`old`) devices
- **DNS query logging** — Always on. Every domain the device resolves is logged to `logs/dns.log`. Press **`l`** to tail the last 30 entries — useful for immediately seeing what services a device is trying to contact
- **DNS spoofing** — `-D` redirects all DNS queries back to your machine via dnsmasq's `address=/#/` directive. Useful when capturing credentials from devices that authenticate to hostnames
- **Optional internet sharing** — Share internet from one interface (e.g. `eth0`) to the DHCP network via NAT/iptables
- **Cleanup on exit** — Removes iptables rules, alias IPs and VLAN subinterfaces, and restores the host's original IP-forwarding setting when you stop the script (Ctrl+C)
- **Device scan** — Press **Enter** to run `arp-scan` and list devices on the current subnet
- **Credential capture** — Press **`c`** to capture traffic for 60s and extract creds (NTLM, HTTP basic, SQL, SMB, Kerberos, etc.) via **PCredz** or **NetCredz** if installed; results are flagged and appended to `creds/creds.log`. Passive only (no Responder-style poisoning)
- **Rolling background pcap** — `-r` starts a continuous background capture in 5-minute rotating files (last ~1 hour kept in `creds/`). Captures auth that happens before you manually press `c`
- **Burp redirect** — With **`-b [port]`**, device HTTP/HTTPS (80, 443) is transparently redirected to a Burp proxy on the host (default port 8080). Run Burp in invisible/transparent mode on that port
- **CA cert server** — Automatically started with `-b`. Generates a self-signed CA cert, serves it via HTTP on the gateway IP (`http://GATEWAY/ca.crt`), and keeps it reachable by excluding the gateway from the Burp port-80 redirect. Drop any file in `serve/` to serve it to the device

## Requirements

- Linux with `root` (or `sudo`)
- **dnsmasq** — DHCP/DNS server
- **arp-scan** — Network device discovery
- **tcpdump** — Used for static-IP detection, credential capture, and rolling pcap
- **iptables** — For NAT when using internet sharing (`-s`) or Burp redirect (`-b`)
- **openssl** (optional) — Auto-generates a CA cert when `-b` is used; without it, place your CA manually in `serve/`
- **python3** (optional) — Required for the CA cert HTTP server (`-b`)
- **PCredz** or **NetCredz** (optional) — To extract credentials from captures; without one, **`c`** still saves a pcap for manual analysis

### Install dependencies (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y dnsmasq arp-scan tcpdump
# Optional: credential extraction (Kali often has pcredz)
sudo apt-get install -y pcredz
# Or clone PCredz / NetCredz and ensure in PATH
```

## Usage

Run as **root** (e.g. `sudo ./proxlink.sh`).

```text
./proxlink.sh [-p prefix] [-i interface] [-s internet_interface] [-b [port]] [-o allow_dest] [-v vlan_id] [-D] [-r]
```

| Option | Description |
|--------|-------------|
| `-p prefix` | Network prefix as `X.Y.Z` (e.g. `10.0.0`, `10.16.75`). Default: `10.0.0` |
| `-i interface` | Interface to run the DHCP server on. Default: `eth2` |
| `-s internet_interface` | Interface with internet to share via NAT to the DHCP network |
| `-b [port]` | Redirect device HTTP/HTTPS (80, 443) to Burp proxy on host. Default port: **8080** |
| `-o allow_dest` | When using `-s`, only allow device traffic to this single IP/domain (others are dropped) |
| `-v vlan_id` | Create a VLAN subinterface for the given 802.1Q tag ID (e.g. `-v 42` on `eth2` uses `eth2.42`) |
| `-D` | Spoof all DNS queries back to this machine |
| `-r` | Record rolling background pcap (5min chunks, last ~1hr kept in `creds/`) |
| `-h` | Show usage |

> **Note:** all three `-b` forms work — `-b` (default port), `-b8443`, and `-b 8443`.

- `-h` works without root; everything else requires it.
- The script sets the DHCP server IP on the chosen interface to `PREFIX.1` (e.g. `10.0.0.1`).
- DHCP range is `PREFIX.3`–`PREFIX.200`, lease 12h.
- While the script is running: **Enter** = `arp-scan`; **`d`** = detect static-IP subnets; **`c`** = capture & extract credentials; **`l`** = tail DNS query log. **Ctrl+C** = exit and cleanup.

### VLAN subinterfaces

If the device is on a tagged VLAN, your regular interface (`eth2`) won't see its traffic at all — the 802.1Q tag makes the frames look malformed. Use `-v <id>` to create a subinterface that strips the tag and handles the traffic:

```bash
sudo ./proxlink.sh -i eth2 -v 42
```

This creates `eth2.42`, assigns your gateway IP to it, runs DHCP on it, and removes it on exit. Use `ip link` or check switch documentation to find the VLAN ID.

### Static-IP detection

If the device doesn't take DHCP (e.g. kiosk or medical device with a fixed IP), you'd normally have to watch traffic, guess the subnet, then rerun with `-p`. Instead:

1. Start the script (default subnet is fine).
2. Connect or wake the device, then press **`d`**.
3. The script captures traffic for ~15 seconds, parses ARP and IP to find addresses outside the current subnet, and prints suggested `-p` values.
4. Optionally answer **y** to add those subnets as **alias IPs** on your interface (the script uses `.254` per subnet, e.g. `192.168.1.254/24`, to avoid conflicting with devices that use `.1`). You can then reach the device without rerunning; aliases are removed on exit.

### Device watcher

The device watcher is always on. It uses dnsmasq's `--dhcp-script` hook to fire whenever a lease is granted, which means it catches both:

- **New devices** (`add`) — first time a MAC address is seen
- **Reconnecting devices** (`old`) — same device plugging back in

On each event it prints the device's IP and MAC and runs an automatic `arp-scan`.

### DNS query logging and spoofing

DNS logging is always on. Every domain the device resolves is written to `logs/dns.log` — press **`l`** to view the most recent queries. This is often the fastest way to understand what a device is talking to without digging through pcaps.

With **`-D`**, all DNS queries are answered with your machine's IP. Combine with a listener (e.g. `nc`, `responder`, or a fake HTTP server) to intercept service connections or capture credentials sent to hostnames.

### Rolling background pcap

Use **`-r`** to run a continuous background capture in time-rotated files alongside the session. Files are written to `creds/rolling_<timestamp>.pcap` in 5-minute chunks; the last 12 are kept (~1 hour). This ensures you don't miss auth events that happen before you manually press **`c`**.

### Burp proxy redirect and CA cert server

Use **`-b`** (default port 8080) or **`-b 8443`** to send device HTTP/HTTPS traffic to a Burp proxy on the host. The script adds iptables REDIRECT rules so traffic from the device to any host:80 or host:443 is sent to the host's proxy port. Start Burp listening on **0.0.0.0:8080** (or your chosen port) in **invisible** / **transparent** proxy mode.

When `-b` is used, a CA cert HTTP server is started automatically on `http://GATEWAY_IP/` (e.g. `http://10.0.0.1/ca.crt`). The port-80 Burp redirect rule excludes the gateway IP so this stays reachable without going through Burp first. If `openssl` is available, a CA cert is generated at `serve/ca.crt`; otherwise place one there manually.

Everything in `serve/` is reachable by the device, so the generated **private key is kept out of it** — it lives in `ca/ca.key` (mode 600) and is never served. If a `.key` or `.pem` ever turns up in `serve/`, the script moves it to `ca/` and warns.

To use with Burp:

1. Export Burp's CA: **Proxy > Proxy Settings > Import/Export CA Certificate > Export Certificate in DER format** — save to `serve/ca.crt`
2. On the device, browse to `http://GATEWAY_IP/ca.crt` and install it as a trusted CA
3. Burp will now be able to intercept HTTPS

Any file placed in `serve/` is served to the device over HTTP. Combines with **`-s`** to give the device internet while proxying: `./proxlink.sh -i eth2 -s eth0 -b`.

### Internet sharing allowlist (`-o`)

When you share internet with **`-s`**, you can lock the device down to a single destination:

- `-o 203.0.113.10` — only allow traffic to that IP.
- `-o example.com` — resolve the domain once, use the first IPv4, and only allow that.

Return traffic (RELATED,ESTABLISHED) is still allowed back in.

### Credential capture

Devices (kiosks, medical gear, etc.) sometimes send NTLM, HTTP basic, SQL or SMB auth over the wire. Press **`c`** to capture traffic for 60 seconds, then run **PCredz** or **NetCredz** on the pcap if installed. Extracted creds are appended to **`creds/creds.log`** with a timestamp and a **\*\*\* CREDENTIALS FOUND \*\*\*** line. Raw pcaps are kept under `creds/`. This is passive only (no LLMNR/NBT-NS poisoning like Responder). If no extractor is installed, the pcap is still saved; run e.g. `pcredz -f creds/capture_<ts>.pcap -o <dir>` manually.

## Examples

**DHCP only on `eth2`, default subnet `10.0.0.0/24`:**

```bash
sudo ./proxlink.sh -i eth2
```

**DHCP on `eth2` with custom subnet `10.16.75.0/24`:**

```bash
sudo ./proxlink.sh -i eth2 -p 10.16.75
```

**DHCP on `eth2` and share internet from `eth0`:**

```bash
sudo ./proxlink.sh -i eth2 -s eth0
```

**Device on VLAN 42:**

```bash
sudo ./proxlink.sh -i eth2 -v 42
```

**DNS spoofing + rolling pcap (capture everything, redirect all DNS to yourself):**

```bash
sudo ./proxlink.sh -i eth2 -D -r
```

**Redirect device traffic to Burp (auto-generates and serves CA cert):**

```bash
sudo ./proxlink.sh -i eth2 -b
```

**Internet sharing + Burp + rolling pcap (full interception session):**

```bash
sudo ./proxlink.sh -i eth2 -s eth0 -b -r
```

**Custom prefix and internet sharing:**

```bash
sudo ./proxlink.sh -i eth2 -p 192.168.42 -s wlan0
```

## When this might still not connect

- **Device sends no traffic** — Static-IP detection only sees what the device sends. If it's completely passive until it gets a packet first, press **`d`** after it's powered and wait; or try pinging common gateways (e.g. `ping 192.168.1.1`) from another terminal while **`d`** is capturing.
- **Wrong 15-second window** — Device might only ARP on boot or rarely. Run **`d`** right after connecting/waking the device, or run it a few times.
- **VLAN** — If the device is on a VLAN and your interface isn't, you won't see its traffic. Find the VLAN ID from switch documentation or a managed switch port config, then use `-v <id>`.
- **Non-/24 subnet** — Everything assumes /24. If the device is on e.g. 10.0.0.0/25 or 172.16.0.0/16, the suggested `-p` or alias might not put you on the same logical subnet; adjust manually (e.g. `ip addr add` with the right CIDR).
- **Device is the ".1" or ".254"** — When you rerun with `-p`, the script sets your IP to `PREFIX.1`; if the device is also `.1`, you get an IP conflict. Alias IPs use `.254` to reduce that; if the device is `.254`, add a different host manually.
- **IPv6 only** — The script is IPv4-only (DHCP, ARP, detection). It won't assign or detect IPv6-only devices.
- **Link-local (169.254.x.x)** — Devices that fall back to APIPA might be detected and you can add an alias in 169.254.x.x, but manual `ip addr add 169.254.1.1/16 dev …` and testing is sometimes needed.
- **Firewall / host hardening** — You can be on the right subnet and have an IP, but the device might drop your connections (host firewall, only listening on a specific interface, or no services listening).
- **DHCP options** — Some devices need specific DHCP options (e.g. Option 66/150 for TFTP). This setup uses a minimal dnsmasq config; the device may get an IP but not fully "boot" until you add the right options in dnsmasq.

## Notes

- **Root required** — Everything except `-h` exits with an error if not run as root.
- **Paths are script-relative** — `creds/`, `logs/`, `serve/` and `ca/` are created next to `proxlink.sh`, not in your current directory, so you can run it by absolute path from anywhere. (dnsmasq is started by systemd with a working directory of `/`, so relative paths in its config don't resolve.)
- **File ownership** — Output directories are mode `700` and chowned to the user who invoked `sudo`, so captures stay private to you but still open in Wireshark without root.
- **Backup** — Writes a custom config to `/etc/dnsmasq.d/custom-dhcp.conf` and backs up `/etc/dnsmasq.conf` to `/etc/dnsmasq.conf.bak` (only on first run — won't overwrite an existing backup).
- **Other DHCP servers are stopped** — At startup the script stops `dnsmasq`, `dhclient` and `isc-dhcp-server` so nothing competes for the link. This is deliberately broad: if you run **libvirt or LXD**, their `dnsmasq` is stopped too and VM networking will need restarting afterwards. On exit only the unit this script started is stopped.
- **IP forwarding** — `-s`/`-b` enable `net.ipv4.ip_forward` and cleanup restores whatever the host had before, rather than forcing `0` (Docker, libvirt and VPNs need it on).
- **Cleanup** — On exit (Ctrl+C or SIGTERM), the script stops dnsmasq, removes `custom-dhcp.conf`, removes any alias IPs and VLAN subinterfaces added during the session, kills background processes (rolling pcap, CA server, device watcher), removes its temp directory, and removes the NAT/forward/redirect rules it added.
- **Non-interactive use** — If stdin is closed (e.g. backgrounded), the script keeps the DHCP server and captures running and holds until signalled instead of exiting.
- **Interface names** — Use your actual interface names (e.g. `eth0`, `enp0s3`, `wlan0`). List them with `ip link`.
- **IPv4 only** — DHCP, ARP scanning and detection are all IPv4.

## License

MIT — see [LICENSE](LICENSE).
