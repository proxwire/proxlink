#!/bin/bash
set -o pipefail

# Captures can contain credentials — keep everything this script writes private.
umask 077

# Variables
INTERFACE="eth2"
DHCP_RANGE="10.0.0.3,10.0.0.200,12h"
INITIAL_STATIC_IP="10.0.0.1"
PREFIX_LEN=24
DETECT_STATIC_DURATION=15
CRED_CAPTURE_DURATION=60
# Absolute, and anchored to the script rather than the caller's cwd: dnsmasq is
# launched by systemd with cwd "/", so a relative log-facility path makes it
# refuse to start outright.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CREDS_DIR="$SCRIPT_DIR/creds"
LOGS_DIR="$SCRIPT_DIR/logs"
SERVE_DIR="$SCRIPT_DIR/serve"
CA_DIR="$SCRIPT_DIR/ca"
INTERNET_INTERFACE=""
NETWORK_PREFIX="10.0.0"
SHARE_INTERNET=0
DEFAULT_BURP_PORT=8080
BURP_PORT=$DEFAULT_BURP_PORT
BURP_ENABLED=0
ALLOW_DEST=""
ALLOW_IP=""
VLAN_ID=""
VLAN_IFACE=""
DNS_SPOOF=0
ROLLING_PCAP=0
ROLLING_DURATION=300   # Seconds per rolling pcap chunk
ROLLING_COUNT=12       # Max rolling pcap files to keep (~1hr at 5min chunks)
ROLLING_TCPDUMP_PID=""
RUN_TMPDIR=""
DEVICE_FIFO=""
DHCP_HOOK=""
DEVICE_WATCHER_PID=""
CA_SERVER_PID=""
CLEANED_UP=0
ADDED_ALIASES=()
DNSMASQ_CONF="/etc/dnsmasq.d/custom-dhcp.conf"
ORIG_IP_FORWARD=""

# ── Cyberpunk 2077 palette ──────────────────────────────────────────────────
# Signature neon yellow, cyan and hot magenta on black, red for alerts. Colour
# is emitted only to a real terminal (and honours NO_COLOR), so piped output and
# the dnsmasq/pcap logs never get polluted with escape codes.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_YEL=$'\033[38;5;226m'   # CP2077 signature yellow
    C_CYN=$'\033[38;5;51m'    # neon cyan
    C_MAG=$'\033[38;5;198m'   # hot magenta / pink
    C_GRN=$'\033[38;5;48m'    # matrix green
    C_RED=$'\033[38;5;196m'   # alert red
    C_DIM=$'\033[38;5;244m'   # dim grey
    C_BLD=$'\033[1m'
    C_RST=$'\033[0m'
else
    C_YEL=""; C_CYN=""; C_MAG=""; C_GRN=""; C_RED=""; C_DIM=""; C_BLD=""; C_RST=""
fi

pl_msg() { echo "    ${C_YEL}${C_BLD}>>${C_RST} $*"; }
pl_err() { echo "    ${C_RED}${C_BLD}>> ERROR:${C_RST} ${C_RED}$*${C_RST}" >&2; }

# Remove only the firewall rules this script adds. Called once before setup to
# clear leftovers from a previous run, and again on exit. Kept separate from
# cleanup() so the pre-setup call cannot tear down state setup just built.
reset_firewall_rules() {
    if [[ -n "$INTERNET_INTERFACE" ]]; then
        iptables -t nat -D POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE 2>/dev/null
        if [[ -n "$ALLOW_IP" ]]; then
            iptables -D FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -d "$ALLOW_IP" -j ACCEPT 2>/dev/null
            iptables -D FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -j DROP 2>/dev/null
        else
            iptables -D FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT 2>/dev/null
        fi
        iptables -D FORWARD -i "$INTERNET_INTERFACE" -o "$INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    fi
    if [[ "$BURP_ENABLED" -eq 1 ]]; then
        iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 80 ! -d "$INITIAL_STATIC_IP" -j REDIRECT --to-port "$BURP_PORT" 2>/dev/null
        iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port "$BURP_PORT" 2>/dev/null
    fi
}

# Output is written by root but handed to whoever invoked sudo: mode 700 keeps
# captured credentials away from other local accounts, while the ownership means
# pcaps open in Wireshark without sudo.
own_as_invoker() {
    [[ -n "${SUDO_UID:-}" ]] || return 0
    chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$@" 2>/dev/null
}

make_output_dir() {
    mkdir -p "$1" || return 1
    chmod 700 "$1"
    own_as_invoker "$1"
}

# Records the host's current value the first time it is called so cleanup can
# put it back exactly as it was.
enable_ip_forwarding() {
    [[ -z "$ORIG_IP_FORWARD" ]] && ORIG_IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

# Setup-time only: clears any other DHCP server that would compete for the
# link. Deliberately broad — note it also stops a libvirt/LXD dnsmasq if one
# is running on this host.
clear_competing_dhcp() {
    systemctl stop dnsmasq 2>/dev/null
    pkill -f dhclient 2>/dev/null
    pkill -f dnsmasq 2>/dev/null
    pkill -f isc-dhcp-server 2>/dev/null
}

cleanup() {
    [[ $CLEANED_UP -eq 1 ]] && return
    CLEANED_UP=1
    echo ""
    pl_msg "cleaning up..."
    reset_firewall_rules
    # Restore the host's original setting rather than forcing 0 — other things
    # (Docker, libvirt, a VPN) may legitimately need forwarding enabled.
    if [[ -n "$ORIG_IP_FORWARD" ]]; then
        sysctl -w "net.ipv4.ip_forward=$ORIG_IP_FORWARD" >/dev/null
    fi
    for alias in "${ADDED_ALIASES[@]}"; do
        ip addr del "$alias" dev "$INTERFACE" 2>/dev/null
    done
    # Rolling pcaps and the DNS log are written by root while running.
    own_as_invoker "$CREDS_DIR" "$LOGS_DIR"
    [[ -n "$ROLLING_TCPDUMP_PID" ]]  && kill "$ROLLING_TCPDUMP_PID" 2>/dev/null
    [[ -n "$CA_SERVER_PID" ]]       && kill "$CA_SERVER_PID" 2>/dev/null
    [[ -n "$DEVICE_WATCHER_PID" ]]  && kill "$DEVICE_WATCHER_PID" 2>/dev/null
    exec 3>&-  # Close FIFO write end so the watcher's reader gets EOF and exits
    [[ -n "$VLAN_IFACE" ]] && ip link del "$VLAN_IFACE" 2>/dev/null
    rm -f "$DNSMASQ_CONF"
    [[ -n "$RUN_TMPDIR" ]] && rm -rf "$RUN_TMPDIR"
    # Stop only the unit this script started; no broad pkill, which would take
    # down an unrelated libvirt/LXD dnsmasq along with it.
    systemctl stop dnsmasq 2>/dev/null
    pl_msg "cleanup complete."
}

usage() {
    cat <<USAGE
Usage: $(basename "$0") [-p prefix] [-i interface] [-s internet_interface]
                     [-b [port]] [-o allow_dest] [-v vlan_id] [-D] [-r]

  -p <X.Y.Z>   Network prefix for the DHCP subnet (default: $NETWORK_PREFIX)
  -i <iface>   Interface to serve DHCP on (default: $INTERFACE)
  -s <iface>   Share internet from this interface via NAT
  -b [port]    Redirect device 80/443 to a Burp proxy (default port: $DEFAULT_BURP_PORT)
  -o <dest>    With -s, only allow device traffic to this IP/hostname
  -v <id>      Create an 802.1Q VLAN subinterface (e.g. -v 42 on eth2 -> eth2.42)
  -D           Spoof all DNS queries back to this machine
  -r           Record rolling background pcap (${ROLLING_DURATION}s chunks, last ${ROLLING_COUNT} kept)
  -h           Show this help

While running: Enter=scan  d=detect static IPs  c=capture creds  l=dns log  Ctrl+C=exit
USAGE
}

ORIGINAL_ARGS=("$@")

# bash getopts cannot express an optional option-argument, so a bare "-b" would
# otherwise swallow the following flag (or fail outright). Supply the default
# port only when "-b" is not already followed by one.
normalized_args=()
argc=$#
for ((n = 1; n <= argc; n++)); do
    arg="${!n}"
    if [[ "$arg" == "-b" ]]; then
        next_idx=$((n + 1))
        if [[ "${!next_idx:-}" =~ ^[0-9]+$ ]]; then
            normalized_args+=("-b" "${!next_idx}")
            ((n++))
        else
            normalized_args+=("-b" "$DEFAULT_BURP_PORT")
        fi
    else
        normalized_args+=("$arg")
    fi
done
set -- "${normalized_args[@]}"

while getopts "p:i:s:b:o:v:Drh?" opt; do
  case $opt in
    p)
      NETWORK_PREFIX="$OPTARG"
      if ! [[ "$NETWORK_PREFIX" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        pl_err "network prefix must be in the form X.Y.Z (e.g. 10.16.75)"
        exit 1
      fi
      ;;
    i) INTERFACE="$OPTARG";;
    s)
      SHARE_INTERNET=1
      INTERNET_INTERFACE="$OPTARG"
      if ! ip link show "$INTERNET_INTERFACE" >/dev/null 2>&1; then
        pl_err "interface $INTERNET_INTERFACE does not exist"
        exit 1
      fi
      ;;
    b)
      BURP_ENABLED=1
      BURP_PORT="$OPTARG"
      if ! [[ "$BURP_PORT" =~ ^[0-9]+$ ]] || [[ "$BURP_PORT" -lt 1 ]] || [[ "$BURP_PORT" -gt 65535 ]]; then
        pl_err "burp port must be 1-65535 (got: $BURP_PORT)"
        exit 1
      fi
      ;;
    o) ALLOW_DEST="$OPTARG";;
    v)
      VLAN_ID="$OPTARG"
      if ! [[ "$VLAN_ID" =~ ^[0-9]+$ ]] || [[ "$VLAN_ID" -lt 1 ]] || [[ "$VLAN_ID" -gt 4094 ]]; then
        pl_err "VLAN ID must be 1-4094"
        exit 1
      fi
      ;;
    D) DNS_SPOOF=1;;
    r) ROLLING_PCAP=1;;
    h) usage; exit 0;;
    ?) usage; exit 1;;
  esac
done
shift $((OPTIND - 1))

if [[ $# -gt 0 ]]; then
    pl_err "unexpected argument: $1"
    usage
    exit 1
fi

if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    pl_err "interface $INTERFACE does not exist"
    pl_msg "available: $(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')"
    exit 1
fi

if [[ -n "$ALLOW_DEST" && $SHARE_INTERNET -eq 0 ]]; then
    pl_err "-o requires -s (an allowlist only applies to shared internet)"
    exit 1
fi

# Privileged work starts here — arguments and -h are handled above so they
# work without sudo.
if [[ $EUID -ne 0 ]]; then
    pl_err "this script must be run as root (try: sudo $0 ${ORIGINAL_ARGS[*]})"
    exit 1
fi

RUN_TMPDIR=$(mktemp -d /tmp/proxlink.XXXXXX) || { pl_err "could not create temp dir"; exit 1; }
DEVICE_FIFO="$RUN_TMPDIR/notify.fifo"
DHCP_HOOK="$RUN_TMPDIR/dhcp-hook.sh"

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

DHCP_RANGE="${NETWORK_PREFIX}.3,${NETWORK_PREFIX}.200,12h"
INITIAL_STATIC_IP="${NETWORK_PREFIX}.1"

echo ""
echo "    ${C_MAG}::${C_RST} ${C_YEL}${C_BLD}proxlink${C_RST} ${C_MAG}::${C_RST} ${C_CYN}initiating personal link...${C_RST}"
missing=""
command -v dnsmasq  &>/dev/null || missing="$missing dnsmasq"
command -v arp-scan &>/dev/null || missing="$missing arp-scan"
command -v tcpdump  &>/dev/null || missing="$missing tcpdump"
if [[ -n "$missing" ]]; then
    pl_err "missing dependency:$missing"
    pl_msg "install: apt-get install -y dnsmasq arp-scan tcpdump"
    exit 1
fi
if [[ $BURP_ENABLED -eq 1 || $SHARE_INTERNET -eq 1 ]]; then
    command -v iptables &>/dev/null || { pl_err "missing: iptables (required for -s/-b)"; exit 1; }
fi
if [[ -n "$ALLOW_DEST" ]]; then
    if [[ "$ALLOW_DEST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ALLOW_IP="$ALLOW_DEST"
    else
        ALLOW_IP=$(getent ahostsv4 "$ALLOW_DEST" | awk 'NR==1 {print $1}')
        if [[ -z "$ALLOW_IP" ]]; then
            pl_err "could not resolve allowlist destination: $ALLOW_DEST"
            exit 1
        fi
    fi
    pl_msg "internet allowlist: $ALLOW_DEST ($ALLOW_IP)"
fi
pl_msg "dependencies OK"
echo ""

# ── Feature functions ─────────────────────────────────────────────────────────

detect_static_ips() {
    local tmpcap
    tmpcap=$(mktemp)
    echo "Listening on $INTERFACE for ${DETECT_STATIC_DURATION}s (plug in the device or wake it now)..."
    timeout "$DETECT_STATIC_DURATION" tcpdump -i "$INTERFACE" -n -q 2>/dev/null > "$tmpcap" || true
    local subnets=()
    local ip prefix
    while read -r ip; do
        [[ -z "$ip" ]] && continue
        [[ "$ip" == "$INITIAL_STATIC_IP" ]] && continue
        [[ "$ip" == ${NETWORK_PREFIX}.* ]] && continue
        [[ "$ip" == 0.0.0.0 ]] && continue
        [[ "$ip" =~ ^(127|22[4-9]|23[0-9]|255)\. ]] && continue
        prefix="${ip%.*}"
        [[ " ${subnets[*]} " == *" $prefix "* ]] && continue
        subnets+=("$prefix")
    done < <(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$tmpcap" 2>/dev/null || true)
    rm -f "$tmpcap"
    if [[ ${#subnets[@]} -eq 0 ]]; then
        echo "No other subnets detected. Device might use DHCP on $NETWORK_PREFIX.0/24, or try again with device active."
        return
    fi
    echo "${C_CYN}── Possible static-IP device(s) on different subnet(s) ──${C_RST}"
    for prefix in "${subnets[@]}"; do
        printf "  ${C_CYN}Subnet:${C_RST} ${C_MAG}%s.0/24${C_RST}  -> rerun with:  ${C_YEL}-p %s${C_RST}\n" "$prefix" "$prefix"
    done
    echo "${C_CYN}──${C_RST}"
    echo "Add these as alias IPs on $INTERFACE so you can reach them without rerunning? (y/n)"
    read -r add_aliases
    if [[ "$add_aliases" == [yY] || "$add_aliases" == [yY][eE][sS] ]]; then
        for prefix in "${subnets[@]}"; do
            local alias_cidr="$prefix.254/24"
            if ip addr add "$alias_cidr" dev "$INTERFACE" 2>/dev/null; then
                ADDED_ALIASES+=("$alias_cidr")
                echo "  Added $alias_cidr on $INTERFACE."
            fi
        done
        echo "You can now scan with arp-scan or connect to devices on those subnets. Aliases are removed on exit."
    fi
}

capture_creds() {
    make_output_dir "$CREDS_DIR"
    local ts run_dir pcap
    ts=$(date +%Y%m%d-%H%M%S)
    run_dir="$CREDS_DIR/run_$ts"
    pcap="$CREDS_DIR/capture_$ts.pcap"
    echo "Capturing on $INTERFACE for ${CRED_CAPTURE_DURATION}s... (trigger device logins/auth if you can)"
    timeout "$CRED_CAPTURE_DURATION" tcpdump -i "$INTERFACE" -w "$pcap" 2>/dev/null
    echo "Capture done. Extracting credentials..."
    mkdir -p "$run_dir"
    cp "$pcap" "$run_dir/capture.pcap"
    local extracted=0
    if command -v pcredz &>/dev/null; then
        (cd "$run_dir" && pcredz -f capture.pcap -o . 2>/dev/null) || (cd "$run_dir" && pcredz -f capture.pcap 2>/dev/null)
        extracted=1
    elif command -v Pcredz &>/dev/null; then
        (cd "$run_dir" && Pcredz -f capture.pcap -o . 2>/dev/null) || (cd "$run_dir" && Pcredz -f capture.pcap 2>/dev/null)
        extracted=1
    elif command -v netcredz &>/dev/null; then
        (cd "$run_dir" && netcredz -f capture.pcap 2>/dev/null)
        extracted=1
    else
        for pc in /usr/share/pcredz/Pcredz /opt/pcredz/Pcredz; do
            if [[ -f "$pc" ]]; then
                (cd "$run_dir" && python3 "$pc" -f capture.pcap -o . 2>/dev/null) || (cd "$run_dir" && python3 "$pc" -f capture.pcap 2>/dev/null)
                extracted=1
                break
            fi
        done
    fi
    local found=0
    local logfile="$CREDS_DIR/creds.log"
    # *.log covers PCredz's CredentialDump*.log; *.txt covers NTLMv1/NTLMv2/MSKerb.
    # Listing those names explicitly as well would append each match twice.
    for f in "$run_dir"/*.log "$run_dir"/*.txt; do
        [[ -s "$f" ]] || continue
        found=1
        {
            echo ""
            echo "=== $ts | $(basename "$f") ==="
            echo "*** CREDENTIALS FOUND ***"
            cat "$f"
        } >> "$logfile"
    done
    own_as_invoker "$CREDS_DIR"
    if [[ $found -eq 1 ]]; then
        echo "${C_RED}${C_BLD}*** CREDENTIALS FOUND! ***${C_RST} ${C_YEL}stored in $logfile${C_RST}"
    elif [[ $extracted -eq 1 ]]; then
        echo "No credentials in this capture. Pcap saved at $pcap"
    else
        echo "No credential extractor found (install PCredz or NetCredz). Pcap saved at $pcap"
        echo "  Run manually: pcredz -f $pcap -o <outdir>"
    fi
}

scan_network() {
    arp-scan -I "$INTERFACE" --localnet 2>/dev/null | grep -F "$NETWORK_PREFIX" || true
}

show_dns_log() {
    if [[ -f "$LOGS_DIR/dns.log" ]]; then
        echo "${C_CYN}── last 30 DNS queries ──${C_RST}"
        tail -n 30 "$LOGS_DIR/dns.log"
        echo "${C_CYN}──${C_RST}"
    else
        pl_msg "No DNS log yet (queries appear after the first device connects)."
    fi
}

# Rolling background capture: -G seconds per file, -W max files, strftime filename
start_rolling_pcap() {
    make_output_dir "$CREDS_DIR"
    pl_msg "rolling pcap: ${ROLLING_DURATION}s chunks, max ${ROLLING_COUNT} files -> $CREDS_DIR/"
    tcpdump -i "$INTERFACE" \
        -G "$ROLLING_DURATION" \
        -W "$ROLLING_COUNT" \
        -w "$CREDS_DIR/rolling_%Y%m%d-%H%M%S.pcap" 2>/dev/null &
    ROLLING_TCPDUMP_PID=$!
}

# Device watcher: dnsmasq calls DHCP_HOOK on every lease event.
# Handles both 'add' (new device) and 'old' (reconnect) so second connections
# are announced — dnsmasq only fires 'add' on a brand-new lease, 'old' on renewal.
# A named FIFO carries hook output to a background reader without polling or
# file-watching. FD 3 is kept open on the write end so hook writes never block
# and the reader never gets a premature EOF between connections.
start_device_watcher() {
    mkfifo "$DEVICE_FIFO"

    cat > "$DHCP_HOOK" << HOOKEOF
#!/bin/bash
ACTION="\$1"; MAC="\$2"; IP="\$3"; HOST="\${4:-}"
[[ "\$ACTION" == "add" || "\$ACTION" == "old" ]] && printf "%s %s %s %s\n" "\$ACTION" "\$MAC" "\$IP" "\$HOST" > "$DEVICE_FIFO"
HOOKEOF
    chmod +x "$DHCP_HOOK"

    # Read-write (3<>) rather than write-only (3>) is essential: opening a FIFO
    # write-only blocks until a reader attaches, and the reader below is started
    # after this line — write-only deadlocks here and the script never proceeds.
    # Holding this end open also stops hook writes from blocking and stops the
    # reader from seeing EOF between lease events.
    exec 3<>"$DEVICE_FIFO"

    (
        while read -r action mac ip host; do
            label="NEW"; [[ "$action" == "old" ]] && label="RECONNECT"
            lc="$C_CYN"; [[ "$action" == "old" ]] && lc="$C_MAG"
            printf "\n    ${C_YEL}${C_BLD}>>${C_RST} ${lc}${C_BLD}[%s DEVICE]${C_RST} ${C_YEL}%s${C_RST}  ${C_DIM}mac:${C_RST} %s%s\n" \
                "$label" "$ip" "$mac" "${host:+  ${C_DIM}host:${C_RST} $host}"
            scan_network
            printf "    ${C_YEL}${C_BLD}>>${C_RST} ${C_DIM}await input...${C_RST}\n"
        done
    ) < "$DEVICE_FIFO" &
    DEVICE_WATCHER_PID=$!

    pl_msg "device watcher: active (new + reconnecting devices announced automatically)"
}

# CA server: generate a self-signed CA cert and serve it over HTTP on the
# gateway IP. The Burp PREROUTING rule excludes the gateway IP on port 80 so
# the device can reach http://GATEWAY/ca.crt without going through Burp first.
start_ca_server() {
    if ! command -v python3 &>/dev/null; then
        pl_msg "CA server: python3 not found, skipping"
        return
    fi
    make_output_dir "$SERVE_DIR"
    make_output_dir "$CA_DIR"
    # Everything in SERVE_DIR is reachable by the device. A private key must
    # never live there — relocate any that does (e.g. left by an older run).
    for key in "$SERVE_DIR"/*.key "$SERVE_DIR"/*.pem; do
        [[ -f "$key" ]] || continue
        mv -f "$key" "$CA_DIR/" \
            && pl_err "moved $(basename "$key") out of $SERVE_DIR into $CA_DIR (private keys are never served)"
    done
    if [[ ! -f "$SERVE_DIR/ca.crt" ]]; then
        if command -v openssl &>/dev/null; then
            pl_msg "CA server: generating self-signed CA..."
            if openssl req -newkey rsa:2048 -nodes \
                    -keyout "$CA_DIR/ca.key" \
                    -x509 -days 365 \
                    -out "$SERVE_DIR/ca.crt" \
                    -subj "/CN=proxlink-ca/O=proxlink" 2>/dev/null; then
                chmod 600 "$CA_DIR/ca.key"
                pl_msg "CA server: cert -> $SERVE_DIR/ca.crt (key: $CA_DIR/ca.key, not served)"
            else
                pl_msg "CA server: openssl failed — place your CA manually at $SERVE_DIR/ca.crt"
            fi
        else
            pl_msg "CA server: openssl not found — place your CA at $SERVE_DIR/ca.crt"
        fi
    fi
    python3 -m http.server --bind "$INITIAL_STATIC_IP" --directory "$SERVE_DIR" 80 2>/dev/null &
    CA_SERVER_PID=$!
    pl_msg "CA server: http://$INITIAL_STATIC_IP/ca.crt"
    pl_msg "CA server: Burp import — Proxy > Proxy Settings > Import/Export CA Certificate"
}

# ── Setup ─────────────────────────────────────────────────────────────────────

pl_msg "clearing existing dhcp processes..."
clear_competing_dhcp

# Drop any rules a previous run left behind before adding our own.
reset_firewall_rules

if [[ -f /etc/dnsmasq.conf && ! -f /etc/dnsmasq.conf.bak ]]; then
    pl_msg "backing up dnsmasq.conf..."
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
fi

# VLAN subinterface: create eth2.42 from eth2 with 802.1Q tag ID, then use it
if [[ -n "$VLAN_ID" ]]; then
    VLAN_IFACE="${INTERFACE}.${VLAN_ID}"
    pl_msg "vlan: creating $VLAN_IFACE (id $VLAN_ID on $INTERFACE)"
    ip link add link "$INTERFACE" name "$VLAN_IFACE" type vlan id "$VLAN_ID" 2>/dev/null \
        || { pl_err "failed to create VLAN subinterface $VLAN_IFACE"; exit 1; }
    ip link set "$VLAN_IFACE" up
    INTERFACE="$VLAN_IFACE"
fi

# dnsmasq config — always enables DNS query logging and the device watcher hook
make_output_dir "$LOGS_DIR"
pl_msg "dhcp range: $NETWORK_PREFIX.3-$NETWORK_PREFIX.200 on $INTERFACE"
{
    echo "interface=$INTERFACE"
    echo "dhcp-range=$DHCP_RANGE"
    echo "dhcp-script=$DHCP_HOOK"
    echo "log-queries"
    echo "log-facility=$LOGS_DIR/dns.log"
    [[ $DNS_SPOOF -eq 1 ]] && echo "address=/#/$INITIAL_STATIC_IP"
} > "$DNSMASQ_CONF"

pl_msg "interface $INTERFACE @ $INITIAL_STATIC_IP/$PREFIX_LEN"
ip addr flush dev "$INTERFACE"
ip addr add "$INITIAL_STATIC_IP/$PREFIX_LEN" dev "$INTERFACE"
ip link set "$INTERFACE" up

if [[ $SHARE_INTERNET -eq 1 ]]; then
    if [[ -n "$ALLOW_IP" ]]; then
        pl_msg "nat: $INTERNET_INTERFACE -> $INTERFACE (forwarding enabled, allow: $ALLOW_IP only)"
    else
        pl_msg "nat: $INTERNET_INTERFACE -> $INTERFACE (forwarding enabled)"
    fi
    enable_ip_forwarding
    iptables -t nat -A POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE
    if [[ -n "$ALLOW_IP" ]]; then
        iptables -A FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -d "$ALLOW_IP" -j ACCEPT
        iptables -A FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -j DROP
    else
        iptables -A FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT
    fi
    iptables -A FORWARD -i "$INTERNET_INTERFACE" -o "$INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# Burp redirect — port 80 rule excludes the gateway IP so the CA server
# on http://GATEWAY_IP/ stays directly reachable without going through Burp
if [[ $BURP_ENABLED -eq 1 ]]; then
    enable_ip_forwarding
    pl_msg "redirect: 80/443 -> port $BURP_PORT (start Burp in invisible mode on 0.0.0.0:$BURP_PORT)"
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 ! -d "$INITIAL_STATIC_IP" -j REDIRECT --to-port "$BURP_PORT"
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port "$BURP_PORT"
fi

# The watcher's FIFO and dhcp-script must exist before dnsmasq starts, or the
# first lease event fires against a missing hook.
start_device_watcher

pl_msg "starting dnsmasq..."
systemctl restart dnsmasq
if ! systemctl is-active --quiet dnsmasq; then
    pl_err "dnsmasq failed to start. Config: $DNSMASQ_CONF"
    journalctl -u dnsmasq -n 5 --no-pager 2>/dev/null | sed 's/^/       /'
    exit 1
fi

[[ $ROLLING_PCAP -eq 1 ]] && start_rolling_pcap
[[ $BURP_ENABLED -eq 1 ]] && start_ca_server
[[ $DNS_SPOOF   -eq 1 ]] && pl_msg "dns spoof: all queries -> $INITIAL_STATIC_IP"

# ── Banner ────────────────────────────────────────────────────────────────────

echo ""
echo "    ${C_MAG}::${C_RST} ${C_YEL}${C_BLD}proxlink${C_RST} ${C_MAG}::${C_RST}  ${C_CYN}═══${C_RST}  ${C_YEL}${C_BLD}[PERSONAL LINK ACTIVE]${C_RST}  ${C_CYN}═══${C_RST}  ${C_MAG}::${C_RST}"
printf "    ${C_YEL}${C_BLD}>>${C_RST} ${C_CYN}interface:${C_RST} ${C_MAG}%-8s${C_RST} ${C_DIM}|${C_RST} ${C_CYN}subnet:${C_RST} ${C_YEL}%s.0/%s${C_RST} ${C_DIM}|${C_RST} ${C_CYN}dhcp:${C_RST} ${C_GRN}ONLINE${C_RST}" "$INTERFACE" "$NETWORK_PREFIX" "$PREFIX_LEN"
if [[ $BURP_ENABLED -eq 1 ]]; then
    printf " ${C_DIM}|${C_RST} ${C_CYN}burp:${C_RST} ${C_YEL}%s${C_RST}\n" "$BURP_PORT"
else
    printf " ${C_DIM}|${C_RST} ${C_CYN}burp:${C_RST} ${C_DIM}--${C_RST}\n"
fi
[[ $SHARE_INTERNET -eq 1 ]] && pl_msg "internet sharing: $INTERNET_INTERFACE -> $INTERFACE"
[[ $DNS_SPOOF     -eq 1 ]] && pl_msg "dns spoof: ON -> $INITIAL_STATIC_IP  |  dns log: $LOGS_DIR/dns.log"
[[ $DNS_SPOOF     -eq 0 ]] && pl_msg "dns log: $LOGS_DIR/dns.log  (press l to tail)"
[[ $ROLLING_PCAP  -eq 1 ]] && pl_msg "rolling pcap: ON (pid $ROLLING_TCPDUMP_PID) -> $CREDS_DIR/"
[[ $BURP_ENABLED  -eq 1 ]] && pl_msg "CA cert: http://$INITIAL_STATIC_IP/ca.crt  (files: $SERVE_DIR/)"
echo ""

# ── Interactive loop ──────────────────────────────────────────────────────────

KEYS="${C_CYN}Enter${C_RST}=scan  ${C_CYN}d${C_RST}=detect static IPs  ${C_CYN}c${C_RST}=capture creds  ${C_CYN}l${C_RST}=dns log  ${C_DIM}(Ctrl+C=exit)${C_RST}"
pl_msg "$KEYS"
# `while read` (not `while true; do read`) so a closed stdin ends the loop
# instead of spinning at 100% CPU.
while read -r input; do
    case "$input" in
        d|D) detect_static_ips ;;
        c|C) capture_creds ;;
        l|L) show_dns_log ;;
        "")  echo "${C_CYN}scanning...${C_RST}"; scan_network ;;
        *)   pl_msg "$KEYS" ;;
    esac
done

# stdin closed (backgrounded or non-interactive): hold the session open so the
# DHCP server and background captures keep running until signalled.
pl_msg "stdin closed — holding session open (Ctrl+C or SIGTERM to exit)."
# `wait` on a background sleep, not a foreground `sleep`: bash defers trap
# handlers until the current foreground command finishes, so a plain
# `sleep 86400` would swallow Ctrl+C and skip cleanup entirely.
while :; do
    sleep 86400 &
    wait $! 2>/dev/null
done
