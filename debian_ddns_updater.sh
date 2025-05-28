#!/usr/bin/env bash
#
# dyn-iptables-debian.sh
# Debian adaptation of dyn-iptables:
#  - migrates existing nftables → iptables-legacy
#  - removes nftables, installs dependencies
#  - forces iptables-legacy backend
#  - dynamic IP lookup + visible cron job
#

set -euo pipefail

#####################################
# CONFIGURATION
#####################################

# Path & name of this script
SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")

# Debian packages to ensure present
DEBIAN_PKGS=(iptables iptables-persistent dnsutils perl cron)

# Commands that must then exist
REQUIRED_CMDS=(bash dig perl grep cut tail mkdir chmod crontab dirname basename hostname date sleep iptables iptables-save)

# Default cron interval in minutes
CRON_MINUTES=15

# Directory to store last-seen IP files
CONFDIR="/root/.dyn-iptables"

# IPTables chain to modify
CHAIN="INPUT"

# Where to save persistent IPv4 rules
RULES_FILE="/etc/iptables/rules.v4"

# Logging
LOGDIR="/var/log"
LOGFILE="dyn-iptables.log"


#####################################
# HELPER FUNCTIONS
#####################################

# Migrate nftables→legacy, install iptables-legacy & persistence,
# restore rules, merge any legacy backup, but never abort on missing pkgs.
migrate_and_cleanup() {
  echo "Backing up current nft-based rules…"
  iptables-save > /tmp/iptables-nft-backup.rules

  echo "Installing persistence, DNS- und Cron-Dependencies…"
  apt-get update
  apt-get install -y "${DEBIAN_PKGS[@]}"

  echo "Switching alternatives to nft-wrapper…"
  update-alternatives --set iptables      /usr/sbin/iptables-nft
  update-alternatives --set ip6tables     /usr/sbin/ip6tables-nft

  echo "Flushing **all** iptables-legacy tables (filter, nat, mangle, raw, security)…"
  if command -v iptables-legacy &>/dev/null; then
    for tbl in filter nat mangle raw security; do
      iptables-legacy -t "$tbl" -F 2>/dev/null || true
      iptables-legacy -t "$tbl" -X 2>/dev/null || true
      iptables-legacy -t "$tbl" -Z 2>/dev/null || true
    done
  fi

  echo "Restoring backup under nft-wrapper…"
  iptables-restore < /tmp/iptables-nft-backup.rules

  echo "Persisting to $RULES_FILE…"
  mkdir -p "$(dirname "$RULES_FILE")"
  iptables-save > "$RULES_FILE"
  log_msg "Migrated to nft-wrapper and persisted to $RULES_FILE"
}






# If nftables is installed, migrate & remove it
handle_nftables() {
  if dpkg-query -W -f='${Status}' nftables &>/dev/null | grep -q "install ok installed"; then
    echo "WARNING: Detected nftables package."
    read -p "Migrate rules to iptables-legacy and remove nftables? [y/N] " ans
    case "$ans" in
      [Yy]* )
        migrate_and_cleanup
        echo "Purging nftables..."
        apt-get purge -y nftables nftables-bin || true
        apt-get autoremove -y
        ;;
      * )
        echo "User chose not to remove nftables. Aborting."
        exit 1
        ;;
    esac
  fi
}

# Ensure all required commands exist
check_dependencies() {
  local miss=()
  for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      miss+=("$cmd")
    fi
  done

  if [ ${#miss[@]} -gt 0 ]; then
    echo "Missing commands: ${miss[*]}. Installing packages: ${DEBIAN_PKGS[*]}…"
    apt-get update
    apt-get install -y "${DEBIAN_PKGS[@]}" || {
      echo "Failed to install dependencies, aborting."
      exit 1
    }

    # Re-check
    miss=()
    for cmd in "${REQUIRED_CMDS[@]}"; do
      if ! command -v "$cmd" &>/dev/null; then
        miss+=("$cmd")
      fi
    done
    if [ ${#miss[@]} -gt 0 ]; then
      echo "ERROR: Still missing after install: ${miss[*]}"
      exit 1
    fi
  fi
}


# Pick legacy vs nft backend for iptables/iptables-save
select_iptables_backend() {
  IPTABLES_CMD=iptables-nft
  IPTABLES_SAVE_CMD=iptables-nft-save
}


# Timestamped logger
log_msg() {
  local msg="$1"
  local ts
  ts=$("$(command -v date)" +'%b %d %T')
  echo "$ts $(hostname) dyn-iptables: $msg" >> "$LOGDIR/$LOGFILE"
}


#####################################
# CORE: dynamic-IP + iptables update
#####################################
build_firewall() {
  local host="$1" proto="$2" ports="$3"
  local ip_file="$CONFDIR/ipaddr_$host"

  # Create work DIR
  mkdir -p "$CONFDIR" && chmod 700 "$CONFDIR"

  echo "Resolving $host…"
  local newip
  newip=$(dig @8.8.8.8 +short "$host" | tail -n1) || { echo "DNS lookup failed"; exit 1; }
  [[ -z "$newip" ]] && { echo "Could not resolve $host"; exit 1; }

  # Load old IP
  local oldip=""
  if [[ -f "$ip_file" ]]; then
    oldip=$(<"$ip_file")
  fi

  # Translate Ports in multiport- / single-port-Option 
  local multi
  if [[ "$ports" =~ [,|:] ]]; then
    multi="-m multiport --dports $ports"
  else
    multi="--dport $ports"
  fi

  # 1) Remove old rule, if IP changed
  if [[ -n "$oldip" && "$oldip" != "$newip" ]]; then
    if $IPTABLES_CMD -C "$CHAIN" -s "${oldip}/32" -p "$proto" $multi -j ACCEPT 2>/dev/null; then
      $IPTABLES_CMD -D "$CHAIN" -s "${oldip}/32" -p "$proto" $multi -j ACCEPT
      log_msg "Deleted old $proto rule for $oldip"
    fi
  fi

  # 2) Add new rules, if non-existend
  if ! $IPTABLES_CMD -C "$CHAIN" -s "${newip}/32" -p "$proto" $multi -j ACCEPT 2>/dev/null; then
    $IPTABLES_CMD -A "$CHAIN" -s "${newip}/32" -p "$proto" $multi -j ACCEPT
    log_msg "Appended new $proto rule for $newip"
  else
    log_msg "Rule for $newip already exists, no change"
  fi

  # 3) Update configuration files
  echo "$newip" > "$ip_file"
  mkdir -p "$(dirname "$RULES_FILE")"
  $IPTABLES_SAVE_CMD > "$RULES_FILE"
}



#####################################
# CRON INSTALLATION (visible in crontab -e)
#####################################
install_cron() {
  local host="$1" proto_flag="$2" ports="$3"
  local tmpfile
  tmpfile=$(mktemp)

  crontab -u root -l > "$tmpfile" 2>/dev/null || true

  # remove old lines for this script name + host
  grep -v "$SCRIPT_NAME.*-H $host.*$proto_flag" "$tmpfile" > "${tmpfile}.new" || true
  mv "${tmpfile}.new" "$tmpfile"

  # append new job
  echo "*/$CRON_MINUTES * * * * /usr/bin/env bash $SCRIPT_PATH -H $host $proto_flag $ports" \
    >> "$tmpfile"

  crontab -u root "$tmpfile"
  rm -f "$tmpfile"

  echo "Cron job installed: runs every $CRON_MINUTES min for $host [$proto_flag $ports]"
}


#####################################
# USAGE & ARG PARSING
#####################################
show_usage() {
  cat <<EOF
Usage: $0 -H <hostname> (-TP <tcp_ports> | -UP <udp_ports>) [-M <minutes>]

  -H   DDNS hostname
  -TP  TCP ports (comma or range)
  -UP  UDP ports
  -M   Cron interval in minutes (default $CRON_MINUTES)
EOF
  exit 1
}

(( EUID == 0 )) || { echo "Must be run as root"; exit 1; }

# 1) migration & nftables removal
handle_nftables

# 2) check deps
check_dependencies

# 3) pick legacy backend if needed
select_iptables_backend

# parse args
if [ $# -eq 0 ]; then show_usage; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    -H) HOST="$2"; shift 2 ;;
    -M) CRON_MINUTES="$2"; shift 2 ;;
    -TP) PROTO="tcp"; PROTO_FLAG="-TP"; PORTS="$2"; shift 2 ;;
    -UP) PROTO="udp"; PROTO_FLAG="-UP"; PORTS="$2"; shift 2 ;;
    -h|--help) show_usage ;;
    *) echo "Unknown: $1"; show_usage ;;
  esac
done

[[ -z "${HOST:-}" || -z "${PROTO:-}" ]] && show_usage

# run update + cron
build_firewall "$HOST" "$PROTO" "$PORTS"
install_cron    "$HOST" "$PROTO_FLAG" "$PORTS"

exit 0
