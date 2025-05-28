#!/usr/bin/env bash
#
# dyn-iptables-debian.sh
# Debian adaptation of dyn-iptables:
#  - checks for required commands on startup
#  - detects & refuses to run if nftables is active
#  - forces iptables-legacy backend to avoid "iptables-nft" conflicts
#  - dynamic IP updates + cron job installation
#

set -euo pipefail

#####################################
# Configuration
#####################################

# Minimum commands we need to exist
REQUIRED_CMDS=(bash dig perl grep cut tail mkdir chmod crontab dirname basename hostname date sleep)

# Default cron interval (minutes)
CRON_MINUTES=15

# Storage for last seen IP
CONFDIR="/root/.dyn-iptables"

# IPTables chain to modify
CHAIN="INPUT"

# Where to save persistent IPv4 rules (Debian standard)
RULES_FILE="/etc/iptables/rules.v4"

# Logging
LOGDIR="/var/log"
LOGFILE="dyn-iptables.log"

#####################################
# Helper functions
#####################################

# Check that all required commands exist
check_dependencies() {
  local miss=()
  for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      miss+=("$cmd")
    fi
  done
  if [ ${#miss[@]} -gt 0 ]; then
    echo "ERROR: Missing required commands: ${miss[*]}"
    exit 1
  fi
}

# Detect if nftables service is running
check_nftables() {
  if systemctl is-active --quiet nftables; then
    echo "ERROR: nftables is active. Please disable nftables before using this script."
    exit 1
  fi
  # also detect any leftover tables
  if command -v nft &>/dev/null && nft list tables &>/dev/null; then
    if [ -n "$(nft list tables)" ]; then
      echo "ERROR: nftables has active tables. Please flush/disable nftables first."
      exit 1
    fi
  fi
}

# Force use of iptables-legacy on Debian
select_iptables_backend() {
  # Detect if iptables binary is nft-based
  if iptables --version 2>&1 | grep -qi 'nf_tables'; then
    if command -v iptables-legacy &>/dev/null && command -v iptables-save-legacy &>/dev/null; then
      IPTABLES_CMD=iptables-legacy
      IPTABLES_SAVE_CMD=iptables-save-legacy
    else
      echo "ERROR: nftables-backend detected but iptables-legacy is missing."
      exit 1
    fi
  else
    IPTABLES_CMD=iptables
    IPTABLES_SAVE_CMD=iptables-save
  fi
}

# Write a timestamped log message
log_msg() {
  local msg="$1"
  local timestamp
  timestamp=$("$DATE_CMD" +'%b %d %T')
  echo "$timestamp $(hostname) dyn-iptables: $msg" >> "$LOGDIR/$LOGFILE"
}

#####################################
# Main dynamic-IP + iptables logic
#####################################

build_firewall() {
  mkdir -p "$CONFDIR"
  chmod 700 "$CONFDIR"

  local host="$1"
  local proto="$2"
  local ports="$3"
  local ip_file="$CONFDIR/ipaddr_$host"

  echo "Resolving $host..."
  local newip
  newip=$("$DIG_CMD" @8.8.8.8 +short "$host" | tail -n1) \
    || { echo "ERROR: DNS lookup failed"; exit 1; }

  if [[ -z "$newip" ]]; then
    echo "ERROR: Could not find IP for $host"
    exit 1
  fi

  # find existing rule numbers for old & new IP
  local oldip old_rule new_rule
  if [[ -f "$ip_file" ]]; then
    oldip=$(cat "$ip_file")
    old_rule=$($IPTABLES_CMD -L "$CHAIN" -n --line-numbers \
      | awk -v ip="$oldip" -v p="$proto" '$0 ~ p && $0 ~ ip {print $1}')
  fi
  new_rule=$($IPTABLES_CMD -L "$CHAIN" -n --line-numbers \
    | awk -v ip="$newip" -v p="$proto" '$0 ~ p && $0 ~ ip {print $1}')

  # prepare multiport flag
  if [[ "$ports" =~ [,|:] ]]; then
    multi="-m multiport --dports $ports"
  else
    multi="--dport $ports"
  fi

  # Compare and update rules
  if [[ -n "$old_rule" && -n "$new_rule" ]]; then
    if [[ "$old_rule" != "$new_rule" ]]; then
      $IPTABLES_CMD -D "$CHAIN" "$old_rule"
      log_msg "Deleted old $proto rule for $oldip"
      $IPTABLES_CMD -A "$CHAIN" -s "$newip"/32 -p "$proto" $multi -j ACCEPT
      log_msg "Appended new $proto rule for $newip"
    else
      # same line-number, rewrite just in case ports changed
      $IPTABLES_CMD -R "$CHAIN" "$new_rule" -s "$newip"/32 -p "$proto" $multi -j ACCEPT
      log_msg "Replaced existing $proto rule at line $new_rule for $newip"
    fi
  elif [[ -n "$old_rule" && -z "$new_rule" ]]; then
    $IPTABLES_CMD -R "$CHAIN" "$old_rule" -s "$newip"/32 -p "$proto" $multi -j ACCEPT
    log_msg "Replaced old-rule #$old_rule ($oldip) → new IP $newip"
  elif [[ -z "$old_rule" && -n "$new_rule" ]]; then
    $IPTABLES_CMD -R "$CHAIN" "$new_rule" -s "$newip"/32 -p "$proto" $multi -j ACCEPT
    log_msg "Updated rule #$new_rule to ensure ports $ports for $newip"
  else
    $IPTABLES_CMD -A "$CHAIN" -s "$newip"/32 -p "$proto" $multi -j ACCEPT
    log_msg "Appended new $proto rule for $newip"
  fi

  echo "$newip" > "$ip_file"
  $IPTABLES_SAVE_CMD > "$RULES_FILE"
}

install_cron() {
  local host="$1" proto_flag="$2" ports="$3"
  local tmp=$(mktemp)
  crontab -u root -l > "$tmp" 2>/dev/null || true

  # remove any existing dyn-iptables line for this host+proto
  grep -v "dyn-iptables-debian.sh.*-H $host.*$proto_flag" "$tmp" > "${tmp}.new" && mv "${tmp}.new" "$tmp"

  # append new cron job
  echo "*/$CRON_MINUTES * * * * /usr/bin/env bash /opt/scripts/dyn-iptables-debian.sh -H $host $proto_flag $ports > /dev/null 2>&1" >> "$tmp"
  crontab -u root "$tmp"
  rm -f "$tmp"

  echo "Cron job installed: every $CRON_MINUTES minutes for $host [$proto_flag $ports]"
}

#####################################
# Argument parsing
#####################################

show_usage() {
  cat <<EOF
Usage: $0 -H <hostname> (-TP <tcp_ports> | -UP <udp_ports>) [-M <minutes>]

  -H   hostname to monitor
  -TP  comma/range list of TCP ports
  -UP  comma/range list of UDP ports
  -M   cron interval in minutes (default $CRON_MINUTES)

Example:
  $0 -H myhost.dyndns.org -TP 22,80,443 -M 30
EOF
  exit 1
}

# ensure root
if (( EUID != 0 )); then
  echo "ERROR: must be run as root"
  exit 1
fi

# initial checks
check_dependencies
check_nftables
select_iptables_backend

# locate tools explicitly
DIG_CMD=$(command -v dig)
DATE_CMD=$(command -v date)

# parse flags
if [ $# -eq 0 ]; then show_usage; fi
while [[ $# -gt 0 ]]; do
  case $1 in
    -H) HOST="$2"; shift 2 ;;
    -M) CRON_MINUTES="$2"; shift 2 ;;
    -TP) PROTO="tcp"; PROTO_FLAG="-TP"; PORTS="$2"; shift 2 ;;
    -UP) PROTO="udp"; PROTO_FLAG="-UP"; PORTS="$2"; shift 2 ;;
    -h|--help) show_usage ;;
    *) echo "Unknown option: $1"; show_usage ;;
  esac
done

if [[ -z "${HOST:-}" || -z "${PROTO:-}" ]]; then
  show_usage
fi

#####################################
# Run
#####################################

build_firewall "$HOST" "$PROTO" "$PORTS"
install_cron "$HOST" "$PROTO_FLAG" "$PORTS"

exit 0
