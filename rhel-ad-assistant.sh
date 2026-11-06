#!/usr/bin/env bash
# rhel-ad-assistant.sh
# Version 3.0.1-runtime-sanitization
#
# Self-contained Samba Active Directory Domain Controller assistant for
# Enterprise Linux-style systems.
#
# Primary DC targets:
#   - Rocky Linux 9 / 10
#   - AlmaLinux 9 / 10
#
# RHEL note:
#   Red Hat documents Samba AD Domain Controller operation as unsupported on
#   RHEL. This script therefore blocks provisioning on ID=rhel unless the
#   operator explicitly enables --allow-unsupported-rhel-dc and confirms the
#   unsupported boundary. No third-party repository is added automatically.
#
# Principles:
#   - detect before modify
#   - never reprovision an existing sam.ldb
#   - require a persistent/static DC address
#   - snapshot files and NetworkManager state before bootstrap changes
#   - validate installed Samba AD-DC capability before provisioning
#   - never disable SELinux to force a successful start
#   - use Samba internal DNS and require a validated external forwarder
#   - scope AD firewall openings to an operator-selected trusted CIDR
#   - use a dedicated systemd unit when the distribution does not provide one
#   - remain usable as one readable/editable Bash script

# Fail clearly when launched as "sh script.sh" (dash/busybox) or with an old Bash.
# Keep this block POSIX sh so non-Bash shells can parse and execute it.
if [ -z "${BASH_VERSION:-}" ]; then
    printf '%s\n' "This assistant requires Bash 4+. Run: sudo bash $0 --help" \
        "Este asistente requiere Bash 4+. Ejecuta: sudo bash $0 --help" >&2
    exit 2
fi
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    printf '%s\n' "Bash 4+ is required; found ${BASH_VERSION}." \
        "Se requiere Bash 4+; versión detectada: ${BASH_VERSION}." >&2
    exit 2
fi

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

SCRIPT_VERSION="3.0.1-runtime-sanitization"
PRODUCT_NAME="RHEL AD Control Plane"
MODE="interactive"
FORCE_NO_COLOR=0
UI_LANG="${RHEL_AD_LANG:-en}"

# Base state paths must be defined before any derived security/report paths.
# Keep this ordering safe under `set -u` so even --help and first-run startup
# cannot fail with an unbound STATE_DIR.
STATE_DIR="/var/lib/rhel-ad-assistant"
LOG_DIR="/var/log/rhel-ad-assistant"
BACKUP_ROOT="/var/backups/rhel-ad-assistant"

DEFENSE_DIR="${STATE_DIR}/defense"
DEFENSE_CONFIG="${DEFENSE_DIR}/defense.conf"
DEFENSE_TRUSTED="${DEFENSE_DIR}/trusted-ips.txt"
TELEGRAM_CONFIG="${DEFENSE_DIR}/telegram.conf"
DOMAIN_REPORT_DIR="${STATE_DIR}/reports/domain"
SSH_CONTROL_DIR="/run/radssh"
REMOTE_SERVICE_USER="adremote"
ALLOW_UNSUPPORTED_RHEL_DC=0
ALLOW_ISOLATED_DNS=0
EXTERNAL_DNS_PROBE="www.redhat.com"
ADMIN_USER="Administrator"
INITIAL_AUTH_USER="Administrator"
TIMEZONE="UTC"
NTP_POOL="pool.ntp.org"

REPORT_DIR="${STATE_DIR}/reports"
GPO_DIR="${STATE_DIR}/gpo"
GPO_BUILTIN_DIR="${GPO_DIR}/builtin"
GPO_CUSTOM_DIR="${GPO_DIR}/custom"
MIGRATION_DIR="${STATE_DIR}/migration"
IDS_STATE_DIR="${STATE_DIR}/ids"
IDS_REPORT_DIR="${IDS_STATE_DIR}/reports"
IDS_CONFIG="/etc/suricata/rhel-ad-assistant.yaml"
IDS_DROPIN="/etc/systemd/system/suricata.service.d/90-rhel-ad-assistant.conf"
IDS_EVE_DIR="/var/log/suricata"
IDS_EVE_GLOB="${IDS_EVE_DIR}/eve.json*"
IDS_DAILY_SERVICE="/etc/systemd/system/rhel-ad-ids-daily.service"
IDS_DAILY_TIMER="/etc/systemd/system/rhel-ad-ids-daily.timer"
REMOTE_OPS_DIR="${STATE_DIR}/remote-ops"
REMOTE_EVIDENCE_DIR="${REMOTE_OPS_DIR}/evidence"
REMOTE_OPS_LOG="${REMOTE_OPS_DIR}/operations.tsv"
CLI_LIBEXEC="/usr/local/libexec/rhel-ad-assistant"
CLI_LINK_DIR="/usr/local/sbin"
HEALTH_HELPER="/usr/local/libexec/rhel-ad-samba-health"
HEALTH_SERVICE="/etc/systemd/system/rhel-ad-samba-health.service"
CONFIG_FILE="${STATE_DIR}/config.env"
LOCK_FILE="${STATE_DIR}/assistant.lock"
CUSTOM_UNIT="/etc/systemd/system/rhel-samba-ad-dc.service"

RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
LOG_FILE=""
REPORT_FILE=""
EVENT_FILE=""
INPUT_FD=0
TTY_MODE=0
REMOTE_SESSION=0
RUN_OUTCOME="COMPLETE"
BOOTSTRAP_ACTIVE=0
BOOTSTRAP_COMMITTED=0
BOOTSTRAP_SNAPSHOT=""
BOOTSTRAP_ROLLBACK=0

DISTRO_ID=""
DISTRO_NAME=""
DISTRO_VERSION=""
DISTRO_MAJOR=""

DOMAIN=""
REALM=""
NETBIOS_DOMAIN=""
DC_HOSTNAME=""
DC_FQDN=""
DC_IP=""
AD_IFACE=""
NM_CONNECTION=""
NM_CONNECTION_UUID=""
AD_CLIENT_CIDR=""
DNS_FORWARDER=""
DC_SERVICE=""
SAMBA_BIN=""
SAMBA_TOOL=""
SAMBA_VERSION=""
DNS_FORWARDING_STATUS="unknown"
PRIMARY_ZONE=""
SELINUX_STATE="unknown"
CRYPTO_POLICY="unknown"
REMOTE_TARGET=""
REMOTE_TARGET_OS=""
REMOTE_SSH_USER=""
IDS_LOCAL_RULES="${IDS_STATE_DIR}/local.rules"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
CHANGES=0
MENU_MAIN_REQUESTED=0

C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_DIM=$'\033[2m'
C_RED=$'\033[31m'
C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'
C_CYAN=$'\033[36m'
C_MAGENTA=$'\033[35m'

command_exists() { command -v "$1" >/dev/null 2>&1; }

log() {
    [[ -n "$LOG_FILE" ]] || return 0
    printf '%s %s\n' "$(date -Is)" "$*" >>"$LOG_FILE"
}

record_event() {
    local level="$1"; shift
    [[ -n "${EVENT_FILE:-}" ]] || return 0
    printf '%s\t%s\t%s\n' "$(date -Is)" "$level" "${*//$'\t'/ }" >>"$EVENT_FILE"
}
info() { printf '%b[INFO]%b %s\n' "$C_CYAN" "$C_RESET" "$*"; log "INFO $*"; record_event INFO "$*"; }
ok()   { printf '%b[ OK ]%b %s\n' "$C_GREEN" "$C_RESET" "$*"; log "OK $*"; record_event PASS "$*"; ((PASS_COUNT+=1)); }
warn() { printf '%b[WARN]%b %s\n' "$C_YELLOW" "$C_RESET" "$*"; log "WARN $*"; record_event WARN "$*"; ((WARN_COUNT+=1)); }
err()  { printf '%b[ERROR]%b %s\n' "$C_RED" "$C_RESET" "$*" >&2; log "ERROR $*"; record_event FAIL "$*"; ((FAIL_COUNT+=1)); }
changed() { ((CHANGES+=1)); log "CHANGE $*"; record_event CHANGE "$*"; }

ui_t() {
    local key="$1"
    [[ "${UI_LANG,,}" == es ]] || { printf '%s' "$key"; return; }
    case "$key" in
      'Action') printf 'Acción' ;; 'Workspace') printf 'Área de trabajo' ;; 'Area') printf 'Área' ;; 'Module') printf 'Módulo' ;; 'Select operation') printf 'Selecciona operación' ;;
      'Daily operations') printf 'Operaciones diarias' ;; 'Directory') printf 'Directorio' ;; 'Policy / GPO / DNS') printf 'Política / GPO / DNS' ;; 'Security') printf 'Seguridad' ;;
      'Remote operations') printf 'Operaciones remotas' ;; 'Insights / IDS') printf 'Información / IDS' ;; 'Maintenance') printf 'Mantenimiento' ;; 'All modules') printf 'Todos los módulos' ;;
      'Status') printf 'Estado' ;; 'Validate DC') printf 'Validar DC' ;; 'Audit/evidence') printf 'Auditoría/evidencia' ;; 'DNS health') printf 'Salud DNS' ;; 'Time health') printf 'Salud de hora' ;;
      'Directory users') printf 'Usuarios del directorio' ;; 'Computers / OUs') printf 'Equipos / OUs' ;; 'Backup') printf 'Copia de seguridad' ;; 'Remote endpoint operations') printf 'Operaciones remotas de endpoints' ;;
      'IDS / Suricata') printf 'IDS / Suricata' ;; 'Wazuh integration') printf 'Integración Wazuh' ;; 'IDS / IPS response center') printf 'Centro de respuesta IDS / IPS' ;; 'Daily domain reports') printf 'Informes diarios del dominio' ;;
      'Language / Idioma') printf 'Idioma / Language' ;; 'Back') printf 'Volver' ;; 'Exit') printf 'Salir' ;; 'Invalid selection.') printf 'Selección no válida.' ;;
      'Press Enter to continue') printf 'Pulsa Enter para continuar' ;; *) printf '%s' "$key" ;;
    esac
}
set_ui_language(){ case "${1,,}" in en|es) UI_LANG="${1,,}" ;; *) err "Language must be en or es."; return 1;; esac; }
toggle_ui_language(){ [[ "$UI_LANG" == en ]] && UI_LANG=es || UI_LANG=en; }

ask() {
    local prompt="$1" default="${2:-}" value=""
    prompt="$(ui_t "$prompt")"
    if [[ -n "$default" ]]; then printf '%s [%s]: ' "$prompt" "$default" >&${INPUT_FD}; else printf '%s: ' "$prompt" >&${INPUT_FD}; fi
    IFS= read -r -u "$INPUT_FD" value || return 1
    [[ -n "$value" ]] || value="$default"
    printf '%s' "$value"
}

ask_secret_confirmed() {
    local prompt="$1" a="" b=""
    while true; do
        printf '%s: ' "$prompt" >&${INPUT_FD}; IFS= read -r -s -u "$INPUT_FD" a || return 1; printf '\n' >&${INPUT_FD}
        printf 'Confirm %s: ' "$prompt" >&${INPUT_FD}; IFS= read -r -s -u "$INPUT_FD" b || return 1; printf '\n' >&${INPUT_FD}
        [[ -n "$a" ]] || { warn "Value cannot be empty."; continue; }
        [[ "$a" == "$b" ]] || { warn "Values do not match."; continue; }
        printf '%s' "$a"; return 0
    done
}

confirm() {
    local prompt="$1" default="${2:-N}" answer=""
    prompt="$(ui_t "$prompt")"
    local shown="$default"; [[ "$UI_LANG" == es && "${default^^}" == Y ]] && shown=S
    printf '%s [%s]: ' "$prompt" "$shown" >&${INPUT_FD}
    IFS= read -r -u "$INPUT_FD" answer || return 1
    [[ -n "$answer" ]] || answer="$default"
    [[ "${answer,,}" =~ ^(y|yes|s|si|sí)$ ]]
}

confirm_literal() {
    local prompt="$1" literal="$2" answer=""
    if [[ "$UI_LANG" == es ]]; then printf '%s\nEscribe %s para continuar: ' "$prompt" "$literal" >&${INPUT_FD}; else printf '%s\nType %s to continue: ' "$prompt" "$literal" >&${INPUT_FD}; fi
    IFS= read -r -u "$INPUT_FD" answer || return 1
    [[ "$answer" == "$literal" ]]
}

pause_ui() {
    [[ $TTY_MODE -eq 1 ]] || return 0
    printf '\n%s...' "$(ui_t 'Press Enter to continue')" >&${INPUT_FD}
    read -r -u "$INPUT_FD" _ || true
}

atomic_write() {
    local path="$1"
    local tmp="${path}.tmp.$$"
    cat >"$tmp"
    chmod 0600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$path"
}

valid_domain() {
    local name="${1,,}" label
    [[ ${#name} -ge 3 && ${#name} -le 253 && "$name" == *.* && "$name" != .* && "$name" != *. && "$name" != *..* ]] || return 1
    IFS='.' read -r -a labels <<<"$name"
    for label in "${labels[@]}"; do
        [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    done
}

valid_netbios() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$ ]]; }

valid_ipv4() {
    local ip="$1" a b c d extra octet
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS='.' read -r a b c d extra <<<"$ip"
    [[ -z "${extra:-}" ]] || return 1
    for octet in "$a" "$b" "$c" "$d"; do ((10#$octet >= 0 && 10#$octet <= 255)) || return 1; done
}

valid_cidr() {
    local raw="$1" ip prefix
    [[ "$raw" == */* ]] || return 1
    ip="${raw%/*}"; prefix="${raw#*/}"
    valid_ipv4 "$ip" && [[ "$prefix" =~ ^[0-9]{1,2}$ ]] && ((10#$prefix <= 32))
}

init_runtime() {
    ((EUID == 0)) || { printf 'Run this assistant as root (sudo).\n' >&2; exit 1; }
    mkdir -p "$STATE_DIR" "$LOG_DIR" "$BACKUP_ROOT" "$REPORT_DIR" "$GPO_BUILTIN_DIR" "$GPO_CUSTOM_DIR" "$MIGRATION_DIR" "$IDS_REPORT_DIR" "$REMOTE_EVIDENCE_DIR"
    chmod 0700 "$STATE_DIR" "$LOG_DIR" "$BACKUP_ROOT" "$REPORT_DIR" "$GPO_DIR" "$MIGRATION_DIR" "$IDS_STATE_DIR" "$REMOTE_OPS_DIR" 2>/dev/null || true

    exec 9>"$LOCK_FILE"
    flock -n 9 || { printf 'Another RHEL AD Assistant process appears to be running.\n' >&2; exit 2; }

    LOG_FILE="${LOG_DIR}/${RUN_ID}.log"
    REPORT_FILE="${REPORT_DIR}/${RUN_ID}.json"
    EVENT_FILE="${STATE_DIR}/events-${RUN_ID}.tsv"
    : >"$LOG_FILE"; : >"$EVENT_FILE"; chmod 0600 "$LOG_FILE" "$EVENT_FILE"

    if { exec {INPUT_FD}<>/dev/tty; } 2>/dev/null; then TTY_MODE=1; fi
    [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_CLIENT:-}" ]] && REMOTE_SESSION=1

    detect_os
    detect_network
    load_config || true
    detect_samba_capability || true
    trap finish EXIT
}

finish() {
    local rc=$?
    if ((BOOTSTRAP_ACTIVE == 1 && BOOTSTRAP_COMMITTED == 0 && BOOTSTRAP_ROLLBACK == 0)) &&
       [[ -n "$BOOTSTRAP_SNAPSHOT" && -d "$BOOTSTRAP_SNAPSHOT" ]]; then
        if ! samdb_path >/dev/null 2>&1; then
            BOOTSTRAP_ROLLBACK=1
            printf '
%b[RECOVERY]%b Interrupted pre-provision bootstrap detected; restoring local host/network state.
' "$C_YELLOW" "$C_RESET" >&2
            restore_bootstrap_snapshot "$BOOTSTRAP_SNAPSHOT" || true
            RUN_OUTCOME="PREPROVISION_ROLLBACK"
        else
            RUN_OUTCOME="PROVISIONED_RECOVERY_REQUIRED"
            warn "Samba AD database exists; automatic bootstrap rollback is disabled after the domain commit boundary."
        fi
    fi
    cleanup_admin_ticket >/dev/null 2>&1 || true
    write_report || true
    return "$rc"
}

write_report() {
    command_exists python3 || return 0
    local role service_state selinux crypto
    role="$(samba_role 2>/dev/null || printf unknown)"
    service_state="$([[ -n "${DC_SERVICE:-}" ]] && systemctl is-active "$DC_SERVICE" 2>/dev/null || printf unavailable)"
    selinux="$(getenforce 2>/dev/null || printf unavailable)"
    crypto="$(update-crypto-policies --show 2>/dev/null || printf unavailable)"
    python3 - "$REPORT_FILE" "$EVENT_FILE" "$PRODUCT_NAME" "$SCRIPT_VERSION" "$RUN_ID" "$RUN_OUTCOME" "$DISTRO_NAME" "$DOMAIN" "$DC_FQDN" "$DC_IP" "$AD_IFACE" "$role" "$DC_SERVICE" "$service_state" "$selinux" "$crypto" "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT" "$CHANGES" "$LOG_FILE" <<'PY' 2>/dev/null || true
import json,sys,datetime,os
(path,eventfile,product,version,run_id,outcome,os_name,domain,dc,ip,iface,role,unit,service_state,selinux,crypto,p,w,f,c,logfile)=sys.argv[1:]
events=[]
if os.path.exists(eventfile):
    with open(eventfile,encoding='utf-8',errors='replace') as fh:
        for raw in fh:
            parts=raw.rstrip('\n').split('\t',2)
            if len(parts)==3: events.append({'Time':parts[0],'Type':parts[1],'Message':parts[2]})
data={
  'SchemaVersion':2,'Assistant':product,'Version':version,'RunId':run_id,
  'GeneratedAt':datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(),
  'Outcome':outcome,
  'Host':{'OS':os_name,'Domain':domain,'DC':dc,'IP':ip,'Interface':iface,'Role':role},
  'Security':{'SELinux':selinux,'CryptoPolicy':crypto},
  'Service':{'Unit':unit,'State':service_state},
  'BaselineClaim':'Selected baseline-oriented controls; not a CIS or vendor-support certification',
  'Counts':{'Pass':int(p),'Warn':int(w),'Fail':int(f),'Changes':int(c)},
  'Log':logfile,'Events':events[-500:]
}
with open(path,'w',encoding='utf-8') as fh:
    json.dump(data,fh,indent=2); fh.write('\n')
PY
}

detect_os() {
    [[ -r /etc/os-release ]] || { err "/etc/os-release unavailable."; return 1; }
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
    DISTRO_VERSION="${VERSION_ID:-unknown}"
    DISTRO_MAJOR="${DISTRO_VERSION%%.*}"

    case "$DISTRO_ID" in
        rocky|almalinux|rhel|centos) ;;
        *) err "This build targets Enterprise Linux systems; detected $DISTRO_NAME."; return 1 ;;
    esac
    if [[ ! "$DISTRO_MAJOR" =~ ^(9|10)$ ]]; then
        warn "Primary validation target is Enterprise Linux 9/10; detected $DISTRO_NAME."
    fi
    command_exists systemctl && [[ -d /run/systemd/system ]] || { err "systemd is required."; return 1; }
}

detect_network() {
    AD_IFACE="$(ip -4 route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')"
    [[ -n "$AD_IFACE" ]] || AD_IFACE="$(ip -4 -o addr show scope global 2>/dev/null | awk 'NR==1{print $2}')"
    DC_IP="$(ip -4 -o addr show dev "$AD_IFACE" scope global 2>/dev/null | awk 'NR==1{split($4,a,"/"); print a[1]}')"
    NM_CONNECTION=""; NM_CONNECTION_UUID=""
    if command_exists nmcli && systemctl is-active --quiet NetworkManager.service 2>/dev/null && [[ -n "$AD_IFACE" ]]; then
        NM_CONNECTION="$(nmcli -g GENERAL.CONNECTION device show "$AD_IFACE" 2>/dev/null || true)"
        [[ "$NM_CONNECTION" == "--" ]] && NM_CONNECTION=""
        [[ -n "$NM_CONNECTION" ]] && NM_CONNECTION_UUID="$(nmcli -g connection.uuid connection show "$NM_CONNECTION" 2>/dev/null || true)"
    fi
}

load_config() {
    [[ -r "$CONFIG_FILE" ]] || return 1
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
}

save_config() {
    {
        printf 'CONFIG_VERSION=%q\n' '1'
        printf 'DOMAIN=%q\n' "$DOMAIN"
        printf 'REALM=%q\n' "$REALM"
        printf 'NETBIOS_DOMAIN=%q\n' "$NETBIOS_DOMAIN"
        printf 'DC_HOSTNAME=%q\n' "$DC_HOSTNAME"
        printf 'DC_FQDN=%q\n' "$DC_FQDN"
        printf 'DC_IP=%q\n' "$DC_IP"
        printf 'AD_IFACE=%q\n' "$AD_IFACE"
        printf 'NM_CONNECTION=%q\n' "$NM_CONNECTION"
        printf 'NM_CONNECTION_UUID=%q\n' "$NM_CONNECTION_UUID"
        printf 'AD_CLIENT_CIDR=%q\n' "$AD_CLIENT_CIDR"
        printf 'DNS_FORWARDER=%q\n' "$DNS_FORWARDER"
        printf 'ADMIN_USER=%q\n' "$ADMIN_USER"
        printf 'TIMEZONE=%q\n' "$TIMEZONE"
        printf 'NTP_POOL=%q\n' "$NTP_POOL"
    } | atomic_write "$CONFIG_FILE"
}

detect_samba_capability() {
    SAMBA_BIN="$(command -v samba 2>/dev/null || true)"
    SAMBA_TOOL="$(command -v samba-tool 2>/dev/null || true)"
    SAMBA_VERSION="$([[ -n "$SAMBA_BIN" ]] && "$SAMBA_BIN" -V 2>/dev/null || true)"
    DC_SERVICE=""
    local unit
    for unit in samba-ad-dc.service rhel-samba-ad-dc.service samba.service; do
        if systemctl cat "$unit" >/dev/null 2>&1; then
            if [[ "$unit" == samba.service ]]; then
                systemctl cat "$unit" 2>/dev/null | grep -Eq '(^|[[:space:]/])samba([[:space:]]|$)' || continue
            fi
            DC_SERVICE="$unit"
            break
        fi
    done
    [[ -n "$DC_SERVICE" ]] || [[ ! -f "$CUSTOM_UNIT" ]] || DC_SERVICE="rhel-samba-ad-dc.service"
    SELINUX_STATE="$(getenforce 2>/dev/null || printf unavailable)"
    CRYPTO_POLICY="$(update-crypto-policies --show 2>/dev/null || printf unavailable)"
}

samdb_path() {
    local candidates=(/var/lib/samba/private/sam.ldb /var/lib/samba/private/sam.ldb.d)
    [[ -e "${candidates[0]}" ]] && { printf '%s' "${candidates[0]}"; return 0; }
    return 1
}

samba_role() {
    if samdb_path >/dev/null 2>&1; then printf 'ad-dc'; return 0; fi
    if [[ -r /etc/samba/smb.conf ]] && grep -Eqi '^[[:space:]]*server role[[:space:]]*=[[:space:]]*active directory domain controller' /etc/samba/smb.conf; then printf 'ad-dc-config'; return 0; fi
    printf 'none'
}

vendor_support_gate() {
    if [[ "$DISTRO_ID" == rhel ]]; then
        warn "Red Hat documents Samba AD Domain Controller operation as unsupported on RHEL."
        warn "This does not mean Samba upstream lacks AD-DC functionality; it means the vendor does not support this role on RHEL."
        ((ALLOW_UNSUPPORTED_RHEL_DC)) || {
            err "Provisioning on RHEL is blocked. Use Rocky/Alma, or rerun with --allow-unsupported-rhel-dc after accepting the support boundary."
            return 1
        }
        confirm_literal "You are explicitly choosing a Samba AD DC role that Red Hat does not support on RHEL." "UNSUPPORTED-RHEL-DC" || return 1
    fi
}

header() {
    clear 2>/dev/null || true
    printf '%b%s%b\n' "$C_BOLD" "$PRODUCT_NAME" "$C_RESET"
    printf 'Version : %s\n' "$SCRIPT_VERSION"
    printf 'OS      : %s\n' "$DISTRO_NAME"
    printf 'Host    : %s\n' "$(hostname -f 2>/dev/null || hostname)"
    printf 'Role    : %s\n' "$(samba_role)"
    printf 'Network : %s / %s / %s\n' "${AD_IFACE:-unknown}" "${DC_IP:-no-ip}" "${NM_CONNECTION:-unmanaged}"
    printf 'Domain  : %s\n' "${DOMAIN:-unconfigured}"
    printf 'Samba   : %s\n' "${SAMBA_VERSION:-unavailable}"
    printf 'Security: SELinux=%s / crypto=%s\n' "${SELINUX_STATE:-unknown}" "${CRYPTO_POLICY:-unknown}"
    if [[ -n "$DC_SERVICE" ]]; then
        printf 'Service : %s / %s\n' "$DC_SERVICE" "$(systemctl is-active "$DC_SERVICE" 2>/dev/null || true)"
    else
        printf 'Service : not configured\n'
    fi
    printf '%s\n\n' '--------------------------------------------------------------------------------'
}

package_available() {
    dnf -q list --available "$1" >/dev/null 2>&1 || dnf -q list --installed "$1" >/dev/null 2>&1
}

install_dependencies() {
    # Package names vary between Enterprise Linux vendors and enabled repositories.
    # Install useful candidates only when the configured repositories expose them;
    # the authoritative gate is the resulting command/capability set below.
    local -a candidates=(
        samba samba-common-tools python3-samba
        samba-dc samba-dc-provision samba-dc-libs python3-samba-dc
        krb5-workstation bind-utils chrony firewalld
    )
    local -a install=() unavailable=()
    local pkg

    for pkg in "${candidates[@]}"; do
        rpm -q "$pkg" >/dev/null 2>&1 && continue
        if package_available "$pkg"; then
            install+=("$pkg")
        else
            unavailable+=("$pkg")
        fi
    done

    if ((${#install[@]})); then
        info "Relevant packages exposed by the currently configured distribution repositories:"
        printf '  %s\n' "${install[@]}"
        confirm "Install these available packages with dnf?" Y || return 1
        dnf install -y "${install[@]}" || { err "Package installation failed."; return 1; }
        changed "Installed available Samba AD dependencies"
    fi

    if ((${#unavailable[@]})); then
        info "Candidate package names not exposed by the configured repositories (not automatically enabled):"
        printf '  %s\n' "${unavailable[@]}"
    fi

    detect_samba_capability
    local missing=0 cmd
    for cmd in samba samba-tool kinit dig chronyc firewall-cmd nmcli; do
        if command_exists "$cmd"; then
            ok "Capability available: $cmd"
        else
            err "Required runtime capability is unavailable: $cmd"
            missing=1
        fi
    done
    ((missing == 0)) || {
        warn "The assistant will not enable third-party or supplemental repositories automatically."
        return 1
    }

    if ! "$SAMBA_TOOL" domain provision --help >/dev/null 2>&1; then
        err "Installed Samba tooling does not expose 'domain provision'. This distribution build cannot be used by this assistant as an AD DC."
        return 1
    fi
    ok "Installed Samba exposes AD domain provisioning capability."
}

network_snapshot() {
    local snap="$1"
    [[ -n "$NM_CONNECTION" ]] || return 0
    {
        printf 'NM_CONNECTION=%q\n' "$NM_CONNECTION"
        printf 'NM_CONNECTION_UUID=%q\n' "$NM_CONNECTION_UUID"
        printf 'IPV4_METHOD=%q\n' "$(nmcli -g ipv4.method con show "$NM_CONNECTION" 2>/dev/null || true)"
        printf 'IPV4_ADDRESSES=%q\n' "$(nmcli -g ipv4.addresses con show "$NM_CONNECTION" 2>/dev/null || true)"
        printf 'IPV4_GATEWAY=%q\n' "$(nmcli -g ipv4.gateway con show "$NM_CONNECTION" 2>/dev/null || true)"
        printf 'IPV4_DNS=%q\n' "$(nmcli -g ipv4.dns con show "$NM_CONNECTION" 2>/dev/null || true)"
        printf 'IPV4_DNS_SEARCH=%q\n' "$(nmcli -g ipv4.dns-search con show "$NM_CONNECTION" 2>/dev/null || true)"
        printf 'IPV4_IGNORE_AUTO_DNS=%q\n' "$(nmcli -g ipv4.ignore-auto-dns con show "$NM_CONNECTION" 2>/dev/null || true)"
    } >"$snap/network.env"
}

snapshot_file() {
    local snap="$1" path="$2"
    local key
    key="$(printf '%s' "$path" | sed 's#^/##;s#/#__#g')"
    mkdir -p "$snap/files"
    if [[ -e "$path" || -L "$path" ]]; then cp -a -- "$path" "$snap/files/$key"; printf '%s\tpresent\t%s\n' "$path" "$key" >>"$snap/files.tsv";
    else printf '%s\tabsent\t%s\n' "$path" "$key" >>"$snap/files.tsv"; fi
}

create_bootstrap_snapshot() {
    local snap="${BACKUP_ROOT}/bootstrap-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$snap"; chmod 0700 "$snap"; : >"$snap/files.tsv"
    snapshot_file "$snap" /etc/samba/smb.conf
    snapshot_file "$snap" /etc/krb5.conf
    snapshot_file "$snap" /etc/hosts
    snapshot_file "$snap" /etc/resolv.conf
    network_snapshot "$snap"
    printf '%s\n' "$(hostnamectl --static 2>/dev/null || hostname)" >"$snap/hostname.txt"
    printf '%s' "$snap"
}

restore_bootstrap_file() {
    local snap="$1" path="$2" line state key
    line="$(awk -F'\t' -v p="$path" '$1==p{print; exit}' "$snap/files.tsv" 2>/dev/null || true)"
    [[ -n "$line" ]] || return 0
    IFS=$'\t' read -r _ state key <<<"$line"
    if [[ "$state" == present && ( -e "$snap/files/$key" || -L "$snap/files/$key" ) ]]; then
        rm -rf -- "$path"
        cp -a -- "$snap/files/$key" "$path"
    else
        rm -rf -- "$path"
    fi
}

restore_bootstrap_network() {
    local snap="$1"
    [[ -r "$snap/network.env" ]] || return 0
    unset NM_CONNECTION NM_CONNECTION_UUID IPV4_METHOD IPV4_ADDRESSES IPV4_GATEWAY IPV4_DNS IPV4_DNS_SEARCH IPV4_IGNORE_AUTO_DNS
    # shellcheck disable=SC1090
    . "$snap/network.env"
    local con_ref="${NM_CONNECTION_UUID:-${NM_CONNECTION:-}}"
    [[ -n "$con_ref" ]] || return 0
    command_exists nmcli && nmcli connection show "$con_ref" >/dev/null 2>&1 || return 0
    nmcli connection modify "$con_ref" \
        ipv4.method "${IPV4_METHOD:-auto}" \
        ipv4.addresses "${IPV4_ADDRESSES:-}" \
        ipv4.gateway "${IPV4_GATEWAY:-}" \
        ipv4.dns "${IPV4_DNS:-}" \
        ipv4.dns-search "${IPV4_DNS_SEARCH:-}" \
        ipv4.ignore-auto-dns "${IPV4_IGNORE_AUTO_DNS:-no}" || true
    nmcli connection up "$con_ref" >/dev/null 2>&1 || true
}

restore_bootstrap_snapshot() {
    local snap="$1" original_host=""
    [[ -d "$snap" ]] || return 1
    restore_bootstrap_file "$snap" /etc/samba/smb.conf
    restore_bootstrap_file "$snap" /etc/krb5.conf
    restore_bootstrap_file "$snap" /etc/hosts
    restore_bootstrap_file "$snap" /etc/resolv.conf
    restore_bootstrap_network "$snap"
    original_host="$(cat "$snap/hostname.txt" 2>/dev/null || true)"
    [[ -n "$original_host" ]] && hostnamectl set-hostname "$original_host" >/dev/null 2>&1 || true
    detect_network || true
    ok "Pre-provision bootstrap host/network snapshot restored."
}

ensure_static_dc_address() {
    [[ -n "$NM_CONNECTION" ]] || { err "A NetworkManager-managed connection is required for safe DC bootstrap."; return 1; }
    local method addresses current_cidr gateway count
    method="$(nmcli -g ipv4.method connection show "$NM_CONNECTION" 2>/dev/null || true)"
    addresses="$(nmcli -g ipv4.addresses connection show "$NM_CONNECTION" 2>/dev/null || true)"
    current_cidr="$(ip -4 -o addr show dev "$AD_IFACE" scope global | awk 'NR==1{print $4}')"
    count="$(ip -4 -o addr show dev "$AD_IFACE" scope global | awk 'END{print NR+0}')"
    gateway="$(ip -4 route show default dev "$AD_IFACE" | awk 'NR==1{print $3}')"

    if [[ "$method" == manual && -n "$addresses" ]]; then ok "NetworkManager connection already uses static/manual IPv4 addressing."; return 0; fi
    warn "A domain controller should not depend on a DHCP lease. Current NetworkManager method: ${method:-unknown}."
    ((count == 1)) || { err "Automatic conversion is disabled because multiple global IPv4 addresses exist on $AD_IFACE."; return 1; }
    [[ -n "$current_cidr" && -n "$gateway" ]] || { err "Current address/gateway could not be derived safely."; return 1; }
    ((REMOTE_SESSION)) && warn "Converting a remote management interface can interrupt the SSH session if the lease topology changes."
    confirm_literal "Persist current lease values as static: ${current_cidr}, gateway ${gateway}, connection ${NM_CONNECTION}." "STATICIZE" || return 1
    nmcli connection modify "$NM_CONNECTION" ipv4.method manual ipv4.addresses "$current_cidr" ipv4.gateway "$gateway"
    nmcli device reapply "$AD_IFACE" >/dev/null 2>&1 || nmcli connection up "$NM_CONNECTION"
    changed "Converted current DC IPv4 lease to static NetworkManager configuration"
    ok "Current IPv4 address is now persistent/static."
}

validate_forwarder() {
    local ip="$1" result
    valid_ipv4 "$ip" || { err "Invalid DNS forwarder IPv4 address: $ip"; return 1; }
    [[ -z "$DC_IP" || "$ip" != "$DC_IP" ]] || { err "The DC cannot use its own address as an upstream DNS forwarder."; return 1; }
    result="$(dig +time=3 +tries=1 @"$ip" "$EXTERNAL_DNS_PROBE" A +short 2>/dev/null || true)"
    if [[ -n "$result" ]]; then
        ok "DNS forwarder $ip resolves external names."
        return 0
    fi
    if ((ALLOW_ISOLATED_DNS)); then
        warn "DNS forwarder $ip did not resolve $EXTERNAL_DNS_PROBE; external-resolution requirement explicitly waived for this isolated deployment."
        return 0
    fi
    err "DNS forwarder $ip cannot resolve $EXTERNAL_DNS_PROBE."
    warn "Repair the upstream resolver or use --allow-isolated-dns only for an intentionally isolated domain."
    return 1
}

ensure_hosts_record() {
    local ip="$1" fqdn="$2" short="$3"
    if grep -Eq "^[[:space:]]*${ip//./\\.}[[:space:]]+.*(^|[[:space:]])${fqdn//./\\.}([[:space:]]|$)" /etc/hosts 2>/dev/null; then return 0; fi
    printf '%s\t%s %s\n' "$ip" "$fqdn" "$short" >>/etc/hosts
    changed "Added DC identity to /etc/hosts"
}

configure_dc_resolver() {
    nmcli connection modify "$NM_CONNECTION" \
        ipv4.ignore-auto-dns yes \
        ipv4.dns "$DC_IP" \
        ipv4.dns-search "$DOMAIN,~." \
        ipv4.dns-priority -100
    nmcli device reapply "$AD_IFACE" >/dev/null 2>&1 || nmcli connection up "$NM_CONNECTION"
    changed "Pointed DC system resolver to Samba DNS"
}

ensure_dc_unit() {
    detect_samba_capability
    if systemctl cat samba-ad-dc.service >/dev/null 2>&1; then DC_SERVICE="samba-ad-dc.service"; return 0; fi
    [[ -n "$SAMBA_BIN" ]] || { err "Samba daemon unavailable."; return 1; }
    cat >"$CUSTOM_UNIT" <<EOF_UNIT
[Unit]
Description=Samba Active Directory Domain Controller (managed by RHEL AD Assistant)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SAMBA_BIN} --foreground --no-process-group
ExecReload=/bin/kill -HUP \$MAINPID
LimitNOFILE=16384
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF_UNIT
    chmod 0644 "$CUSTOM_UNIT"
    systemctl daemon-reload
    DC_SERVICE="rhel-samba-ad-dc.service"
    changed "Created dedicated Samba AD DC systemd unit"
}

firewall_zone_for_iface() {
    local iface="${1:-$AD_IFACE}" zone=""
    command_exists firewall-cmd || return 1
    zone="$(firewall-cmd --get-zone-of-interface="$iface" 2>/dev/null || true)"
    [[ -n "$zone" && "$zone" != no ]] || zone="$(firewall-cmd --get-default-zone 2>/dev/null || true)"
    [[ -n "$zone" ]] || return 1
    printf '%s' "$zone"
}

firewall_rule_add() {
    local cidr="$1" port="$2" proto="$3" zone="${4:-}"
    [[ -n "$zone" ]] || zone="$(firewall_zone_for_iface "$AD_IFACE" || true)"
    [[ -n "$zone" ]] || { err "Could not determine firewalld zone for $AD_IFACE."; return 1; }
    local rule="rule family=\"ipv4\" source address=\"${cidr}\" port port=\"${port}\" protocol=\"${proto}\" accept"
    firewall-cmd --permanent --zone="$zone" --query-rich-rule="$rule" >/dev/null 2>&1 ||
        firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule" >/dev/null
}

configure_firewall() {
    local cidr="$1" spec port proto zone
    systemctl enable --now firewalld.service >/dev/null 2>&1 || { warn "firewalld could not be activated; firewall automation skipped."; return 1; }
    zone="$(firewall_zone_for_iface "$AD_IFACE" || true)"
    [[ -n "$zone" ]] || { err "No firewalld zone could be resolved for $AD_IFACE."; return 1; }
    local -a ports=(53/tcp 53/udp 88/tcp 88/udp 135/tcp 137/udp 138/udp 139/tcp 389/tcp 389/udp 445/tcp 464/tcp 464/udp 636/tcp 3268/tcp 3269/tcp 49152-65535/tcp)
    for spec in "${ports[@]}"; do port="${spec%/*}"; proto="${spec#*/}"; firewall_rule_add "$cidr" "$port" "$proto" "$zone"; done
    firewall-cmd --reload >/dev/null
    changed "Scoped AD service firewall rules to $cidr in zone $zone"
    ok "AD service ports are allowed from trusted source $cidr in firewalld zone $zone."
}

prepare_service_conflicts() {
    local unit
    for unit in smb.service nmb.service winbind.service; do
        if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
        fi
    done
}

copy_generated_krb5() {
    local generated="/var/lib/samba/private/krb5.conf"
    if [[ -r "$generated" ]]; then
        cp -f "$generated" /etc/krb5.conf
        chmod 0644 /etc/krb5.conf
        changed "Installed Samba-generated Kerberos client configuration"
    else
        warn "Samba-generated krb5.conf not found at $generated; leaving /etc/krb5.conf unchanged."
    fi
}

bootstrap_dc() {
    vendor_support_gate || return 1
    [[ "$(samba_role)" == none ]] || { err "Existing Samba AD state/configuration detected. Bootstrap will never reprovision an existing DC."; return 1; }
    [[ ! -e /var/lib/ipa/sysrestore/sysrestore.state ]] || { err "This host appears to be an IdM/FreeIPA server. Refusing Samba AD DC bootstrap."; return 1; }

    detect_network
    [[ -n "$DC_IP" ]] || { err "No global IPv4 address found on the primary interface."; return 1; }

    DOMAIN="$(ask 'AD DNS domain' '')"; DOMAIN="${DOMAIN,,}"; valid_domain "$DOMAIN" || { err "Invalid AD DNS domain."; return 1; }
    REALM="${DOMAIN^^}"
    local default_netbios="${DOMAIN%%.*}"; default_netbios="${default_netbios^^}"
    NETBIOS_DOMAIN="$(ask 'NetBIOS domain' "$default_netbios")"; NETBIOS_DOMAIN="${NETBIOS_DOMAIN^^}"; valid_netbios "$NETBIOS_DOMAIN" || { err "Invalid NetBIOS domain."; return 1; }
    DC_HOSTNAME="$(ask 'DC short hostname' "$(hostname -s)")"; [[ "$DC_HOSTNAME" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$ ]] || { err "Use a DNS-safe DC hostname of at most 15 characters."; return 1; }
    DC_HOSTNAME="${DC_HOSTNAME,,}"
    DC_FQDN="${DC_HOSTNAME}.${DOMAIN}"
    AD_CLIENT_CIDR="$(ask 'Trusted client CIDR allowed to reach AD services' '')"; valid_cidr "$AD_CLIENT_CIDR" || { err "Invalid IPv4 CIDR."; return 1; }
    DNS_FORWARDER="$(ask 'External/upstream DNS forwarder IPv4' '')"; validate_forwarder "$DNS_FORWARDER" || return 1

    local snap
    snap="$(create_bootstrap_snapshot)"
    BOOTSTRAP_ACTIVE=1
    BOOTSTRAP_SNAPSHOT="$snap"
    info "Bootstrap recovery snapshot: $snap"

    install_dependencies || return 1
    ensure_static_dc_address || return 1
    detect_network
    DC_IP="$(ip -4 -o addr show dev "$AD_IFACE" scope global | awk 'NR==1{split($4,a,"/");print a[1]}')"

    save_config
    hostnamectl set-hostname "$DC_FQDN"; changed "Set DC hostname to $DC_FQDN"
    ensure_hosts_record "$DC_IP" "$DC_FQDN" "$DC_HOSTNAME"

    prepare_service_conflicts
    if samdb_path >/dev/null 2>&1; then err "sam.ldb appeared before provision; refusing to continue."; return 1; fi

    printf '\n%bSAMBA DOMAIN PROVISION%b\n' "$C_BOLD" "$C_RESET"
    info "Samba will prompt securely for the domain Administrator password. The assistant does not store it."
    if ! "$SAMBA_TOOL" domain provision \
        --use-rfc2307 \
        --realm="$REALM" \
        --domain="$NETBIOS_DOMAIN" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --host-name="$DC_HOSTNAME" \
        --host-ip="$DC_IP" \
        --option="dns forwarder = ${DNS_FORWARDER}"; then
        err "Samba domain provisioning failed. Review $LOG_FILE and Samba output."
        return 1
    fi
    changed "Provisioned Samba Active Directory domain $REALM"

    samdb_path >/dev/null 2>&1 || { err "Provision command returned success but sam.ldb was not found."; return 1; }
    BOOTSTRAP_COMMITTED=1
    BOOTSTRAP_ACTIVE=0
    copy_generated_krb5
    ensure_dc_unit
    configure_dc_resolver
    configure_firewall "$AD_CLIENT_CIDR" || true

    systemctl enable --now chronyd.service >/dev/null 2>&1 || warn "chronyd could not be enabled. Kerberos requires reliable time."
    systemctl enable --now "$DC_SERVICE" || {
        err "Samba AD DC service failed to start. SELinux is not being disabled automatically."
        journalctl -u "$DC_SERVICE" -n 80 --no-pager || true
        if command_exists ausearch; then ausearch -m AVC -ts recent 2>/dev/null | tail -n 30 || true; fi
        return 1
    }
    changed "Enabled Samba AD DC service"

    save_config
    RUN_OUTCOME="BOOTSTRAPPED"
    validate_dc
}

service_listener() {
    local port="$1"
    ss -H -lntup 2>/dev/null | awk -v p=":${port}" '$5 ~ p"$" {found=1} END{exit !found}'
}

status_dc() {
    load_config || true
    detect_network
    detect_samba_capability
    header
    [[ -n "$DC_SERVICE" ]] && systemctl --no-pager --full status "$DC_SERVICE" 2>/dev/null | sed -n '1,12p' || true
    printf '\nDNS resolver\n'
    cat /etc/resolv.conf 2>/dev/null || true
    printf '\nTime\n'
    timedatectl status 2>/dev/null | sed -n '1,12p' || true
}

backup_domain() {
    load_config || { err "Assistant configuration unavailable."; return 1; }
    [[ "$(samba_role)" == ad-dc ]] || { err "This host is not a provisioned Samba AD DC."; return 1; }
    local target="${BACKUP_ROOT}/domain-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$target"; chmod 0700 "$target"
    info "Online backup target: $target"
    info "Samba will request credentials if required; no password is stored."
    if "$SAMBA_TOOL" domain backup online --targetdir="$target" --server="${DC_FQDN:-127.0.0.1}" -UAdministrator; then
        changed "Created online Samba domain backup"
        ok "Domain backup completed: $target"
    else
        err "Online Samba domain backup failed."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Extended control-plane utilities (v2)
# ---------------------------------------------------------------------------

require_dc() {
    load_config || true
    detect_samba_capability || true
    [[ "$(samba_role)" == ad-dc ]] || {
        err "A provisioned Samba AD DC was not detected."
        return 1
    }
    [[ -n "$SAMBA_TOOL" ]] || { err "samba-tool is unavailable."; return 1; }
}

domain_dn() {
    local d="${DOMAIN:-}" out="" label
    [[ -n "$d" ]] || return 1
    IFS='.' read -r -a _labels <<<"$d"
    for label in "${_labels[@]}"; do
        [[ -n "$out" ]] && out+=","
        out+="DC=${label}"
    done
    printf '%s' "$out"
}

private_krb5_cache() {
    printf 'FILE:%s/krb5cc-%s' "$STATE_DIR" "$RUN_ID"
}

ensure_admin_ticket() {
    require_dc || return 1
    local principal="${ADMIN_USER:-Administrator}@${REALM:-${DOMAIN^^}}"
    export KRB5CCNAME="$(private_krb5_cache)"
    if command_exists klist && klist -s >/dev/null 2>&1; then return 0; fi
    info "Kerberos authentication required for this operation: $principal"
    kinit "$principal" || { err "Kerberos authentication failed for $principal."; return 1; }
}

cleanup_admin_ticket() {
    local cache="$(private_krb5_cache)"
    command_exists kdestroy && KRB5CCNAME="$cache" kdestroy >/dev/null 2>&1 || true
    rm -f -- "${cache#FILE:}" 2>/dev/null || true
}

samba_help_has() {
    local section="$1" action="$2"
    "$SAMBA_TOOL" "$section" "$action" --help >/dev/null 2>&1
}

object_is_protected_builtin() {
    case "${1,,}" in
        administrator|guest|krbtgt|domain\ admins|enterprise\ admins|schema\ admins|domain\ controllers|read-only\ domain\ controllers) return 0 ;;
        *) return 1 ;;
    esac
}

select_from_lines() {
    local title="$1" data="$2" default="${3:-1}" count=0 line choice
    printf '\n%s\n' "$title"
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        ((count+=1))
        printf '  [%3d] %s\n' "$count" "$line"
    done <<<"$data"
    ((count > 0)) || return 1
    choice="$(ask 'Selection' "$default")" || return 1
    [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= count)) || return 1
    awk -v n="$choice" 'NF{c++; if(c==n){print; exit}}' <<<"$data"
}

show_runtime_paths() {
    printf 'State       : %s\n' "$STATE_DIR"
    printf 'Logs        : %s\n' "$LOG_DIR"
    printf 'Reports     : %s\n' "$REPORT_DIR"
    printf 'Backups     : %s\n' "$BACKUP_ROOT"
    printf 'GPO library : %s\n' "$GPO_DIR"
    printf 'IDS reports : %s\n' "$IDS_REPORT_DIR"
    printf 'Remote ev.  : %s\n' "$REMOTE_EVIDENCE_DIR"
}

show_findings_summary() {
    printf '\nRUN SUMMARY\n'
    printf '  PASS    : %d\n' "$PASS_COUNT"
    printf '  WARN    : %d\n' "$WARN_COUNT"
    printf '  FAIL    : %d\n' "$FAIL_COUNT"
    printf '  CHANGES : %d\n' "$CHANGES"
    printf '  Log     : %s\n' "$LOG_FILE"
    printf '  Report  : %s\n' "$REPORT_FILE"
}

# ---------------------------------------------------------------------------
# Directory operations
# ---------------------------------------------------------------------------

users_inventory() {
    require_dc || return 1
    local users
    users="$($SAMBA_TOOL user list 2>/dev/null | sort -f || true)"
    [[ -n "$users" ]] || { warn "No users returned."; return 0; }
    printf '%s\n' "$users"
}

user_select() {
    local users selected
    users="$(users_inventory)" || return 1
    selected="$(select_from_lines 'AD USERS' "$users" 1)" || return 1
    printf '%s' "$selected"
}

user_show_full() {
    local user="${1:-}"
    [[ -n "$user" ]] || user="$(user_select || true)"
    [[ -n "$user" ]] || return 1
    printf '\nUSER: %s\n' "$user"
    "$SAMBA_TOOL" user show "$user" || return 1
    printf '\nDIRECT GROUP MEMBERSHIPS\n'
    "$SAMBA_TOOL" user getgroups "$user" 2>/dev/null || true
    printf '\nDELEGATION SENSITIVITY\n'
    "$SAMBA_TOOL" user sensitive "$user" show 2>/dev/null || true
}

user_create_guided() {
    require_dc || return 1
    local user given surname display mail ou
    user="$(ask 'Logon name (sAMAccountName)' '')"; [[ "$user" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { err "Invalid logon name."; return 1; }
    "$SAMBA_TOOL" user show "$user" >/dev/null 2>&1 && { err "User already exists: $user"; return 1; }
    given="$(ask 'Given name' '')"
    surname="$(ask 'Surname' '')"
    display="$(ask 'Display name' "${given} ${surname}")"
    mail="$(ask 'Email address (optional)' '')"
    ou="$(ask 'Parent OU/container DN (optional; e.g. OU=People)' '')"
    info "Samba will request the new user's password securely; it is not stored."
    local -a args=(user add "$user")
    [[ -n "$given" ]] && args+=("--given-name=$given")
    [[ -n "$surname" ]] && args+=("--surname=$surname")
    [[ -n "$display" ]] && args+=("--display-name=$display")
    [[ -n "$mail" ]] && args+=("--mail-address=$mail")
    [[ -n "$ou" ]] && args+=("--userou=$ou")
    "$SAMBA_TOOL" "${args[@]}" || return 1
    changed "Created AD user $user"
    if confirm "Require password change at next logon?" Y; then
        "$SAMBA_TOOL" user setpassword "$user" --must-change-at-next-login >/dev/null 2>&1 || warn "Could not set must-change-at-next-login automatically."
    fi
    ok "AD user created: $user"
}

user_rename_guided() {
    local user given surname display mail upn new_sam
    user="$(user_select || true)"; [[ -n "$user" ]] || return 1
    given="$(ask 'Given name (blank = unchanged)' '')"
    surname="$(ask 'Surname (blank = unchanged)' '')"
    display="$(ask 'Display name (blank = unchanged)' '')"
    mail="$(ask 'Mail address (blank = unchanged)' '')"
    upn="$(ask 'UPN (blank = unchanged)' '')"
    new_sam="$(ask 'New sAMAccountName (blank = unchanged)' '')"
    local -a args=(user rename "$user")
    [[ -n "$given" ]] && args+=("--given-name=$given")
    [[ -n "$surname" ]] && args+=("--surname=$surname")
    [[ -n "$display" ]] && args+=("--display-name=$display")
    [[ -n "$mail" ]] && args+=("--mail-address=$mail")
    [[ -n "$upn" ]] && args+=("--upn=$upn")
    [[ -n "$new_sam" ]] && args+=("--samaccountname=$new_sam")
    ((${#args[@]} > 3)) || { warn "No attributes selected for change."; return 0; }
    "$SAMBA_TOOL" "${args[@]}" || return 1
    changed "Updated AD user identity attributes for $user"
    ok "User attributes updated."
}

user_move_guided() {
    local user parent
    user="$(user_select || true)"; [[ -n "$user" ]] || return 1
    parent="$(ask 'Destination OU/container (e.g. OU=Engineering)' '')"; [[ -n "$parent" ]] || return 1
    "$SAMBA_TOOL" user move "$user" "$parent" || return 1
    changed "Moved AD user $user to $parent"
    ok "User moved."
}

user_membership_menu() {
    local user group c
    user="$(user_select || true)"; [[ -n "$user" ]] || return 1
    while true; do
        printf '\nUSER MEMBERSHIPS: %s\n  [1] Show direct groups\n  [2] Add to group\n  [3] Remove from group\n  [4] Set primary group\n  [0] Back\n' "$user"
        c="$(ask 'Action' '1')"
        case "$c" in
            1) "$SAMBA_TOOL" user getgroups "$user" ;;
            2) group="$(ask 'Group' '')"; "$SAMBA_TOOL" group addmembers "$group" "$user" && changed "Added $user to $group" ;;
            3) group="$(ask 'Group' '')"; "$SAMBA_TOOL" group removemembers "$group" "$user" && changed "Removed $user from $group" ;;
            4) group="$(ask 'Primary group' '')"; "$SAMBA_TOOL" user setprimarygroup "$user" "$group" && changed "Set primary group for $user to $group" ;;
            0) return 0 ;;
            *) warn "Invalid selection." ;;
        esac
    done
}

user_password_menu() {
    local user c
    user="$(user_select || true)"; [[ -n "$user" ]] || return 1
    printf '\nPASSWORD / ACCOUNT: %s\n  [1] Reset password\n  [2] Require change at next logon\n  [3] Unlock account\n  [4] Enable account\n  [5] Disable account\n  [6] Set expiry\n  [7] Mark sensitive to delegation\n  [8] Clear sensitive-to-delegation\n  [0] Back\n' "$user"
    c="$(ask 'Action' '1')"
    case "$c" in
        1) "$SAMBA_TOOL" user setpassword "$user" && changed "Reset password for $user" ;;
        2) "$SAMBA_TOOL" user setpassword "$user" --must-change-at-next-login && changed "Required password change for $user" ;;
        3) "$SAMBA_TOOL" user unlock "$user" && changed "Unlocked $user" ;;
        4) "$SAMBA_TOOL" user enable "$user" && changed "Enabled $user" ;;
        5) object_is_protected_builtin "$user" && { err "Protected built-in account cannot be disabled by this workflow."; return 1; }; confirm "Disable $user?" N && { "$SAMBA_TOOL" user disable "$user"; changed "Disabled $user"; } ;;
        6) local days; days="$(ask 'Days until expiry (0 = never, if supported)' '0')"; [[ "$days" =~ ^[0-9]+$ ]] || return 1; if ((days==0)); then "$SAMBA_TOOL" user setexpiry "$user" --noexpiry; else "$SAMBA_TOOL" user setexpiry "$user" --days="$days"; fi; changed "Changed expiry for $user" ;;
        7) "$SAMBA_TOOL" user sensitive "$user" on && changed "Marked $user sensitive to delegation" ;;
        8) "$SAMBA_TOOL" user sensitive "$user" off && changed "Cleared delegation sensitivity for $user" ;;
        0) return 0 ;;
    esac
}

user_rfc2307() {
    local user uid
    user="$(user_select || true)"; [[ -n "$user" ]] || return 1
    uid="$(ask 'Unique uidNumber' '')"; [[ "$uid" =~ ^[0-9]+$ ]] || { err "uidNumber must be numeric."; return 1; }
    "$SAMBA_TOOL" user addunixattrs "$user" "$uid" || return 1
    changed "Added RFC2307 Unix attributes to $user"
    ok "RFC2307 attributes added. Verify idmap strategy across all Linux clients."
}

user_delete_guided() {
    local user
    user="$(user_select || true)"; [[ -n "$user" ]] || return 1
    object_is_protected_builtin "$user" && { err "Protected built-in account cannot be deleted."; return 1; }
    user_show_full "$user" || true
    confirm_literal "Permanently delete AD user '$user'?" "DELETE-USER" || return 0
    "$SAMBA_TOOL" user delete "$user" || return 1
    changed "Deleted AD user $user"
    ok "User deleted."
}

users_menu() {
    require_dc || return 1
    while true; do
        printf '\nUSERS\n  [1] List users\n  [2] Inspect user\n  [3] Create user\n  [4] Rename / identity attributes\n  [5] Move user to OU/container\n  [6] Memberships / primary group\n  [7] Password / account lifecycle\n  [8] RFC2307 Unix attributes\n  [9] Raw AD object editor\n  [D] Delete user\n  [0] Back\n'
        local c user
        c="$(ask 'Action' '1')"; c="${c^^}"
        case "$c" in
            1) users_inventory ;;
            2) user_show_full ;;
            3) user_create_guided ;;
            4) user_rename_guided ;;
            5) user_move_guided ;;
            6) user_membership_menu ;;
            7) user_password_menu ;;
            8) user_rfc2307 ;;
            9) user="$(user_select || true)"; [[ -n "$user" ]] && "$SAMBA_TOOL" user edit "$user" ;;
            D) user_delete_guided ;;
            0) return 0 ;;
            *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}

groups_inventory() { require_dc || return 1; "$SAMBA_TOOL" group list | sort -f; }

group_select() {
    local groups selected
    groups="$(groups_inventory)" || return 1
    selected="$(select_from_lines 'AD GROUPS' "$groups" 1)" || return 1
    printf '%s' "$selected"
}

group_create_guided() {
    local group scope category description
    group="$(ask 'Group name' '')"; [[ -n "$group" ]] || return 1
    scope="$(ask 'Scope (Global/Domain/Universal)' 'Global')"
    category="$(ask 'Type (Security/Distribution)' 'Security')"
    description="$(ask 'Description (optional)' '')"
    local -a args=(group add "$group")
    args+=("--group-scope=$scope" "--group-type=$category")
    [[ -n "$description" ]] && args+=("--description=$description")
    "$SAMBA_TOOL" "${args[@]}" || return 1
    changed "Created AD group $group"
}

group_membership_menu() {
    local group member c
    group="$(group_select || true)"; [[ -n "$group" ]] || return 1
    while true; do
        printf '\nGROUP MEMBERS: %s\n  [1] List members\n  [2] Add member(s)\n  [3] Remove member(s)\n  [0] Back\n' "$group"
        c="$(ask 'Action' '1')"
        case "$c" in
            1) "$SAMBA_TOOL" group listmembers "$group" ;;
            2) member="$(ask 'Member(s), comma-separated' '')"; "$SAMBA_TOOL" group addmembers "$group" "$member" && changed "Added member(s) to $group" ;;
            3) member="$(ask 'Member(s), comma-separated' '')"; "$SAMBA_TOOL" group removemembers "$group" "$member" && changed "Removed member(s) from $group" ;;
            0) return 0 ;;
        esac
    done
}

group_rfc2307() {
    local group gid
    group="$(group_select || true)"; [[ -n "$group" ]] || return 1
    gid="$(ask 'Unique gidNumber' '')"; [[ "$gid" =~ ^[0-9]+$ ]] || { err "gidNumber must be numeric."; return 1; }
    "$SAMBA_TOOL" group addunixattrs "$group" "$gid" || return 1
    changed "Added RFC2307 Unix attributes to group $group"
}

group_delete_guided() {
    local group
    group="$(group_select || true)"; [[ -n "$group" ]] || return 1
    object_is_protected_builtin "$group" && { err "Protected AD group cannot be deleted by this workflow."; return 1; }
    "$SAMBA_TOOL" group listmembers "$group" 2>/dev/null || true
    confirm_literal "Permanently delete AD group '$group'?" "DELETE-GROUP" || return 0
    "$SAMBA_TOOL" group delete "$group" || return 1
    changed "Deleted AD group $group"
}

groups_menu() {
    require_dc || return 1
    while true; do
        printf '\nGROUPS\n  [1] List groups\n  [2] Show group object\n  [3] Create group\n  [4] Memberships\n  [5] RFC2307 Unix attributes\n  [6] Raw AD object editor\n  [D] Delete group\n  [0] Back\n'
        local c group
        c="$(ask 'Action' '1')"; c="${c^^}"
        case "$c" in
            1) groups_inventory ;;
            2) group="$(group_select || true)"; [[ -n "$group" ]] && "$SAMBA_TOOL" group show "$group" ;;
            3) group_create_guided ;;
            4) group_membership_menu ;;
            5) group_rfc2307 ;;
            6) group="$(group_select || true)"; [[ -n "$group" ]] && "$SAMBA_TOOL" group edit "$group" ;;
            D) group_delete_guided ;;
            0) return 0 ;;
            *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}

computers_inventory() { require_dc || return 1; "$SAMBA_TOOL" computer list | sort -f; }

computer_select() {
    local items selected
    items="$(computers_inventory)" || return 1
    selected="$(select_from_lines 'AD COMPUTERS' "$items" 1)" || return 1
    printf '%s' "$selected"
}

computer_network_evidence() {
    local computer fqdn ip
    computer="$(computer_select || true)"; [[ -n "$computer" ]] || return 1
    computer="${computer%$}"
    fqdn="${computer,,}.${DOMAIN}"
    printf '\nCOMPUTER NETWORK EVIDENCE\n'
    printf '  Account : %s\n  FQDN    : %s\n' "$computer" "$fqdn"
    ip="$(dig +short A "$fqdn" 2>/dev/null | head -1 || true)"
    printf '  DNS A   : %s\n' "${ip:-not-resolved}"
    [[ -n "$ip" ]] && ping -c 1 -W 1 "$ip" >/dev/null 2>&1 && printf '  ICMP    : reachable\n' || printf '  ICMP    : no-response/not-tested\n'
    [[ -n "$ip" ]] && timeout 2 bash -c "</dev/tcp/$ip/445" >/dev/null 2>&1 && printf '  SMB/445 : reachable\n' || printf '  SMB/445 : unavailable/not-tested\n'
    "$SAMBA_TOOL" computer show "$computer" 2>/dev/null || true
}

computer_delete_guided() {
    local computer
    computer="$(computer_select || true)"; [[ -n "$computer" ]] || return 1
    "$SAMBA_TOOL" computer show "$computer" 2>/dev/null || true
    confirm_literal "Delete '$computer' only when the endpoint is retired or its AD object is genuinely stale." "DELETE-COMPUTER" || return 0
    "$SAMBA_TOOL" computer delete "$computer" || return 1
    changed "Deleted AD computer $computer"
}

ou_menu() {
    require_dc || return 1
    while true; do
        printf '\nORGANIZATIONAL UNITS\n  [1] List OUs\n  [2] List objects in OU\n  [3] Create OU\n  [4] Move OU\n  [5] Rename OU\n  [6] Delete empty OU\n  [D] Force subtree delete (destructive)\n  [0] Back\n'
        local c ou parent new
        c="$(ask 'Action' '1')"; c="${c^^}"
        case "$c" in
            1) "$SAMBA_TOOL" ou list --full-dn ;;
            2) ou="$(ask 'OU DN' '')"; "$SAMBA_TOOL" ou listobjects "$ou" --full-dn --recursive ;;
            3) ou="$(ask 'OU DN (e.g. OU=Engineering)' '')"; "$SAMBA_TOOL" ou add "$ou" && changed "Created OU $ou" ;;
            4) ou="$(ask 'Existing OU DN' '')"; parent="$(ask 'New parent DN' '')"; "$SAMBA_TOOL" ou move "$ou" "$parent" && changed "Moved OU $ou" ;;
            5) ou="$(ask 'Existing OU DN' '')"; new="$(ask 'New OU DN' '')"; "$SAMBA_TOOL" ou rename "$ou" "$new" && changed "Renamed OU $ou to $new" ;;
            6) ou="$(ask 'OU DN' '')"; confirm "Delete empty OU $ou?" N && { "$SAMBA_TOOL" ou delete "$ou"; changed "Deleted OU $ou"; } ;;
            D) ou="$(ask 'OU DN' '')"; confirm_literal "This recursively deletes the OU and all child objects." "DELETE-SUBTREE" && { "$SAMBA_TOOL" ou delete "$ou" --force-subtree-delete; changed "Force-deleted OU subtree $ou"; } ;;
            0) return 0 ;;
            *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}

computers_menu() {
    require_dc || return 1
    while true; do
        printf '\nCOMPUTERS / OUs\n  [1] List computer accounts\n  [2] Inspect computer\n  [3] Network evidence\n  [4] Organizational Units\n  [D] Delete stale computer object\n  [R] Remote operations for endpoint\n  [0] Back\n'
        local c computer
        c="$(ask 'Action' '1')"; c="${c^^}"
        case "$c" in
            1) computers_inventory ;;
            2) computer="$(computer_select || true)"; [[ -n "$computer" ]] && "$SAMBA_TOOL" computer show "$computer" ;;
            3) computer_network_evidence ;;
            4) ou_menu ;;
            D) computer_delete_guided ;;
            R) remote_ops_menu ;;
            0) return 0 ;;
            *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}

dsacl_subcommand_supported() {
    local subcmd="$1"
    "$SAMBA_TOOL" dsacl "$subcmd" --help >/dev/null 2>&1
}

permissions_menu() {
    require_dc || return 1
    while true; do
        printf '\nDIRECTORY PERMISSIONS / DS ACL\n  [1] User direct memberships\n  [2] Group members\n  [3] Read DS ACL on object DN\n  [4] Set DS ACL entry (advanced)\n  [5] Delete DS ACL entry (advanced)\n  [0] Back\n'
        local c user group dn sddl
        c="$(ask 'Action' '1')"
        case "$c" in
            1) user="$(user_select || true)"; [[ -n "$user" ]] && "$SAMBA_TOOL" user getgroups "$user" ;;
            2) group="$(group_select || true)"; [[ -n "$group" ]] && "$SAMBA_TOOL" group listmembers "$group" --full-dn ;;
            3)
                dsacl_subcommand_supported get || { warn "Installed samba-tool does not expose dsacl get."; continue; }
                dn="$(ask 'Directory object DN' '')"; [[ -n "$dn" ]] && "$SAMBA_TOOL" dsacl get --objectdn="$dn"
                ;;
            4)
                dsacl_subcommand_supported set || { warn "Installed samba-tool does not expose dsacl set."; continue; }
                dn="$(ask 'Directory object DN' '')"; sddl="$(ask 'ACE SDDL fragment accepted by samba-tool dsacl set' '')"
                [[ -n "$dn" && -n "$sddl" ]] || continue
                confirm_literal "ACL changes can grant domain-wide privileges. Review the DN and SDDL carefully." "APPLY" || continue
                "$SAMBA_TOOL" dsacl set --objectdn="$dn" --sddl="$sddl" && changed "Modified DS ACL on $dn"
                ;;
            5)
                dsacl_subcommand_supported delete || { warn "Installed samba-tool does not expose dsacl delete."; continue; }
                dn="$(ask 'Directory object DN' '')"; sddl="$(ask 'ACE SDDL fragment accepted by samba-tool dsacl delete' '')"
                [[ -n "$dn" && -n "$sddl" ]] || continue
                confirm_literal "Deleting an ACE can break delegated administration or access." "APPLY" || continue
                "$SAMBA_TOOL" dsacl delete --objectdn="$dn" --sddl="$sddl" && changed "Deleted DS ACL entry on $dn"
                ;;
            0) return 0 ;;
            *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}


# ---------------------------------------------------------------------------
# DNS, resolver, time and service resilience
# ---------------------------------------------------------------------------

smb_global_value() {
    local key="$1"
    command_exists testparm || return 1
    testparm -s --parameter-name="$key" 2>/dev/null | head -1
}

smb_set_global_param() {
    local key="$1" value="$2" file="/etc/samba/smb.conf" backup
    [[ -f "$file" ]] || { err "$file is unavailable."; return 1; }
    backup="${BACKUP_ROOT}/smb.conf.$(date +%Y%m%d-%H%M%S).bak"
    cp -a "$file" "$backup" || return 1
    python3 - "$file" "$key" "$value" <<'PY'
import sys,re,os,tempfile
path,key,value=sys.argv[1:]
with open(path,encoding='utf-8',errors='surrogateescape') as f: lines=f.readlines()
sec=None; global_start=None; global_end=len(lines); found=None
for i,line in enumerate(lines):
    m=re.match(r'^\s*\[([^]]+)\]\s*$',line)
    if m:
        new=m.group(1).strip().lower()
        if sec=='global' and global_end==len(lines): global_end=i
        sec=new
        if sec=='global' and global_start is None: global_start=i
    elif sec=='global':
        m=re.match(r'^\s*([^#;][^=]+?)\s*=.*$',line)
        if m and m.group(1).strip().lower()==key.lower(): found=i
if global_start is None:
    lines=['[global]\n',f'    {key} = {value}\n','\n']+lines
elif found is not None:
    indent=re.match(r'^(\s*)',lines[found]).group(1) or '    '
    lines[found]=f'{indent}{key} = {value}\n'
else:
    lines.insert(global_end,f'    {key} = {value}\n')
fd,tmp=tempfile.mkstemp(prefix='.smb.conf.',dir=os.path.dirname(path),text=True)
os.close(fd)
try:
    with open(tmp,'w',encoding='utf-8',errors='surrogateescape') as f: f.writelines(lines)
    os.chmod(tmp,0o644)
    os.replace(tmp,path)
finally:
    try: os.unlink(tmp)
    except FileNotFoundError: pass
PY
    if ! testparm -s "$file" >/dev/null 2>&1; then
        cp -a "$backup" "$file"
        err "smb.conf validation failed; restored $backup."
        return 1
    fi
    changed "Set smb.conf global '$key = $value' (backup: $backup)"
}

dns_forwarder_health() {
    require_dc || return 1
    local configured="" direct="" via_dc=""
    configured="$(smb_global_value 'dns forwarder' || true)"
    [[ -n "$configured" ]] || configured="${DNS_FORWARDER:-}"
    printf '\nDNS FORWARDING HEALTH\n'
    printf '  Configured forwarder : %s\n' "${configured:-none}"
    if [[ -n "$configured" ]]; then
        direct="$(dig +time=3 +tries=1 @"$configured" "$EXTERNAL_DNS_PROBE" A +short 2>/dev/null || true)"
        [[ -n "$direct" ]] && ok "Upstream $configured resolves $EXTERNAL_DNS_PROBE." || warn "Upstream $configured did not resolve $EXTERNAL_DNS_PROBE."
    fi
    via_dc="$(dig +time=4 +tries=1 @127.0.0.1 "$EXTERNAL_DNS_PROBE" A +short 2>/dev/null || true)"
    if [[ -n "$via_dc" ]]; then
        DNS_FORWARDING_STATUS="ok"
        ok "Samba DNS forwards external names through the configured path."
        return 0
    fi
    DNS_FORWARDING_STATUS="bad"
    warn "Samba DNS cannot currently resolve $EXTERNAL_DNS_PROBE through forwarding."
    return 1
}

network_upstream_dns_candidates() {
    command_exists nmcli || return 0
    nmcli -t -f IP4.DNS device show "$AD_IFACE" 2>/dev/null | sed -n 's/^IP4\.DNS[^:]*://p' | awk 'NF' | awk '!seen[$0]++'
}

dns_forwarder_repair() {
    require_dc || return 1
    local current candidate chosen=""
    current="$(smb_global_value 'dns forwarder' || true)"
    printf '\nDNS FORWARDER REPAIR\n'
    printf 'Current: %s\n' "${current:-unset}"
    printf 'NetworkManager-observed candidates (may be empty after DC resolver ownership):\n'
    network_upstream_dns_candidates | sed 's/^/  - /'
    chosen="$(ask 'Upstream DNS IPv4 to configure' "${DNS_FORWARDER:-$current}")"
    validate_forwarder "$chosen" || return 1
    smb_set_global_param 'dns forwarder' "$chosen" || return 1
    DNS_FORWARDER="$chosen"; save_config
    systemctl restart "$DC_SERVICE" || { err "Samba restart failed after forwarder change."; return 1; }
    sleep 2
    dns_forwarder_health
}

resolver_diagnostics() {
    printf '\nRESOLVER / NETWORKMANAGER DIAGNOSTICS\n'
    printf 'Interface : %s\nConnection: %s\n' "${AD_IFACE:-unknown}" "${NM_CONNECTION:-unknown}"
    printf '\n/etc/resolv.conf -> %s\n' "$(readlink -f /etc/resolv.conf 2>/dev/null || printf /etc/resolv.conf)"
    sed -n '1,80p' /etc/resolv.conf 2>/dev/null || true
    if command_exists nmcli && [[ -n "$AD_IFACE" ]]; then
        printf '\nNetworkManager runtime DNS\n'
        nmcli -f GENERAL.CONNECTION,IP4.ADDRESS,IP4.GATEWAY,IP4.DNS device show "$AD_IFACE" 2>/dev/null || true
        printf '\nPersistent profile DNS\n'
        nmcli -f ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv4.dns-search,ipv4.ignore-auto-dns connection show "$NM_CONNECTION" 2>/dev/null || true
    fi
}

resolver_repair() {
    require_dc || return 1
    detect_network
    [[ -n "$NM_CONNECTION" ]] || { err "NetworkManager connection unavailable."; return 1; }
    resolver_diagnostics
    printf '\nTarget resolver policy: the DC resolves through its own Samba DNS (%s), which forwards external names upstream.\n' "$DC_IP"
    dns_forwarder_health || warn "Repair forwarding before or immediately after resolver convergence."
    confirm "Re-apply the DC DNS policy to NetworkManager?" N || return 0
    configure_dc_resolver || return 1
    nmcli device reapply "$AD_IFACE" >/dev/null 2>&1 || nmcli connection up "$NM_CONNECTION" >/dev/null 2>&1 || true
    sleep 2
    dig @127.0.0.1 "_ldap._tcp.dc._msdcs.${DOMAIN}" SRV +short || true
    getent hosts "$DC_FQDN" || true
    changed "Repaired DC resolver convergence through NetworkManager"
}

samba_dns_cmd() {
    ensure_admin_ticket || return 1
    "$SAMBA_TOOL" "$@" --use-kerberos=required
}

dns_records_menu() {
    require_dc || return 1
    local server="${DC_FQDN:-127.0.0.1}" c zone name type data old new
    while true; do
        printf '\nAD DNS RECORDS\n  [1] List zones\n  [2] Query record\n  [3] Add record\n  [4] Update record\n  [5] Delete record\n  [6] Create zone\n  [7] Delete zone\n  [0] Back\n'
        c="$(ask 'Action' '1')"
        case "$c" in
            1) samba_dns_cmd dns zonelist "$server" ;;
            2) zone="$(ask 'Zone' "$DOMAIN")"; name="$(ask 'Name (@ or host label)' '@')"; type="$(ask 'Type' 'ALL')"; samba_dns_cmd dns query "$server" "$zone" "$name" "$type" ;;
            3) zone="$(ask 'Zone' "$DOMAIN")"; name="$(ask 'Name' '')"; type="$(ask 'Type (A/AAAA/CNAME/TXT/SRV/PTR)' 'A')"; data="$(ask 'Data' '')"; samba_dns_cmd dns add "$server" "$zone" "$name" "$type" "$data" && changed "Added AD DNS record $name.$zone" ;;
            4) zone="$(ask 'Zone' "$DOMAIN")"; name="$(ask 'Name' '')"; type="$(ask 'Type' 'A')"; old="$(ask 'Old data' '')"; new="$(ask 'New data' '')"; samba_dns_cmd dns update "$server" "$zone" "$name" "$type" "$old" "$new" && changed "Updated AD DNS record $name.$zone" ;;
            5) zone="$(ask 'Zone' "$DOMAIN")"; name="$(ask 'Name' '')"; type="$(ask 'Type' 'A')"; data="$(ask 'Exact data to remove' '')"; confirm "Delete this DNS record?" N && { samba_dns_cmd dns delete "$server" "$zone" "$name" "$type" "$data"; changed "Deleted AD DNS record $name.$zone"; } ;;
            6) zone="$(ask 'New AD-integrated zone' '')"; samba_dns_cmd dns zonecreate "$server" "$zone" && changed "Created AD DNS zone $zone" ;;
            7) zone="$(ask 'Zone to delete' '')"; confirm_literal "Deleting an AD-integrated DNS zone is destructive." "DELETE-ZONE" && { samba_dns_cmd dns zonedelete "$server" "$zone"; changed "Deleted AD DNS zone $zone"; } ;;
            0) return 0 ;;
        esac
        pause_ui
    done
}

dns_menu() {
    require_dc || return 1
    while true; do
        printf '\nDNS / RESOLVER\n  [1] AD locator queries\n  [2] Forwarding health\n  [3] Repair/change DNS forwarder\n  [4] Resolver diagnostics\n  [5] Re-apply DC resolver policy\n  [6] AD DNS zones / records\n  [0] Back\n'
        local c
        c="$(ask 'Action' '1')"
        case "$c" in
            1) printf '\nLDAP DC locator\n'; dig @127.0.0.1 "_ldap._tcp.dc._msdcs.${DOMAIN}" SRV +short; printf '\nKerberos locator\n'; dig @127.0.0.1 "_kerberos._tcp.${DOMAIN}" SRV +short ;;
            2) dns_forwarder_health || true ;;
            3) dns_forwarder_repair || true ;;
            4) resolver_diagnostics ;;
            5) resolver_repair || true ;;
            6) dns_records_menu ;;
            0) return 0 ;;
            *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}

chrony_managed_block() {
    local cidr="${AD_CLIENT_CIDR:-}" pool="${NTP_POOL:-pool.ntp.org}"
    cat <<EOF_BLOCK
# BEGIN RHEL-AD-ASSISTANT
# Upstream time for this DC. Kerberos requires tight clock discipline.
pool ${pool} iburst
# Allow signed NTP responses to AD clients when Samba ntp_signd is available.
ntpsigndsocket /var/lib/samba/ntp_signd
allow ${cidr}
# END RHEL-AD-ASSISTANT
EOF_BLOCK
}

configure_domain_time() {
    require_dc || return 1
    rpm -q chrony >/dev/null 2>&1 || { package_available chrony && dnf install -y chrony || { err "chrony unavailable."; return 1; }; }
    local file=/etc/chrony.conf backup="${BACKUP_ROOT}/chrony.conf.$(date +%Y%m%d-%H%M%S).bak" tmp
    cp -a "$file" "$backup"
    tmp="$(mktemp)"
    awk '/^# BEGIN RHEL-AD-ASSISTANT$/{skip=1;next}/^# END RHEL-AD-ASSISTANT$/{skip=0;next}!skip{print}' "$file" >"$tmp"
    printf '\n' >>"$tmp"; chrony_managed_block >>"$tmp"
    cat "$tmp" >"$file"; rm -f "$tmp"
    if ! chronyd -p -f "$file" >/dev/null 2>"${STATE_DIR}/chrony-parse.err"; then
        cp -a "$backup" "$file"
        err "chronyd rejected the managed configuration; previous config restored."
        sed -n '1,80p' "${STATE_DIR}/chrony-parse.err" >&2 || true
        return 1
    fi
    systemctl enable --now chronyd.service >/dev/null 2>&1 || true
    systemctl restart chronyd.service || { cp -a "$backup" "$file"; systemctl restart chronyd.service || true; err "chronyd restart failed; configuration restored."; return 1; }
    changed "Configured signed domain time policy with chronyd"
    sleep 2
    chronyc tracking 2>/dev/null || true
    chronyc sources -v 2>/dev/null || true
}

time_health() {
    printf '\nTIME / KERBEROS CLOCK HEALTH\n'
    timedatectl status 2>/dev/null | sed -n '1,16p' || true
    systemctl is-active --quiet chronyd.service && ok "chronyd is active." || warn "chronyd is not active."
    command_exists chronyc && chronyc tracking 2>/dev/null || true
    if [[ -S /var/lib/samba/ntp_signd/socket ]]; then ok "Samba ntp_signd socket is available."; else warn "Samba ntp_signd socket not detected."; fi
}

# ---------------------------------------------------------------------------
# GPO control plane and SYSVOL
# ---------------------------------------------------------------------------

ensure_builtin_gpo_library() {
    mkdir -p "$GPO_BUILTIN_DIR" "$GPO_CUSTOM_DIR"
    chmod 0700 "$GPO_DIR" "$GPO_BUILTIN_DIR" "$GPO_CUSTOM_DIR" 2>/dev/null || true
    cat >"${GPO_BUILTIN_DIR}/windows-powershell-logging.json" <<'JSON'
[
 {"keyname":"Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging","valuename":"EnableScriptBlockLogging","class":"MACHINE","type":"REG_DWORD","data":1},
 {"keyname":"Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging","valuename":"EnableModuleLogging","class":"MACHINE","type":"REG_DWORD","data":1}
]
JSON
    cat >"${GPO_BUILTIN_DIR}/windows-disable-llmnr.json" <<'JSON'
[
 {"keyname":"Software\\Policies\\Microsoft\\Windows NT\\DNSClient","valuename":"EnableMulticast","class":"MACHINE","type":"REG_DWORD","data":0}
]
JSON
    cat >"${GPO_BUILTIN_DIR}/windows-smb-guest-hardening.json" <<'JSON'
[
 {"keyname":"Software\\Policies\\Microsoft\\Windows\\LanmanWorkstation","valuename":"AllowInsecureGuestAuth","class":"MACHINE","type":"REG_DWORD","data":0}
]
JSON
    cat >"${GPO_BUILTIN_DIR}/windows-rdp-nla.json" <<'JSON'
[
 {"keyname":"Software\\Policies\\Microsoft\\Windows NT\\Terminal Services","valuename":"UserAuthentication","class":"MACHINE","type":"REG_DWORD","data":1}
]
JSON
    cat >"${GPO_BUILTIN_DIR}/windows-screen-lock.json" <<'JSON'
[
 {"keyname":"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop","valuename":"ScreenSaveActive","class":"USER","type":"REG_SZ","data":"1"},
 {"keyname":"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop","valuename":"ScreenSaverIsSecure","class":"USER","type":"REG_SZ","data":"1"},
 {"keyname":"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop","valuename":"ScreenSaveTimeOut","class":"USER","type":"REG_SZ","data":"900"}
]
JSON
    cat >"${GPO_BUILTIN_DIR}/windows-disable-always-install-elevated.json" <<'JSON'
[
 {"keyname":"Software\\Policies\\Microsoft\\Windows\\Installer","valuename":"AlwaysInstallElevated","class":"MACHINE","type":"REG_DWORD","data":0},
 {"keyname":"Software\\Policies\\Microsoft\\Windows\\Installer","valuename":"AlwaysInstallElevated","class":"USER","type":"REG_DWORD","data":0}
]
JSON
    cat >"${GPO_BUILTIN_DIR}/windows-legal-notice.json" <<'JSON'
[
 {"keyname":"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","valuename":"legalnoticecaption","class":"MACHINE","type":"REG_SZ","data":"Authorized access only"},
 {"keyname":"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","valuename":"legalnoticetext","class":"MACHINE","type":"REG_SZ","data":"Use of this system may be monitored and is restricted to authorized users."}
]
JSON
}

gpo_list() { require_dc || return 1; samba_dns_cmd gpo listall; }

gpo_create() {
    local name
    name="$(ask 'GPO display name' '')"; [[ -n "$name" ]] || return 1
    ensure_admin_ticket || return 1
    "$SAMBA_TOOL" gpo create "$name" --use-kerberos=required && changed "Created GPO $name"
}

gpo_show() {
    local guid
    guid="$(ask 'GPO GUID (including braces)' '')"; [[ -n "$guid" ]] || return 1
    ensure_admin_ticket || return 1
    "$SAMBA_TOOL" gpo show "$guid" --use-kerberos=required
}

gpo_link_menu() {
    local c dn guid
    printf '\nGPO LINKS\n  [1] Show links on container\n  [2] Link/update GPO\n  [3] Unlink GPO\n  [4] Show inheritance\n  [5] Set inheritance\n'
    c="$(ask 'Action' '1')"
    dn="$(ask 'Container DN (domain DN or OU DN)' "$(domain_dn)")"; [[ -n "$dn" ]] || return 1
    ensure_admin_ticket || return 1
    case "$c" in
        1) "$SAMBA_TOOL" gpo getlink "$dn" --use-kerberos=required ;;
        2) guid="$(ask 'GPO GUID' '')"; "$SAMBA_TOOL" gpo setlink "$dn" "$guid" --use-kerberos=required && changed "Linked GPO $guid to $dn" ;;
        3) guid="$(ask 'GPO GUID' '')"; "$SAMBA_TOOL" gpo dellink "$dn" "$guid" --use-kerberos=required && changed "Unlinked GPO $guid from $dn" ;;
        4) "$SAMBA_TOOL" gpo getinheritance "$dn" --use-kerberos=required ;;
        5) local mode; mode="$(ask 'Inheritance (block/inherit)' 'inherit')"; [[ "$mode" =~ ^(block|inherit)$ ]] || return 1; "$SAMBA_TOOL" gpo setinheritance "$dn" "$mode" --use-kerberos=required && changed "Set GPO inheritance $mode on $dn" ;;
    esac
}

gpo_builtin_apply() {
    ensure_builtin_gpo_library
    local files selected guid
    files="$(find "$GPO_BUILTIN_DIR" -maxdepth 1 -type f -name '*.json' -printf '%f\n' | sort)"
    selected="$(select_from_lines 'BUILT-IN WINDOWS POLICY JSON' "$files" 1)" || return 1
    guid="$(ask 'Target GPO GUID' '')"; [[ -n "$guid" ]] || return 1
    ensure_admin_ticket || return 1
    info "Policy file: ${GPO_BUILTIN_DIR}/${selected}"
    cat "${GPO_BUILTIN_DIR}/${selected}"
    confirm "Merge these settings into $guid?" N || return 0
    "$SAMBA_TOOL" gpo load "$guid" --content="${GPO_BUILTIN_DIR}/${selected}" --use-kerberos=required || return 1
    changed "Loaded built-in policy $selected into GPO $guid"
    "$SAMBA_TOOL" gpo show "$guid" --use-kerberos=required || true
}

gpo_custom_load() {
    local path guid mode=""
    path="$(ask 'Absolute JSON policy file path' '')"; [[ -r "$path" ]] || { err "File not readable."; return 1; }
    python3 -m json.tool "$path" >/dev/null 2>&1 || { err "Invalid JSON."; return 1; }
    guid="$(ask 'Target GPO GUID' '')"; [[ -n "$guid" ]] || return 1
    confirm "Replace existing registry policies instead of merging?" N && mode="--replace"
    ensure_admin_ticket || return 1
    if [[ -n "$mode" ]]; then "$SAMBA_TOOL" gpo load "$guid" --content="$path" "$mode" --use-kerberos=required; else "$SAMBA_TOOL" gpo load "$guid" --content="$path" --use-kerberos=required; fi
    changed "Loaded custom GPO JSON $(basename "$path") into $guid"
}

gpo_backup_one() {
    local guid target="${BACKUP_ROOT}/gpo-$(date +%Y%m%d-%H%M%S)"
    guid="$(ask 'GPO GUID' '')"; [[ -n "$guid" ]] || return 1
    mkdir -p "$target"; chmod 0700 "$target"
    ensure_admin_ticket || return 1
    "$SAMBA_TOOL" gpo backup "$guid" --tmpdir="$target" --use-kerberos=required || return 1
    changed "Backed up GPO $guid to $target"
    ok "GPO backup stored under $target"
}

gpo_delete() {
    local guid
    guid="$(ask 'GPO GUID' '')"; [[ -n "$guid" ]] || return 1
    ensure_admin_ticket || return 1
    "$SAMBA_TOOL" gpo show "$guid" --use-kerberos=required || true
    "$SAMBA_TOOL" gpo listcontainers "$guid" --use-kerberos=required || true
    confirm_literal "Delete the GPO itself after reviewing its links/containers." "DELETE-GPO" || return 0
    "$SAMBA_TOOL" gpo del "$guid" --use-kerberos=required || return 1
    changed "Deleted GPO $guid"
}

sysvol_acl_menu() {
    require_dc || return 1
    printf '\nSYSVOL ACL\n  [1] Check SYSVOL ACLs\n  [2] Check GPO LDAP/SYSVOL ACL consistency\n  [3] Reset SYSVOL ACLs to Samba defaults\n'
    local c
    c="$(ask 'Action' '1')"
    case "$c" in
        1) "$SAMBA_TOOL" ntacl sysvolcheck ;;
        2) ensure_admin_ticket && "$SAMBA_TOOL" gpo aclcheck --use-kerberos=required ;;
        3) backup_domain || return 1; confirm_literal "SYSVOL ACL reset rewrites ACLs to Samba defaults. A fresh domain backup has been requested first." "RESET-SYSVOL-ACL" || return 0; "$SAMBA_TOOL" ntacl sysvolreset && changed "Reset SYSVOL ACLs" ;;
    esac
}

gpo_linux_policy_menu() {
    require_dc || return 1
    local guid c setting value
    guid="$(ask 'GPO GUID' '')"; [[ -n "$guid" ]] || return 1
    ensure_admin_ticket || return 1
    printf '\nSAMBA LINUX/WINBIND GPO\n  [1] List registered CSEs\n  [2] List Samba security policy\n  [3] Set Samba security policy value\n  [4] List smb.conf policy values\n  [5] Set smb.conf policy value\n'
    c="$(ask 'Action' '1')"
    case "$c" in
        1) "$SAMBA_TOOL" gpo cse list ;;
        2) "$SAMBA_TOOL" gpo manage security list "$guid" --use-kerberos=required ;;
        3) setting="$(ask 'Security policy key (e.g. MinimumPasswordLength)' '')"; value="$(ask 'Value' '')"; "$SAMBA_TOOL" gpo manage security set "$guid" "$setting" "$value" --use-kerberos=required && changed "Set Samba GPO security $setting" ;;
        4) "$SAMBA_TOOL" gpo manage smb_conf list "$guid" --use-kerberos=required ;;
        5) setting="$(ask 'smb.conf parameter' '')"; value="$(ask 'Value (blank removes policy)' '')"; "$SAMBA_TOOL" gpo manage smb_conf set "$guid" "$setting" "$value" --use-kerberos=required && changed "Set Samba GPO smb.conf $setting" ;;
    esac
}

gpo_menu() {
    require_dc || return 1
    ensure_builtin_gpo_library
    while true; do
        printf '\nGROUP POLICY\n  [1] List all GPOs\n  [2] Show GPO\n  [3] Create empty GPO\n  [4] Links / inheritance\n  [5] Apply built-in Windows policy JSON\n  [6] Load custom policy JSON\n  [7] Backup GPO\n  [8] SYSVOL / GPO ACL health\n  [9] Samba Linux policy / CSE\n  [D] Delete GPO\n  [0] Back\n'
        local c
        c="$(ask 'Action' '1')"; c="${c^^}"
        case "$c" in
            1) gpo_list ;;
            2) gpo_show ;;
            3) gpo_create ;;
            4) gpo_link_menu ;;
            5) gpo_builtin_apply ;;
            6) gpo_custom_load ;;
            7) gpo_backup_one ;;
            8) sysvol_acl_menu ;;
            9) gpo_linux_policy_menu ;;
            D) gpo_delete ;;
            0) cleanup_admin_ticket; return 0 ;;
            *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}


# ---------------------------------------------------------------------------
# Security, Kerberos, audit and validation
# ---------------------------------------------------------------------------

security_param_report() {
    local key current
    printf '\nSAMBA SECURITY PARAMETERS\n'
    for key in 'server min protocol' 'client min protocol' 'server signing' 'client signing' 'ldap server require strong auth' 'ntlm auth' 'tls enabled' 'dns forwarder'; do
        current="$(smb_global_value "$key" 2>/dev/null || true)"
        printf '  %-34s %s\n' "$key" "${current:-default/unset}"
    done
}

security_host_report() {
    printf '\nRHEL-LIKE HOST SECURITY\n'
    printf '  SELinux       : %s\n' "$(getenforce 2>/dev/null || printf unavailable)"
    printf '  Crypto policy : %s\n' "$(update-crypto-policies --show 2>/dev/null || printf unavailable)"
    printf '  firewalld     : %s\n' "$(systemctl is-active firewalld.service 2>/dev/null || printf unavailable)"
    printf '  FIPS          : %s\n' "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || printf unknown)"
    printf '  SSH session   : %s\n' "$([[ $REMOTE_SESSION -eq 1 ]] && printf yes || printf no)"
    if command_exists firewall-cmd; then
        printf '\nActive firewalld zones\n'
        firewall-cmd --get-active-zones 2>/dev/null || true
        printf '\nAssistant-relevant rich rules\n'
        firewall-cmd --list-rich-rules 2>/dev/null | grep -E '(^| )source address=|port port=' || true
    fi
}

selinux_audit() {
    printf '\nSELINUX\n'
    getenforce 2>/dev/null || true
    sestatus 2>/dev/null | sed -n '1,25p' || true
    if command_exists ausearch; then
        printf '\nRecent AVC denials\n'
        ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | tail -n 100 || true
    else
        warn "ausearch is unavailable; install audit tooling from configured repositories for AVC evidence."
    fi
    printf '\nThe assistant never disables SELinux or writes broad allow-all policy.\n'
}

kerberos_client_audit() {
    require_dc || return 1
    printf '\nKERBEROS CLIENT CONFIGURATION\n'
    printf 'Realm      : %s\n' "$REALM"
    printf 'KRB5 config: /etc/krb5.conf\n'
    grep -Ev '^[[:space:]]*(#|$)' /etc/krb5.conf 2>/dev/null | sed -n '1,120p' || true
    if [[ -r /var/lib/samba/private/krb5.conf ]]; then
        if cmp -s /etc/krb5.conf /var/lib/samba/private/krb5.conf; then ok "System krb5.conf matches Samba-generated configuration."; else warn "System krb5.conf differs from Samba-generated configuration."; fi
    else
        warn "Samba-generated /var/lib/samba/private/krb5.conf is unavailable."
    fi
    command_exists klist && klist -e 2>/dev/null || true
}

kerberos_client_repair() {
    require_dc || return 1
    local generated=/var/lib/samba/private/krb5.conf backup
    [[ -r "$generated" ]] || { err "Samba-generated krb5.conf is unavailable."; return 1; }
    backup="${BACKUP_ROOT}/krb5.conf.$(date +%Y%m%d-%H%M%S).bak"
    cp -a /etc/krb5.conf "$backup" 2>/dev/null || true
    printf '\nGenerated Kerberos configuration:\n'
    sed -n '1,160p' "$generated"
    confirm "Install this Samba-generated Kerberos configuration as /etc/krb5.conf?" N || return 0
    cp -f "$generated" /etc/krb5.conf; chmod 0644 /etc/krb5.conf
    changed "Repaired /etc/krb5.conf from Samba-generated configuration"
    ok "Kerberos client configuration installed; previous file: $backup"
}

kerberos_crypto_readiness() {
    require_dc || return 1
    local db
    db="$(samdb_path || true)"; [[ -n "$db" ]] || return 1
    command_exists ldbsearch || { warn "ldbsearch unavailable; install Samba LDB tools for account-level crypto evidence."; return 1; }
    printf '\nKERBEROS ACCOUNT ENCRYPTION READINESS\n'
    printf 'Accounts with explicit msDS-SupportedEncryptionTypes are classified by AES bits (0x08/0x10).\n'
    local tmp="${STATE_DIR}/krb-crypto-${RUN_ID}.txt"
    ldbsearch -H "$db" '(|(objectClass=user)(objectClass=computer))' sAMAccountName msDS-SupportedEncryptionTypes >"$tmp" 2>/dev/null || { err "LDB encryption-type query failed."; return 1; }
    python3 - "$tmp" <<'PY'
import sys
records=[]; cur={}
for raw in open(sys.argv[1],encoding='utf-8',errors='ignore'):
    line=raw.strip()
    if not line:
        if cur: records.append(cur); cur={}
        continue
    if ': ' in line:
        k,v=line.split(': ',1); cur[k]=v
if cur: records.append(cur)
counts={'AES_READY':0,'RC4_ONLY':0,'OTHER_EXPLICIT':0,'IMPLICIT_DEFAULT':0}
weak=[]
for r in records:
    n=r.get('sAMAccountName');
    if not n: continue
    raw=r.get('msDS-SupportedEncryptionTypes')
    if raw is None:
        cls='IMPLICIT_DEFAULT'
    else:
        try: val=int(raw,0)
        except: val=0
        if val & 0x18: cls='AES_READY'
        elif val & 0x04: cls='RC4_ONLY'
        else: cls='OTHER_EXPLICIT'
    counts[cls]+=1
    if cls in ('RC4_ONLY','OTHER_EXPLICIT'): weak.append((n,raw,cls))
print('  AES-ready explicit :',counts['AES_READY'])
print('  RC4-only explicit  :',counts['RC4_ONLY'])
print('  Other explicit     :',counts['OTHER_EXPLICIT'])
print('  Implicit/default   :',counts['IMPLICIT_DEFAULT'])
if weak:
    print('\nExplicit accounts requiring review before any AES-only policy:')
    for n,v,c in weak[:100]: print(f'  {n:32} {v!s:8} {c}')
PY
    printf '\nCrypto policy: %s\n' "$(update-crypto-policies --show 2>/dev/null || printf unavailable)"
    warn "Do not enforce AES-only merely from this report. Validate all trusts, service accounts and legacy clients first."
}

domain_password_policy_menu() {
    require_dc || return 1
    while true; do
        printf '\nDOMAIN PASSWORD POLICY\n  [1] Show current policy\n  [2] Minimum password length\n  [3] Complexity on/off\n  [4] Password history length\n  [5] Maximum password age\n  [6] Minimum password age\n  [0] Back\n'
        local c v
        c="$(ask 'Action' '1')"
        case "$c" in
            1) "$SAMBA_TOOL" domain passwordsettings show ;;
            2) v="$(ask 'Minimum length' '14')"; [[ "$v" =~ ^[0-9]+$ ]] || continue; confirm "Apply min-pwd-length=$v?" N && { "$SAMBA_TOOL" domain passwordsettings set --min-pwd-length="$v"; changed "Changed domain minimum password length"; } ;;
            3) v="$(ask 'Complexity (on/off)' 'on')"; [[ "$v" =~ ^(on|off)$ ]] || continue; confirm "Apply complexity=$v?" N && { "$SAMBA_TOOL" domain passwordsettings set --complexity="$v"; changed "Changed domain password complexity"; } ;;
            4) v="$(ask 'History length' '24')"; [[ "$v" =~ ^[0-9]+$ ]] || continue; confirm "Apply history-length=$v?" N && { "$SAMBA_TOOL" domain passwordsettings set --history-length="$v"; changed "Changed domain password history"; } ;;
            5) v="$(ask 'Maximum password age in days (0 may mean never)' '60')"; [[ "$v" =~ ^[0-9]+$ ]] || continue; confirm "Apply max-pwd-age=$v?" N && { "$SAMBA_TOOL" domain passwordsettings set --max-pwd-age="$v"; changed "Changed domain maximum password age"; } ;;
            6) v="$(ask 'Minimum password age in days' '1')"; [[ "$v" =~ ^[0-9]+$ ]] || continue; confirm "Apply min-pwd-age=$v?" N && { "$SAMBA_TOOL" domain passwordsettings set --min-pwd-age="$v"; changed "Changed domain minimum password age"; } ;;
            0) return 0 ;;
        esac
        pause_ui
    done
}

samba_security_apply() {
    require_dc || return 1
    printf '\nSAFE MODERN SAMBA BASELINE\n'
    printf 'This profile strengthens transport/authentication defaults but can break legacy SMB/LDAP/NTLM clients.\n'
    security_param_report
    confirm "Create a domain backup before proposing the baseline?" Y || return 0
    backup_domain || { err "Backup failed; security baseline aborted."; return 1; }
    confirm_literal "Apply modern transport baseline after reviewing legacy-client compatibility." "APPLY" || return 0
    smb_set_global_param 'server min protocol' 'SMB2_02' || return 1
    smb_set_global_param 'client min protocol' 'SMB2_02' || return 1
    smb_set_global_param 'server signing' 'mandatory' || return 1
    smb_set_global_param 'ldap server require strong auth' 'yes' || return 1
    if confirm "Also require NTLMv2-only? This may affect legacy clients/trusts." N; then smb_set_global_param 'ntlm auth' 'ntlmv2-only' || return 1; fi
    systemctl restart "$DC_SERVICE" || { err "Samba restart failed after baseline. Restore a recorded smb.conf backup if needed."; return 1; }
    changed "Applied selected modern Samba security baseline"
    validate_dc || true
}

security_menu() {
    require_dc || return 1
    while true; do
        printf '\nSECURITY\n  [1] Host / SELinux / crypto / firewalld evidence\n  [2] Samba transport security audit\n  [3] Apply modern Samba baseline\n  [4] Kerberos client audit\n  [5] Repair Kerberos client config\n  [6] Kerberos account crypto readiness\n  [7] Domain password policy\n  [8] Database consistency check\n  [9] SYSVOL ACL health\n  [0] Back\n'
        local c
        c="$(ask 'Action' '1')"
        case "$c" in
            1) security_host_report; selinux_audit ;;
            2) security_param_report ;;
            3) samba_security_apply ;;
            4) kerberos_client_audit ;;
            5) kerberos_client_repair ;;
            6) kerberos_crypto_readiness ;;
            7) domain_password_policy_menu ;;
            8) "$SAMBA_TOOL" dbcheck --cross-ncs ;;
            9) sysvol_acl_menu ;;
            0) return 0 ;;
            *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}

samba_listener_snapshot() {
    ss -H -lntup 2>/dev/null || true
}

validate_listener() {
    local label="$1" port="$2" data="$3"
    if grep -Eq ":${port}([[:space:]]|$)" <<<"$data"; then ok "$label listener present on port $port."; else err "$label listener missing on port $port."; return 1; fi
}

validate_dc() {
    load_config || true
    detect_samba_capability || true
    printf '\nAD/DC VALIDATION\n'
    [[ "$(samba_role)" == ad-dc ]] || { err "Samba AD database not detected."; return 1; }
    [[ -n "$DC_SERVICE" ]] || { err "No Samba AD service unit detected."; return 1; }
    systemctl is-active --quiet "$DC_SERVICE" && ok "$DC_SERVICE is active." || err "$DC_SERVICE is not active."
    local listeners
    listeners="$(samba_listener_snapshot)"
    validate_listener DNS 53 "$listeners" || true
    validate_listener Kerberos 88 "$listeners" || true
    validate_listener LDAP 389 "$listeners" || true
    validate_listener SMB 445 "$listeners" || true
    validate_listener KPASSWD 464 "$listeners" || true
    if dig +time=3 +tries=1 @127.0.0.1 "_ldap._tcp.dc._msdcs.${DOMAIN}" SRV +short 2>/dev/null | grep -qi "${DOMAIN}"; then ok "LDAP DC locator SRV resolves locally."; else err "LDAP DC locator SRV failed."; fi
    if dig +time=3 +tries=1 @127.0.0.1 "_kerberos._tcp.${DOMAIN}" SRV +short 2>/dev/null | grep -qi "${DOMAIN}"; then ok "Kerberos SRV resolves locally."; else err "Kerberos SRV failed."; fi
    dns_forwarder_health || true
    systemctl is-active --quiet chronyd.service && ok "chronyd is active." || warn "chronyd is inactive."
    command_exists chronyc && chronyc waitsync 3 0.5 >/dev/null 2>&1 && ok "chronyd reports synchronization." || warn "Chrony synchronization could not be confirmed quickly."
    [[ "$(getenforce 2>/dev/null || true)" == Enforcing ]] && ok "SELinux is enforcing." || warn "SELinux is not enforcing."
    [[ "$(update-crypto-policies --show 2>/dev/null || true)" != LEGACY ]] && ok "System crypto policy is not LEGACY." || warn "System crypto policy is LEGACY."
    "$SAMBA_TOOL" dbcheck --cross-ncs >/dev/null 2>&1 && ok "Samba database cross-NC check passed." || warn "Samba dbcheck reported findings."
    printf '\nFSMO\n'; "$SAMBA_TOOL" fsmo show 2>/dev/null || true
    printf '\nREPLICATION\n'; "$SAMBA_TOOL" drs showrepl --summary 2>/dev/null || "$SAMBA_TOOL" drs showrepl 2>/dev/null | sed -n '1,120p' || true
    printf '\nSYSVOL ACL\n'; "$SAMBA_TOOL" ntacl sysvolcheck >/dev/null 2>&1 && ok "SYSVOL ACL check passed." || warn "SYSVOL ACL check reported differences."
    show_findings_summary
    ((FAIL_COUNT == 0))
}

audit_dc() {
    load_config || true
    detect_network || true
    detect_samba_capability || true
    header
    printf 'READ-ONLY AUDIT / EVIDENCE\n'
    printf '\nOS / packages\n'
    uname -a || true
    rpm -q samba samba-common-tools python3-samba krb5-workstation chrony firewalld 2>/dev/null || true
    printf '\nNetwork\n'
    ip -brief address 2>/dev/null || true
    ip route 2>/dev/null || true
    resolver_diagnostics
    printf '\nSamba role/config\n'
    printf 'Role: %s\n' "$(samba_role)"
    command_exists testparm && testparm -s 2>/dev/null | sed -n '1,220p' || true
    printf '\nServices\n'
    for unit in "$DC_SERVICE" chronyd.service firewalld.service suricata.service; do [[ -n "$unit" ]] && printf '  %-30s %s / %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)" "$(systemctl is-enabled "$unit" 2>/dev/null || true)"; done
    security_host_report
    security_param_report
    kerberos_client_audit || true
    time_health
    dns_forwarder_health || true
    if [[ "$(samba_role)" == ad-dc ]]; then
        printf '\nDirectory counts\n'
        printf '  Users     : %s\n' "$($SAMBA_TOOL user list 2>/dev/null | awk 'NF{n++}END{print n+0}')"
        printf '  Groups    : %s\n' "$($SAMBA_TOOL group list 2>/dev/null | awk 'NF{n++}END{print n+0}')"
        printf '  Computers : %s\n' "$($SAMBA_TOOL computer list 2>/dev/null | awk 'NF{n++}END{print n+0}')"
        printf '  OUs       : %s\n' "$($SAMBA_TOOL ou list 2>/dev/null | awk 'NF{n++}END{print n+0}')"
        printf '\nFSMO\n'; "$SAMBA_TOOL" fsmo show 2>/dev/null || true
        printf '\nReplication summary\n'; "$SAMBA_TOOL" drs showrepl --summary 2>/dev/null || true
    fi
    show_runtime_paths
}

# ---------------------------------------------------------------------------
# Backup, recovery bundles, dependency lifecycle and boot health
# ---------------------------------------------------------------------------

list_backups() {
    printf '\nBACKUPS\n'
    find "$BACKUP_ROOT" -mindepth 1 -maxdepth 2 -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort -r | head -n 100 || true
}

recovery_bundle() {
    local target="${BACKUP_ROOT}/recovery-$(date +%Y%m%d-%H%M%S)" archive
    mkdir -p "$target"; chmod 0700 "$target"
    cp -a "$CONFIG_FILE" "$target/" 2>/dev/null || true
    cp -a /etc/samba/smb.conf "$target/" 2>/dev/null || true
    cp -a /etc/krb5.conf "$target/" 2>/dev/null || true
    cp -a /etc/chrony.conf "$target/" 2>/dev/null || true
    cp -a "$CUSTOM_UNIT" "$target/" 2>/dev/null || true
    [[ -n "$DC_SERVICE" ]] && systemctl cat "$DC_SERVICE" >"$target/samba-unit.txt" 2>/dev/null || true
    nmcli connection show "$NM_CONNECTION" >"$target/networkmanager.txt" 2>/dev/null || true
    firewall-cmd --list-all-zones >"$target/firewalld.txt" 2>/dev/null || true
    getenforce >"$target/selinux.txt" 2>/dev/null || true
    update-crypto-policies --show >"$target/crypto-policy.txt" 2>/dev/null || true
    journalctl -u "$DC_SERVICE" -n 500 --no-pager >"$target/samba-journal.txt" 2>/dev/null || true
    "$SAMBA_TOOL" fsmo show >"$target/fsmo.txt" 2>&1 || true
    "$SAMBA_TOOL" drs showrepl >"$target/showrepl.txt" 2>&1 || true
    "$SAMBA_TOOL" domain level show >"$target/domain-level.txt" 2>&1 || true
    archive="${target}.tar.gz"
    tar -C "$(dirname "$target")" -czf "$archive" "$(basename "$target")" || return 1
    chmod 0600 "$archive"
    changed "Created recovery/evidence bundle $archive"
    ok "Recovery bundle: $archive"
}

backup_menu() {
    require_dc || return 1
    while true; do
        printf '\nBACKUP / RECOVERY EVIDENCE\n  [1] Online domain backup\n  [2] Offline domain backup (stops/locks as Samba requires)\n  [3] GPO backup\n  [4] Recovery/evidence bundle\n  [5] List backups\n  [0] Back\n'
        local c target
        c="$(ask 'Action' '1')"
        case "$c" in
            1) backup_domain ;;
            2) target="${BACKUP_ROOT}/domain-offline-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$target"; "$SAMBA_TOOL" domain backup offline --targetdir="$target" && { changed "Created offline Samba domain backup"; ok "Offline backup: $target"; } ;;
            3) gpo_backup_one ;;
            4) recovery_bundle ;;
            5) list_backups ;;
            0) return 0 ;;
        esac
        pause_ui
    done
}

package_status_line() {
    local pkg="$1" version="not-installed" repo=""
    rpm -q "$pkg" >/dev/null 2>&1 && version="$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}' "$pkg" 2>/dev/null || true)"
    repo="$(dnf -q repoquery --installed --qf '%{repoid}' "$pkg" 2>/dev/null | head -1 || true)"
    printf '  %-30s %-34s %s\n' "$pkg" "$version" "${repo:-n/a}"
}

dependencies_audit() {
    printf '\nDEPENDENCY / CAPABILITY AUDIT\n'
    printf '  %-30s %-34s %s\n' PACKAGE VERSION REPOSITORY
    local pkg
    for pkg in samba samba-common-tools python3-samba krb5-workstation bind-utils chrony firewalld NetworkManager jq openssh-clients policycoreutils-python-utils suricata; do package_status_line "$pkg"; done
    printf '\nCapabilities\n'
    for pkg in samba samba-tool testparm ldbsearch dig kinit chronyd firewall-cmd nmcli ssh net suricata jq python3; do
        if command_exists "$pkg"; then printf '  [OK] %-24s %s\n' "$pkg" "$(command -v "$pkg")"; else printf '  [--] %s\n' "$pkg"; fi
    done
    detect_samba_capability
    if [[ -n "$SAMBA_TOOL" ]] && "$SAMBA_TOOL" domain provision --help >/dev/null 2>&1; then ok "Samba build exposes AD-DC provisioning capability."; else warn "Samba build does not expose AD-DC provisioning capability."; fi
    printf '\nAvailable package updates (read-only)\n'
    dnf -q check-update samba\* krb5\* chrony firewalld NetworkManager 2>/dev/null | sed -n '1,100p' || true
}

dependencies_menu() {
    while true; do
        printf '\nDEPENDENCIES\n  [1] Audit packages/capabilities\n  [2] Install/repair required dependencies\n  [3] Check available updates\n  [4] Refresh DNF metadata\n  [0] Back\n'
        local c
        c="$(ask 'Action' '1')"
        case "$c" in
            1) dependencies_audit ;;
            2) install_dependencies ;;
            3) dnf check-update samba\* krb5\* chrony firewalld NetworkManager || true ;;
            4) confirm "Refresh metadata from already configured repositories?" Y && dnf makecache ;;
            0) return 0 ;;
        esac
        pause_ui
    done
}

configure_boot_ordering() {
    require_dc || return 1
    [[ -n "$DC_SERVICE" ]] || return 1
    local dropin="/etc/systemd/system/${DC_SERVICE}.d/90-rhel-ad-network-online.conf"
    mkdir -p "$(dirname "$dropin")" /usr/local/libexec
    cat >"$dropin" <<'EOF_DROP'
[Unit]
Wants=network-online.target NetworkManager-wait-online.service
After=network-online.target NetworkManager-wait-online.service chronyd.service
EOF_DROP
    cat >"$HEALTH_HELPER" <<EOF_HELPER
#!/usr/bin/env bash
set -uo pipefail
unit=$(printf '%q' "$DC_SERVICE")
logger -t rhel-ad-samba-health "checking Samba AD listeners after boot"
sleep 3
missing=0
for p in 53 88 389 445 464; do ss -H -lntup 2>/dev/null | grep -Eq ":\${p}([[:space:]]|$)" || missing=1; done
if ((missing)); then
  logger -t rhel-ad-samba-health "one or more AD listeners missing; restarting \$unit once"
  systemctl restart "\$unit"
  sleep 3
fi
exit 0
EOF_HELPER
    chmod 0755 "$HEALTH_HELPER"
    cat >"$HEALTH_SERVICE" <<EOF_SERVICE
[Unit]
Description=RHEL AD Assistant post-boot Samba listener health check
After=${DC_SERVICE} network-online.target
Requires=${DC_SERVICE}

[Service]
Type=oneshot
ExecStart=${HEALTH_HELPER}

[Install]
WantedBy=multi-user.target
EOF_SERVICE
    systemctl daemon-reload
    systemctl enable NetworkManager-wait-online.service >/dev/null 2>&1 || true
    systemctl enable rhel-ad-samba-health.service >/dev/null 2>&1 || true
    changed "Installed Samba AD network-online ordering and post-boot listener health check"
    ok "Boot ordering/health guard installed. Vendor service file was not edited."
}

boot_health_status() {
    printf '\nBOOT ORDERING / HEALTH\n'
    systemctl is-enabled NetworkManager-wait-online.service 2>/dev/null || true
    [[ -n "$DC_SERVICE" ]] && systemctl cat "$DC_SERVICE" 2>/dev/null | sed -n '1,160p' || true
    systemctl status rhel-ad-samba-health.service --no-pager 2>/dev/null | sed -n '1,40p' || true
}

# ---------------------------------------------------------------------------
# Migration and controlled reset/decommission
# ---------------------------------------------------------------------------

migration_readiness() {
    printf '\nAD MIGRATION / ADDITIONAL-DC READINESS\n'
    detect_network
    printf 'Host             : %s\n' "$(hostname -f 2>/dev/null || hostname)"
    printf 'Address/interface: %s / %s\n' "$DC_IP" "$AD_IFACE"
    printf 'Samba role       : %s\n' "$(samba_role)"
    printf 'SELinux          : %s\n' "$(getenforce 2>/dev/null || true)"
    printf 'Crypto policy    : %s\n' "$(update-crypto-policies --show 2>/dev/null || true)"
    dependencies_audit
}

migration_join_additional_dc() {
    vendor_support_gate || return 1
    [[ "$(samba_role)" == none ]] || { err "Existing AD/DC state detected; additional-DC join is only for a clean host."; return 1; }
    local existing_dns existing_dc trusted snap
    DOMAIN="$(ask 'Existing AD DNS domain' '')"; DOMAIN="${DOMAIN,,}"; valid_domain "$DOMAIN" || return 1
    REALM="${DOMAIN^^}"
    local default_netbios="${DOMAIN%%.*}"; default_netbios="${default_netbios^^}"
    NETBIOS_DOMAIN="$(ask 'Existing NetBIOS domain' "$default_netbios")"; NETBIOS_DOMAIN="${NETBIOS_DOMAIN^^}"; valid_netbios "$NETBIOS_DOMAIN" || return 1
    DC_HOSTNAME="$(ask 'New DC short hostname' "$(hostname -s)")"; DC_HOSTNAME="${DC_HOSTNAME,,}"
    DC_FQDN="${DC_HOSTNAME}.${DOMAIN}"
    existing_dns="$(ask 'Existing AD DNS/DC IPv4 used for discovery' '')"; valid_ipv4 "$existing_dns" || return 1
    AD_CLIENT_CIDR="$(ask 'Trusted AD client CIDR' '')"; valid_cidr "$AD_CLIENT_CIDR" || return 1
    DNS_FORWARDER="$(ask 'External DNS forwarder for this DC after join' '')"; validate_forwarder "$DNS_FORWARDER" || return 1
    install_dependencies || return 1
    ensure_static_dc_address || return 1
    if ! dig +time=3 +tries=1 @"$existing_dns" "_ldap._tcp.dc._msdcs.${DOMAIN}" SRV +short | grep -qi "$DOMAIN"; then err "Existing AD DNS does not answer the DC locator query."; return 1; fi
    snap="$(create_bootstrap_snapshot)"; BOOTSTRAP_ACTIVE=1; BOOTSTRAP_SNAPSHOT="$snap"
    hostnamectl set-hostname "$DC_FQDN"; ensure_hosts_record "$DC_IP" "$DC_FQDN" "$DC_HOSTNAME"
    nmcli connection modify "$NM_CONNECTION" ipv4.ignore-auto-dns yes ipv4.dns "$existing_dns" ipv4.dns-search "$DOMAIN,~." ipv4.dns-priority -100
    nmcli device reapply "$AD_IFACE" >/dev/null 2>&1 || nmcli connection up "$NM_CONNECTION"
    info "The additional-DC join will prompt for domain credentials. Passwords are not stored."
    confirm_literal "Join this clean host to $REALM as an additional Samba DC?" "JOIN-DC" || return 0
    if ! "$SAMBA_TOOL" domain join "$REALM" DC --dns-backend=SAMBA_INTERNAL -U"${ADMIN_USER:-Administrator}" --option="dns forwarder = ${DNS_FORWARDER}"; then
        err "Additional-DC join failed before a successful commit was established."
        return 1
    fi
    samdb_path >/dev/null 2>&1 || { err "Join returned success but sam.ldb is absent."; return 1; }
    BOOTSTRAP_COMMITTED=1; BOOTSTRAP_ACTIVE=0
    copy_generated_krb5; ensure_dc_unit; configure_dc_resolver; configure_firewall "$AD_CLIENT_CIDR" || true
    systemctl enable --now "$DC_SERVICE" || return 1
    save_config
    changed "Joined $DC_FQDN as additional Samba AD DC for $REALM"
    validate_dc || true
}

migration_menu() {
    while true; do
        printf '\nMIGRATION / ADDITIONAL DC\n  [1] Readiness evidence\n  [2] Join clean host as additional DC\n  [3] Replication status\n  [4] FSMO role inventory\n  [5] Trigger KCC\n  [0] Back\n'
        local c
        c="$(ask 'Action' '1')"
        case "$c" in
            1) migration_readiness ;;
            2) migration_join_additional_dc ;;
            3) require_dc && "$SAMBA_TOOL" drs showrepl ;;
            4) require_dc && "$SAMBA_TOOL" fsmo show ;;
            5) require_dc && confirm "Trigger Samba KCC topology calculation?" Y && "$SAMBA_TOOL" drs kcc "$DC_FQDN" ;;
            0) return 0 ;;
        esac
        pause_ui
    done
}

domain_dc_count() {
    require_dc || return 1
    local sam dbdn count=""
    sam="$(samdb_path 2>/dev/null || true)"
    dbdn="$(domain_dn 2>/dev/null || true)"

    # Prefer a direct SamDB query: SERVER_TRUST_ACCOUNT (0x2000 / 8192) is the
    # directory flag used by DC computer accounts. Fall back to the Domain
    # Controllers OU inventory when ldbsearch is unavailable.
    if command_exists ldbsearch && [[ -n "$sam" && -n "$dbdn" ]]; then
        count="$(ldbsearch -H "$sam" -b "$dbdn" -s sub \
            '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' dn \
            2>/dev/null | awk '/^dn: /{n++} END{print n+0}')"
        [[ "$count" =~ ^[0-9]+$ ]] && { printf '%s' "$count"; return 0; }
    fi

    "$SAMBA_TOOL" ou listobjects 'OU=Domain Controllers' --full-dn --recursive 2>/dev/null |
        awk '/^CN=/ || /^dn: CN=/{n++} END{print n+0}'
}

reset_domain() {
    require_dc || return 1
    local count bundle="${BACKUP_ROOT}/reset-$(date +%Y%m%d-%H%M%S)" archive
    count="$(domain_dc_count)"
    if [[ "$count" =~ ^[0-9]+$ ]] && ((count > 1)); then
        err "More than one Domain Controller object is present ($count). Destructive local reset is refused."
        warn "Demote/remove this DC using a multi-DC migration procedure instead of wiping local AD state."
        return 1
    fi
    printf '\nSINGLE-DC RESET / DECOMMISSION\n'
    warn "This destroys local Samba AD state after creating recovery artifacts. It is not a normal troubleshooting action."
    "$SAMBA_TOOL" fsmo show 2>/dev/null || true
    "$SAMBA_TOOL" drs showrepl 2>/dev/null || true
    backup_domain || { err "A fresh online domain backup is required before reset."; return 1; }
    recovery_bundle || { err "Recovery bundle creation failed; reset aborted."; return 1; }
    confirm_literal "Destroy local Samba AD database/configuration on this single-DC host?" "RESET-DOMAIN" || return 0
    mkdir -p "$bundle"; chmod 0700 "$bundle"
    systemctl disable --now "$DC_SERVICE" >/dev/null 2>&1 || true
    tar -czf "$bundle/samba-state.tar.gz" /etc/samba /var/lib/samba /var/cache/samba 2>/dev/null || { err "Could not archive Samba state; reset aborted before deletion."; systemctl start "$DC_SERVICE" >/dev/null 2>&1 || true; return 1; }
    cp -a "$CONFIG_FILE" "$bundle/" 2>/dev/null || true
    find /var/lib/samba -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true
    find /var/cache/samba -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true
    rm -f /etc/samba/smb.conf "$CONFIG_FILE"
    if [[ -n "$NM_CONNECTION" && -n "$DNS_FORWARDER" ]]; then
        nmcli connection modify "$NM_CONNECTION" ipv4.dns "$DNS_FORWARDER" ipv4.dns-search "" ipv4.ignore-auto-dns no ipv4.dns-priority 0 >/dev/null 2>&1 || true
        nmcli device reapply "$AD_IFACE" >/dev/null 2>&1 || true
    fi
    archive="${bundle}.tar.gz"; tar -C "$(dirname "$bundle")" -czf "$archive" "$(basename "$bundle")"; chmod 0600 "$archive"
    changed "Reset local single-DC Samba AD state; recovery bundle $archive"
    RUN_OUTCOME="DOMAIN_RESET"
    ok "Local Samba AD state removed. Recovery archive: $archive"
    warn "Hostname/firewall rules are intentionally left for operator review rather than guessed rollback."
}


# ---------------------------------------------------------------------------
# Remote endpoint operations
# ---------------------------------------------------------------------------

remote_log() {
    mkdir -p "$REMOTE_OPS_DIR"; touch "$REMOTE_OPS_LOG"; chmod 0600 "$REMOTE_OPS_LOG" 2>/dev/null || true
    printf '%s\t%s\t%s\t%s\t%s\n' "$(date -Is)" "${REMOTE_TARGET:-unknown}" "${REMOTE_TARGET_OS:-unknown}" "$1" "$2" >>"$REMOTE_OPS_LOG"
}

valid_remote_target() {
    local target="$1"
    # Accept IPv4, IPv6 text and DNS hostnames only. This value is later used
    # by /dev/tcp and SSH, so shell metacharacters must never be accepted.
    [[ -n "$target" && "$target" =~ ^[A-Za-z0-9_.:-]+$ ]]
}

valid_ssh_user() {
    local user="$1"
    [[ -n "$user" && "$user" =~ ^[A-Za-z0-9_.@\-]+$ ]]
}

valid_systemd_unit_name() {
    local unit="$1"
    [[ -n "$unit" && "$unit" =~ ^[A-Za-z0-9_.@:-]+$ ]]
}

remote_tcp_open() {
    local host="$1" port="$2"
    valid_remote_target "$host" || return 1
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    timeout 2 bash -c "</dev/tcp/${host}/${port}" >/dev/null 2>&1
}

remote_select_target() {
    require_dc || return 1
    local computer fqdn ip
    computer="$(computer_select || true)"; [[ -n "$computer" ]] || return 1
    computer="${computer%$}"
    fqdn="${computer,,}.${DOMAIN}"
    ip="$(dig +short A "$fqdn" 2>/dev/null | head -1 || true)"
    if [[ -z "$ip" ]]; then
        ip="$(ask 'DNS did not return IPv4; enter target IP/hostname' "$fqdn")"
    fi
    valid_remote_target "$ip" || { err "Invalid remote target syntax."; return 1; }
    REMOTE_TARGET="$ip"
    REMOTE_TARGET_OS="unknown"
    if remote_tcp_open "$ip" 22; then REMOTE_TARGET_OS="linux/ssh"
    elif remote_tcp_open "$ip" 445; then REMOTE_TARGET_OS="windows/smb-rpc"
    fi
    printf 'Selected: %s (%s) -> %s / %s\n' "$computer" "$fqdn" "$REMOTE_TARGET" "$REMOTE_TARGET_OS"
}

remote_ssh() {
    local cmd="$1" user cp
    [[ -n "$REMOTE_TARGET" ]] || remote_select_target || return 1
    remote_tcp_open "$REMOTE_TARGET" 22 || { err "SSH/22 is not reachable on $REMOTE_TARGET."; return 1; }
    user="${REMOTE_SSH_USER:-$REMOTE_SERVICE_USER}"
    mkdir -p "$SSH_CONTROL_DIR"; chmod 0700 "$SSH_CONTROL_DIR" 2>/dev/null || true; cp="$SSH_CONTROL_DIR/%C"
    remote_log SSH "$cmd"
    local keyopt=(); [[ -f "$REMOTE_OPS_DIR/controller_ed25519" ]] && keyopt=(-i "$REMOTE_OPS_DIR/controller_ed25519" -o IdentitiesOnly=yes); ssh "${keyopt[@]}" -o ConnectTimeout=12 -o ConnectionAttempts=3 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o ControlMaster=auto -o ControlPersist=180 -o ControlPath="$cp" "${user}@${REMOTE_TARGET}" "$cmd"
}

remote_windows_rpc() {
    local action="$1"; shift
    [[ -n "$REMOTE_TARGET" ]] || remote_select_target || return 1
    command_exists net || { err "Samba net utility unavailable."; return 1; }
    local account
    account="$(ask 'Windows/domain RPC account' "${NETBIOS_DOMAIN}\\${ADMIN_USER}")"
    remote_log RPC "$action $*"
    case "$action" in
        service-list) net rpc service list -S "$REMOTE_TARGET" -U "$account" ;;
        shutdown) net rpc shutdown -S "$REMOTE_TARGET" -U "$account" -t 60 "$@" ;;
        reboot) net rpc shutdown -S "$REMOTE_TARGET" -U "$account" -r -t 60 "$@" ;;
        abort) net rpc abortshutdown -S "$REMOTE_TARGET" -U "$account" ;;
        *) err "Unsupported RPC action."; return 1 ;;
    esac
}

remote_diagnostics() {
    [[ -n "$REMOTE_TARGET" ]] || remote_select_target || return 1
    local dir="${REMOTE_EVIDENCE_DIR}/$(date +%Y%m%d-%H%M%S)-${REMOTE_TARGET//[^A-Za-z0-9_.-]/_}"
    mkdir -p "$dir"; chmod 0700 "$dir"
    {
        printf 'Target: %s\nDetected: %s\nTime: %s\n' "$REMOTE_TARGET" "$REMOTE_TARGET_OS" "$(date -Is)"
        printf '\nDNS reverse/forward\n'; getent hosts "$REMOTE_TARGET" || true
        printf '\nRoute\n'; ip route get "$REMOTE_TARGET" 2>/dev/null || true
        printf '\nPorts\n'
        local p; for p in 22 53 88 135 389 445 5985 5986; do remote_tcp_open "$REMOTE_TARGET" "$p" && printf '%s open\n' "$p" || printf '%s closed/unreachable\n' "$p"; done
    } >"$dir/controller-diagnostics.txt"
    if remote_tcp_open "$REMOTE_TARGET" 22; then
        [[ -n "$REMOTE_SSH_USER" ]] || REMOTE_SSH_USER="$(ask 'SSH user' 'root')"
        if valid_ssh_user "$REMOTE_SSH_USER"; then
            ssh -o ConnectTimeout=5 "${REMOTE_SSH_USER}@${REMOTE_TARGET}" 'hostname -f; date -Is; uptime; ip -brief address 2>/dev/null || true; systemctl --failed --no-pager 2>/dev/null || true' >"$dir/ssh-evidence.txt" 2>&1 || true
        else
            printf 'Invalid SSH user syntax; SSH evidence skipped.\n' >"$dir/ssh-evidence.txt"
        fi
    fi
    remote_log EVIDENCE "$dir"
    ok "Remote evidence directory: $dir"
}

remote_ops_menu() {
    require_dc || return 1
    while true; do
        printf '\nREMOTE OPERATIONS\n  Target: %s / %s\n' "${REMOTE_TARGET:-not-selected}" "${REMOTE_TARGET_OS:-unknown}"
        printf '  [1] Select AD computer\n  [2] Readiness / port diagnostics\n  [3] Linux SSH: sessions + uptime\n  [4] Linux SSH: service status\n  [5] Linux SSH: restart service\n  [6] Linux SSH: wall message\n  [7] Linux SSH: reboot now\n  [8] Linux SSH: shutdown now\n  [9] Windows RPC: list services\n  [R] Windows RPC: reboot in 60s\n  [S] Windows RPC: shutdown in 60s\n  [C] Windows RPC: cancel shutdown\n  [B] Bootstrap managed Linux SSH identity\n  [E] Export evidence\n  [G] Guardrails\n  [0] Back\n'
        local c svc message
        c="$(ask 'Action' '1')"; c="${c^^}"
        case "$c" in
            1) remote_select_target ;;
            2) remote_diagnostics ;;
            3) remote_ssh 'hostname -f; uptime; who; w' ;;
            4)
                svc="$(ask 'systemd service' 'sshd.service')"
                valid_systemd_unit_name "$svc" || { err "Invalid systemd unit name."; continue; }
                remote_ssh "systemctl --no-pager --full status '$svc' | head -80"
                ;;
            5)
                svc="$(ask 'systemd service to restart' '')"
                valid_systemd_unit_name "$svc" || { err "Invalid systemd unit name."; continue; }
                confirm "Restart $svc on $REMOTE_TARGET?" N && remote_ssh "sudo systemctl restart '$svc' && systemctl is-active '$svc'"
                ;;
            6) message="$(ask 'Broadcast message' 'Administrative maintenance will begin shortly.')"; remote_ssh "printf '%s\\n' $(printf '%q' "$message") | wall" ;;
            7) confirm_literal "Reboot remote Linux endpoint $REMOTE_TARGET." "REBOOT" && remote_ssh "sudo systemd-run --unit=rhel-ad-reboot-$(date +%s) --on-active=2s /usr/bin/systemctl reboot >/dev/null && echo REBOOT-SCHEDULED" ;;
            8) confirm_literal "Shut down remote Linux endpoint $REMOTE_TARGET." "SHUTDOWN" && remote_ssh "sudo systemd-run --unit=rhel-ad-poweroff-$(date +%s) --on-active=2s /usr/bin/systemctl poweroff >/dev/null && echo POWEROFF-SCHEDULED" ;;
            9) remote_windows_rpc service-list ;;
            R) confirm_literal "Schedule Windows reboot through authenticated Samba RPC." "REBOOT" && remote_windows_rpc reboot ;;
            S) confirm_literal "Schedule Windows shutdown through authenticated Samba RPC." "SHUTDOWN" && remote_windows_rpc shutdown ;;
            C) remote_windows_rpc abort ;;
            B) remote_bootstrap_service ;;
            E) remote_diagnostics ;;
            G) printf '\nGuardrails:\n  - Credentials are requested by ssh/net interactively and are not stored.\n  - Power actions require literal confirmation.\n  - Prefer JEA/least-privilege endpoints for repeat Windows administration.\n  - Use SSH keys/sudo policy rather than embedding Linux passwords.\n  - Evidence is stored under %s.\n' "$REMOTE_EVIDENCE_DIR" ;;
            0) return 0 ;;
            *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}

# ---------------------------------------------------------------------------
# Passive IDS / Suricata
# ---------------------------------------------------------------------------

ids_package_available() { package_available suricata; }

ids_install_runtime_copy() {
    mkdir -p "$(dirname "$CLI_LIBEXEC")"
    cp -f "$0" "$CLI_LIBEXEC"; chmod 0750 "$CLI_LIBEXEC"
}

ids_install() {
    if ! command_exists suricata; then
        if ids_package_available; then
            info "Suricata is available in an already configured repository."
            confirm "Install Suricata without enabling any new repository?" Y || return 1
            dnf install -y suricata || return 1
            changed "Installed Suricata from configured repositories"
        else
            err "Suricata is not available from the currently configured repositories."
            warn "The assistant will not enable EPEL or another repository automatically."
            return 1
        fi
    fi
    ok "Suricata available: $(suricata --build-info 2>/dev/null | head -1 || command -v suricata)"
}

ids_validate_config() {
    local bin config setarg
    bin="$(command -v suricata)"; config=/etc/suricata/suricata.yaml
    [[ -x "$bin" && -r "$config" ]] || return 1
    setarg="vars.address-groups.HOME_NET=${AD_CLIENT_CIDR:-any}"
    "$bin" -T -c "$config" --set "$setarg"
}

ids_configure() {
    require_dc || return 1
    ids_install || return 1
    [[ -n "$AD_CLIENT_CIDR" ]] || { err "Trusted AD client CIDR is not configured."; return 1; }
    [[ -n "$AD_IFACE" ]] || detect_network
    ids_validate_config >/dev/null || { err "Vendor Suricata configuration does not validate with the requested HOME_NET overlay."; return 1; }
    local bin config=/etc/suricata/suricata.yaml modearg
    bin="$(command -v suricata)"
    if "$bin" --help 2>&1 | grep -q -- '--af-packet'; then modearg="--af-packet=${AD_IFACE}"; else modearg="-i ${AD_IFACE}"; fi
    mkdir -p "$(dirname "$IDS_DROPIN")" "$IDS_STATE_DIR" "$IDS_REPORT_DIR"
    cat >"$IDS_DROPIN" <<EOF_IDS
[Service]
ExecStart=
ExecStart=${bin} -c ${config} ${modearg} --set vars.address-groups.HOME_NET=${AD_CLIENT_CIDR}
EOF_IDS
    chmod 0644 "$IDS_DROPIN"
    systemctl daemon-reload
    if command_exists suricata-update; then
        info "Updating Suricata rules with the installed suricata-update utility."
        suricata-update || warn "suricata-update returned an error; existing rules are preserved by the vendor tooling."
    else
        warn "suricata-update is unavailable; using the rules currently provided by the installation."
    fi
    ids_validate_config >/dev/null || { err "Suricata validation failed after configuration; service will not be restarted."; return 1; }
    systemctl enable --now suricata.service || { err "Suricata service failed to start."; journalctl -u suricata.service -n 80 --no-pager || true; return 1; }
    changed "Configured passive Suricata monitoring on $AD_IFACE with HOME_NET=$AD_CLIENT_CIDR"
    ok "Suricata passive sensor enabled. No inline blocking was configured."
}

ids_sensor_health() {
    printf '\nIDS SENSOR HEALTH\n'
    if ! command_exists suricata; then warn "Suricata is not installed."; return 1; fi
    printf 'Version : %s\n' "$(suricata --build-info 2>/dev/null | head -1 || true)"
    printf 'Service : %s / %s\n' "$(systemctl is-active suricata.service 2>/dev/null || true)" "$(systemctl is-enabled suricata.service 2>/dev/null || true)"
    printf 'Interface: %s\nHOME_NET : %s\n' "$AD_IFACE" "$AD_CLIENT_CIDR"
    printf 'Drop-in  : %s\n' "$IDS_DROPIN"
    [[ -r /etc/suricata/suricata.yaml ]] && ids_validate_config >/dev/null 2>&1 && ok "Suricata configuration validates." || warn "Suricata configuration validation failed/unavailable."
    local eve="${IDS_EVE_DIR}/eve.json"
    [[ -r "$eve" ]] && printf 'EVE log  : %s (%s bytes)\n' "$eve" "$(stat -c %s "$eve" 2>/dev/null || printf '?')" || warn "EVE JSON log is not readable at $eve."
}

ids_report() {
    local eve="${IDS_EVE_DIR}/eve.json" output="${1:-}"
    [[ -r "$eve" ]] || { warn "No readable EVE log at $eve."; return 1; }
    local tmp="${output:-/dev/stdout}"
    python3 - "$eve" >"$tmp" <<'PY'
import json,sys,collections,os
p=sys.argv[1]
alerts=collections.Counter(); sigs=collections.Counter(); src=collections.Counter(); dst=collections.Counter(); app=collections.Counter(); total=0
# Keep memory bounded while still emphasizing recent activity.
from collections import deque
q=deque(maxlen=20000)
with open(p,encoding='utf-8',errors='ignore') as f:
    for line in f: q.append(line)
for line in q:
    try: e=json.loads(line)
    except: continue
    total+=1; et=e.get('event_type','unknown'); alerts[et]+=1
    if et=='alert':
        a=e.get('alert') or {}; sigs[a.get('signature','unknown')]+=1
        if e.get('src_ip'): src[e['src_ip']]+=1
        if e.get('dest_ip'): dst[e['dest_ip']]+=1
    if e.get('app_proto'): app[e['app_proto']]+=1
print('SURICATA RECENT EVE SUMMARY')
print('Source:',p)
print('Events analyzed:',total)
print('\nEvent types:')
for k,v in alerts.most_common(15): print(f'  {k:20} {v}')
print('\nTop alert signatures:')
for k,v in sigs.most_common(20): print(f'  {v:5}  {k}')
print('\nTop alert sources:')
for k,v in src.most_common(15): print(f'  {k:40} {v}')
print('\nTop application protocols:')
for k,v in app.most_common(15): print(f'  {k:20} {v}')
PY
    [[ -n "$output" ]] && { chmod 0600 "$output"; ok "IDS report: $output"; }
}

ids_daily_report() {
    mkdir -p "$IDS_REPORT_DIR"
    local out="${IDS_REPORT_DIR}/ids-$(date +%Y%m%d-%H%M%S).txt"
    ids_report "$out" || return 0
}

ids_enable_daily_timer() {
    ids_install_runtime_copy
    cat >"$IDS_DAILY_SERVICE" <<EOF_SVC
[Unit]
Description=RHEL AD Assistant daily IDS report
After=suricata.service

[Service]
Type=oneshot
ExecStart=${CLI_LIBEXEC} --ids-daily --no-color
EOF_SVC
    cat >"$IDS_DAILY_TIMER" <<'EOF_TIMER'
[Unit]
Description=Daily RHEL AD IDS evidence report

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=20m

[Install]
WantedBy=timers.target
EOF_TIMER
    systemctl daemon-reload
    systemctl enable --now rhel-ad-ids-daily.timer
    changed "Enabled daily passive IDS evidence timer"
}


# ---------------------------------------------------------------------------
# Modern IDS/Wazuh response, managed SSH and daily domain reporting
# ---------------------------------------------------------------------------

defense_init(){ mkdir -p "$DEFENSE_DIR" "$DOMAIN_REPORT_DIR" "$SSH_CONTROL_DIR"; chmod 0700 "$DEFENSE_DIR" "$SSH_CONTROL_DIR" 2>/dev/null || true; touch "$DEFENSE_TRUSTED"; chmod 0600 "$DEFENSE_TRUSTED"; [[ -f "$DEFENSE_CONFIG" ]] || { printf 'BUSINESS_START=08:00\nBUSINESS_END=18:00\nBUSINESS_HOURS_WINDOW=1\nAFTER_HOURS_WINDOW=8\nBLOCK_TTL_MINUTES=30\n' >"$DEFENSE_CONFIG"; chmod 0600 "$DEFENSE_CONFIG"; }; }
defense_load(){ defense_init; BUSINESS_START=08:00; BUSINESS_END=18:00; BUSINESS_HOURS_WINDOW=1; AFTER_HOURS_WINDOW=8; BLOCK_TTL_MINUTES=30; source "$DEFENSE_CONFIG" 2>/dev/null || true; }
defense_public_ipv4() {
    local ip="$1" a b
    valid_ipv4 "$ip" || return 1
    IFS=. read -r a b _ _ <<<"$ip"
    a=$((10#$a)); b=$((10#$b))
    ((a >= 1 && a <= 223)) || return 1
    ((a == 10 || a == 127 || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168))) && return 1
    return 0
}
defense_nft_setup(){ command_exists nft || { warn "nft command unavailable."; return 1; }; nft list table inet rhel_ad_guard >/dev/null 2>&1 || nft add table inet rhel_ad_guard; nft list set inet rhel_ad_guard blocked4 >/dev/null 2>&1 || nft 'add set inet rhel_ad_guard blocked4 { type ipv4_addr; flags timeout; }'; nft list chain inet rhel_ad_guard input >/dev/null 2>&1 || { nft 'add chain inet rhel_ad_guard input { type filter hook input priority -5; policy accept; }'; nft add rule inet rhel_ad_guard input ip saddr @blocked4 counter drop comment 'RHEL AD guarded IPS'; }; }
defense_list_blocks(){ defense_init; if command_exists nft && nft list set inet rhel_ad_guard blocked4 >/dev/null 2>&1; then nft list set inet rhel_ad_guard blocked4; else info "No assistant-managed temporary blocks."; fi; }
defense_unblock(){ local ip="$1"; nft delete element inet rhel_ad_guard blocked4 "{ $ip }" 2>/dev/null && ok "Unblocked $ip." || warn "$ip not present."; }
defense_unblock_all(){ confirm_literal "Emergency removal of every assistant-managed temporary block." "UNBLOCK-ALL" || return 0; nft flush set inet rhel_ad_guard blocked4 2>/dev/null || true; ok "All temporary blocks cleared."; }
defense_block(){ defense_load; local ip="$1" ttl="${2:-$BLOCK_TTL_MINUTES}"; defense_public_ipv4 "$ip" || { warn "Guarded response accepts only public IPv4 sources."; return 1; }; grep -Fxq "$ip" "$DEFENSE_TRUSTED" 2>/dev/null && { warn "$ip is trusted."; return 1; }; defense_nft_setup || return 1; nft delete element inet rhel_ad_guard blocked4 "{ $ip }" 2>/dev/null || true; nft add element inet rhel_ad_guard blocked4 "{ $ip timeout ${ttl}m }"; ok "Blocked $ip for ${ttl} minutes."; }
defense_trusted(){ defense_init; printf '\nTRUSTED IP / IP DE CONFIANZA\n'; nl -ba "$DEFENSE_TRUSTED" 2>/dev/null || true; }
defense_trust_add(){ local ip="$1"; [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1; grep -Fxq "$ip" "$DEFENSE_TRUSTED" || echo "$ip" >>"$DEFENSE_TRUSTED"; defense_unblock "$ip" >/dev/null 2>&1 || true; ok "$ip trusted and unblocked."; }
defense_trust_remove(){ local ip="$1"; grep -Fxv "$ip" "$DEFENSE_TRUSTED" >"${DEFENSE_TRUSTED}.tmp" || true; mv "${DEFENSE_TRUSTED}.tmp" "$DEFENSE_TRUSTED"; chmod 0600 "$DEFENSE_TRUSTED"; }

wazuh_status(){ printf '\nWAZUH\n'; local svc=''; for x in wazuh-agent wazuh; do systemctl list-unit-files "$x.service" >/dev/null 2>&1 && { svc="$x"; break; }; done; printf '  service: %s\n' "${svc:-not detected}"; [[ -n "$svc" ]] && printf '  state  : %s\n' "$(systemctl is-active "$svc" 2>/dev/null || true)"; [[ -r /var/ossec/etc/ossec.conf ]] && printf '  config : /var/ossec/etc/ossec.conf\n'; }
wazuh_suricata_integrate(){ local cfg=/var/ossec/etc/ossec.conf eve="${IDS_EVE_DIR}/eve.json"; [[ -r "$cfg" ]] || { warn "Wazuh agent is not configured."; return 1; }; [[ -e "$eve" ]] || { warn "Suricata EVE JSON is not available."; return 1; }; grep -Fq "$eve" "$cfg" && { ok "Wazuh already ingests Suricata EVE."; return 0; }; confirm "Add Suricata EVE telemetry to Wazuh?" Y || return 0; cp -a "$cfg" "${cfg}.rhel-ad.$(date +%s).bak"; local tmp; tmp="$(mktemp)"; awk -v eve="$eve" 'BEGIN{d=0} /<\/ossec_config>/&&!d{print "  <localfile>\n    <log_format>json</log_format>\n    <location>" eve "</location>\n  </localfile>";d=1}{print}' "$cfg" >"$tmp"; install -m 0640 "$tmp" "$cfg"; rm -f "$tmp"; systemctl restart wazuh-agent 2>/dev/null || systemctl restart wazuh 2>/dev/null || { warn "Wazuh restart failed; backup preserved."; return 1; }; ok "Wazuh now ingests Suricata EVE."; }

ids_human_review(){ defense_load; local eve="${IDS_EVE_DIR}/eve.json" hm hours label; [[ -r "$eve" ]] || { warn "No readable EVE JSON."; return 1; }; hm="$(date +%H:%M)"; hours="$BUSINESS_HOURS_WINDOW"; label=business; if [[ "$hm" < "$BUSINESS_START" || "$hm" > "$BUSINESS_END" ]]; then hours="$AFTER_HOURS_WINDOW"; label=after-hours; fi; printf '\nINTRUSION REVIEW / REVISIÓN DE INTRUSIONES (%s, %sh)\n' "$label" "$hours"; python3 - "$eve" "$hours" <<'PY_REV'
import sys,json,datetime,collections
p,h=sys.argv[1],int(sys.argv[2]); cut=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=h); c=collections.Counter()
for line in open(p,errors='replace'):
 try:e=json.loads(line)
 except:continue
 if e.get('event_type')!='alert':continue
 try:
  t=datetime.datetime.fromisoformat(str(e.get('timestamp','')).replace('Z','+00:00'))
  if t<cut:continue
 except:pass
 a=e.get('alert') or {}; sig=str(a.get('signature','unknown')); cat=str(a.get('category','')); sev=a.get('severity','?'); src=e.get('src_ip','?'); dst=e.get('dest_ip','?')
 low=(sig+' '+cat).lower(); kind='Recon/scan' if any(x in low for x in ('scan','recon','probe')) else 'Credential/auth' if any(x in low for x in ('brute','login','password','kerberos','ntlm')) else 'Malware/C2' if any(x in low for x in ('malware','trojan','c2','command and control')) else 'Exploit/intrusion' if any(x in low for x in ('exploit','attack','shell','overflow','injection')) else 'Protocol/anomaly'
 c[(kind,src,dst,sev,sig)]+=1
for (kind,src,dst,sev,sig),n in c.most_common(50):print(f'{n:4} {kind:18} sev={sev} {src:15}->{dst:15} {sig}')
PY_REV
}
ids_recommended_response(){
    local eve="${IDS_EVE_DIR}/eve.json"; [[ -r "$eve" ]] || return 1
    local rows ip; rows="$(python3 - "$eve" <<'PY_REC'
import sys,json,collections,ipaddress,datetime
p=sys.argv[1]; cut=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=8); c=collections.Counter()
with open(p,errors='replace') as f:
 for l in f:
  try:
   e=json.loads(l); a=e.get('alert') or {}; ip=e.get('src_ip')
   if e.get('event_type')!='alert' or int(a.get('severity',9))!=1 or not ip or not ipaddress.ip_address(ip).is_global: continue
   try:
    if datetime.datetime.fromisoformat(str(e.get('timestamp','')).replace('Z','+00:00'))<cut: continue
   except Exception: pass
   c[ip]+=1
  except Exception: pass
for ip,n in c.most_common(20): print(f'{ip}\t{n}')
PY_REC
)"
    [[ -n "$rows" ]] || { info "No qualifying severity-1 public source."; return 0; }
    printf '%s\n' "$rows" | nl -ba
    ip="$(ask 'IPv4 to block (blank cancels)' '')"; [[ -n "$ip" ]] && defense_block "$ip"
}
defense_schedule(){ defense_load; local a b c d e; a="$(ask 'Business start HH:MM' "$BUSINESS_START")"; b="$(ask 'Business end HH:MM' "$BUSINESS_END")"; c="$(ask 'Business IDS lookback hours' "$BUSINESS_HOURS_WINDOW")"; d="$(ask 'After-hours IDS lookback hours' "$AFTER_HOURS_WINDOW")"; e="$(ask 'Default block TTL minutes' "$BLOCK_TTL_MINUTES")"; printf 'BUSINESS_START=%s\nBUSINESS_END=%s\nBUSINESS_HOURS_WINDOW=%s\nAFTER_HOURS_WINDOW=%s\nBLOCK_TTL_MINUTES=%s\n' "$a" "$b" "$c" "$d" "$e" >"$DEFENSE_CONFIG"; chmod 0600 "$DEFENSE_CONFIG"; ok "Awareness schedule saved."; }
defense_telegram(){ defense_init; local token chat; token="$(ask 'Telegram bot token' '')"; chat="$(ask 'Telegram chat/channel ID' '')"; [[ -n "$token" && -n "$chat" ]] || return 1; printf 'TOKEN=%s\nCHAT_ID=%s\n' "$token" "$chat" >"$TELEGRAM_CONFIG"; chmod 0600 "$TELEGRAM_CONFIG"; curl -fsS --max-time 12 -X POST "https://api.telegram.org/bot${token}/sendMessage" --data-urlencode "chat_id=$chat" --data-urlencode "text=RHEL AD Assistant notification test on $(hostname -f 2>/dev/null||hostname)" >/dev/null && ok "Telegram test sent." || warn "Telegram test failed."; }
defense_response_menu(){ while true; do printf '\nIDS / IPS RESPONSE CENTER / CENTRO DE RESPUESTA\n  [1] List blocks / Ver bloqueos\n  [2] Unblock IP / Desbloquear IP\n  [3] Emergency unblock all / Desbloqueo total\n  [4] Temporary manual block / Bloqueo temporal\n  [5] Trusted IPs / IP de confianza\n  [6] Remove trusted IP / Quitar confianza\n  [7] Recommended severity-1 response\n  [8] Awareness schedule / Horario de vigilancia\n  [9] Telegram hook\n  [10] Enable 15-minute alert timer\n  [0] Back / Volver\n'; local c ip; c="$(ask 'Action' '1')"; case "$c" in 1) defense_list_blocks;;2) ip="$(ask 'IPv4' '')"; [[ -n "$ip" ]]&&defense_unblock "$ip";;3) defense_unblock_all;;4) ip="$(ask 'Public IPv4' '')"; [[ -n "$ip" ]]&&defense_block "$ip";;5) defense_trusted; ip="$(ask 'IPv4 to trust (blank skips)' '')"; [[ -n "$ip" ]]&&defense_trust_add "$ip";;6) defense_trusted; ip="$(ask 'IPv4 to remove' '')"; [[ -n "$ip" ]]&&defense_trust_remove "$ip";;7) ids_recommended_response;;8) defense_schedule;;9) defense_telegram;;10) ids_enable_alert_timer;;0)return 0;;esac; pause_ui; done; }

ids_alert_watch_once(){
    defense_load
    local eve="${IDS_EVE_DIR}/eve.json"; [[ -r "$eve" && -r "$TELEGRAM_CONFIG" ]] || return 0
    local TOKEN CHAT_ID; source "$TELEGRAM_CONFIG"; [[ -n "${TOKEN:-}" && -n "${CHAT_ID:-}" ]] || return 0
    local summary; summary="$(python3 - "$eve" <<'PY_ALERT'
import sys,json,collections,ipaddress,datetime
p=sys.argv[1]; cut=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=8); c=collections.Counter()
with open(p,errors='replace') as f:
 for l in f:
  try:
   e=json.loads(l);a=e.get('alert') or {};ip=e.get('src_ip')
   if e.get('event_type')!='alert' or int(a.get('severity',9))>1 or not ip or not ipaddress.ip_address(ip).is_global: continue
   try:
    if datetime.datetime.fromisoformat(str(e.get('timestamp','')).replace('Z','+00:00'))<cut: continue
   except Exception: pass
   c[(ip,a.get('signature','unknown'))]+=1
  except Exception: pass
for (ip,sig),n in c.most_common(5): print(f'{n}x {ip} {sig}')
PY_ALERT
)"
    [[ -n "$summary" ]] || return 0
    curl -fsS --max-time 12 -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" --data-urlencode "chat_id=$CHAT_ID" --data-urlencode "text=RHEL AD security attention required on $(hostname -f 2>/dev/null||hostname):\n${summary}\nReview manually in the assistant; no action was executed from Telegram." >/dev/null || true
}
ids_enable_alert_timer(){ install_cli_shortcuts; cat >/etc/systemd/system/rhel-ad-ids-awareness.service <<EOF_SVC
[Unit]
Description=RHEL AD IDS awareness notification check
[Service]
Type=oneshot
ExecStart=$CLI_LIBEXEC --ids-alert-watch
EOF_SVC
cat >/etc/systemd/system/rhel-ad-ids-awareness.timer <<'EOF_TIM'
[Unit]
Description=RHEL AD IDS awareness timer
[Timer]
OnBootSec=5m
OnUnitActiveSec=15m
Persistent=true
[Install]
WantedBy=timers.target
EOF_TIM
systemctl daemon-reload; systemctl enable --now rhel-ad-ids-awareness.timer; ok "15-minute IDS awareness timer enabled."; }

domain_daily_report(){ defense_init; local f="$DOMAIN_REPORT_DIR/domain-$(date +%F).txt"; { echo "RHEL AD DAILY DOMAIN REPORT / INFORME DIARIO AD"; echo "Generated: $(date -Is)"; echo "Host: $(hostname -f 2>/dev/null||hostname)"; echo; echo '== SERVICES =='; for u in "$DC_SERVICE" chronyd firewalld suricata wazuh-agent; do [[ -n "$u" ]]&&printf '%-24s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null||true)"; done; echo; echo '== FAILED UNITS =='; systemctl --failed --no-pager 2>/dev/null||true; echo; echo '== AD VALIDATION =='; "$SAMBA_TOOL" domain info "$(hostname -f 2>/dev/null||hostname)" 2>&1||true; "$SAMBA_TOOL" dbcheck --cross-ncs --quiet 2>&1||true; echo; echo '== DNS / NETWORK =='; dig +short _ldap._tcp."${DOMAIN:-invalid}" SRV 2>/dev/null||true; ip -brief addr 2>/dev/null||true; echo; echo '== TIME =='; chronyc tracking 2>/dev/null||true; echo; echo '== RECENT AUTH / SERVICE WARNINGS =='; journalctl --since '-24 hours' -p warning --no-pager 2>/dev/null|tail -n 200||true; echo; echo '== SURICATA HUMAN REVIEW =='; ids_human_review 2>&1||true; echo; echo '== HUMAN ATTENTION =='; systemctl --failed --no-legend 2>/dev/null|grep -q . && echo '[ATTENTION] Failed systemd units present.' || echo '[OK] No failed systemd units.'; } >"$f"; find "$DOMAIN_REPORT_DIR" -type f -name 'domain-*.txt' -mtime +90 -delete 2>/dev/null||true; ok "Domain report saved: $f"; printf '%s\n' "$f"; }
domain_reports_menu(){ while true; do printf '\nDAILY DOMAIN REPORTS / INFORMES DIARIOS\n  [1] Generate now / Generar ahora\n  [2] List reports / Listar informes\n  [3] View latest / Ver último\n  [4] Enable daily timer / Activar temporizador\n  [0] Back / Volver\n'; local c latest; c="$(ask 'Action' '1')"; case "$c" in 1) domain_daily_report;;2) ls -lh "$DOMAIN_REPORT_DIR" 2>/dev/null||true;;3) latest="$(ls -1t "$DOMAIN_REPORT_DIR"/domain-*.txt 2>/dev/null|head -1||true)"; [[ -n "$latest" ]]&&less "$latest"||warn "No reports.";;4) install_cli_shortcuts; cat >/etc/systemd/system/rhel-ad-domain-report.service <<EOF_SVC
[Unit]
Description=RHEL AD Assistant daily domain report
[Service]
Type=oneshot
ExecStart=$CLI_LIBEXEC --domain-report
EOF_SVC
cat >/etc/systemd/system/rhel-ad-domain-report.timer <<'EOF_TIM'
[Unit]
Description=Daily RHEL AD Assistant domain report
[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=20m
[Install]
WantedBy=timers.target
EOF_TIM
systemctl daemon-reload; systemctl enable --now rhel-ad-domain-report.timer; ok "Daily report timer enabled.";;0)return 0;;esac; pause_ui; done; }

remote_control_path(){ mkdir -p "$SSH_CONTROL_DIR"; chmod 0700 "$SSH_CONTROL_DIR"; printf '%s/%%C' "$SSH_CONTROL_DIR"; }
remote_ssh_managed(){ local cmd="$1" user="${REMOTE_SSH_USER:-$REMOTE_SERVICE_USER}" cp; [[ -n "$REMOTE_TARGET" ]]||remote_select_target||return 1; cp="$(remote_control_path)"; ssh -o ConnectTimeout=12 -o ConnectionAttempts=3 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o ControlMaster=auto -o ControlPersist=180 -o ControlPath="$cp" "${user}@${REMOTE_TARGET}" "$cmd"; }
remote_bootstrap_service(){ [[ -n "$REMOTE_TARGET" ]]||remote_select_target||return 1; local admin pub key; admin="$(ask 'Bootstrap SSH administrator (for example admin@domain)' '')"; [[ -n "$admin" ]]||return 0; defense_init; key="$REMOTE_OPS_DIR/controller_ed25519"; mkdir -p "$REMOTE_OPS_DIR"; chmod 0700 "$REMOTE_OPS_DIR"; [[ -f "$key" ]]||ssh-keygen -q -t ed25519 -N '' -f "$key"; pub="$(cat "$key.pub")"; info "One bootstrap login is required; its password is never stored."; ssh -o ConnectTimeout=20 "${admin}@${REMOTE_TARGET}" "sudo useradd --system --create-home --shell /bin/bash $REMOTE_SERVICE_USER 2>/dev/null || true; sudo install -d -m 700 -o $REMOTE_SERVICE_USER -g $REMOTE_SERVICE_USER /home/$REMOTE_SERVICE_USER/.ssh; printf '%s\\n' '$pub' | sudo tee /home/$REMOTE_SERVICE_USER/.ssh/authorized_keys >/dev/null; sudo chown $REMOTE_SERVICE_USER:$REMOTE_SERVICE_USER /home/$REMOTE_SERVICE_USER/.ssh/authorized_keys; sudo chmod 600 /home/$REMOTE_SERVICE_USER/.ssh/authorized_keys; printf '%s\\n' '$REMOTE_SERVICE_USER ALL=(root) NOPASSWD:/usr/bin/systemctl,/usr/bin/loginctl,/usr/bin/journalctl,/usr/bin/ss,/usr/bin/hostnamectl,/usr/bin/systemd-run' | sudo tee /etc/sudoers.d/rhel-ad-remote-ops >/dev/null; sudo chmod 440 /etc/sudoers.d/rhel-ad-remote-ops" && ok "Managed remote identity prepared on $REMOTE_TARGET."; }

ids_menu() {
    while true; do
        printf '\nIDS / SURICATA + WAZUH\n  [1] Readiness / sensor health\n  [2] Install/configure passive sensor\n  [3] Update rules\n  [4] Human intrusion review / Revisión de intrusiones\n  [5] Generate report file\n  [6] Recent alerts\n  [7] Enable daily report timer\n  [8] Wazuh status / Estado Wazuh\n  [9] Integrate Suricata EVE -> Wazuh\n  [R] IDS / IPS response center\n  [D] Daily domain reports\n  [0] Back / Volver\n'
        local c
        c="$(ask 'Action' '1')"
        case "$c" in
            1) ids_sensor_health || true ;;
            2) ids_configure ;;
            3) command_exists suricata-update && suricata-update || warn "suricata-update unavailable." ;;
            4) ids_human_review ;;
            5) ids_daily_report ;;
            6) [[ -r "${IDS_EVE_DIR}/eve.json" ]] && grep '"event_type":"alert"\|"event_type": "alert"' "${IDS_EVE_DIR}/eve.json" | tail -n 30 || warn "No EVE alerts available." ;;
            7) ids_enable_daily_timer ;;
            8) wazuh_status ;;
            9) wazuh_suricata_integrate ;;
            R|r) defense_response_menu ;;
            D|d) domain_reports_menu ;;
            0) return 0 ;;
        esac
        pause_ui
    done
}

# ---------------------------------------------------------------------------
# CLI shortcuts, post-install checklist and operations console
# ---------------------------------------------------------------------------

install_cli_shortcuts() {
    mkdir -p "$(dirname "$CLI_LIBEXEC")" "$CLI_LINK_DIR"
    cp -f "$0" "$CLI_LIBEXEC"; chmod 0750 "$CLI_LIBEXEC"
    local name mode
    while read -r name mode; do
        cat >"${CLI_LINK_DIR}/${name}" <<EOF_WRAP
#!/usr/bin/env bash
exec ${CLI_LIBEXEC} ${mode} "\$@"
EOF_WRAP
        chmod 0755 "${CLI_LINK_DIR}/${name}"
    done <<'EOF_CMDS'
adctl --manage
ad-status --status
ad-audit --audit
ad-validate --validate
ad-users --users
ad-groups --groups
ad-computers --computers
ad-permissions --permissions
ad-gpo --gpo
ad-security --security
ad-backup --backup
ad-remote --remote
ad-ids --ids
EOF_CMDS
    changed "Installed RHEL AD CLI shortcuts in $CLI_LINK_DIR"
    ok "CLI shortcuts installed; runtime copy: $CLI_LIBEXEC"
}

cli_info() {
    printf '\nCLI SHORTCUTS\n'
    local name
    for name in adctl ad-status ad-audit ad-validate ad-users ad-groups ad-computers ad-permissions ad-gpo ad-security ad-backup ad-remote ad-ids; do
        if [[ -x "${CLI_LINK_DIR}/${name}" ]]; then printf '  [OK] %s\n' "${CLI_LINK_DIR}/${name}"; else printf '  [--] %s\n' "${CLI_LINK_DIR}/${name}"; fi
    done
    [[ -x "$CLI_LIBEXEC" ]] && printf 'Runtime copy: %s\n' "$CLI_LIBEXEC" || true
}

post_install_checklist() {
    require_dc || return 1
    printf '\nPOST-INSTALL / OPERATIONS CHECKLIST\n'
    printf '  [ ] Keep at least two tested domain backups outside this host.\n'
    printf '  [ ] Validate a second DC before relying on multi-DC resilience.\n'
    printf '  [ ] Verify AD clients use only AD DNS, not public resolver fallbacks.\n'
    printf '  [ ] Verify the Samba DNS forwarder resolves required external zones.\n'
    printf '  [ ] Validate Chrony/Kerberos clock skew and signed NTP requirements.\n'
    printf '  [ ] Review SELinux AVCs; never solve them by disabling SELinux.\n'
    printf '  [ ] Review firewalld source CIDR and dynamic RPC exposure.\n'
    printf '  [ ] Test GPO application on representative Windows/Linux clients.\n'
    printf '  [ ] Test restore/recovery procedures in an isolated lab.\n'
    printf '  [ ] Keep the assistant and Samba packages patched through configured repositories.\n'
    printf '\nLive checks\n'
    validate_dc || true
}

operations_console() {
    while true; do
        printf '\nDAILY OPERATIONS / OPERACIONES DIARIAS\n  [1] Status\n  [2] Validate DC\n  [3] Audit/evidence\n  [4] DNS health\n  [5] Time health\n  [6] Directory users\n  [7] Computers / OUs\n  [8] Backup\n  [9] Remote endpoint operations\n  [H] Daily domain reports\n  [0] Back\n'
        local c
        c="$(ask 'Action' '2')"
        case "$c" in
            1) status_dc ;;
            2) validate_dc || true ;;
            3) audit_dc ;;
            4) dns_menu ;;
            5) time_health ;;
            6) users_menu ;;
            7) computers_menu ;;
            8) backup_menu ;;
            9) remote_ops_menu ;;
            H|h) domain_reports_menu ;;
            0) return 0 ;;
        esac
        pause_ui
    done
}

maintenance_menu() {
    while true; do
        printf '\nMAINTENANCE / MANTENIMIENTO\n  [B] Backup / recovery evidence\n  [T] Time / Chrony\n  [D] Resolver / DNS repair\n  [O] Boot ordering / self-heal\n  [P] Dependencies\n  [M] Migration / additional DC\n  [C] CLI shortcuts\n  [X] Controlled domain reset\n  [0] Back\n'
        local c
        c="$(ask 'Action' 'B')"; c="${c^^}"
        case "$c" in
            B) backup_menu ;;
            T) printf '\n  [1] Health\n  [2] Configure signed domain time\n'; local t; t="$(ask 'Action' '1')"; [[ "$t" == 2 ]] && configure_domain_time || time_health ;;
            D) dns_menu ;;
            O) printf '\n  [1] Status\n  [2] Install/repair ordering + health guard\n'; local o; o="$(ask 'Action' '1')"; [[ "$o" == 2 ]] && configure_boot_ordering || boot_health_status ;;
            P) dependencies_menu ;;
            M) migration_menu ;;
            C) printf '\n  [1] Show status\n  [2] Install/update shortcuts\n'; local q; q="$(ask 'Action' '1')"; [[ "$q" == 2 ]] && install_cli_shortcuts || cli_info ;;
            X) reset_domain ;;
            0) return 0 ;;
        esac
        pause_ui
    done
}

all_modules_menu() {
    while true; do
        printf '\nALL MODULES / TODOS LOS MÓDULOS\n'
        printf '  [ 1] Audit / evidence                 [12] Operations console\n'
        printf '  [ 2] Validate AD/DC                  [13] Boot ordering / health\n'
        printf '  [ 3] DNS / resolver                  [14] CLI shortcuts\n'
        printf '  [ 4] Time / Chrony                   [15] Migration / additional DC\n'
        printf '  [ 5] firewalld / SELinux evidence    [16] Samba / Kerberos security\n'
        printf '  [ 6] Users                           [17] Domain reset\n'
        printf '  [ 7] Groups                          [18] Dependencies\n'
        printf '  [ 8] Computers / OUs                 [19] Suricata IDS\n'
        printf '  [ 9] Permissions / DS ACL            [20] Remote operations\n'
        printf '  [10] GPO / SYSVOL                    [21] Post-install checklist\n'
        printf '  [11] Backup / recovery\n  [ 0] Back\n'
        local c
        c="$(ask 'Module' '2')"
        case "$c" in
            1) audit_dc ;; 2) validate_dc || true ;; 3) dns_menu ;; 4) time_health ;; 5) security_host_report; selinux_audit ;;
            6) users_menu ;; 7) groups_menu ;; 8) computers_menu ;; 9) permissions_menu ;; 10) gpo_menu ;; 11) backup_menu ;;
            12) operations_console ;; 13) boot_health_status ;; 14) cli_info ;; 15) migration_menu ;; 16) security_menu ;; 17) reset_domain ;;
            18) dependencies_menu ;; 19) ids_menu ;; 20) remote_ops_menu ;; 21) post_install_checklist ;; 0) return 0 ;; *) warn "Invalid selection." ;;
        esac
        pause_ui
    done
}

manage_menu() {
    while true; do
        load_config || true
        detect_network || true
        detect_samba_capability || true
        header
        if [[ "$(samba_role)" == none ]]; then
            printf 'INITIAL / RECOVERY CONTROL PLANE\n'
            printf '  [P] Provision NEW Samba AD domain\n'
            printf '  [J] Join an existing domain as additional DC\n'
            printf '  [A] Read-only host/capability audit\n'
            printf '  [D] Dependencies / package capabilities\n'
            printf '  [0] Exit\n\n'
            local pre
            pre="$(ask 'Action' 'A')"; pre="${pre^^}"
            case "$pre" in
                P) bootstrap_dc; pause_ui ;;
                J) migration_join_additional_dc; pause_ui ;;
                A) audit_dc; pause_ui ;;
                D) dependencies_menu ;;
                0) return 0 ;;
                *) warn "Invalid selection."; pause_ui ;;
            esac
            continue
        fi

        printf 'WORKSPACES / ÁREAS DE TRABAJO\n'
        printf '  [O] %-24s [D] %s\n' "$(ui_t 'Daily operations')" "$(ui_t 'Directory')"
        printf '  [P] %-24s [S] %s\n' "$(ui_t 'Policy / GPO / DNS')" "$(ui_t 'Security')"
        printf '  [R] %-24s [I] %s\n' "$(ui_t 'Remote operations')" "$(ui_t 'Insights / IDS')"
        printf '  [M] %-24s [A] %s\n' "$(ui_t 'Maintenance')" "$(ui_t 'All modules')"
        printf '  [L] %s [%s]\n' "$(ui_t 'Language / Idioma')" "${UI_LANG^^}"
        printf '  [0] %s\n\n' "$(ui_t 'Exit')"
        local c
        c="$(ask 'Workspace' 'O')"; c="${c^^}"
        case "$c" in
            O) operations_console ;;
            D) directory_workspace ;;
            P) policy_workspace ;;
            S) security_workspace ;;
            R) remote_ops_menu ;;
            I) insights_workspace ;;
            M) maintenance_menu ;;
            A) all_modules_menu ;;
            L) toggle_ui_language ;;
            0) return 0 ;;
            *) warn "Invalid selection."; pause_ui ;;
        esac
    done
}

directory_workspace() {
    while true; do
        printf '\nDIRECTORY WORKSPACE / DIRECTORIO\n  [U] Users\n  [G] Groups / access\n  [C] Computers / OUs\n  [P] Permissions / DS ACL\n  [R] Remote endpoint operations\n  [0] Back\n'
        local c
        c="$(ask 'Area' 'U')"; c="${c^^}"
        case "$c" in U) users_menu ;; G) groups_menu ;; C) computers_menu ;; P) permissions_menu ;; R) remote_ops_menu ;; 0) return 0 ;; *) warn "Invalid selection." ;; esac
    done
}

policy_workspace() {
    while true; do
        printf '\nPOLICY / GPO / DNS\n  [G] Group Policy / SYSVOL\n  [N] AD DNS / resolver\n  [P] Domain password policy\n  [M] Migration / replication\n  [0] Back\n'
        local c
        c="$(ask 'Area' 'G')"; c="${c^^}"
        case "$c" in G) gpo_menu ;; N) dns_menu ;; P) domain_password_policy_menu ;; M) migration_menu ;; 0) return 0 ;; *) warn "Invalid selection." ;; esac
    done
}

security_workspace() {
    while true; do
        printf '\nSECURITY WORKSPACE / SEGURIDAD\n  [H] Host / SELinux / crypto / firewall\n  [S] Samba / Kerberos security\n  [I] Passive Suricata IDS\n  [R] Remote operations guardrails\n  [0] Back\n'
        local c
        c="$(ask 'Area' 'H')"; c="${c^^}"
        case "$c" in H) security_host_report; selinux_audit; pause_ui ;; S) security_menu ;; I) ids_menu ;; R) printf '\nUse least-privilege SSH/sudo or Windows JEA/RPC delegation; credentials are never persisted.\n'; pause_ui ;; 0) return 0 ;; *) warn "Invalid selection." ;; esac
    done
}

insights_workspace() {
    while true; do
        printf '\nINSIGHTS / IDS\n  [V] Validate DC\n  [A] Full audit / evidence\n  [F] Run summary / paths\n  [I] Suricata IDS\n  [K] Kerberos crypto readiness\n  [0] Back\n'
        local c
        c="$(ask 'Area' 'V')"; c="${c^^}"
        case "$c" in V) validate_dc || true; pause_ui ;; A) audit_dc; pause_ui ;; F) show_findings_summary; show_runtime_paths; pause_ui ;; I) ids_menu ;; K) kerberos_crypto_readiness; pause_ui ;; 0) return 0 ;; *) warn "Invalid selection." ;; esac
    done
}

usage() {
    cat <<EOF_USAGE
$PRODUCT_NAME $SCRIPT_VERSION

Self-contained Samba Active Directory control plane for Enterprise Linux-style
systems. Primary AD-DC targets are Rocky Linux and AlmaLinux 9/10 when the
installed Samba build actually exposes AD-DC capabilities.

--preflight: read-only launch prerequisites; no root required.

Usage: sudo ./rhel-ad-assistant.sh [mode] [options]

Control-plane modes:
  --manage, --interactive   Workspace-based interactive control plane (default)
  --audit                   Read-only host/DC evidence
  --validate                Functional AD/DC validation
  --status                  Compact status
  --admin                   Daily operations console

Provisioning / lifecycle:
  --bootstrap               Provision a NEW Samba AD domain after safeguards
  --migration               Migration / additional-DC workspace
  --reset-domain            Controlled single-DC reset/decommission workflow
  --dependencies            Package/capability lifecycle

Directory / policy:
  --users                   AD user operations
  --groups                  AD group operations
  --computers               Computer / OU operations
  --permissions             Memberships and DS ACL operations
  --gpo                     GPO / SYSVOL control plane
  --dns                     DNS / resolver diagnostics and repair

Security / operations:
  --security                Host/Samba/Kerberos security workspace
  --samba-security          Samba transport-security audit/workspace
  --kerberos-security       Kerberos audit/readiness workspace
  --backup                  Backup / recovery workspace
  --remote                  Remote endpoint operations center
  --ids                     Passive Suricata IDS workspace
  --ids-daily               Generate a noninteractive IDS report
  --domain-report           Generate daily AD/domain health-security report
  --ids-alert-watch         Noninteractive IDS attention notification check
  --install-cli             Install/update adctl/ad-users/... local shortcuts
  --cli-info                Show installed shortcut status

Options:
  --allow-unsupported-rhel-dc
                            Present the explicit unsupported-role gate on RHEL.
                            Red Hat does not support Samba as an AD DC on RHEL.
  --external-dns-probe NAME External name used to verify DNS forwarding
  --allow-isolated-dns      Waive external DNS resolution only for isolated domains
  --lang en|es              UI language
  --no-color                Disable ANSI colors
  -h, --help                Show help

Safety model:
  - never reprovision an existing sam.ldb
  - no third-party repository is enabled automatically
  - SELinux is never disabled automatically
  - destructive directory/GPO/reset operations require explicit confirmation
  - domain/security changes are backed up where practical
  - NetworkManager/firewalld/systemd are used through platform-native interfaces
  - passwords are never persisted by the assistant
EOF_USAGE
}

parse_args() {
    while (($#)); do
        case "$1" in
            --manage|--interactive) MODE=interactive ;;
            --preflight) MODE=preflight ;;
            --audit) MODE=audit ;;
            --validate) MODE=validate ;;
            --bootstrap) MODE=bootstrap ;;
            --status) MODE=status ;;
            --admin) MODE=admin ;;
            --backup) MODE=backup ;;
            --users) MODE=users ;;
            --groups) MODE=groups ;;
            --computers) MODE=computers ;;
            --permissions) MODE=permissions ;;
            --gpo) MODE=gpo ;;
            --dns) MODE=dns ;;
            --security) MODE=security ;;
            --samba-security) MODE=samba-security ;;
            --kerberos-security|--kerberos) MODE=kerberos-security ;;
            --migration) MODE=migration ;;
            --reset-domain) MODE=reset-domain ;;
            --dependencies) MODE=dependencies ;;
            --remote) MODE=remote ;;
            --ids) MODE=ids ;;
            --ids-daily) MODE=ids-daily ;;
            --domain-report) MODE=domain-report ;;
            --ids-alert-watch) MODE=ids-alert-watch ;;
            --lang) shift; [[ $# -gt 0 ]] || { printf 'Missing value for --lang (en|es).\n' >&2; exit 2; }; set_ui_language "$1" || exit 2 ;;
            --lang=*) set_ui_language "${1#*=}" || exit 2 ;;
            --install-cli) MODE=install-cli ;;
            --cli-info) MODE=cli-info ;;
            --allow-unsupported-rhel-dc) ALLOW_UNSUPPORTED_RHEL_DC=1 ;;
            --external-dns-probe) shift; [[ $# -gt 0 ]] || { printf 'Missing value for --external-dns-probe\n' >&2; exit 2; }; EXTERNAL_DNS_PROBE="$1" ;;
            --allow-isolated-dns) ALLOW_ISOLATED_DNS=1 ;;
            --no-color) FORCE_NO_COLOR=1 ;;
            -h|--help) usage; exit 0 ;;
            *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
        esac
        shift
    done
}

# Read-only launch check: no elevation, package installation or runtime state.
launch_preflight() {
    local failures=0 tool os_id=unknown
    printf 'Preflight: Enterprise Linux domain controller\n'
    printf 'Bash: %s | UID: %s\n' "$BASH_VERSION" "$EUID"
    if [[ "$(uname -s)" != Linux ]]; then
        printf '[FAIL] Linux is required.\n'; failures=1
    fi
    if [[ -r /etc/os-release ]]; then
        os_id="$(. /etc/os-release; printf '%s' "${ID:-unknown}")"
    fi
    [[ "$os_id" != rhel ]] || printf '[WARN] Samba AD DC provisioning is unsupported on RHEL.\n'
    printf 'Distribution: %s\n' "$os_id"
    if [[ ! -d /run/systemd/system ]]; then
        printf '[FAIL] A running systemd host is required for lifecycle operations.\n'
        failures=1
    fi
    for tool in ip systemctl flock hostname nmcli; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '[OK] %s\n' "$tool"
        else
            printf '[FAIL] Missing launch prerequisite: %s\n' "$tool"; failures=1
        fi
    done
    for tool in samba-tool testparm kinit firewall-cmd; do
        command -v "$tool" >/dev/null 2>&1 || printf '[WARN] Not available: %s (role operations may require it).\n' "$tool"
    done
    ((EUID == 0)) || printf '[INFO] Operational modes require sudo/root; this check does not.\n'
    if [[ ! -t 0 ]]; then
        printf '[INFO] No input terminal. Use a local console or ssh -t for interactive modes.\n'
    fi
    printf 'No changes made. Next: review warnings, then run --audit on the target host.\n'
    return "$failures"
}

main() {
    parse_args "$@"
    if [[ "$MODE" == preflight ]]; then launch_preflight; return $?; fi
    UI_LANG="${UI_LANG,,}"; [[ "$UI_LANG" == en || "$UI_LANG" == es ]] || UI_LANG=en
    if ((FORCE_NO_COLOR)) || [[ ! -t 1 || -n "${NO_COLOR:-}" ]]; then
        C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_CYAN="" C_MAGENTA=""
    fi
    case "$MODE" in
        audit|validate|status|ids-daily|domain-report|ids-alert-watch|cli-info|samba-security) ;;
        *) if ! (: </dev/tty) 2>/dev/null; then
               printf 'Mode %s requires a terminal. Use a local console or ssh -t.\n' "$MODE" >&2
               return 2
           fi ;;
    esac
    init_runtime
    case "$MODE" in
        interactive) manage_menu ;;
        audit) audit_dc ;;
        validate) validate_dc ;;
        bootstrap) bootstrap_dc ;;
        status) status_dc ;;
        admin) operations_console ;;
        backup) backup_menu ;;
        users) users_menu ;;
        groups) groups_menu ;;
        computers) computers_menu ;;
        permissions) permissions_menu ;;
        gpo) gpo_menu ;;
        dns) dns_menu ;;
        security) security_menu ;;
        samba-security) security_param_report ;;
        kerberos-security) kerberos_client_audit; kerberos_crypto_readiness || true ;;
        migration) migration_menu ;;
        reset-domain) reset_domain ;;
        dependencies) dependencies_menu ;;
        remote) remote_ops_menu ;;
        ids) ids_menu ;;
        ids-daily) ids_daily_report ;;
        domain-report) domain_daily_report ;;
        ids-alert-watch) ids_alert_watch_once ;;
        install-cli) install_cli_shortcuts ;;
        cli-info) cli_info ;;
        *) err "Internal mode dispatch error: $MODE"; exit 2 ;;
    esac
}

main "$@"
