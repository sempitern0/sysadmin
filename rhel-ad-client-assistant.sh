#!/usr/bin/env bash
# rhel-ad-client-assistant.sh
# Version 2.0.1-runtime-sanitization
#
# Reversible Active Directory client join assistant for Linux.
#
# Primary supported package families:
#   - Debian / Ubuntu and derivatives using APT
#   - RHEL / Fedora / Rocky / Alma and derivatives using DNF/YUM
#
# Generic mode:
#   - Other systemd distributions can continue when the required commands already exist.
#   - Non-systemd automated lifecycle is intentionally not supported.
#
# Core design:
#   detect -> snapshot -> packages -> DNS -> discover -> join -> validate
#   leave  -> restore pre-join state -> optional package cleanup
#
# No passwords are stored. No third-party repository is added.

set -uo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="2.0.1-runtime-sanitization"
PRODUCT_NAME="RHEL AD Client Assistant"

STATE_ROOT="/var/lib/ad-client-assistant"
BACKUP_ROOT="/var/backups/ad-client-assistant"
LOG_ROOT="/var/log/ad-client-assistant"
CURRENT_STATE="${STATE_ROOT}/current.env"
INPUT_FD=0

# Endpoint-defense state. These paths are initialized here (rather than lazily
# inside the menu) because init_runtime creates the directory under `set -u`.
REMOTE_SECURITY_DIR="${STATE_ROOT}/security"
SECURITY_CONFIG="${REMOTE_SECURITY_DIR}/security.conf"
SECURITY_TRUSTED="${REMOTE_SECURITY_DIR}/trusted-ips.txt"
SECURITY_BLOCKS="${REMOTE_SECURITY_DIR}/blocks.tsv"
TELEGRAM_CONFIG="${REMOTE_SECURITY_DIR}/telegram.conf"
SURICATA_EVE_DEFAULT="/var/log/suricata/eve.json"

# Network operations are intentionally tolerant of slow virtual/lab environments.
# Override from the environment when needed without editing the script.
AD_CLIENT_NETWORK_TIMEOUT="${AD_CLIENT_NETWORK_TIMEOUT:-60}"
AD_CLIENT_MEMBERSHIP_TIMEOUT="${AD_CLIENT_MEMBERSHIP_TIMEOUT:-180}"
AD_CLIENT_SLOW_NETWORK_TIMEOUT="${AD_CLIENT_SLOW_NETWORK_TIMEOUT:-180}"
AD_CLIENT_SSH_SETUP="${AD_CLIENT_SSH_SETUP:-yes}"
AD_CLIENT_REMOTE_USER="${AD_CLIENT_REMOTE_USER:-adremote}"

USE_COLOR=1
[[ -t 1 && -z "${NO_COLOR:-}" ]] || USE_COLOR=0

if (( USE_COLOR )); then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'
else
    C_RESET=""
    C_BOLD=""
    C_DIM=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_CYAN=""
fi

RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
RUN_LOG=""
DISTRO_ID=""
DISTRO_LIKE=""
PKG_FAMILY="generic"
ACTIVE_IFACE=""
DNS_BACKEND=""
NM_CONNECTION=""
REMOTE_SESSION=0
HOSTNAME_CHANGED_RESULT=0
NM_CONNECTION_UUID=""
PRIVATE_KRB5CCACHE="${STATE_ROOT}/krb5cc-${RUN_ID}"
JOIN_COMPUTER_NAME=""
JOIN_REALM_NAME=""
JOIN_TRANSACTION_ACTIVE=0
JOIN_TRANSACTION_COMMITTED=0
JOIN_TRANSACTION_SNAPSHOT=""
JOIN_TRANSACTION_ROLLBACK=0
SYSTEM_RESOLVER_BACKEND=""
RESOLV_CONF_TARGET=""
AD_DNS_FORWARDING_OK=0
UI_LANG="${AD_ASSISTANT_LANG:-en}"
PRESET_DOMAIN=""
PRESET_DNS=""
PRESET_HOSTNAME=""
PRESET_COMPUTER=""
PRESET_OU=""
PRESET_ID_MAPPING=""
PRESET_SWITCH_MODE=0

# ---------------------------------------------------------------------------
# UI / logging
# ---------------------------------------------------------------------------

acquire_runtime_lock() {
    exec {RUNTIME_LOCK_FD}>"$STATE_ROOT/assistant.lock" || return 1
    flock -n "$RUNTIME_LOCK_FD" || { printf 'Another AD client assistant is running.\n' >&2; return 1; }
}

init_runtime() {
    (( EUID == 0 )) || {
        printf 'Run this assistant as root (sudo).\n' >&2
        exit 1
    }

    command_exists flock || { printf 'flock is required for safe concurrent operation.\n' >&2; return 1; }
    [[ -d /run/systemd/system ]] || { printf 'A running systemd host is required.\n' >&2; return 1; }
    mkdir -p "$STATE_ROOT" "$BACKUP_ROOT" "$LOG_ROOT" "$REMOTE_SECURITY_DIR" || return 1
    chmod 0700 "$STATE_ROOT" "$BACKUP_ROOT" "$LOG_ROOT" "$REMOTE_SECURITY_DIR" || return 1
    # Keep the lock for the entire process, including recovery and cleanup.
    acquire_runtime_lock || return 1

    RUN_LOG="${LOG_ROOT}/${RUN_ID}.log"
    : >"$RUN_LOG" || return 1
    chmod 0600 "$RUN_LOG" || return 1

    if { exec {INPUT_FD}<>/dev/tty; } 2>/dev/null; then :; fi

    [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_CLIENT:-}" ]] && REMOTE_SESSION=1

    detect_os
    detect_active_interface
    detect_dns_backend
    detect_system_resolver

    trap on_exit_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

log() {
    printf '%s %s\n' "$(date -Is)" "$*" >>"$RUN_LOG"
}

info() {
    printf '%b[INFO]%b %s\n' "$C_CYAN" "$C_RESET" "$*"
    log "INFO $*"
}

ok() {
    printf '%b[ OK ]%b %s\n' "$C_GREEN" "$C_RESET" "$*"
    log "OK $*"
}

warn() {
    printf '%b[WARN]%b %s\n' "$C_YELLOW" "$C_RESET" "$*"
    log "WARN $*"
}

err() {
    printf '%b[ERROR]%b %s\n' "$C_RED" "$C_RESET" "$*" >&2
    log "ERROR $*"
}

header() {
    clear 2>/dev/null || true
    printf '%b%s%b\n' "$C_BOLD" "$PRODUCT_NAME" "$C_RESET"
    printf 'Version: %s\n' "$SCRIPT_VERSION"
    printf 'Host   : %s\n' "$(hostname 2>/dev/null || printf unknown)"
    printf 'OS     : %s\n' "${DISTRO_ID:-unknown}"
    detect_system_resolver
    printf 'Network: %s / config=%s / resolver=%s\n' \
        "${ACTIVE_IFACE:-unknown}" "${DNS_BACKEND:-unknown}" "${SYSTEM_RESOLVER_BACKEND:-unknown}"
    printf '%s\n\n' '------------------------------------------------------------------------'
}

normalize_ui_language() {
    case "${1,,}" in en|es) printf '%s' "${1,,}" ;; *) printf 'en' ;; esac
}

set_ui_language() {
    case "${1,,}" in
        en|es) UI_LANG="${1,,}" ;;
        *) err "Unsupported language: $1 (expected en or es)."; return 1 ;;
    esac
}

toggle_ui_language() {
    [[ "$UI_LANG" == "en" ]] && UI_LANG="es" || UI_LANG="en"
}

ui_text() {
    local t="$1"
    [[ "$UI_LANG" == "es" ]] || { printf '%s' "$t"; return; }
    case "$t" in
        'Press Enter to continue...') printf 'Pulsa Enter para continuar...' ;;
        'Select operation') printf 'Selecciona una operación' ;;
        'Readiness audit') printf 'Auditoría de preparación' ;;
        'Guided domain join') printf 'Unión guiada al dominio' ;;
        'Domain client status') printf 'Estado del cliente de dominio' ;;
        'Leave domain cleanly') printf 'Salir limpiamente del dominio' ;;
        'Switch to another domain') printf 'Cambiar a otro dominio' ;;
        'AD connectivity test') printf 'Prueba de conectividad AD' ;;
        'Troubleshoot / repair') printf 'Diagnóstico / reparación' ;;
        'Export diagnostic bundle') printf 'Exportar paquete de diagnóstico' ;;
        'Restore pre-join state') printf 'Restaurar estado previo a la unión' ;;
        'List snapshots') printf 'Listar snapshots' ;;
        'Language / Idioma') printf 'Idioma / Language' ;;
        'Exit') printf 'Salir' ;;
        'AD DNS domain (for example corp.example.com)') printf 'Dominio DNS de AD (por ejemplo corp.example.com)' ;;
        'AD DNS server IPv4 addresses (comma separated)') printf 'Direcciones IPv4 de los DNS de AD (separadas por comas)' ;;
        'Target AD DNS domain (for example corp.example.com)') printf 'Dominio DNS de AD destino (por ejemplo corp.example.com)' ;;
        'Target AD DNS server IPv4 addresses (comma separated)') printf 'Direcciones IPv4 de los DNS AD destino (separadas por comas)' ;;
        'System hostname') printf 'Hostname del sistema' ;;
        'AD computer name (NetBIOS, max 15 chars)') printf 'Nombre del equipo en AD (NetBIOS, máximo 15 caracteres)' ;;
        'Computer OU DN (optional)') printf 'DN de la OU del equipo (opcional)' ;;
        'Optional AD user for SSSD identity lookup (not Kerberos authentication; blank to skip)') printf 'Usuario AD opcional para validar resolución de identidad por SSSD (no autenticación Kerberos; vacío para omitir)' ;;
        'Reboot now?') printf '¿Reiniciar ahora?' ;;
        'Endpoint security / Suricata + Wazuh') printf 'Seguridad del endpoint / Suricata + Wazuh' ;;
        'Security status') printf 'Estado de seguridad' ;;
        'Validate Suricata') printf 'Validar Suricata' ;;
        'Configure Wazuh integration') printf 'Configurar integración Wazuh' ;;
        'IDS / IPS response center') printf 'Centro de respuesta IDS / IPS' ;;
        'Blocked IP addresses') printf 'Direcciones IP bloqueadas' ;;
        'Unblock IP address') printf 'Desbloquear dirección IP' ;;
        'Emergency unblock all') printf 'Desbloqueo de emergencia total' ;;
        'Temporarily block IP') printf 'Bloquear IP temporalmente' ;;
        'Trusted IP addresses') printf 'Direcciones IP de confianza' ;;
        'Awareness schedule') printf 'Horario de vigilancia' ;;
        'Telegram notifications') printf 'Notificaciones de Telegram' ;;
        *) printf '%s' "$t" ;;
    esac
}

UI_LANG="$(normalize_ui_language "$UI_LANG")"

pause_ui() {
    printf '\n%s' "$(ui_text 'Press Enter to continue...')" >&${INPUT_FD}
    read -r -u "$INPUT_FD" _ || true
}

ask() {
    local prompt="$(ui_text "$1")" default="${2:-}" value=""
    if [[ -n "$default" ]]; then
        printf '%s [%s]: ' "$prompt" "$default" >&${INPUT_FD}
    else
        printf '%s: ' "$prompt" >&${INPUT_FD}
    fi
    IFS= read -r -u "$INPUT_FD" value || return 1
    [[ -n "$value" ]] || value="$default"
    printf '%s' "$value"
}

confirm() {
    # Keep declarations separate under `set -u`: Bash expands assignments in a
    # single `local` command before sibling variables are guaranteed to exist.
    local prompt=""
    local default="${2:-N}"
    local answer=""
    local shown=""
    prompt="$(ui_text "$1")"
    shown="$default"
    [[ "$UI_LANG" == "es" && "${default^^}" == "Y" ]] && shown="S"
    printf '%s [%s]: ' "$prompt" "$shown" >&${INPUT_FD}
    IFS= read -r -u "$INPUT_FD" answer || return 1
    [[ -n "$answer" ]] || answer="$default"
    [[ "${answer,,}" == "y" || "${answer,,}" == "yes" || "${answer,,}" == "s" || "${answer,,}" == "si" || "${answer,,}" == "sí" ]]
}

confirm_literal() {
    local prompt="$1" literal="$2" answer=""
    if [[ "$UI_LANG" == "es" ]]; then
        printf '%s\nEscribe %s para continuar: ' "$prompt" "$literal" >&${INPUT_FD}
    else
        printf '%s\nType %s to continue: ' "$prompt" "$literal" >&${INPUT_FD}
    fi
    IFS= read -r -u "$INPUT_FD" answer || return 1
    [[ "$answer" == "$literal" ]]
}

request_reboot_now() {
    # Reboot is a terminal action: once accepted, do not return to the menu and
    # do not show the generic "Press Enter" pause while systemd is scheduling it.
    confirm "Reboot now?" N || return 1

    info "Reboot requested. The assistant will close now; systemd is scheduling the restart."
    sync 2>/dev/null || true

    if systemctl reboot --no-block; then
        # Exit the assistant immediately so the caller cannot consume a stray
        # keypress in pause_ui() before the reboot job takes effect.
        exit 0
    fi

    err "The reboot request could not be submitted to systemd."
    warn "Reboot manually when convenient."
    return 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Bound non-interactive probes so a broken NSS/SSSD/DNS path never leaves the
# operator staring at a frozen terminal.  Mutating membership operations are
# intentionally NOT wrapped here because killing them mid-commit can create an
# ambiguous AD state.
run_probe() {
    local seconds="$1" label="$2"
    shift 2
    local rc=0

    # Network/directory probes get a higher floor so nested virtualization,
    # busy DCs and NetLogon/LDAP discovery are not mistaken for failures.
    case "${label,,}" in
        *dns*|*realm*|*ldap*|*kerberos*|*sssd*|*identity*|*trust*|*network*|*ad\ computer*)
            (( seconds < AD_CLIENT_NETWORK_TIMEOUT )) && seconds="$AD_CLIENT_NETWORK_TIMEOUT"
            ;;
    esac

    if command_exists timeout; then
        timeout --foreground --signal=TERM --kill-after=10s "${seconds}s" "$@"
        rc=$?
    else
        "$@"
        rc=$?
    fi

    if (( rc == 124 || rc == 137 )); then
        warn "$label timed out after ${seconds}s; continuing diagnostics instead of blocking the console."
        return 124
    fi
    return "$rc"
}

capture_probe() {
    local seconds="$1" label="$2"
    shift 2
    local output="" rc=0

    if command_exists timeout; then
        output="$(timeout --foreground --signal=TERM --kill-after=3s "${seconds}s" "$@" 2>&1)"
        rc=$?
    else
        output="$("$@" 2>&1)"
        rc=$?
    fi

    printf '%s' "$output"
    if (( rc == 124 || rc == 137 )); then
        log "WARN $label timed out after ${seconds}s"
        return 124
    fi
    return "$rc"
}


run_membership_operation() {
    local seconds="$1" label="$2" logfile="$3"
    shift 3
    local rc=0

    (( seconds < AD_CLIENT_MEMBERSHIP_TIMEOUT )) && seconds="$AD_CLIENT_MEMBERSHIP_TIMEOUT"
    info "$label (maximum wait: ${seconds}s)."
    info "Live output is mirrored to: $logfile"

    if command_exists timeout; then
        timeout --foreground --signal=TERM --kill-after=15s "${seconds}s" "$@" 2>&1 | tee "$logfile"
        rc=${PIPESTATUS[0]}
    else
        warn "GNU timeout is unavailable; this membership operation cannot be safely time-bounded."
        "$@" 2>&1 | tee "$logfile"
        rc=${PIPESTATUS[0]}
    fi

    if (( rc == 124 || rc == 137 || rc == 143 )); then
        warn "$label exceeded ${seconds}s and was stopped to avoid an indefinitely frozen console."
        warn "A membership-changing command may have reached AD before the timeout; local rollback is intentionally NOT assumed."
        return 124
    fi

    return "$rc"
}

membership_evidence_after_leave() {
    local domain="$1"
    local realms="" trust_rc=1

    realms="$(capture_probe 8 'post-leave realm membership query' realm list --name-only || true)"
    if ! grep -Fiqx "$domain" <<<"$realms"; then
        ok "Post-operation evidence: realmd no longer reports membership in $domain."
        return 0
    fi

    if command_exists adcli; then
        run_probe 15 'post-leave machine trust validation' adcli testjoin -D "$domain" >/dev/null 2>&1
        trust_rc=$?
        if (( trust_rc == 0 )); then
            warn "Post-operation evidence: realmd still reports $domain and the machine trust is still valid."
            return 1
        fi
        if (( trust_rc == 124 )); then
            warn "Post-operation evidence is inconclusive: realmd reports membership but machine-trust validation timed out."
            return 2
        fi
    fi

    warn "Post-operation evidence is ambiguous: realmd still reports $domain but the secure-channel test does not validate."
    return 2
}


server_side_membership_state() {
    local domain="$1"
    local output="" rc=0 dns_ok=0 dc="" dns_csv=""

    SERVER_MEMBERSHIP_STATE="unknown"
    SERVER_MEMBERSHIP_DETAIL=""

    if domain_srv_query "$domain" "" >/dev/null 2>&1; then
        dns_ok=1
    fi

    if [[ -f "$CURRENT_STATE" ]]; then
        local AD_DNS_SERVERS=""
        load_state_file "$CURRENT_STATE" || true
        dns_csv="${AD_DNS_SERVERS:-}"
    fi
    if [[ -z "$dns_csv" ]]; then
        dns_csv="$(current_dns_summary | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | paste -sd, - || true)"
    fi

    if [[ -n "$dns_csv" ]] && validate_dns_list "$dns_csv"; then
        dc="$(ad_dc_targets_from_dns "$domain" "$dns_csv" | awk 'NR==1{print}')"
    fi

    if ! command_exists adcli; then
        SERVER_MEMBERSHIP_DETAIL="adcli unavailable"
        return 2
    fi

    info "Checking whether the computer account still has a valid trust with Active Directory."
    output="$(capture_probe "$AD_CLIENT_NETWORK_TIMEOUT" 'pre-leave machine trust validation' adcli testjoin -v -D "$domain")"
    rc=$?
    log "pre-leave adcli testjoin rc=$rc output=$(tr '\n' ' ' <<<"$output")"

    if (( rc == 0 )); then
        SERVER_MEMBERSHIP_STATE="valid"
        SERVER_MEMBERSHIP_DETAIL="machine trust validates"
        ok "The server-side computer account still has a valid machine trust."
        return 0
    fi

    if (( rc == 124 || rc == 137 )); then
        SERVER_MEMBERSHIP_STATE="slow-or-unknown"
        SERVER_MEMBERSHIP_DETAIL="machine-trust validation timed out"
        warn "Machine-trust validation is slow/inconclusive; the normal authenticated leave path will be used."
        return 2
    fi

    if grep -Eiq \
        'client.*not found in kerberos database|credentials have been revoked|no such object|computer account.*(not found|does not exist)|account.*(not found|deleted|disabled)|unable to find.*computer|not found.*computer|preauthentication failed' \
        <<<"$output"; then
        if (( dns_ok == 1 )); then
            SERVER_MEMBERSHIP_STATE="server-unlinked"
            SERVER_MEMBERSHIP_DETAIL="AD is discoverable but the machine account/trust is absent or revoked"
            warn "Active Directory is reachable, but this computer no longer has a usable server-side machine trust."
            info "This commonly occurs when the computer object was deleted/reset from the server before the client was detached."
            return 3
        fi
    fi

    SERVER_MEMBERSHIP_STATE="invalid-or-unknown"
    SERVER_MEMBERSHIP_DETAIL="machine trust failed without conclusive server-side deletion evidence"
    warn "The machine trust did not validate, but the evidence is not strong enough to assume that the server-side object was deleted."
    return 2
}

local_detach_after_server_unlink() {
    local domain="$1"
    local leave_log="${LOG_ROOT}/${RUN_ID}-realm-local-detach.log"
    local rc=0

    printf '\n%bSERVER-SIDE ACCOUNT ALREADY UNLINKED%b\n' "$C_BOLD" "$C_RESET"
    warn "The client still has local realm/SSSD state, but AD no longer accepts the machine trust."
    info "Skipping the remote computer-delete step because there is no valid server-side account to remove."
    info "The assistant will detach the local realm state and restore the pre-join client configuration."

    # Do not pass -U here. Supplying an administrator account makes realmd/adcli
    # attempt a remote delete-computer operation, which is unnecessary and can
    # stall when the AD object was already removed on the server.
    if command_exists realm; then
        run_membership_operation "$AD_CLIENT_NETWORK_TIMEOUT" "Local realm detach" "$leave_log" \
            realm leave "$domain"
        rc=$?
        if (( rc != 0 )); then
            warn "Local realm detach did not return cleanly; continuing with assistant-owned local restoration because the server-side trust is already absent."
            warn "Local detach output: $leave_log"
        else
            ok "Local realm configuration detached."
        fi
    fi

    local snap=""
    if [[ -f "$CURRENT_STATE" ]]; then
        local SNAPSHOT_PATH=""
        load_state_file "$CURRENT_STATE" || true
        snap="${SNAPSHOT_PATH:-}"
    fi

    if [[ -n "$snap" && -d "$snap" ]]; then
        restore_network_from_snapshot "$snap" || warn "DNS restore reported a problem."
        restore_identity_files "$snap"
        restore_hostname_from_snapshot "$snap" || warn "Hostname restore reported a problem."
        restore_sssd_runtime_from_snapshot "$snap" || true
        rm -f "$CURRENT_STATE" 2>/dev/null || true
        ok "Local AD client state was restored from the pre-join snapshot."
    else
        warn "No assistant snapshot was found; only the realm detach was attempted."
        warn "Use Deep diagnostics before manually removing SSSD/keytab/DNS configuration."
    fi

    if command_exists sss_cache; then
        run_probe 10 "SSSD cache cleanup" sss_cache -E >/dev/null 2>&1 || true
    fi
    systemctl try-restart sssd.service >/dev/null 2>&1 || true

    ok "Client-side domain detachment completed for an already-unlinked server account."

    request_reboot_now || true
}

leave_connectivity_diagnostics() {
    local domain="$1"
    local dns_csv="" dc="" adcli_info=""

    printf '\n%bLEAVE CONNECTIVITY DIAGNOSTICS%b\n' "$C_BOLD" "$C_RESET"

    if [[ -f "$CURRENT_STATE" ]]; then
        local AD_DNS_SERVERS=""
        load_state_file "$CURRENT_STATE" || true
        dns_csv="${AD_DNS_SERVERS:-}"
    fi
    if [[ -z "$dns_csv" ]]; then
        dns_csv="$(current_dns_summary | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | paste -sd, - || true)"
    fi

    if domain_srv_query "$domain" "" >/dev/null 2>&1; then
        ok "System resolver can discover AD DC locator SRV records."
    else
        err "System resolver cannot resolve AD DC locator SRV records."
    fi

    if [[ -n "$dns_csv" ]] && validate_dns_list "$dns_csv"; then
        dc="$(ad_dc_targets_from_dns "$domain" "$dns_csv" | awk 'NR==1{print}')"
        [[ -n "$dc" ]] && info "First discovered DC: $dc"
        validate_ad_network_ports "$domain" "$dns_csv" || true
    fi

    if command_exists adcli; then
        adcli_info="$(capture_probe 15 'adcli domain discovery' adcli info "$domain" || true)"
        if [[ -n "$adcli_info" ]]; then
            printf '\nadcli discovery:\n'
            sed 's/^/  /' <<<"$adcli_info"
        else
            warn "adcli could not return domain discovery information within the diagnostic window."
        fi
    fi

    if [[ -n "$dc" ]]; then
        local dc_ip=""
        dc_ip="$(getent ahostsv4 "$dc" 2>/dev/null | awk 'NR==1{print $1}')"
        if [[ -n "$dc_ip" ]]; then
            info "DC IPv4 resolution: $dc -> $dc_ip"
            local route_iface=""
            route_iface="$(route_interface_for_target "$dc_ip" || true)"
            [[ -n "$route_iface" ]] && info "Kernel route to DC uses interface: $route_iface"
        else
            warn "The discovered DC hostname did not resolve to IPv4 through NSS."
        fi
    fi

    audit_time_sync || true
    warn "If TCP/389 is reachable but adcli reports 'Can't contact LDAP server', inspect DC hostname resolution, IPv4/IPv6 path selection, TLS/SASL policy, firewall stateful inspection, and the adcli/realmd logs above."
}


valid_dns_domain() {
    local name="$1" label=""
    local -a labels=()
    (( ${#name} >= 3 && ${#name} <= 253 )) || return 1
    [[ "$name" == *.* && "$name" != .* && "$name" != *. && "$name" != *..* ]] || return 1
    local old_ifs="$IFS"
    IFS='.'
    read -r -a labels <<<"$name"
    IFS="$old_ifs"
    ((${#labels[@]} >= 2)) || return 1
    for label in "${labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

valid_system_hostname() {
    local name="$1" label=""
    local -a labels=()
    (( ${#name} >= 1 && ${#name} <= 64 )) || return 1
    [[ "$name" != .* && "$name" != *. && "$name" != *..* ]] || return 1
    local old_ifs="$IFS"
    IFS='.'
    read -r -a labels <<<"$name"
    IFS="$old_ifs"
    for label in "${labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

valid_ad_computer_name() {
    local name="$1"
    (( ${#name} >= 1 && ${#name} <= 15 )) || return 1
    [[ "$name" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$ ]]
}


current_boot_id() {
    cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf 'unknown'
}

cleanup_private_ccache() {
    if command_exists kdestroy; then
        kdestroy -c "FILE:${PRIVATE_KRB5CCACHE}" >/dev/null 2>&1 || true
    fi
    rm -f -- "$PRIVATE_KRB5CCACHE" >/dev/null 2>&1 || true
}

join_transaction_mark() {
    local snap="$1" phase="$2"
    [[ -n "$snap" && -d "$snap" ]] || return 0
    printf 'PHASE=%q\nUPDATED_AT=%q\nPID=%q\n' \
        "$phase" "$(date -Is)" "$$" >"${snap}/join-transaction.env"
    chmod 0600 "${snap}/join-transaction.env" 2>/dev/null || true
}

on_exit_cleanup() {
    local rc=$?
    cleanup_private_ccache

    if (( JOIN_TRANSACTION_ACTIVE == 1 &&
          JOIN_TRANSACTION_COMMITTED == 0 &&
          JOIN_TRANSACTION_ROLLBACK == 0 )) &&
       [[ -n "$JOIN_TRANSACTION_SNAPSHOT" &&
          -d "$JOIN_TRANSACTION_SNAPSHOT" ]]; then
        JOIN_TRANSACTION_ROLLBACK=1
        JOIN_TRANSACTION_ACTIVE=0

        printf '\n%b[RECOVERY]%b Interrupted pre-membership join detected; restoring local pre-join configuration.\n' \
            "$C_YELLOW" "$C_RESET" >&2
        rollback_failed_join_local_state "$JOIN_TRANSACTION_SNAPSHOT" "noninteractive" || true
        join_transaction_mark "$JOIN_TRANSACTION_SNAPSHOT" "INTERRUPTED_ROLLBACK"
    fi

    return "$rc"
}

latest_assistant_snapshot() {
    local newest="" newest_mtime=0 dir mtime
    [[ -d "$BACKUP_ROOT" ]] || return 1

    for dir in "$BACKUP_ROOT"/*; do
        [[ -d "$dir" && -f "$dir/snapshot.env" ]] || continue
        mtime="$(stat -c '%Y' "$dir" 2>/dev/null || printf 0)"
        if [[ "$mtime" =~ ^[0-9]+$ ]] && (( mtime > newest_mtime )); then
            newest_mtime="$mtime"
            newest="$dir"
        fi
    done

    [[ -n "$newest" ]] || return 1
    printf '%s' "$newest"
}

snapshot_domain() {
    local snap="$1" DOMAIN=""
    [[ -f "$snap/snapshot.env" ]] || return 1
    # shellcheck disable=SC1090
    . "$snap/snapshot.env"
    printf '%s' "${DOMAIN:-}"
}

incomplete_sssd_residue_present() {
    command_exists sss_cache || return 1

    # A previous attempt is considered incomplete only when realmd has no
    # membership and SSSD is not fully initialized. Installed SSSD tooling by
    # itself is not an error condition.
    local realms=""
    if command_exists realm; then
        realms="$(capture_probe 10 "realm membership query" realm list --name-only || true)"
        [[ -z "$realms" ]] || return 1
    fi

    [[ ! -s /etc/sssd/sssd.conf || ! -s /var/lib/sss/db/config.ldb ]]
}

kerberos_machine_identity_present() {
    [[ -s /etc/krb5.keytab ]] || return 1
    command_exists klist || return 1
    klist -k /etc/krb5.keytab 2>/dev/null | grep -Eqi '(^|[[:space:]])(host|restrictedkrbhost)/'
}

previous_join_evidence() {
    local snap="${1:-}" domain="${2:-}"
    local realms="" trust="unknown" keytab="no" sssd_conf="no" confdb="no" kerberos_realm=""

    command_exists realm && realms="$(capture_probe 10 "realm membership query" realm list --name-only || true)"

    if command_exists klist && [[ -s /etc/krb5.keytab ]]; then
        kerberos_realm="$(klist -k /etc/krb5.keytab 2>/dev/null | awk '''/^[[:space:]]*[0-9]+[[:space:]]+[^[:space:]]+@/{p=$NF; sub(/^.*@/,"",p); if(p!=""){print p; exit}}''')"
    fi
    if [[ -z "$kerberos_realm" && -r /etc/krb5.conf ]]; then
        kerberos_realm="$(awk -F= '''tolower($1) ~ /^[[:space:]]*default_realm[[:space:]]*$/ {gsub(/[[:space:]]/,"",$2); print $2; exit}''' /etc/krb5.conf 2>/dev/null || true)"
    fi
    [[ -s /etc/sssd/sssd.conf ]] && sssd_conf="yes"
    [[ -s /var/lib/sss/db/config.ldb ]] && confdb="yes"
    kerberos_machine_identity_present && keytab="yes"

    if command_exists adcli && [[ -n "$domain" ]]; then
        if run_probe 20 "adcli machine trust validation" adcli testjoin -D "$domain" >/dev/null 2>&1; then
            trust="valid"
        else
            trust="not-validated"
        fi
    fi

    printf '\nPREVIOUS JOIN EVIDENCE\n'
    printf '  Snapshot domain : %s\n' "${domain:-unknown}"
    printf '  realmd realms   : %s\n' "${realms:-none}"
    printf '  Kerberos realm  : %s\n' "${kerberos_realm:-none detected}"
    printf '  Machine trust   : %s\n' "$trust"
    printf '  Kerberos keytab : %s\n' "$keytab"
    printf '  sssd.conf       : %s\n' "$sssd_conf"
    printf '  SSSD config DB  : %s\n' "$confdb"

    if [[ "$trust" == "valid" && -z "$realms" ]]; then
        warn "AD still accepts the local machine credentials, but realmd/SSSD membership is incomplete."
        info "This is a partial local configuration, not a clean unjoined state."
    elif [[ "$keytab" == "yes" && -z "$realms" ]]; then
        warn "Kerberos machine principals exist locally, but realmd reports no realm membership."
        info "The keytab may be residue from a failed or manually altered join."
    fi
}

clean_failed_join_for_retry() {
    local snap="$1"
    [[ -n "$snap" && -d "$snap" ]] || {
        err "No usable assistant snapshot is available for cleanup."
        return 1
    }

    info "Restoring the pre-attempt local identity and resolver baseline."
    restore_network_from_snapshot "$snap" || warn "DNS/network restoration reported a problem."
    restore_identity_files "$snap"
    restore_hostname_from_snapshot "$snap" || warn "Hostname restoration reported a problem."
    restore_sssd_runtime_from_snapshot "$snap"
    rm -f "$CURRENT_STATE" 2>/dev/null || true

    # Keep AD client packages installed. They are safe and make the immediate
    # retry faster; package cleanup remains available from the normal leave/
    # restore workflows.
    ok "Failed-attempt local residue cleaned. AD client packages were kept for an immediate retry."
}

recover_incomplete_previous_join() {
    incomplete_sssd_residue_present || return 0

    local snap="" domain=""
    snap="$(latest_assistant_snapshot || true)"

    if [[ -n "$snap" ]]; then
        domain="$(snapshot_domain "$snap" || true)"
    fi

    printf '\n%bINCOMPLETE PREVIOUS JOIN DETECTED%b\n' "$C_BOLD" "$C_RESET"
    warn "A previous AD join did not leave a complete realmd/SSSD configuration."

    if [[ -n "$snap" ]]; then
        info "Latest assistant snapshot: $snap"
        previous_join_evidence "$snap" "$domain"
    else
        warn "No assistant snapshot is available; automatic cleanup is intentionally limited."
        previous_join_evidence "" ""
    fi

    printf '\n'
    printf '  [1] Clean failed-attempt local state and retry the join (recommended)\n'
    printf '  [2] Keep current residue and retry the join\n'
    printf '  [3] Show diagnostics again\n'
    printf '  [0] Cancel\n'

    local choice=""
    while true; do
        choice="$(ask 'Recovery action' '1')" || return 1
        case "$choice" in
            1)
                [[ -n "$snap" ]] || {
                    err "Cleanup requires an assistant snapshot. Choose option 2 only if you intentionally want to retry over the current local state."
                    continue
                }
                clean_failed_join_for_retry "$snap" || return 1
                return 0
                ;;
            2)
                warn "Continuing with the previous SSSD/Kerberos residue in place."
                warn "The guided join will still perform DNS, Kerberos and AD connectivity validation before membership changes."
                return 0
                ;;
            3)
                previous_join_evidence "$snap" "$domain"
                ;;
            0)
                return 1
                ;;
            *)
                warn "Invalid recovery selection."
                ;;
        esac
    done
}


require_supported_init() {
    if ! command_exists systemctl || [[ ! -d /run/systemd/system ]]; then
        err "Automated join/leave requires a systemd-based Linux client."
        warn "This build intentionally does not modify OpenRC/runit/SysV identity configuration."
        return 1
    fi
}

route_interface_for_target() {
    local target="$1" route=""
    [[ -n "$target" ]] || return 1
    route="$(ip -4 route get "$target" 2>/dev/null || true)"
    awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$route"
}

active_ipv4_interfaces() {
    local data=""
    data="$(ip -4 -o addr show scope global 2>/dev/null || true)"
    awk '{print $2}' <<<"$data" | awk '!seen[$0]++'
}

show_network_candidates() {
    local iface addr route metric manager
    while IFS= read -r iface; do
        [[ -n "$iface" ]] || continue
        addr="$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null | awk 'NR==1{print $4}')"
        route="$(ip -4 route show default dev "$iface" 2>/dev/null | awk 'NR==1{print}')"
        metric="$(awk '{for(i=1;i<=NF;i++) if($i=="metric"){print $(i+1); exit}}' <<<"$route")"
        [[ -n "$metric" ]] || metric="-"
        manager="kernel"
        if command_exists nmcli && systemctl is-active --quiet NetworkManager.service 2>/dev/null; then
            local state=""
            state="$(nmcli -g GENERAL.STATE device show "$iface" 2>/dev/null || true)"
            [[ -n "$state" ]] && manager="NetworkManager"
        elif command_exists networkctl && systemctl is-active --quiet systemd-networkd.service 2>/dev/null; then
            manager="systemd-networkd"
        fi
        printf '%s\t%s\t%s\t%s\n' "$iface" "${addr:--}" "$metric" "$manager"
    done < <(active_ipv4_interfaces)
}

select_join_interface() {
    local target_ip="${1:-}" suggested="" rows="" count=0

    if [[ -n "$target_ip" ]]; then
        suggested="$(route_interface_for_target "$target_ip" || true)"
    fi
    if [[ -z "$suggested" && $REMOTE_SESSION -eq 1 ]]; then
        local ssh_ip=""
        ssh_ip="${SSH_CLIENT:-}"
        ssh_ip="${ssh_ip%% *}"
        if [[ -z "$ssh_ip" ]]; then
            ssh_ip="${SSH_CONNECTION:-}"
            ssh_ip="${ssh_ip%% *}"
        fi
        [[ -n "$ssh_ip" ]] && suggested="$(route_interface_for_target "$ssh_ip" || true)"
    fi
    [[ -n "$suggested" ]] || suggested="$ACTIVE_IFACE"

    rows="$(show_network_candidates)"
    count="$(awk 'NF{n++}END{print n+0}' <<<"$rows")"
    if (( count == 0 )); then
        err "No active global IPv4 interface was detected."
        return 1
    fi

    if (( count == 1 )); then
        ACTIVE_IFACE="$(awk 'NF{print $1; exit}' <<<"$rows")"
        detect_dns_backend
        return 0
    fi

    printf '\nNETWORK INTERFACES\n'
    local i=0 iface addr metric manager default_choice=1 line
    while IFS=$'\t' read -r iface addr metric manager; do
        [[ -n "$iface" ]] || continue
        ((i++))
        [[ "$iface" == "$suggested" ]] && default_choice="$i"
        printf '  [%d] %-16s %-20s metric=%-6s %s' "$i" "$iface" "$addr" "$metric" "$manager"
        [[ "$iface" == "$suggested" ]] && printf '  <- suggested route'
        printf '\n'
    done <<<"$rows"

    local choice=""
    choice="$(ask 'Select interface used to reach Active Directory' "$default_choice")" || return 1
    [[ "$choice" =~ ^[0-9]+$ ]] || { err "Invalid interface selection."; return 1; }
    ACTIVE_IFACE="$(awk -v n="$choice" 'NF{c++; if(c==n){print $1; exit}}' <<<"$rows")"
    [[ -n "$ACTIVE_IFACE" ]] || { err "Invalid interface selection."; return 1; }

    if [[ -n "$suggested" && "$ACTIVE_IFACE" != "$suggested" ]]; then
        warn "Selected interface '$ACTIVE_IFACE' differs from the kernel route to the AD target ('$suggested')."
        confirm "Continue without changing routing?" N || return 1
    fi

    detect_dns_backend
    ok "Selected AD interface: $ACTIVE_IFACE ($DNS_BACKEND)."
}

identity_precheck() {
    local conflicts=0
    printf '\nIDENTITY PRECHECK\n'

    if [[ -s /etc/sssd/sssd.conf ]]; then
        warn "Existing /etc/sssd/sssd.conf detected."
        conflicts=1
    fi

    if [[ -s /etc/krb5.keytab ]]; then
        if kerberos_machine_identity_present; then
            warn "Existing Kerberos machine principals detected in /etc/krb5.keytab; they will be snapshotted before join."
        else
            warn "Existing /etc/krb5.keytab detected; it will be snapshotted before join."
        fi
        conflicts=1
    fi

    if grep -Eq '(^|[[:space:]])sss([[:space:]]|$)' /etc/nsswitch.conf 2>/dev/null; then
        info "NSS already references SSSD. This alone does not block a new join."
    fi

    if (( conflicts )); then
        warn "Existing identity material may belong to a prior or manually configured domain client."
        confirm "Snapshot the current identity state and continue with the guided join?" Y || return 1
    else
        ok "No conflicting pre-existing identity configuration detected."
    fi
}

record_assistant_package() {
    local snap="$1" pkg="$2" file="${snap}/packages-installed-by-assistant.txt"
    touch "$file"
    grep -Fxq "$pkg" "$file" 2>/dev/null || printf '%s\n' "$pkg" >>"$file"
}

set_current_phase() {
    local phase="$1"
    [[ -f "$CURRENT_STATE" ]] || return 1
    local tmp="${CURRENT_STATE}.tmp.$$"
    awk -v q="PHASE=$(printf '%q' "$phase")" '
        BEGIN{done=0}
        /^PHASE=/{if(!done){print q; done=1}; next}
        {print}
        END{if(!done) print q}
    ' "$CURRENT_STATE" >"$tmp" && mv "$tmp" "$CURRENT_STATE"
    chmod 0600 "$CURRENT_STATE"
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

detect_os() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_LIKE="${ID_LIKE:-}"
    else
        DISTRO_ID="unknown"
        DISTRO_LIKE=""
    fi

    if command_exists apt-get ||
       [[ "$DISTRO_ID" =~ ^(debian|ubuntu|linuxmint|pop)$ ]] ||
       [[ "$DISTRO_LIKE" == *debian* ]]; then
        PKG_FAMILY="apt"
    elif command_exists dnf || command_exists yum ||
         [[ "$DISTRO_ID" =~ ^(rhel|fedora|rocky|almalinux|centos)$ ]] ||
         [[ "$DISTRO_LIKE" == *rhel* || "$DISTRO_LIKE" == *fedora* ]]; then
        PKG_FAMILY="dnf"
    else
        PKG_FAMILY="generic"
    fi
}

detect_active_interface() {
    local preferred="" ssh_ip=""

    if [[ -n "${SSH_CLIENT:-}" || -n "${SSH_CONNECTION:-}" ]]; then
        ssh_ip="${SSH_CLIENT:-}"
        ssh_ip="${ssh_ip%% *}"
        if [[ -z "$ssh_ip" ]]; then
            ssh_ip="${SSH_CONNECTION:-}"
            ssh_ip="${ssh_ip%% *}"
        fi
        [[ -n "$ssh_ip" ]] && preferred="$(route_interface_for_target "$ssh_ip" || true)"
    fi

    if [[ -z "$preferred" ]]; then
        local routes=""
        routes="$(ip -4 route show default 2>/dev/null || true)"
        preferred="$(awk '
            NR==1 {best=$0; bestm=2147483647}
            {
                m=0
                for(i=1;i<=NF;i++) if($i=="metric") m=$(i+1)
                if(m < bestm){best=$0; bestm=m}
            }
            END{
                n=split(best,a," ")
                for(i=1;i<=n;i++) if(a[i]=="dev"){print a[i+1]; exit}
            }
        ' <<<"$routes")"
    fi

    if [[ -z "$preferred" ]]; then
        preferred="$(active_ipv4_interfaces | awk 'NR==1{print}')"
    fi
    ACTIVE_IFACE="$preferred"
}

detect_dns_backend() {
    DNS_BACKEND="resolv.conf"
    NM_CONNECTION=""
    NM_CONNECTION_UUID=""

    if command_exists nmcli &&
       systemctl is-active --quiet NetworkManager.service 2>/dev/null &&
       [[ -n "$ACTIVE_IFACE" ]]; then
        local con="" uuid=""
        con="$(nmcli -g GENERAL.CONNECTION device show "$ACTIVE_IFACE" 2>/dev/null || true)"
        if [[ -n "$con" && "$con" != "--" ]]; then
            uuid="$(nmcli -g connection.uuid connection show "$con" 2>/dev/null || true)"
            DNS_BACKEND="NetworkManager"
            NM_CONNECTION="$con"
            NM_CONNECTION_UUID="$uuid"
            return
        fi
    fi

    if command_exists resolvectl &&
       systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
        DNS_BACKEND="systemd-resolved"
        return
    fi
}


detect_system_resolver() {
    SYSTEM_RESOLVER_BACKEND="resolv.conf"
    RESOLV_CONF_TARGET="$(readlink -f /etc/resolv.conf 2>/dev/null || true)"
    [[ -n "$RESOLV_CONF_TARGET" ]] || RESOLV_CONF_TARGET="/etc/resolv.conf"

    if command_exists resolvectl &&
       systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
        SYSTEM_RESOLVER_BACKEND="systemd-resolved"
        return 0
    fi

    if [[ "$RESOLV_CONF_TARGET" == "/run/NetworkManager/resolv.conf" ||
          "$RESOLV_CONF_TARGET" == "/run/NetworkManager/no-stub-resolv.conf" ]]; then
        SYSTEM_RESOLVER_BACKEND="NetworkManager-resolv.conf"
    fi
}

wait_for_system_ad_dns() {
    local domain="$1" attempts="${2:-8}" i output=""
    for ((i=1; i<=attempts; i++)); do
        output="$(domain_srv_query "$domain" "" || true)"
        [[ -n "$output" ]] && return 0
        sleep 1
    done
    return 1
}

resolved_can_discover_ad() {
    local domain="$1" output=""
    command_exists resolvectl || return 1
    systemctl is-active --quiet systemd-resolved.service 2>/dev/null || return 1
    output="$(resolvectl query --type=SRV "_ldap._tcp.dc._msdcs.${domain}" 2>/dev/null || true)"
    grep -Fqi "${domain}" <<<"$output" || grep -Fqi 'service:' <<<"$output"
}

resolver_diagnostics() {
    local domain="$1"
    detect_system_resolver
    printf '\nSYSTEM RESOLVER DIAGNOSTICS\n'
    printf '  Network owner   : %s\n' "$DNS_BACKEND"
    printf '  System resolver : %s\n' "$SYSTEM_RESOLVER_BACKEND"
    printf '  /etc/resolv.conf: %s\n' "$RESOLV_CONF_TARGET"
    printf '  Interface       : %s\n' "${ACTIVE_IFACE:-unknown}"

    if [[ -r /etc/resolv.conf ]]; then
        printf '  resolv.conf nameservers:\n'
        awk '/^[[:space:]]*nameserver[[:space:]]+/{print "    "$2}' /etc/resolv.conf
    fi

    if command_exists nmcli && [[ -n "${ACTIVE_IFACE:-}" ]]; then
        local nm_dns=""
        nm_dns="$(nmcli -g IP4.DNS device show "$ACTIVE_IFACE" 2>/dev/null || true)"
        printf '  NetworkManager IP4.DNS:\n'
        if [[ -n "$nm_dns" ]]; then sed 's/^/    /' <<<"$nm_dns"; else printf '    (none)\n'; fi
    fi

    if command_exists resolvectl &&
       systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
        printf '  systemd-resolved link DNS:\n'
        resolvectl dns "$ACTIVE_IFACE" 2>/dev/null | sed 's/^/    /' || true
        printf '  systemd-resolved link domains:\n'
        resolvectl domain "$ACTIVE_IFACE" 2>/dev/null | sed 's/^/    /' || true
    fi
}

apply_resolved_runtime_dns() {
    local domain="$1" dns_csv="$2" iface="$3"
    command_exists resolvectl || return 1
    systemctl is-active --quiet systemd-resolved.service 2>/dev/null || return 1

    local -a dns_array=()
    mapfile -t dns_array < <(parse_dns_csv "$dns_csv")
    ((${#dns_array[@]})) || return 1

    # Standard AD client policy: the AD DNS servers are the resolver path for
    # all names. They are authoritative for AD and must forward external names.
    # "~." prevents public/DHCP DNS from racing AD lookups.
    resolvectl dns "$iface" "${dns_array[@]}" || return 1
    resolvectl domain "$iface" "$domain" "~." || return 1
    resolvectl default-route "$iface" yes >/dev/null 2>&1 || true
    resolvectl flush-caches >/dev/null 2>&1 || true
}

repair_resolver_convergence() {
    local domain="$1" dns_csv="$2" iface="$3"
    detect_system_resolver
    wait_for_system_ad_dns "$domain" 5 && return 0

    warn "AD DNS is reachable directly, but the host system resolver has not converged."
    resolver_diagnostics "$domain"

    if command_exists resolvectl &&
       systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
        info "Applying the AD DNS to systemd-resolved on '$iface' for live convergence."
        if apply_resolved_runtime_dns "$domain" "$dns_csv" "$iface" &&
           wait_for_system_ad_dns "$domain" 5; then
            ok "System resolver converged through systemd-resolved."
            return 0
        fi

        if resolved_can_discover_ad "$domain"; then
            detect_system_resolver
            case "$RESOLV_CONF_TARGET" in
                /run/systemd/resolve/stub-resolv.conf|/run/systemd/resolve/resolv.conf|/run/NetworkManager/resolv.conf)
                    ;;
                *)
                    warn "systemd-resolved can discover AD, but /etc/resolv.conf is detached from the active resolver."
                    if [[ -e /run/systemd/resolve/stub-resolv.conf ]] &&
                       confirm "Repair /etc/resolv.conf to the systemd-resolved stub? Snapshot rollback remains available." Y; then
                        rm -f /etc/resolv.conf || return 1
                        ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || return 1
                        resolvectl flush-caches >/dev/null 2>&1 || true
                        if wait_for_system_ad_dns "$domain" 5; then
                            detect_system_resolver
                            ok "System resolver repaired through systemd-resolved."
                            return 0
                        fi
                    fi
                    ;;
            esac
        fi
    fi

    if [[ "$DNS_BACKEND" == "NetworkManager" &&
          -e /run/NetworkManager/resolv.conf ]]; then
        detect_system_resolver
        if grep -Fq "$(dns_first "$dns_csv")" /run/NetworkManager/resolv.conf 2>/dev/null &&
           ! wait_for_system_ad_dns "$domain" 1; then
            case "$RESOLV_CONF_TARGET" in
                /run/NetworkManager/resolv.conf)
                    ;;
                *)
                    warn "NetworkManager generated the correct AD resolver file, but /etc/resolv.conf is using another source."
                    if confirm "Attach /etc/resolv.conf to NetworkManager's runtime resolver file? Snapshot rollback remains available." Y; then
                        rm -f /etc/resolv.conf || return 1
                        ln -s /run/NetworkManager/resolv.conf /etc/resolv.conf || return 1
                        if wait_for_system_ad_dns "$domain" 5; then
                            detect_system_resolver
                            ok "System resolver repaired through NetworkManager."
                            return 0
                        fi
                    fi
                    ;;
            esac
        fi
    fi

    resolver_diagnostics "$domain"
    return 1
}


# ---------------------------------------------------------------------------
# State serialization / snapshots
# ---------------------------------------------------------------------------

write_env_kv() {
    local file="$1" key="$2" value="${3:-}"
    printf '%s=%q\n' "$key" "$value" >>"$file"
}

load_state_file() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    # Values are written with printf %q by this assistant.
    # shellcheck disable=SC1090
    . "$file"
}

snapshot_copy() {
    local src="$1" dest_root="$2"
    [[ -e "$src" || -L "$src" ]] || return 0
    local rel="${src#/}"
    mkdir -p "${dest_root}/files/$(dirname "$rel")"
    cp -a -- "$src" "${dest_root}/files/${rel}"
}

create_prejoin_snapshot() {
    local domain="$1" iface="$2"
    local snap="${BACKUP_ROOT}/${RUN_ID}"
    local meta="${snap}/snapshot.env"

    mkdir -p "$snap/files"
    chmod 0700 "$snap"

    snapshot_copy /etc/resolv.conf "$snap"
    snapshot_copy /etc/hosts "$snap"
    snapshot_copy /etc/krb5.conf "$snap"
    snapshot_copy /etc/krb5.keytab "$snap"
    snapshot_copy /etc/realmd.conf "$snap"
    snapshot_copy /etc/sssd/sssd.conf "$snap"
    snapshot_copy /etc/sssd/conf.d "$snap"
    snapshot_copy /etc/nsswitch.conf "$snap"
    snapshot_copy /etc/pam.d/common-session "$snap"
    snapshot_copy /etc/pam.d/common-session-noninteractive "$snap"
    snapshot_copy /etc/systemd/resolved.conf.d/90-ad-client-assistant.conf "$snap"

    : >"$meta"
    write_env_kv "$meta" SNAPSHOT_VERSION "2"
    write_env_kv "$meta" SNAPSHOT_PATH "$snap"
    write_env_kv "$meta" CREATED_AT "$(date -Is)"
    write_env_kv "$meta" DOMAIN "$domain"
    write_env_kv "$meta" OLD_HOSTNAME "$(hostnamectl --static 2>/dev/null || hostname)"
    write_env_kv "$meta" ACTIVE_IFACE "$iface"
    write_env_kv "$meta" DNS_BACKEND "$DNS_BACKEND"
    write_env_kv "$meta" PKG_FAMILY "$PKG_FAMILY"
    write_env_kv "$meta" NM_CONNECTION "$NM_CONNECTION"
    write_env_kv "$meta" NM_CONNECTION_UUID "$NM_CONNECTION_UUID"
    write_env_kv "$meta" REMOTE_SESSION "$REMOTE_SESSION"
    write_env_kv "$meta" PREJOIN_BOOT_ID "$(current_boot_id)"
    local sssd_active="0" sssd_enabled="0"
    systemctl is-active --quiet sssd.service 2>/dev/null && sssd_active="1"
    systemctl is-enabled --quiet sssd.service 2>/dev/null && sssd_enabled="1"
    write_env_kv "$meta" PREJOIN_SSSD_ACTIVE "$sssd_active"
    write_env_kv "$meta" PREJOIN_SSSD_ENABLED "$sssd_enabled"
    write_env_kv "$meta" PREJOIN_SSSD_CONF_PRESENT "$([[ -s /etc/sssd/sssd.conf ]] && printf 1 || printf 0)"
    write_env_kv "$meta" PREJOIN_SSSD_CONFDB_PRESENT "$([[ -s /var/lib/sss/db/config.ldb ]] && printf 1 || printf 0)"

    if [[ "$DNS_BACKEND" == "NetworkManager" && -n "$NM_CONNECTION" ]]; then
        write_env_kv "$meta" NM_IPV4_IGNORE_AUTO_DNS \
            "$(nmcli -g ipv4.ignore-auto-dns connection show "$NM_CONNECTION" 2>/dev/null || true)"
        write_env_kv "$meta" NM_IPV4_DNS \
            "$(nmcli -g ipv4.dns connection show "$NM_CONNECTION" 2>/dev/null || true)"
        write_env_kv "$meta" NM_IPV4_DNS_SEARCH \
            "$(nmcli -g ipv4.dns-search connection show "$NM_CONNECTION" 2>/dev/null || true)"
        write_env_kv "$meta" NM_IPV4_DNS_PRIORITY \
            "$(nmcli -g ipv4.dns-priority connection show "$NM_CONNECTION" 2>/dev/null || true)"
        write_env_kv "$meta" NM_IPV6_IGNORE_AUTO_DNS \
            "$(nmcli -g ipv6.ignore-auto-dns connection show "$NM_CONNECTION" 2>/dev/null || true)"
        write_env_kv "$meta" NM_IPV6_DNS \
            "$(nmcli -g ipv6.dns connection show "$NM_CONNECTION" 2>/dev/null || true)"
        write_env_kv "$meta" NM_IPV6_DNS_SEARCH \
            "$(nmcli -g ipv6.dns-search connection show "$NM_CONNECTION" 2>/dev/null || true)"
    fi

    if command_exists authselect; then
        local authselect_state="" backup_name="ad-client-assistant-${RUN_ID}"
        authselect_state="$(authselect current --raw 2>/dev/null || authselect current 2>/dev/null || true)"
        printf '%s\n' "$authselect_state" >"${snap}/authselect-before.txt"
        if authselect backup "$backup_name" >/dev/null 2>&1; then
            write_env_kv "$meta" AUTHSELECT_BACKUP "$backup_name"
        fi
        if grep -Fq 'with-mkhomedir' <<<"$authselect_state"; then
            write_env_kv "$meta" AUTHSELECT_HAD_MKHOMEDIR "1"
        else
            write_env_kv "$meta" AUTHSELECT_HAD_MKHOMEDIR "0"
        fi
    fi

    printf '%s\n' "$snap"
}

restore_snapshot_file() {
    local snap="$1" target="$2"
    local stored="${snap}/files/${target#/}"

    if [[ -e "$stored" || -L "$stored" ]]; then
        rm -rf -- "$target"
        mkdir -p "$(dirname "$target")"
        cp -a -- "$stored" "$target"
    else
        rm -rf -- "$target"
    fi
}

record_current_state() {
    local snap="$1" domain="$2" realm="$3" iface="$4" dns_csv="$5" hostname_changed="$6" computer_name="${7:-}"
    : >"$CURRENT_STATE"
    chmod 0600 "$CURRENT_STATE"
    write_env_kv "$CURRENT_STATE" STATE_VERSION "2"
    write_env_kv "$CURRENT_STATE" PHASE "JOIN_PENDING_REBOOT"
    write_env_kv "$CURRENT_STATE" SNAPSHOT_PATH "$snap"
    write_env_kv "$CURRENT_STATE" DOMAIN "$domain"
    write_env_kv "$CURRENT_STATE" REALM "$realm"
    write_env_kv "$CURRENT_STATE" ACTIVE_IFACE "$iface"
    write_env_kv "$CURRENT_STATE" AD_DNS_SERVERS "$dns_csv"
    write_env_kv "$CURRENT_STATE" HOSTNAME_CHANGED "$hostname_changed"
    write_env_kv "$CURRENT_STATE" COMPUTER_NAME "$computer_name"
    write_env_kv "$CURRENT_STATE" JOIN_BOOT_ID "$(current_boot_id)"
    write_env_kv "$CURRENT_STATE" JOINED_AT "$(date -Is)"
}

# ---------------------------------------------------------------------------
# Package management
# ---------------------------------------------------------------------------

required_packages() {
    case "$PKG_FAMILY" in
        apt)
            printf '%s\n' \
                realmd \
                sssd-ad \
                sssd-tools \
                adcli \
                krb5-user \
                libnss-sss \
                libpam-sss
            ;;
        dnf)
            printf '%s\n' \
                realmd \
                sssd \
                adcli \
                krb5-workstation \
                oddjob \
                oddjob-mkhomedir \
                samba-common-tools
            ;;
        *)
            return 0
            ;;
    esac
}


dns_tools_package_name() {
    # dig is required for AD diagnostics and nsupdate is required for secure
    # Linux host registration in AD-integrated DNS. Treat the provider package
    # as satisfied only when both capabilities are already present.
    command_exists dig && command_exists nsupdate && return 0

    case "$PKG_FAMILY" in
        apt)
            if apt-cache show bind9-dnsutils >/dev/null 2>&1; then
                printf '%s' "bind9-dnsutils"
            elif apt-cache show dnsutils >/dev/null 2>&1; then
                printf '%s' "dnsutils"
            else
                return 1
            fi
            ;;
        dnf)
            printf '%s' "bind-utils"
            ;;
        *)
            return 1
            ;;
    esac
}

pkg_installed() {
    local pkg="$1"
    case "$PKG_FAMILY" in
        apt)
            local status=""
            status="$(dpkg-query -W -f='${db:Status-Abbrev}' "$pkg" 2>/dev/null || true)"
            [[ "$status" == "ii " ]]
            ;;
        dnf)
            rpm -q "$pkg" >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

install_required_packages() {
    local snap="$1"
    local -a required=() missing=()
    local record="${snap}/packages-installed-by-assistant.txt"
    mapfile -t required < <(required_packages)
    : >"$record"

    if [[ "$PKG_FAMILY" == "generic" ]]; then
        warn "Unsupported package family. No repository/package configuration will be changed."
        validate_required_commands
        return $?
    fi

    local pkg dns_pkg=""
    for pkg in "${required[@]}"; do
        [[ -n "$pkg" ]] || continue
        pkg_installed "$pkg" || missing+=("$pkg")
    done

    # DNS tooling is capability-based. The same distribution package normally
    # provides both dig and nsupdate. nsupdate is intentionally required so a
    # Linux client can publish/refresh its own secure AD DNS A record.
    if ! command_exists dig || ! command_exists nsupdate; then
        dns_pkg="$(dns_tools_package_name 2>/dev/null || true)"
        [[ -n "$dns_pkg" ]] || {
            err "dig/nsupdate capability is incomplete and no distribution DNS tools package could be identified."
            return 1
        }
        pkg_installed "$dns_pkg" || missing+=("$dns_pkg")
    else
        ok "DNS diagnostic/update capabilities available: dig + nsupdate."
    fi

    if ((${#missing[@]} == 0)); then
        ok "Required AD client packages are already installed."
        validate_required_commands
        return $?
    fi

    info "Packages required from the distribution repositories:"
    printf '  %s\n' "${missing[@]}"
    confirm "Install these packages from the currently configured official/system repositories?" Y || return 1

    case "$PKG_FAMILY" in
        apt)
            apt-get update || { err "apt-get update failed."; return 1; }
            if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"; then
                for pkg in "${missing[@]}"; do
                    pkg_installed "$pkg" && record_assistant_package "$snap" "$pkg"
                done
                err "APT package installation failed; any packages actually added were recorded for rollback."
                return 1
            fi
            ;;
        dnf)
            local pm="dnf"
            command_exists dnf || pm="yum"
            if ! "$pm" install -y "${missing[@]}"; then
                for pkg in "${missing[@]}"; do
                    pkg_installed "$pkg" && record_assistant_package "$snap" "$pkg"
                done
                err "$pm package installation failed; any packages actually added were recorded for rollback."
                return 1
            fi
            ;;
    esac

    for pkg in "${missing[@]}"; do
        pkg_installed "$pkg" && record_assistant_package "$snap" "$pkg"
    done

    validate_required_commands
}

validate_required_commands() {
    local -a commands=(realm adcli kinit klist getent systemctl hostnamectl ip)
    local missing=0 cmd
    for cmd in "${commands[@]}"; do
        if command_exists "$cmd"; then
            ok "Command available: $cmd"
        else
            err "Missing required command: $cmd"
            missing=1
        fi
    done

    if [[ "$PKG_FAMILY" == "apt" || "$PKG_FAMILY" == "dnf" ]]; then
        if command_exists dig; then
            ok "Command available: dig"
        else
            err "Missing required DNS diagnostic command: dig"
            missing=1
        fi
        if command_exists nsupdate; then
            ok "Command available: nsupdate"
        else
            err "Missing secure AD DNS update command: nsupdate"
            missing=1
        fi
    else
        command_exists dig || warn "dig is unavailable; generic-mode DNS validation will be reduced."
        command_exists nsupdate || warn "nsupdate is unavailable; automatic secure AD DNS registration will be skipped."
    fi

    require_supported_init || missing=1
    (( missing == 0 ))
}

remove_assistant_packages() {
    local snap="$1"
    local file="${snap}/packages-installed-by-assistant.txt"
    [[ -s "$file" ]] || {
        info "No packages were recorded as newly installed by this assistant."
        return 0
    }

    local -a pkgs=()
    mapfile -t pkgs <"$file"
    ((${#pkgs[@]})) || return 0

    printf '\nPackages originally added by the assistant:\n'
    printf '  %s\n' "${pkgs[@]}"

    confirm_literal \
        "Package removal can also remove dependent packages. No autoremove will be executed." \
        "REMOVE-PACKAGES" || return 0

    remove_assistant_packages_now "$snap"
}

remove_assistant_packages_now() {
    local snap="$1"
    local file="${snap}/packages-installed-by-assistant.txt"
    [[ -s "$file" ]] || return 0

    local -a pkgs=() installed=()
    mapfile -t pkgs <"$file"

    local pkg
    for pkg in "${pkgs[@]}"; do
        [[ -n "$pkg" ]] || continue
        pkg_installed "$pkg" && installed+=("$pkg")
    done

    ((${#installed[@]})) || {
        info "Packages recorded for this attempt are already absent."
        return 0
    }

    case "$PKG_FAMILY" in
        apt)
            apt-get remove -y "${installed[@]}" || {
                warn "APT could not remove every recorded package."
                return 1
            }
            ;;
        dnf)
            local pm="dnf"
            command_exists dnf || pm="yum"
            "$pm" remove -y "${installed[@]}" || {
                warn "$pm could not remove every recorded package."
                return 1
            }
            ;;
        *)
            warn "Package removal is not automated for this package family."
            return 1
            ;;
    esac

    ok "Packages added only by the failed join attempt were removed. No autoremove was executed."
}

# ---------------------------------------------------------------------------
# DNS / network
# ---------------------------------------------------------------------------

parse_dns_csv() {
    local raw="$1"
    tr ',;' '  ' <<<"$raw" |
        awk '{
            for(i=1;i<=NF;i++) print $i
        }'
}

valid_ip() {
    # Keep the baseline dependency-free. The assistant currently accepts
    # IPv4 DNS servers because IPv4 is the primary interoperability path for
    # the supported AD client workflow.
    local ip="$1" a b c d extra
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS='.' read -r a b c d extra <<<"$ip"
    [[ -z "${extra:-}" ]] || return 1

    local octet
    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done
}

validate_dns_list() {
    local raw="$1" count=0 ip
    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        valid_ip "$ip" || return 1
        ((count++))
    done < <(parse_dns_csv "$raw")
    (( count >= 1 ))
}

dns_space_list() {
    local raw="$1"
    parse_dns_csv "$raw" | paste -sd' ' -
}

dns_first() {
    local raw="$1"
    parse_dns_csv "$raw" | awk 'NR==1{print}'
}

current_dns_summary() {
    case "$DNS_BACKEND" in
        NetworkManager)
            nmcli -g IP4.DNS device show "$ACTIVE_IFACE" 2>/dev/null || true
            ;;
        systemd-resolved)
            resolvectl dns "$ACTIVE_IFACE" 2>/dev/null || true
            ;;
        *)
            awk '/^[[:space:]]*nameserver[[:space:]]+/{print $2}' /etc/resolv.conf 2>/dev/null || true
            ;;
    esac
}

apply_domain_dns() {
    local domain="$1" dns_csv="$2" iface="$3"
    local dns_space=""
    dns_space="$(dns_space_list "$dns_csv")"

    [[ -n "$dns_space" ]] || { err "No DNS servers supplied."; return 1; }
    (( AD_DNS_FORWARDING_OK == 1 )) || {
        err "AD DNS external forwarding was not validated. Refusing to replace the client resolver and risk losing Internet access."
        return 1
    }

    if (( REMOTE_SESSION )); then
        warn "Remote session detected. DNS changes should not interrupt an existing IP-based SSH session,"
        warn "but a bad DNS choice can prevent reconnecting by hostname."
    fi

    case "$DNS_BACKEND" in
        NetworkManager)
            [[ -n "$NM_CONNECTION" ]] || { err "NetworkManager connection could not be determined."; return 1; }

            # DHCP still owns IP/gateway/routes. Only DNS is overridden.
            # Negative priority excludes DNS from other active connections with
            # a worse priority and "~." makes this the default DNS route.
            nmcli connection modify "$NM_CONNECTION" \
                ipv4.ignore-auto-dns yes \
                ipv4.dns "$dns_space" \
                ipv4.dns-search "$domain,~." \
                ipv4.dns-priority -100 || return 1

            nmcli connection modify "$NM_CONNECTION" \
                ipv6.ignore-auto-dns yes \
                ipv6.dns-priority -100 || true

            if ! nmcli device reapply "$iface" >/dev/null 2>&1; then
                warn "NetworkManager could not reapply DNS live."
                if confirm "Reconnect the NetworkManager connection now? This can interrupt remote sessions." N; then
                    nmcli connection up "$NM_CONNECTION" || return 1
                else
                    return 1
                fi
            fi

            if command_exists resolvectl &&
               systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
                apply_resolved_runtime_dns "$domain" "$dns_csv" "$iface" || \
                    warn "NetworkManager was updated, but systemd-resolved did not accept the live AD DNS policy."
            fi
            ;;
        systemd-resolved)
            local -a dns_array=()
            mapfile -t dns_array < <(parse_dns_csv "$dns_csv")
            local iface_count=""
            iface_count="$(active_ipv4_interfaces | awk 'NF{n++}END{print n+0}')"
            if (( iface_count > 1 )); then
                warn "Multiple IPv4 interfaces are active and systemd-resolved is not owned by NetworkManager."
                warn "The persistent resolved.conf.d fallback is global; per-link runtime settings are also applied."
                confirm "Apply this global AD DNS fallback on a multi-NIC host?" N || return 1
            fi

            mkdir -p /etc/systemd/resolved.conf.d
            cat >/etc/systemd/resolved.conf.d/90-ad-client-assistant.conf <<EOF
# Managed by RHEL AD Client Assistant
# AD DNS is authoritative for the domain and forwards external DNS.
[Resolve]
DNS=${dns_space}
Domains=${domain} ~.
EOF
            systemctl restart systemd-resolved.service || return 1
            apply_resolved_runtime_dns "$domain" "$dns_csv" "$iface" || return 1
            ;;
        resolv.conf)
            warn "No supported persistent DNS manager was detected."
            warn "The assistant will manage /etc/resolv.conf directly and restore it on rollback."
            confirm "Continue with direct /etc/resolv.conf management?" N || return 1

            local tmp="/etc/resolv.conf.ad-client-assistant.$$"
            {
                local ip
                while IFS= read -r ip; do
                    [[ -n "$ip" ]] && printf 'nameserver %s\n' "$ip"
                done < <(parse_dns_csv "$dns_csv")
                printf 'search %s\n' "$domain"
                printf 'options timeout:2 attempts:2\n'
            } >"$tmp" || return 1
            chmod 0644 "$tmp"
            mv -Tf "$tmp" /etc/resolv.conf || return 1
            ;;
    esac

    sleep 1
    ok "AD DNS configuration applied via $DNS_BACKEND; DHCP/static IP addressing was left unchanged."
}

restore_network_from_snapshot() {
    local snap="$1" meta="${snap}/snapshot.env"
    [[ -f "$meta" ]] || { err "Snapshot metadata missing: $meta"; return 1; }

    unset DNS_BACKEND NM_CONNECTION NM_CONNECTION_UUID ACTIVE_IFACE
    load_state_file "$meta" || return 1

    case "${DNS_BACKEND:-}" in
        NetworkManager)
            if command_exists nmcli; then
                local con_ref="${NM_CONNECTION_UUID:-${NM_CONNECTION:-}}"
                if [[ -n "$con_ref" ]] && nmcli connection show "$con_ref" >/dev/null 2>&1; then
                    nmcli connection modify "$con_ref" \
                        ipv4.ignore-auto-dns "${NM_IPV4_IGNORE_AUTO_DNS:-no}" \
                        ipv4.dns "${NM_IPV4_DNS:-}" \
                        ipv4.dns-search "${NM_IPV4_DNS_SEARCH:-}" \
                        ipv4.dns-priority "${NM_IPV4_DNS_PRIORITY:-0}" || true
                    nmcli connection modify "$con_ref" \
                        ipv6.ignore-auto-dns "${NM_IPV6_IGNORE_AUTO_DNS:-no}" \
                        ipv6.dns "${NM_IPV6_DNS:-}" \
                        ipv6.dns-search "${NM_IPV6_DNS_SEARCH:-}" || true
                    [[ -n "${ACTIVE_IFACE:-}" ]] && nmcli device reapply "$ACTIVE_IFACE" >/dev/null 2>&1 || true
                else
                    warn "Original NetworkManager connection is no longer present; automatic DNS rollback is incomplete."
                fi
            fi
            ;;
        systemd-resolved)
            restore_snapshot_file "$snap" /etc/systemd/resolved.conf.d/90-ad-client-assistant.conf
            systemctl restart systemd-resolved.service >/dev/null 2>&1 || true
            if command_exists resolvectl && [[ -n "${ACTIVE_IFACE:-}" ]]; then
                resolvectl revert "$ACTIVE_IFACE" >/dev/null 2>&1 || true
                resolvectl flush-caches >/dev/null 2>&1 || true
            fi
            ;;
        resolv.conf)
            restore_snapshot_file "$snap" /etc/resolv.conf
            ;;
    esac

    detect_active_interface
    detect_dns_backend
    detect_system_resolver
    ok "Pre-join DNS/network resolver state restored."
}

# ---------------------------------------------------------------------------
# Domain validation / join
# ---------------------------------------------------------------------------

domain_srv_query() {
    local domain="$1" server="${2:-}" output=""
    command_exists dig || return 1

    if [[ -n "$server" ]]; then
        output="$(dig +time=3 +tries=1 @"$server" \
            "_ldap._tcp.dc._msdcs.${domain}" SRV +short 2>/dev/null || true)"
    else
        output="$(dig +time=3 +tries=1 \
            "_ldap._tcp.dc._msdcs.${domain}" SRV +short 2>/dev/null || true)"
    fi

    printf '%s\n' "$output"
    [[ -n "$output" ]]
}


preflight_ad_dns_servers() {
    local domain="$1" dns_csv="$2" ip="" output="" external="" failures=0 forwarding_failures=0
    AD_DNS_FORWARDING_OK=0

    if ! command_exists dig; then
        warn "dig is unavailable before dependency installation; direct DNS preflight is deferred."
        return 0
    fi

    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue

        output="$(domain_srv_query "$domain" "$ip" || true)"
        if [[ -n "$output" ]]; then
            ok "Preflight: $ip is an AD-capable DNS server for $domain."
        else
            err "Preflight: $ip does not answer the AD DC locator SRV query."
            failures=1
            continue
        fi

        # A normal AD client should use only AD DNS. Therefore each configured
        # AD DNS must also be able to resolve/forward external names.
        external="$(dig +time=3 +tries=1 @"$ip" example.com A +short 2>/dev/null || true)"
        if grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<<"$external"; then
            ok "Preflight: $ip forwards external DNS queries."
        else
            err "Preflight: $ip is authoritative for AD but cannot resolve external DNS."
            forwarding_failures=1
        fi
    done < <(parse_dns_csv "$dns_csv")

    (( failures == 0 )) || return 1

    if (( forwarding_failures != 0 )); then
        printf '\n%bAD DNS FORWARDING DIAGNOSTIC%b\n' "$C_BOLD" "$C_RESET"
        warn "The AD DNS server can resolve the domain but cannot resolve Internet names."
        info "The client IP may remain DHCP; do not add public DNS as a fallback because it can break AD/Kerberos discovery."
        info "Repair the Samba/AD DNS forwarder on the DC, then retry. No client DNS change has been committed."
        return 2
    fi

    AD_DNS_FORWARDING_OK=1
    return 0
}

ad_dc_targets_from_dns() {
    local domain="$1" dns_csv="$2" first="" output=""
    first="$(dns_first "$dns_csv")"
    output="$(domain_srv_query "$domain" "$first" || true)"
    awk '{host=$4; sub(/\.$/,"",host); if(host!="" && !seen[host]++) print host}' <<<"$output"
}

tcp_port_open() {
    local host="$1" port="$2"
    command_exists timeout || return 2
    timeout 3 bash -c 'exec 3<>"/dev/tcp/${1}/${2}"' _ "$host" "$port" >/dev/null 2>&1
}

validate_ad_network_ports() {
    local domain="$1" dns_csv="$2" dc="" first_dc="" hard_fail=0
    first_dc="$(ad_dc_targets_from_dns "$domain" "$dns_csv" | awk 'NR==1{print}')"
    if [[ -z "$first_dc" ]]; then
        warn "No DC hostname could be extracted from DNS SRV answers; port readiness skipped."
        return 0
    fi
    dc="$first_dc"
    printf '\nAD NETWORK READINESS (%s)\n' "$dc"
    local item port required rc
    for item in 'DNS:53:yes' 'Kerberos:88:yes' 'LDAP:389:yes' 'SMB:445:no'; do
        IFS=: read -r item port required <<<"$item"
        if tcp_port_open "$dc" "$port"; then
            ok "$item/TCP $port reachable."
        else
            rc=$?
            if (( rc == 2 )); then
                warn "timeout command unavailable; TCP readiness cannot be tested without adding dependencies."
                return 0
            fi
            if [[ "$required" == yes ]]; then
                err "$item/TCP $port is not reachable on $dc."
                hard_fail=1
            else
                warn "$item/TCP $port is not reachable; domain join may work but SMB/GPO operations can be limited."
            fi
        fi
    done
    (( hard_fail == 0 ))
}

prompt_domain_admin_account() {
    local purpose="${1:-join}"
    local default_account="${2:-Administrator}"
    local account=""

    # This function is normally called through command substitution.  All UI
    # output MUST go to the interactive descriptor so stdout contains only the
    # selected account.  Otherwise labels such as DOMAIN\user become part of
    # the Kerberos principal and corrupt kinit.
    printf '\n%bDOMAIN CREDENTIAL%b\n' "$C_BOLD" "$C_RESET" >&${INPUT_FD}
    printf '  This credential is used only to authorize the computer membership operation.\n' >&${INPUT_FD}
    printf '  It is not the domain user who will later sign in to this workstation.\n' >&${INPUT_FD}
    printf '  Prefer a delegated computer-join account; Domain Admin is not required when delegation exists.\n' >&${INPUT_FD}
    printf '  Default account: %s\n' "$default_account" >&${INPUT_FD}
    printf '  Accepted forms: user | user@%s | DOMAIN\\user\n\n' "${JOIN_REALM_NAME:-REALM}" >&${INPUT_FD}

    account="$(ask "AD account authorized to ${purpose}" "$default_account")" || return 1
    [[ -n "$account" ]] || account="$default_account"

    # Only the machine-readable return value is written to stdout.
    printf '%s' "$account"
}

analyze_realm_join_failure() {
    local log_file="$1" computer_name="$2"
    [[ -r "$log_file" ]] || return 0

    if grep -Fiq 'Insufficient permissions to modify computer account' "$log_file" ||
       grep -Fiq 'unable to get access to CN=' "$log_file"; then
        printf '\n%bJOIN PERMISSION DIAGNOSTIC%b\n' "$C_BOLD" "$C_RESET"
        warn "The AD computer account '${computer_name}' appears to exist already, or the selected account cannot modify/create it."
        info "Use an account with delegated computer-join rights, or inspect the existing computer object from the AD control plane."
        info "If the object is stale, delete/reset it only after confirming it is not an active machine account."
    fi

    if grep -Fiq "Client's credentials have been revoked" "$log_file"; then
        warn "The credential used by realmd/adcli is disabled, expired or otherwise rejected by Kerberos."
        info "Retry with Administrator or select another enabled/delegated AD account at the credential step."
    fi
}

kerberos_preflight_ticket() {
    local join_user="$1" realm="$2" principal=""

    # Credentials must be a single logical account token.  This catches UI or
    # caller contamination before kinit is invoked.
    if [[ "$join_user" == *$'\n'* || "$join_user" == *$'\r'* || "$join_user" == *$'\t'* ]]; then
        err "Invalid AD account value: embedded whitespace/control characters detected."
        return 1
    fi

    principal="$join_user"
    if [[ "$principal" == *\\* ]]; then
        principal="${principal##*\\}"
    fi
    [[ "$principal" == *@* ]] || principal="${principal}@${realm}"

    rm -f -- "$PRIVATE_KRB5CCACHE"
    info "Kerberos authentication preflight for $principal."
    info "Credential cache is isolated and will be removed after the join attempt."
    if kinit -c "FILE:${PRIVATE_KRB5CCACHE}" "$principal"; then
        ok "Kerberos credentials accepted."
        return 0
    fi
    err "Kerberos authentication failed before realm join."
    return 1
}

validate_domain_dns() {
    local domain="$1" dns_csv="$2" ip="" direct="" failed=0

    if command_exists dig; then
        while IFS= read -r ip; do
            [[ -n "$ip" ]] || continue
            direct="$(domain_srv_query "$domain" "$ip" || true)"
            if [[ -n "$direct" ]]; then
                ok "AD DNS $ip returns DC locator SRV records."
            else
                err "AD DNS $ip did not return _ldap._tcp.dc._msdcs.${domain}."
                failed=1
            fi
        done < <(parse_dns_csv "$dns_csv")
        (( failed == 0 )) || return 1

        if wait_for_system_ad_dns "$domain" 5; then
            ok "System resolver can discover AD DC locator SRV records."
        else
            warn "Direct AD DNS queries pass, but the system resolver cannot yet discover the domain."
            if repair_resolver_convergence "$domain" "$dns_csv" "$ACTIVE_IFACE"; then
                ok "System resolver can now discover AD DC locator SRV records."
            else
                err "System resolver still cannot discover the domain after resolver convergence repair."
                return 1
            fi
        fi
    else
        warn "dig is unavailable; relying on realmd discovery."
    fi

    local discovery=""
    discovery="$(capture_probe 20 "realmd discovery for $domain" realm discover --server-software=active-directory "$domain" || true)"
    if grep -Fiq 'server-software: active-directory' <<<"$discovery"; then
        ok "realmd discovered Active Directory."
        JOIN_REALM_NAME="$(awk -F': *' 'tolower($1) ~ /^[[:space:]]*realm-name$/ {print $2; exit}' <<<"$discovery")"
        [[ -n "$JOIN_REALM_NAME" ]] || JOIN_REALM_NAME="${domain^^}"
    else
        err "realmd could not discover Active Directory."
        printf '%s\n' "$discovery"
        resolver_diagnostics "$domain"
        return 1
    fi
    return 0
}

audit_time_sync() {
    local healthy=0
    if command_exists timedatectl; then
        local synced=""
        synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
        if [[ "$synced" == "yes" ]]; then
            ok "System time reports synchronized."
            healthy=1
        fi
    fi
    if (( ! healthy )) && command_exists chronyc; then
        local leap=""
        leap="$(chronyc tracking 2>/dev/null | awk -F': *' '/Leap status/{print $2; exit}')"
        if [[ "${leap,,}" == normal ]]; then
            ok "Chrony reports Leap status: Normal."
            healthy=1
        fi
    fi
    if (( ! healthy )); then
        warn "System time is not reporting a healthy synchronization state."
        warn "Kerberos is sensitive to clock skew; correct time before treating credential failures as AD issues."
        return 1
    fi
    return 0
}

configure_hostname_if_requested() {
    local requested="$1" old=""
    HOSTNAME_CHANGED_RESULT=0
    old="$(hostnamectl --static 2>/dev/null || hostname)"

    if [[ -z "$requested" || "$requested" == "$old" ]]; then return 0; fi
    if ! valid_system_hostname "$requested"; then
        err "Invalid system hostname: $requested"
        return 1
    fi
    confirm "Change hostname from '$old' to '$requested' before joining?" Y || return 1
    hostnamectl set-hostname "$requested" || return 1
    HOSTNAME_CHANGED_RESULT=1
    ok "Hostname changed to $requested."
}

configure_mkhomedir() {
    local snap="$1"
    confirm "Enable automatic home-directory creation for domain users?" Y || return 0

    if [[ "$PKG_FAMILY" == "apt" ]]; then
        local pam_module=""
        pam_module="$(find /lib /usr/lib -path '*/security/pam_mkhomedir.so' -print -quit 2>/dev/null || true)"
        if [[ -z "$pam_module" ]]; then
            warn "pam_mkhomedir.so is not available in the current base installation."
            warn "No extra package will be added only for this optional feature. Home creation remains unchanged."
            return 1
        fi

        local pamfile
        for pamfile in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
            [[ -f "$pamfile" ]] || continue
            if ! grep -Fq 'pam_mkhomedir.so' "$pamfile"; then
                printf '\nsession optional pam_mkhomedir.so skel=/etc/skel/ umask=0022\n' >>"$pamfile"
            fi
        done
        ok "pam_mkhomedir enabled idempotently using the existing PAM stack."
    elif command_exists authselect; then
        if authselect enable-feature with-mkhomedir >/dev/null 2>&1; then
            systemctl enable --now oddjobd.service >/dev/null 2>&1 || true
            ok "authselect with-mkhomedir enabled."
        else
            warn "authselect could not enable with-mkhomedir automatically."
        fi
    else
        warn "Automatic home-directory configuration is not supported on this platform."
    fi
}

apply_access_policy() {
    local domain="$1"
    printf '\nLogin authorization policy:\n'
    printf '  [1] Keep realmd/default policy unchanged\n'
    printf '  [2] Permit one domain user\n'
    printf '  [3] Permit one domain group\n'
    printf '  [4] Permit all domain users (broad access)\n'

    local choice=""
    choice="$(ask 'Select policy' '1')"

    case "$choice" in
        2)
            local user=""
            user="$(ask 'User (for example user@domain)' '')"
            [[ -n "$user" ]] && realm permit "$user"
            ;;
        3)
            local group=""
            group="$(ask 'Group (for example linux-login@domain)' '')"
            [[ -n "$group" ]] && realm permit -g "$group"
            ;;
        4)
            confirm_literal \
                "This allows every domain user to attempt login on this Linux host." \
                "PERMIT-ALL" || return 0
            realm permit --all
            ;;
        *)
            info "Login authorization policy left unchanged."
            ;;
    esac
}


repair_sssd_config_compatibility() {
    local snap="${1:-}"
    local conf="/etc/sssd/sssd.conf"
    command_exists sssctl || return 0
    [[ -s "$conf" ]] || return 0

    local check=""
    check="$(capture_probe 10 "SSSD configuration validation" sssctl config-check || true)"
    if ! grep -Fq "Attribute 'config_file_version' is not allowed in section 'sssd'" <<<"$check"; then
        return 0
    fi

    warn "SSSD validator reports legacy/unsupported option: config_file_version."
    info "Removing only that deprecated directive from [sssd]; domain/provider settings are left unchanged."

    if [[ -n "$snap" && -d "$snap" && ! -e "${snap}/sssd.conf-postjoin-before-compat-fix" ]]; then
        cp -a -- "$conf" "${snap}/sssd.conf-postjoin-before-compat-fix" 2>/dev/null || true
    fi

    local tmp="${conf}.compat.$$"
    awk '
        BEGIN { section="" }
        /^[[:space:]]*\[/ {
            section=tolower($0)
            gsub(/[[:space:]]/, "", section)
        }
        section=="[sssd]" && /^[[:space:]]*config_file_version[[:space:]]*=/ { next }
        { print }
    ' "$conf" >"$tmp" || { rm -f -- "$tmp"; return 1; }

    chmod --reference="$conf" "$tmp" 2>/dev/null || chmod 0600 "$tmp"
    chown --reference="$conf" "$tmp" 2>/dev/null || true
    mv -f -- "$tmp" "$conf" || return 1

    if run_probe 10 "SSSD configuration validation" sssctl config-check >/dev/null 2>&1; then
        ok "SSSD compatibility repair succeeded; configuration validation now passes."
        return 0
    fi

    err "SSSD still reports configuration errors after removing config_file_version."
    capture_probe 10 "SSSD configuration validation" sssctl config-check 2>&1 | sed 's/^/  /' || true
    return 1
}


ensure_sssd_dynamic_dns() {
    local domain="$1" snap="${2:-}" conf="/etc/sssd/sssd.conf"
    [[ -s "$conf" ]] || {
        warn "SSSD configuration is unavailable; persistent dynamic DNS registration could not be configured."
        return 1
    }

    local backup="${conf}.before-dyndns-${RUN_ID}" tmp="${conf}.dyndns.$$"
    cp -a -- "$conf" "$backup" || return 1
    if [[ -n "$snap" && -d "$snap" && ! -e "${snap}/sssd.conf-before-dyndns" ]]; then
        cp -a -- "$conf" "${snap}/sssd.conf-before-dyndns" 2>/dev/null || true
    fi

    awk -v wanted="domain/${domain,,}" '
        function emit_missing() {
            if (!seen_update)  print "dyndns_update = true"
            if (!seen_refresh) print "dyndns_refresh_interval = 43200"
            if (!seen_ttl)     print "dyndns_ttl = 300"
        }
        function norm_section(s, t) {
            t=tolower(s)
            gsub(/^[[:space:]]*\[/, "", t)
            gsub(/\][[:space:]]*$/, "", t)
            gsub(/[[:space:]]/, "", t)
            return t
        }
        BEGIN {
            in_target=0
            found_target=0
            seen_update=seen_refresh=seen_ttl=0
        }
        /^[[:space:]]*\[/ {
            if (in_target) emit_missing()
            in_target=(norm_section($0) == wanted)
            if (in_target) {
                found_target=1
                seen_update=seen_refresh=seen_ttl=0
            }
            print
            next
        }
        in_target && /^[[:space:]]*dyndns_update[[:space:]]*=/ {
            print "dyndns_update = true"
            seen_update=1
            next
        }
        in_target && /^[[:space:]]*dyndns_refresh_interval[[:space:]]*=/ {
            print "dyndns_refresh_interval = 43200"
            seen_refresh=1
            next
        }
        in_target && /^[[:space:]]*dyndns_ttl[[:space:]]*=/ {
            print "dyndns_ttl = 300"
            seen_ttl=1
            next
        }
        { print }
        END {
            if (in_target) emit_missing()
            if (!found_target) exit 42
        }
    ' "$conf" >"$tmp"
    local rc=$?

    if (( rc == 42 )); then
        rm -f -- "$tmp" "$backup"
        warn "Could not locate [domain/${domain,,}] in sssd.conf; dynamic DNS policy was left unchanged."
        return 1
    elif (( rc != 0 )); then
        rm -f -- "$tmp"
        mv -f -- "$backup" "$conf" 2>/dev/null || true
        return 1
    fi

    chmod --reference="$conf" "$tmp" 2>/dev/null || chmod 0600 "$tmp"
    chown --reference="$conf" "$tmp" 2>/dev/null || true
    mv -f -- "$tmp" "$conf" || {
        mv -f -- "$backup" "$conf" 2>/dev/null || true
        return 1
    }

    if command_exists sssctl && ! run_probe 10 "SSSD dynamic DNS configuration validation" sssctl config-check >/dev/null 2>&1; then
        warn "SSSD rejected the dynamic DNS settings; restoring the previous configuration."
        mv -f -- "$backup" "$conf" 2>/dev/null || true
        return 1
    fi

    rm -f -- "$backup"
    ok "SSSD secure dynamic DNS refresh enabled for ${domain,,}."
    return 0
}

remote_management_controller_ips() {
    local domain="${1:-}" dns_csv="${2:-}" ip="" dc=""
    local -A seen=()

    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        [[ -n "${seen[$ip]:-}" ]] || { seen[$ip]=1; printf '%s\n' "$ip"; }
    done < <(parse_dns_csv "$dns_csv")

    [[ -n "$domain" ]] || return 0
    while IFS= read -r dc; do
        [[ -n "$dc" ]] || continue
        while IFS= read -r ip; do
            [[ "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || continue
            [[ -n "${seen[$ip]:-}" ]] || { seen[$ip]=1; printf '%s\n' "$ip"; }
        done < <(getent ahostsv4 "$dc" 2>/dev/null | awk '{print $1}' | sort -u)
    done < <(ad_dc_targets_from_dns "$domain" "$dns_csv" 2>/dev/null || true)
}

configure_managed_remote_identity() {
    local user="$AD_CLIENT_REMOTE_USER" home="" sudoers="/etc/sudoers.d/debian-ad-remote-ops"
    [[ "$user" =~ ^[a-z_][a-z0-9_-]*$ ]] || {
        warn "Managed remote username '$user' is not a safe local account name."
        return 1
    }

    if ! id "$user" >/dev/null 2>&1; then
        info "Creating the locked local service identity used by Debian AD remote operations: $user"
        useradd -m -s /bin/bash "$user" || return 1
    fi
    passwd -l "$user" >/dev/null 2>&1 || true
    home="$(getent passwd "$user" | cut -d: -f6)"
    [[ -n "$home" ]] || home="/home/$user"
    install -d -m 700 -o "$user" -g "$user" "$home/.ssh" || return 1
    touch "$home/.ssh/authorized_keys"
    chown "$user:$user" "$home/.ssh/authorized_keys"
    chmod 600 "$home/.ssh/authorized_keys"

    mkdir -p /etc/sudoers.d
    cat >"$sudoers" <<EOF
# Managed by RHEL AD Client Assistant ${SCRIPT_VERSION}.
# This passwordless policy is intentionally limited to the operations exposed by
# the Debian AD remote-operations console. The account itself has no password.
${user} ALL=(root) NOPASSWD: /usr/bin/systemctl, /bin/systemctl, /usr/bin/systemd-run, /bin/systemd-run, /usr/bin/loginctl, /bin/loginctl, /usr/bin/wall, /bin/wall, /usr/sbin/shutdown, /sbin/shutdown, /usr/bin/journalctl, /bin/journalctl, /usr/bin/hostnamectl, /bin/hostnamectl, /usr/bin/ss, /bin/ss, /usr/bin/df, /bin/df, /usr/bin/free, /bin/free, /usr/bin/ip, /sbin/ip, /usr/bin/uptime, /bin/uptime
EOF
    chmod 0440 "$sudoers"
    if command_exists visudo && ! visudo -cf "$sudoers" >/dev/null 2>&1; then
        rm -f -- "$sudoers"
        warn "The managed sudo policy did not validate and was removed."
        return 1
    fi

    ok "Managed remote identity is prepared: $user (locked password, SSH-key bootstrap only)."
    info "The Debian AD controller can install its public key on the first remote operation using one interactive administrator login."
    return 0
}

configure_remote_management() {
    local ssh_service="" ssh_pkg="" setup_choice="" domain="" dns_csv="" ip=""

    case "$AD_CLIENT_SSH_SETUP" in
        yes|YES|1|true|TRUE) setup_choice="yes" ;;
        no|NO|0|false|FALSE) setup_choice="no" ;;
        *)
            if confirm "Enable remote administration readiness (OpenSSH server) on this domain client?" Y; then
                setup_choice="yes"
            else
                setup_choice="no"
            fi
            ;;
    esac

    [[ "$setup_choice" == yes ]] || {
        info "Remote administration setup was skipped. It can be enabled later from Troubleshoot / repair."
        return 0
    }

    if [[ -f "$CURRENT_STATE" ]]; then
        local AD_DNS_SERVERS="" DOMAIN=""
        load_state_file "$CURRENT_STATE" || true
        dns_csv="${AD_DNS_SERVERS:-}"
        domain="${DOMAIN:-}"
    fi
    [[ -n "$domain" ]] || domain="$(capture_probe 8 'realm query for remote setup' realm list --name-only 2>/dev/null | awk 'NR==1{print}' || true)"

    if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
        ssh_service="ssh.service"
    elif systemctl list-unit-files sshd.service >/dev/null 2>&1; then
        ssh_service="sshd.service"
    else
        case "$PKG_FAMILY" in
            apt|dnf) ssh_pkg="openssh-server" ;;
            *) ssh_pkg="" ;;
        esac

        if [[ -n "$ssh_pkg" ]]; then
            info "Installing remote-management dependency: $ssh_pkg"
            if [[ "$PKG_FAMILY" == apt ]]; then
                DEBIAN_FRONTEND=noninteractive apt-get install -y "$ssh_pkg" || {
                    warn "Could not install $ssh_pkg; remote commands will remain unavailable."
                    return 1
                }
            else
                if command_exists dnf; then
                    dnf install -y "$ssh_pkg" || return 1
                elif command_exists yum; then
                    yum install -y "$ssh_pkg" || return 1
                fi
            fi
        fi

        if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
            ssh_service="ssh.service"
        elif systemctl list-unit-files sshd.service >/dev/null 2>&1; then
            ssh_service="sshd.service"
        fi
    fi

    [[ -n "$ssh_service" ]] || {
        warn "OpenSSH server service could not be located after setup."
        return 1
    }

    mkdir -p /etc/ssh/sshd_config.d 2>/dev/null || true
    # Use an early drop-in so common cloud-image snippets cannot silently turn
    # PAM/keyboard-interactive authentication back off before our policy is read.
    cat >/etc/ssh/sshd_config.d/10-ad-client-assistant.conf <<'EOF'
# Managed by RHEL AD Client Assistant.
# Domain identities are authenticated through PAM/SSSD.
UsePAM yes
KbdInteractiveAuthentication yes
EOF
    rm -f /etc/ssh/sshd_config.d/90-ad-client-assistant.conf 2>/dev/null || true

    if command_exists sshd && ! sshd -t; then
        rm -f /etc/ssh/sshd_config.d/10-ad-client-assistant.conf
        warn "sshd rejected the managed drop-in; it was removed."
        return 1
    fi

    info "Enabling persistent OpenSSH service for remote AD administration."
    systemctl enable "$ssh_service" >/dev/null 2>&1 || true
    systemctl restart "$ssh_service" || systemctl start "$ssh_service" || {
        warn "Could not start $ssh_service."
        return 1
    }

    configure_managed_remote_identity || {
        warn "OpenSSH is active, but the managed remote identity could not be prepared."
        return 1
    }

    # Keep the firewall scope narrow: AD DNS/DC addresses only. This covers the
    # controller even when the DNS server and the selected DC are not identical.
    if command_exists ufw && ufw status 2>/dev/null | grep -Fq 'Status: active'; then
        while IFS= read -r ip; do
            [[ -n "$ip" ]] || continue
            ufw allow from "$ip" to any port 22 proto tcp comment 'AD remote operations' >/dev/null 2>&1 || true
        done < <(remote_management_controller_ips "$domain" "$dns_csv")
    elif command_exists firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        while IFS= read -r ip; do
            [[ -n "$ip" ]] || continue
            firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip port port=22 protocol=tcp accept" >/dev/null 2>&1 || true
        done < <(remote_management_controller_ips "$domain" "$dns_csv")
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi

    ok "Remote administration readiness enabled via $ssh_service (TCP/22)."
    info "The firewall is restricted to discovered AD controller/DNS addresses when a supported host firewall is active."
    info "New clients are prepared with the locked service identity ${AD_CLIENT_REMOTE_USER}; the controller installs its SSH key on first use."
    info "No reusable password is assigned to that service identity."
    return 0
}

audit_remote_management_readiness() {
    local ssh_service="" ssh_port="" effective="" domain="" fqdn="" resolved="" dns_csv="" ip=""
    local failures=0 warnings=0

    if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
        ssh_service="ssh.service"
    elif systemctl list-unit-files sshd.service >/dev/null 2>&1; then
        ssh_service="sshd.service"
    fi

    printf '\nREMOTE MANAGEMENT READINESS\n'
    if [[ -z "$ssh_service" ]]; then
        warn "OpenSSH server is not installed as a systemd service."
        return 1
    fi

    if run_probe 10 "SSH service state" systemctl is-active --quiet "$ssh_service"; then
        ok "OpenSSH service is active: $ssh_service."
    else
        warn "OpenSSH service exists but is not active: $ssh_service."
        failures=$((failures+1))
    fi

    if command_exists ss; then
        ssh_port="$(ss -lnt 2>/dev/null | awk '$4 ~ /(^|:|\])22$/ {print $4; exit}')"
        if [[ -n "$ssh_port" ]]; then
            ok "SSH is listening on TCP/22 ($ssh_port)."
        else
            warn "OpenSSH is not observed listening on TCP/22."
            failures=$((failures+1))
        fi
    fi

    if command_exists sshd; then
        effective="$(sshd -T 2>/dev/null || true)"
        if grep -Eq '^usepam yes$' <<<"$effective"; then
            ok "sshd PAM integration is enabled for SSSD-backed identities."
        else
            warn "sshd does not report UsePAM=yes."
            failures=$((failures+1))
        fi
        if grep -Eq '^kbdinteractiveauthentication yes$' <<<"$effective"; then
            ok "Interactive PAM authentication is enabled for domain users."
        else
            warn "Keyboard-interactive PAM authentication is disabled; some domain SSH logins may fail."
            warnings=$((warnings+1))
        fi
    fi

    if command_exists ssh-keyscan; then
        if run_probe 8 "Local SSH protocol handshake" ssh-keyscan -T 5 127.0.0.1 >/dev/null 2>&1; then
            ok "Local SSH protocol handshake succeeds."
        else
            warn "TCP/22 may be listening, but a local SSH protocol handshake did not complete."
            warnings=$((warnings+1))
        fi
    fi

    if [[ -f "$CURRENT_STATE" ]]; then
        local AD_DNS_SERVERS="" DOMAIN=""
        load_state_file "$CURRENT_STATE" || true
        dns_csv="${AD_DNS_SERVERS:-}"
        domain="${DOMAIN:-}"
    fi
    [[ -n "$domain" ]] || domain="$(capture_probe 10 'realm membership query' realm list --name-only 2>/dev/null | awk 'NR==1{print}' || true)"

    if [[ -n "$domain" ]]; then
        fqdn="$(client_ad_fqdn "$domain")"
        resolved="$(getent ahostsv4 "$fqdn" 2>/dev/null | awk 'NR==1{print $1}' || true)"
        if [[ -n "$resolved" ]]; then
            ok "Remote-management hostname resolves: $fqdn -> $resolved."
        else
            warn "No DNS A record resolves for $fqdn; name-based remote operations can fail."
            warnings=$((warnings+1))
        fi

        while IFS= read -r ip; do
            [[ -n "$ip" ]] || continue
            if ip route get "$ip" >/dev/null 2>&1; then
                ok "A route exists between this client and AD controller $ip."
            else
                warn "No route to AD controller $ip was found from this client."
                warnings=$((warnings+1))
            fi
        done < <(remote_management_controller_ips "$domain" "$dns_csv")
    fi

    if id "$AD_CLIENT_REMOTE_USER" >/dev/null 2>&1; then
        ok "Managed remote identity exists: $AD_CLIENT_REMOTE_USER."
        local managed_home=""
        managed_home="$(getent passwd "$AD_CLIENT_REMOTE_USER" | cut -d: -f6)"
        if [[ -s "${managed_home}/.ssh/authorized_keys" ]]; then
            ok "A controller SSH key is installed for $AD_CLIENT_REMOTE_USER."
        else
            info "No controller SSH key is installed yet; first-use bootstrap from Debian AD is still pending."
        fi
    else
        warn "Managed remote identity $AD_CLIENT_REMOTE_USER is missing."
        warnings=$((warnings+1))
    fi

    if command_exists ufw && ufw status 2>/dev/null | grep -Fq 'Status: active'; then
        info "UFW is active; remote setup keeps TCP/22 rules scoped to discovered AD controller addresses."
    elif command_exists firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        info "firewalld is active; remote setup keeps TCP/22 rules scoped to discovered AD controller addresses."
    else
        info "No supported active host firewall was detected by this check."
    fi

    if (( failures == 0 )); then
        (( warnings == 0 )) && ok "This client is locally ready for Debian AD remote operations." || \
            warn "Remote management is locally usable, with ${warnings} warning condition(s) to review."
        return 0
    fi

    err "Remote management has ${failures} blocking condition(s). Run repair from Troubleshoot / repair."
    return 1
}

repair_remote_management_readiness() {
    printf '\nREMOTE MANAGEMENT REPAIR\n'
    info "This repair only manages the Linux-side OpenSSH service, PAM integration and narrow host-firewall access from AD controllers."
    info "It does not grant broad sudo rights to domain users."
    configure_remote_management || return 1
    audit_remote_management_readiness
}

validate_sssd_identity_lookup() {
    local input="$1" domain="$2"
    local -a candidates=()
    local candidate="" rc=0

    [[ -n "$input" ]] || return 0
    candidates+=("$input")

    # This is an NSS/SSSD identity-resolution test, not Kerberos
    # authentication. A normal domain account is sufficient.
    if [[ "$input" != *@* && "$input" != *\* && -n "$domain" ]]; then
        candidates+=("${input}@${domain}")
    fi

    for candidate in "${candidates[@]}"; do
        info "Identity lookup probe: $candidate (12s maximum)."
        if run_probe 12 "getent identity lookup for $candidate" getent passwd "$candidate" >/dev/null 2>&1; then
            ok "SSSD/NSS identity lookup succeeded for $candidate."
            return 0
        else
            rc=$?
            (( rc == 124 )) && warn "getent did not return in time; this usually points to SSSD/DC reachability or name-service latency."
        fi

        if run_probe 12 "id identity lookup for $candidate" id "$candidate" >/dev/null 2>&1; then
            ok "SSSD/NSS identity lookup succeeded for $candidate."
            return 0
        else
            rc=$?
            (( rc == 124 )) && warn "id did not return in time; continuing without blocking post-join acceptance."
        fi
    done

    warn "SSSD/NSS identity lookup did not resolve '$input'."
    if [[ "$input" != *@* && "$input" != *\* ]]; then
        info "The test also tried '${input}@${domain}' because fully-qualified names may be required by SSSD."
    fi
    return 1
}


client_primary_ipv4() {
    local iface="${1:-$ACTIVE_IFACE}" ip=""
    [[ -n "$iface" ]] || return 1
    ip="$(ip -4 -o addr show dev "$iface" scope global 2>/dev/null |
        awk 'NR==1{split($4,a,"/"); print a[1]}')"
    [[ -n "$ip" ]] || return 1
    printf '%s' "$ip"
}

client_ad_fqdn() {
    local domain="$1" host=""
    host="$(hostnamectl --static 2>/dev/null || hostname)"
    host="${host,,}"
    if [[ "$host" == *.* ]]; then
        printf '%s' "$host"
    else
        printf '%s.%s' "$host" "${domain,,}"
    fi
}

update_ad_computer_metadata() {
    local domain="$1" os_name="" os_version="" help=""
    command_exists adcli || return 0
    help="$(adcli update --help 2>&1 || true)"
    grep -Fq -- '--os-name' <<<"$help" || return 0

    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        os_name="${PRETTY_NAME:-${NAME:-Linux}}"
        os_version="${VERSION_ID:-}"
    else
        os_name="Linux"
    fi

    local -a args=(update -D "$domain" "--os-name=$os_name")
    [[ -n "$os_version" ]] && args+=("--os-version=$os_version")
    if run_probe 60 "AD computer OS metadata update" adcli "${args[@]}" >/dev/null 2>&1; then
        ok "AD computer object OS metadata updated: $os_name${os_version:+ $os_version}."
    else
        warn "Could not publish Linux OS metadata to the AD computer object; membership remains valid."
    fi
}

register_client_ad_dns() {
    local domain="$1" dns_csv="$2" fqdn="" ip="" dns_server="" realm="" machine_principal=""
    fqdn="$(client_ad_fqdn "$domain")"
    ip="$(client_primary_ipv4 "$ACTIVE_IFACE" || true)"
    dns_server="$(dns_first "$dns_csv")"
    realm="${JOIN_REALM_NAME:-${domain^^}}"

    [[ -n "$ip" && -n "$fqdn" && -n "$dns_server" ]] || {
        warn "Secure AD DNS registration skipped: client FQDN/IP/DNS server could not be determined."
        return 0
    }

    if command_exists dig; then
        local existing=""
        existing="$(dig +time=2 +tries=1 @"$dns_server" "$fqdn" A +short 2>/dev/null | awk 'NR==1{print}')"
        if [[ "$existing" == "$ip" ]]; then
            ok "AD DNS A record already matches: $fqdn -> $ip."
            return 0
        fi
    fi

    if ! command_exists nsupdate; then
        warn "nsupdate is unavailable; membership is valid but the Linux host A record was not registered automatically."
        info "Install the distribution BIND DNS utilities or create ${fqdn} -> ${ip} in AD DNS."
        return 0
    fi

    machine_principal="$(klist -k /etc/krb5.keytab 2>/dev/null |
        awk -v r="$realm" 'toupper($0) ~ /\$@/ && toupper($0) ~ toupper("@" r) {print $NF; exit}')"
    if [[ -z "$machine_principal" ]]; then
        machine_principal="${JOIN_COMPUTER_NAME:-$(hostname -s | tr '[:lower:]' '[:upper:]')}\$@${realm}"
    fi

    local dns_ccache="${STATE_ROOT}/dns-register-${RUN_ID}"
    rm -f -- "$dns_ccache"
    if ! run_probe 60 "machine Kerberos ticket for secure DNS" \
        kinit -k -t /etc/krb5.keytab -c "FILE:${dns_ccache}" "$machine_principal"; then
        warn "Could not obtain a machine Kerberos ticket for secure DNS registration."
        rm -f -- "$dns_ccache"
        return 0
    fi

    local nslog="${LOG_ROOT}/${RUN_ID}-dns-register.log" rc=0
    {
        printf 'server %s\n' "$dns_server"
        printf 'zone %s\n' "$domain"
        printf 'update delete %s A\n' "$fqdn"
        printf 'update add %s 300 A %s\n' "$fqdn" "$ip"
        printf 'send\n'
    } | KRB5CCNAME="FILE:${dns_ccache}" \
        timeout --foreground --signal=TERM --kill-after=3s 60s nsupdate -g >"$nslog" 2>&1
    rc=$?

    command_exists kdestroy && kdestroy -c "FILE:${dns_ccache}" >/dev/null 2>&1 || true
    rm -f -- "$dns_ccache"

    if (( rc != 0 )); then
        warn "Secure AD DNS update did not complete (rc=$rc). Membership is kept; see $nslog."
        info "Linux clients do not always self-register DNS like Windows DHCP/DNS clients do."
        return 0
    fi

    if command_exists dig && dig +time=3 +tries=2 @"$dns_server" "$fqdn" A +short 2>/dev/null | grep -Fxq "$ip"; then
        ok "Secure AD DNS registration verified: $fqdn -> $ip."
    else
        warn "AD DNS update was submitted but the A record is not visible yet; verify DNS policy/replication."
    fi
}

adaptive_adcli_testjoin() {
    local domain="$1"
    local normal_timeout="${AD_CLIENT_NETWORK_TIMEOUT:-60}"
    local slow_timeout="${AD_CLIENT_SLOW_NETWORK_TIMEOUT:-180}"
    local rc=0 dc="" dns_csv=""

    (( slow_timeout < normal_timeout )) && slow_timeout="$normal_timeout"

    info "Validating the machine trust with adcli (initial window: ${normal_timeout}s)."
    info "Slow virtual/bridged networks are handled adaptively; the console will report progress before extending the wait."

    if command_exists timeout; then
        timeout --foreground --signal=TERM --kill-after=10s "${normal_timeout}s" \
            adcli testjoin -D "$domain" >/dev/null 2>&1
        rc=$?
    else
        adcli testjoin -D "$domain" >/dev/null 2>&1
        rc=$?
    fi

    if (( rc == 0 )); then
        ok "adcli secure machine join passed."
        return 0
    fi

    if (( rc != 124 && rc != 137 && rc != 143 )); then
        err "adcli testjoin failed (rc=$rc)."
        return 1
    fi

    warn "The secure-channel check is taking longer than the normal ${normal_timeout}s window."

    if [[ -f "$CURRENT_STATE" ]]; then
        local AD_DNS_SERVERS=""
        load_state_file "$CURRENT_STATE" || true
        dns_csv="${AD_DNS_SERVERS:-}"
    fi
    if [[ -z "$dns_csv" ]]; then
        dns_csv="$(current_dns_summary | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | paste -sd, - || true)"
    fi

    if domain_srv_query "$domain" "" >/dev/null 2>&1; then
        ok "AD discovery is still responding while the trust check is slow."
    else
        warn "AD discovery did not answer during the extended trust validation."
    fi

    if [[ -n "$dns_csv" ]] && validate_dns_list "$dns_csv"; then
        dc="$(ad_dc_targets_from_dns "$domain" "$dns_csv" | awk 'NR==1{print}')"
    fi
    if [[ -n "$dc" ]]; then
        if tcp_port_open "$dc" 88 && tcp_port_open "$dc" 389; then
            ok "The selected DC is still reachable on Kerberos and LDAP; this looks like latency rather than loss of connectivity."
        else
            warn "The selected DC did not answer every Kerberos/LDAP reachability probe during the slow validation window."
        fi
    fi

    if (( slow_timeout > normal_timeout )); then
        info "Extending the machine-trust validation to ${slow_timeout}s because AD connectivity is still present."
        if command_exists timeout; then
            timeout --foreground --signal=TERM --kill-after=10s "${slow_timeout}s" \
                adcli testjoin -D "$domain" >/dev/null 2>&1
            rc=$?
        else
            adcli testjoin -D "$domain" >/dev/null 2>&1
            rc=$?
        fi

        if (( rc == 0 )); then
            ok "adcli secure machine join passed after the extended wait."
            return 0
        fi
    fi

    if (( rc == 124 || rc == 137 || rc == 143 )); then
        warn "adcli testjoin is still inconclusive after the extended wait."
        warn "The realm membership, SSSD, keytab and AD discovery checks will decide whether this is a slow-link degraded state rather than a failed join."
        return 2
    fi

    err "adcli testjoin failed after the extended validation (rc=$rc)."
    return 1
}

postjoin_acceptance() {
    local domain="$1" test_user="${2:-}" failures=0 rc=0 output=""
    printf '
POST-JOIN ACCEPTANCE
'
    info "Acceptance probes are time-bounded; a slow/broken dependency will be reported instead of freezing the terminal."

    local realm_names=""
    realm_names="$(capture_probe 10 'realm membership query' realm list --name-only || true)"
    if grep -Fiqx "$domain" <<<"$realm_names"; then
        ok "Realm membership is present."
    else
        err "Realm membership is not reported for $domain."
        failures=1
    fi

    if command_exists sssctl; then
        output="$(capture_probe 10 'SSSD configuration validation' sssctl config-check || true)"
        if [[ -z "$output" ]] || grep -Fqi 'Issues identified by validators: 0' <<<"$output"; then
            ok "SSSD configuration check passed."
        else
            # Some sssctl releases are silent on success and verbose on failure.
            if run_probe 10 'SSSD configuration validation' sssctl config-check >/dev/null 2>&1; then
                ok "SSSD configuration check passed."
            else
                err "SSSD configuration check failed or timed out."
                [[ -n "$output" ]] && sed 's/^/  /' <<<"$output"
                failures=1
            fi
        fi
    fi

    if systemctl is-active --quiet sssd.service 2>/dev/null; then
        ok "SSSD service is active."
    else
        err "SSSD service is not active."
        run_probe 6 'SSSD journal read' journalctl -u sssd.service -n 40 --no-pager 2>/dev/null | sed 's/^/  /' || true
        failures=1
    fi

    local trust_state="passed"
    if adaptive_adcli_testjoin "$domain"; then
        trust_state="passed"
    else
        rc=$?
        if (( rc == 2 )); then
            trust_state="slow-inconclusive"
        else
            trust_state="failed"
            failures=1
        fi
    fi

    local keytab_listing=""
    keytab_listing="$(capture_probe 5 'Kerberos keytab listing' klist -k /etc/krb5.keytab || true)"
    if [[ -s /etc/krb5.keytab ]] && grep -Eqi '(^|[[:space:]])host/' <<<"$keytab_listing"; then
        ok "Machine keytab contains a host principal."
    else
        err "Machine keytab host principal is missing or unreadable."
        failures=1
    fi

    if domain_srv_query "$domain" "" >/dev/null 2>&1; then
        ok "System resolver still returns AD DC locator SRV records."
    else
        err "System resolver no longer returns AD DC locator SRV records."
        failures=1
    fi

    if [[ -n "$test_user" ]]; then
        validate_sssd_identity_lookup "$test_user" "$domain" || failures=1
    fi

    if (( failures != 0 )); then
        return 1
    fi

    if [[ "$trust_state" == "slow-inconclusive" ]]; then
        warn "All other acceptance checks passed, but adcli trust validation remained slow/inconclusive."
        warn "The host is joined and usable; keep it in a degraded/pending-validation state and re-check later from Status or Diagnostics."
        return 2
    fi

    return 0
}

join_domain_guided() {
    header
    printf '%bGUIDED DOMAIN JOIN%b\n\n' "$C_BOLD" "$C_RESET"

    require_supported_init || return 1
    if (( PRESET_SWITCH_MODE == 0 )); then
        recover_incomplete_previous_join || return 1
    fi

    local existing_realms=""
    existing_realms="$(capture_probe 10 "realm membership query" realm list --name-only || true)"
    if [[ -n "$existing_realms" ]]; then
        warn "This machine already reports realm membership:"
        printf '%s\n' "$existing_realms"
        printf '\n  [1] Show current domain status\n'
        printf '  [2] Switch to another domain\n'
        printf '  [0] Cancel\n'
        local joined_choice=""
        joined_choice="$(ask 'Select operation' '1')" || return 1
        case "$joined_choice" in
            1) status_domain; return 0 ;;
            2) switch_domain_guided; return $? ;;
            *) return 0 ;;
        esac
    fi

    if (( PRESET_SWITCH_MODE == 0 )); then
        identity_precheck || return 1
    fi

    local domain="" dns_csv="" join_user="Administrator" ou="" requested_hostname="" computer_name="" test_user=""
    local id_mapping="yes"

    if [[ -n "$PRESET_DOMAIN" ]]; then domain="$PRESET_DOMAIN"; else domain="$(ask 'AD DNS domain (for example corp.example.com)' '')"; fi
    domain="${domain,,}"
    valid_dns_domain "$domain" || {
        err "A valid DNS domain with RFC-style labels is required."
        return 1
    }

    if [[ -n "$PRESET_DNS" ]]; then dns_csv="$PRESET_DNS"; else dns_csv="$(ask 'AD DNS server IPv4 addresses (comma separated)' '')"; fi
    validate_dns_list "$dns_csv" || {
        err "At least one valid IPv4 AD DNS server is required."
        return 1
    }

    local first_dns=""
    first_dns="$(dns_first "$dns_csv")"
    select_join_interface "$first_dns" || return 1

    printf '\nSelected interface: %s\n' "$ACTIVE_IFACE"
    printf 'DNS backend      : %s\n' "$DNS_BACKEND"
    printf 'Current DNS      :\n'
    current_dns_summary | sed 's/^/  /'

    preflight_ad_dns_servers "$domain" "$dns_csv" || return 1

    if [[ -n "$PRESET_HOSTNAME" ]]; then requested_hostname="$PRESET_HOSTNAME"; else requested_hostname="$(ask 'System hostname' "$(hostnamectl --static 2>/dev/null || hostname)")"; fi
    local short_default="${requested_hostname%%.*}"
    if ((${#short_default} > 15)); then short_default=""; fi

    if [[ -n "$PRESET_COMPUTER" ]]; then computer_name="$PRESET_COMPUTER"; else computer_name="$(ask 'AD computer name (NetBIOS, max 15 chars)' "$short_default")"; fi
    valid_ad_computer_name "$computer_name" || {
        err "AD computer name must be 1-15 characters, start/end alphanumeric, with hyphens only inside."
        return 1
    }
    JOIN_COMPUTER_NAME="${computer_name^^}"

    if (( PRESET_SWITCH_MODE == 1 )); then ou="$PRESET_OU"; else ou="$(ask 'Computer OU DN (optional)' '')"; fi
    if [[ -n "$ou" && ! "$ou" =~ ^(OU|CN)= ]]; then
        warn "OU path does not look like a distinguished name beginning with OU= or CN=."
        confirm "Use this OU value anyway?" N || return 1
    fi

    printf '\nPOSIX identity model:\n'
    printf '  [1] Automatic SSSD SID -> UID/GID mapping (recommended default)\n'
    printf '  [2] Use RFC2307/POSIX attributes already stored in AD\n'
    local map_choice=""
    if [[ -n "$PRESET_ID_MAPPING" ]]; then
        id_mapping="$PRESET_ID_MAPPING"
    else
        map_choice="$(ask 'Select identity model' '1')"
        [[ "$map_choice" == "2" ]] && id_mapping="no"
    fi

    printf '\nPlan:\n'
    printf '  Domain       : %s\n' "$domain"
    printf '  DNS          : %s\n' "$dns_csv"
    printf '  Interface    : %s\n' "$ACTIVE_IFACE"
    printf '  DNS backend  : %s\n' "$DNS_BACKEND"
    printf '  Hostname     : %s\n' "$requested_hostname"
    printf '  AD computer  : %s\n' "$JOIN_COMPUTER_NAME"
    printf '  Join account : Administrator by default; changeable at the final credential step\n'
    printf '  OU           : %s\n' "${ou:-(default Computers container)}"
    printf '  ID mapping   : %s\n' "$id_mapping"

    if (( PRESET_SWITCH_MODE == 0 )); then
        confirm "Create a reversible snapshot and continue?" Y || return 0
    fi

    local snap=""
    snap="$(create_prejoin_snapshot "$domain" "$ACTIVE_IFACE")"
    info "Pre-join snapshot: $snap"

    JOIN_TRANSACTION_SNAPSHOT="$snap"
    JOIN_TRANSACTION_ACTIVE=1
    JOIN_TRANSACTION_COMMITTED=0
    JOIN_TRANSACTION_ROLLBACK=0
    join_transaction_mark "$snap" "SNAPSHOT_READY"

    if ! install_required_packages "$snap"; then
        err "Dependency preparation failed."
        rollback_failed_join_local_state "$snap" "interactive"
        return 1
    fi
    join_transaction_mark "$snap" "PACKAGES_READY"

    if ! preflight_ad_dns_servers "$domain" "$dns_csv"; then
        err "AD DNS preflight failed after dependency preparation."
        rollback_failed_join_local_state "$snap" "interactive"
        return 1
    fi

    local hostname_changed="0"
    if ! configure_hostname_if_requested "$requested_hostname"; then
        rollback_failed_join_local_state "$snap" "interactive"
        return 1
    fi
    hostname_changed="$HOSTNAME_CHANGED_RESULT"

    if ! apply_domain_dns "$domain" "$dns_csv" "$ACTIVE_IFACE"; then
        err "AD DNS configuration failed."
        rollback_failed_join_local_state "$snap" "interactive"
        return 1
    fi
    join_transaction_mark "$snap" "DNS_APPLIED"

    if ! validate_domain_dns "$domain" "$dns_csv"; then
        err "Domain discovery failed."
        rollback_failed_join_local_state "$snap" "interactive"
        return 1
    fi

    audit_time_sync || {
        warn "Time readiness is not healthy."
        confirm "Continue to Kerberos authentication anyway?" N || {
            rollback_failed_join_local_state "$snap" "interactive"
            return 1
        }
    }

    validate_ad_network_ports "$domain" "$dns_csv" || {
        err "Required AD network ports are not reachable."
        rollback_failed_join_local_state "$snap" "interactive"
        return 1
    }

    [[ -n "$JOIN_REALM_NAME" ]] || JOIN_REALM_NAME="${domain^^}"

    join_user="$(prompt_domain_admin_account 'join this computer to the domain' 'Administrator')"
    info "Selected AD join identity: $join_user"

    if ! kerberos_preflight_ticket "$join_user" "$JOIN_REALM_NAME"; then
        rollback_failed_join_local_state "$snap" "interactive"
        return 1
    fi
    join_transaction_mark "$snap" "KERBEROS_READY"

    local -a join_args=(
        join
        --verbose
        --server-software=active-directory
        --client-software=sssd
        "--automatic-id-mapping=${id_mapping}"
        "--computer-name=${JOIN_COMPUTER_NAME}"
    )
    [[ -n "$ou" ]] && join_args+=("--computer-ou=$ou")
    join_args+=("$domain")

    info "Joining with the isolated Kerberos ticket for '$join_user'; no password is stored."
    local join_log="${snap}/realm-join.log" join_rc=0

    KRB5CCNAME="FILE:${PRIVATE_KRB5CCACHE}" \
    KRB5_CCACHE="FILE:${PRIVATE_KRB5CCACHE}" \
        realm "${join_args[@]}" 2>&1 | tee "$join_log"
    join_rc=${PIPESTATUS[0]}

    if (( join_rc != 0 )); then
        err "realm join failed."
        analyze_realm_join_failure "$join_log" "$JOIN_COMPUTER_NAME"
        rollback_failed_join_local_state "$snap" "interactive"
        return 1
    fi

    cleanup_private_ccache

    # Best-effort publication after the machine account/keytab exist. Failure
    # here never rolls back a valid AD membership.
    update_ad_computer_metadata "$domain" || true
    register_client_ad_dns "$domain" "$dns_csv" || true

    JOIN_TRANSACTION_COMMITTED=1
    JOIN_TRANSACTION_ACTIVE=0
    join_transaction_mark "$snap" "MEMBERSHIP_COMMITTED"

    record_current_state \
        "$snap" "$domain" "$JOIN_REALM_NAME" "$ACTIVE_IFACE" \
        "$dns_csv" "$hostname_changed" "$JOIN_COMPUTER_NAME"

    if ! repair_sssd_config_compatibility "$snap"; then
        set_current_phase "JOINED_DEGRADED" || true
        err "Domain membership succeeded, but SSSD configuration requires manual review."
        warn "Membership is retained; do not force a local rollback."
        return 1
    fi

    ensure_sssd_dynamic_dns "$domain" "$snap" ||         warn "Persistent SSSD dynamic DNS refresh could not be enabled; immediate DNS registration will still be attempted."

    if ! run_probe 45 "SSSD enable/start" systemctl enable --now sssd.service; then
        set_current_phase "JOINED_DEGRADED" || true
        err "Domain join succeeded, but SSSD failed to start. AD DNS and snapshot are retained for repair/clean leave."
        journalctl -u sssd.service -n 60 --no-pager 2>/dev/null |
            tee "${snap}/sssd-failure.txt" || true
        return 1
    fi

    # Retry secure registration after SSSD is active so the client leaves the
    # join flow with both immediate and persistent DNS registration paths.
    register_client_ad_dns "$domain" "$dns_csv" || true

    configure_mkhomedir "$snap" || \
        warn "Home-directory automation could not be fully configured."
    apply_access_policy "$domain" || \
        warn "Login authorization policy was not changed."

    configure_remote_management || warn "Remote administration setup is incomplete; domain membership remains valid."
    audit_remote_management_readiness || true

    test_user="$(ask 'Optional AD user for SSSD identity lookup (not Kerberos authentication; blank to skip)' '')"
    postjoin_acceptance "$domain" "$test_user"
    local acceptance_rc=$?
    if (( acceptance_rc == 0 )); then
        set_current_phase "JOIN_PENDING_REBOOT" || true
        join_transaction_mark "$snap" "JOIN_PENDING_REBOOT"
        ok "Domain join passed immediate acceptance checks."
    elif (( acceptance_rc == 2 )); then
        set_current_phase "JOINED_DEGRADED" || true
        join_transaction_mark "$snap" "JOINED_DEGRADED"
        warn "Domain membership is active, but the secure-channel check is slower than the current validation window."
        info "This is treated as a slow-link/degraded acceptance state, not as a failed join."
        info "Use Status or Troubleshoot later to promote the client to fully validated state once the trust probe completes normally."
    else
        set_current_phase "JOINED_DEGRADED" || true
        join_transaction_mark "$snap" "JOINED_DEGRADED"
        err "The machine account was joined, but one or more acceptance checks failed."
        warn "Do not force local rollback. Repair the issue or use a clean domain leave."
        journalctl -u sssd.service -n 80 --no-pager 2>/dev/null \
            >"${snap}/sssd-postjoin-journal.txt" || true
        return 1
    fi

    info "Snapshot retained at: $snap"
    info "A reboot is required for final acceptance and lifecycle completion."
    request_reboot_now || true
}

# ---------------------------------------------------------------------------
# IT administrator diagnostics / domain transition
# ---------------------------------------------------------------------------

collect_target_plan() {
    PRESET_DOMAIN="$(ask 'Target AD DNS domain (for example corp.example.com)' '')"
    PRESET_DOMAIN="${PRESET_DOMAIN,,}"
    valid_dns_domain "$PRESET_DOMAIN" || { err "A valid target DNS domain is required."; return 1; }

    PRESET_DNS="$(ask 'Target AD DNS server IPv4 addresses (comma separated)' '')"
    validate_dns_list "$PRESET_DNS" || { err "At least one valid target AD DNS IPv4 address is required."; return 1; }

    PRESET_HOSTNAME="$(ask 'System hostname' "$(hostnamectl --static 2>/dev/null || hostname)")"
    valid_system_hostname "$PRESET_HOSTNAME" || { err "Invalid system hostname."; return 1; }

    local short_default="${PRESET_HOSTNAME%%.*}"
    ((${#short_default} <= 15)) || short_default=""
    PRESET_COMPUTER="$(ask 'AD computer name (NetBIOS, max 15 chars)' "$short_default")"
    valid_ad_computer_name "$PRESET_COMPUTER" || { err "Invalid AD computer name."; return 1; }
    PRESET_COMPUTER="${PRESET_COMPUTER^^}"

    PRESET_OU="$(ask 'Computer OU DN (optional)' '')"
    if [[ -n "$PRESET_OU" && ! "$PRESET_OU" =~ ^(OU|CN)= ]]; then
        warn "OU path does not look like a distinguished name."
        confirm "Use this OU value anyway?" N || return 1
    fi

    printf '\nPOSIX identity model:\n  [1] Automatic SSSD SID -> UID/GID mapping\n  [2] RFC2307/POSIX attributes from AD\n'
    local map_choice="$(ask 'Select identity model' '1')"
    PRESET_ID_MAPPING="yes"
    [[ "$map_choice" == "2" ]] && PRESET_ID_MAPPING="no"

    local first_dns="$(dns_first "$PRESET_DNS")"
    select_join_interface "$first_dns" || return 1
    preflight_ad_dns_servers "$PRESET_DOMAIN" "$PRESET_DNS" || return 1
    validate_ad_network_ports "$PRESET_DOMAIN" "$PRESET_DNS" || return 1
    return 0
}

switch_domain_guided() {
    header
    printf '%bDOMAIN SWITCH%b\n\n' "$C_BOLD" "$C_RESET"

    local source="$(capture_probe 10 'realm membership query' realm list --name-only | awk 'NR==1{print}')"
    if [[ -z "$source" ]]; then
        info "No current domain membership was detected; starting a normal join."
        join_domain_guided
        return $?
    fi

    collect_target_plan || return 1
    if [[ "${source,,}" == "${PRESET_DOMAIN,,}" ]]; then
        err "Source and target domains are the same."
        return 1
    fi

    printf '\nSource domain : %s\nTarget domain : %s\nTarget DNS    : %s\nComputer      : %s\n' \
        "$source" "$PRESET_DOMAIN" "$PRESET_DNS" "$PRESET_COMPUTER"
    confirm_literal "The source membership will be removed only after the target passed DNS/network preflight. The target join then starts immediately." "SWITCH" || return 0

    local leave_user="$(prompt_domain_admin_account 'remove this computer from the source domain' 'Administrator')"
    local switch_leave_log="${LOG_ROOT}/${RUN_ID}-switch-leave.log"
    local switch_leave_rc=0

    run_membership_operation 60 "Source-domain leave" "$switch_leave_log"         realm leave -v -U "$leave_user" "$source"
    switch_leave_rc=$?

    if (( switch_leave_rc != 0 )); then
        local evidence_rc=0
        membership_evidence_after_leave "$source"
        evidence_rc=$?

        if (( evidence_rc == 0 )); then
            warn "The leave command did not return cleanly, but post-operation evidence indicates that source membership was removed."
        else
            err "Source-domain leave did not complete conclusively. Target join was not attempted."
            leave_connectivity_diagnostics "$source"
            warn "Membership state was left untouched locally. Review: $switch_leave_log"
            return 1
        fi
    fi

    # Restore identity/DNS baseline when available, but preserve current hostname
    # and packages so the target join can proceed immediately.
    if [[ -f "$CURRENT_STATE" ]]; then
        local SNAPSHOT_PATH=""
        load_state_file "$CURRENT_STATE" || true
        if [[ -n "${SNAPSHOT_PATH:-}" && -d "$SNAPSHOT_PATH" ]]; then
            restore_network_from_snapshot "$SNAPSHOT_PATH" || warn "Source DNS restoration reported a problem."
            restore_identity_files "$SNAPSHOT_PATH"
            restore_sssd_runtime_from_snapshot "$SNAPSHOT_PATH"
        fi
        rm -f "$CURRENT_STATE"
    fi

    PRESET_SWITCH_MODE=1
    JOIN_TRANSACTION_ACTIVE=0
    JOIN_TRANSACTION_COMMITTED=0
    JOIN_TRANSACTION_ROLLBACK=0
    JOIN_TRANSACTION_SNAPSHOT=""
    join_domain_guided
    local rc=$?
    PRESET_SWITCH_MODE=0
    PRESET_DOMAIN="" PRESET_DNS="" PRESET_HOSTNAME="" PRESET_COMPUTER="" PRESET_OU="" PRESET_ID_MAPPING=""
    return "$rc"
}

ad_connectivity_test() {
    header
    printf '%bAD CONNECTIVITY TEST%b\n\n' "$C_BOLD" "$C_RESET"

    local domain="" dns_csv=""
    if [[ -f "$CURRENT_STATE" ]]; then
        local DOMAIN="" AD_DNS_SERVERS=""
        load_state_file "$CURRENT_STATE" || true
        domain="${DOMAIN:-}"
        dns_csv="${AD_DNS_SERVERS:-}"
    fi
    domain="$(ask 'AD DNS domain (for example corp.example.com)' "$domain")"
    dns_csv="$(ask 'AD DNS server IPv4 addresses (comma separated)' "$dns_csv")"
    valid_dns_domain "$domain" || { err "Invalid AD DNS domain."; return 1; }
    validate_dns_list "$dns_csv" || { err "Invalid AD DNS list."; return 1; }

    select_join_interface "$(dns_first "$dns_csv")" || return 1
    printf '\nNETWORK / DNS\n'
    local dns_rc=0 ports_rc=0 time_rc=0
    preflight_ad_dns_servers "$domain" "$dns_csv" || dns_rc=$?
    validate_ad_network_ports "$domain" "$dns_csv" || ports_rc=$?
    audit_time_sync || time_rc=$?

    printf '\nSYSTEM RESOLVER\n'
    if domain_srv_query "$domain" "" >/dev/null 2>&1; then
        ok "System resolver can locate AD domain controllers."
    else
        warn "System resolver cannot currently locate AD; direct AD DNS results above may still pass."
        resolver_diagnostics "$domain"
    fi

    printf '\nMEMBERSHIP\n'
    local memberships="$(capture_probe 10 "realm membership query" realm list --name-only || true)"
    if [[ -n "$memberships" ]]; then
        ok "Realm membership: $memberships"
        if command_exists adcli && run_probe 20 "adcli machine trust validation" adcli testjoin -D "$domain" >/dev/null 2>&1; then
            ok "Secure machine channel validates with adcli."
        else
            warn "Secure machine channel did not validate for $domain."
        fi
    else
        info "Machine is not currently joined to a realm."
    fi

    printf '\nRESULT\n'
    if (( dns_rc == 0 && ports_rc == 0 && time_rc == 0 )); then
        ok "READY: DNS, required TCP ports and time synchronization are healthy."
        return 0
    fi
    err "BLOCKED/DEGRADED: one or more readiness checks failed. Review the diagnostics above."
    return 1
}

troubleshoot_ad() {
    header
    printf '%bDEEP AD CLIENT DIAGNOSTICS%b

' "$C_BOLD" "$C_RESET"
    info "Read-only diagnostics are time-bounded. No DNS, SSSD or domain membership change is made unless you explicitly approve a repair."

    detect_active_interface
    detect_dns_backend
    detect_system_resolver

    local domain="" dns_csv="" phase="" computer_name=""
    if [[ -f "$CURRENT_STATE" ]]; then
        local DOMAIN="" AD_DNS_SERVERS="" PHASE="" COMPUTER_NAME=""
        load_state_file "$CURRENT_STATE" || true
        domain="${DOMAIN:-}"
        dns_csv="${AD_DNS_SERVERS:-}"
        phase="${PHASE:-}"
        computer_name="${COMPUTER_NAME:-}"
    fi

    local realm_guess=""
    realm_guess="$(capture_probe 8 'realm membership query' realm list --name-only || true)"
    [[ -n "$domain" ]] || domain="$(awk 'NR==1{print}' <<<"$realm_guess")"
    domain="$(ask 'AD DNS domain (for example corp.example.com)' "$domain")"
    valid_dns_domain "$domain" || { err "A valid AD DNS domain is required for deep diagnostics."; return 1; }

    if [[ -z "$dns_csv" ]]; then
        local discovered_dns=""
        discovered_dns="$(current_dns_summary | awk 'NF{print $NF}' | grep -E '^[0-9]+(\.[0-9]+){3}$' | paste -sd, - || true)"
        dns_csv="$discovered_dns"
    fi
    dns_csv="$(ask 'AD DNS server IPv4 addresses (comma separated)' "$dns_csv")"

    local critical=0 degraded=0
    printf '
HOST / LIFECYCLE
'
    printf '  Hostname       : %s
' "$(hostname -f 2>/dev/null || hostname)"
    printf '  Interface      : %s
' "${ACTIVE_IFACE:-unknown}"
    printf '  DNS owner      : %s
' "${DNS_BACKEND:-unknown}"
    printf '  Resolver       : %s
' "${SYSTEM_RESOLVER_BACKEND:-unknown}"
    printf '  resolv.conf    : %s
' "${RESOLV_CONF_TARGET:-unknown}"
    printf '  Lifecycle      : %s
' "${phase:-none}"
    printf '  AD computer    : %s
' "${computer_name:-unknown}"
    printf '  Realm reported : %s
' "${realm_guess:-none}"

    printf '
DNS DISCOVERY
'
    if validate_dns_list "$dns_csv"; then
        local dns_rc=0
        preflight_ad_dns_servers "$domain" "$dns_csv" || dns_rc=$?
        if (( dns_rc != 0 )); then
            critical=$((critical+1))
        fi
    else
        warn "No valid AD DNS list is available; direct DNS-server validation is skipped."
        degraded=$((degraded+1))
    fi

    if domain_srv_query "$domain" "" >/dev/null 2>&1; then
        ok "System resolver resolves _ldap._tcp.dc._msdcs.${domain}."
    else
        err "System resolver cannot discover AD domain controllers."
        resolver_diagnostics "$domain"
        critical=$((critical+1))
    fi

    local kerberos_srv=""
    kerberos_srv="$(dig +time=3 +tries=1 "_kerberos._tcp.${domain}" SRV +short 2>/dev/null || true)"
    if [[ -n "$kerberos_srv" ]]; then
        ok "System resolver returns Kerberos SRV records."
    else
        warn "No _kerberos._tcp.${domain} SRV answer through the system resolver."
        degraded=$((degraded+1))
    fi

    printf '\nCLIENT DNS REGISTRATION\n'
    local client_fqdn="" client_ip="" registration_dns="" registered_ip=""
    client_fqdn="$(client_ad_fqdn "$domain")"
    client_ip="$(client_primary_ipv4 "$ACTIVE_IFACE" || true)"
    registration_dns="$(dns_first "$dns_csv")"

    printf '  Client FQDN    : %s\n' "${client_fqdn:-unknown}"
    printf '  Client IPv4    : %s\n' "${client_ip:-unknown}"
    printf '  AD DNS target  : %s\n' "${registration_dns:-unknown}"

    if [[ -n "$registration_dns" && -n "$client_fqdn" && -n "$client_ip" ]] && command_exists dig; then
        registered_ip="$(dig +time=3 +tries=1 @"$registration_dns" "$client_fqdn" A +short 2>/dev/null | awk 'NR==1{print}')"
        if [[ "$registered_ip" == "$client_ip" ]]; then
            ok "AD DNS A record matches this client: $client_fqdn -> $client_ip."
        elif [[ -n "$registered_ip" ]]; then
            warn "AD DNS A record points elsewhere: $client_fqdn -> $registered_ip (local IP: $client_ip)."
            degraded=$((degraded+1))
        else
            warn "No AD DNS A record exists for $client_fqdn."
            info "The domain join can still be valid, but name-based remote administration and automatic endpoint discovery will be degraded."
            degraded=$((degraded+1))
        fi
    else
        warn "Client DNS registration could not be fully validated."
        degraded=$((degraded+1))
    fi

    printf '
ROUTING / PORTS
'
    if validate_dns_list "$dns_csv"; then
        local first_dns="" route_iface=""
        first_dns="$(dns_first "$dns_csv")"
        route_iface="$(route_interface_for_target "$first_dns" || true)"
        if [[ -n "$route_iface" ]]; then
            ok "Kernel route to AD DNS $first_dns uses interface $route_iface."
            [[ -z "$ACTIVE_IFACE" || "$route_iface" == "$ACTIVE_IFACE" ]] || {
                warn "Selected/active interface '$ACTIVE_IFACE' differs from route-to-AD interface '$route_iface'."
                degraded=$((degraded+1))
            }
        else
            err "No IPv4 route to AD DNS $first_dns."
            critical=$((critical+1))
        fi
        validate_ad_network_ports "$domain" "$dns_csv" || critical=$((critical+1))
    fi

    printf '
TIME / KERBEROS PREREQUISITES
'
    audit_time_sync || degraded=$((degraded+1))
    if [[ -s /etc/krb5.keytab ]]; then
        local kt=""
        kt="$(capture_probe 5 'Kerberos keytab listing' klist -k /etc/krb5.keytab || true)"
        if grep -Eqi '(^|[[:space:]])host/' <<<"$kt"; then
            ok "Machine keytab has a host principal."
        else
            warn "Keytab exists but no host principal was detected."
            degraded=$((degraded+1))
        fi
    else
        warn "No /etc/krb5.keytab is present."
        degraded=$((degraded+1))
    fi

    printf '
SSSD / NSS
'
    if [[ -s /etc/sssd/sssd.conf ]]; then
        if command_exists sssctl && run_probe 10 'SSSD configuration validation' sssctl config-check >/dev/null 2>&1; then
            ok "SSSD configuration validates."
        else
            err "SSSD configuration validation failed or timed out."
            command_exists sssctl && capture_probe 10 'SSSD configuration validation' sssctl config-check | sed 's/^/  /' || true
            critical=$((critical+1))
        fi
    else
        err "SSSD configuration file is missing or empty."
        critical=$((critical+1))
    fi

    if systemctl is-active --quiet sssd.service 2>/dev/null; then
        ok "SSSD service is active."
    else
        err "SSSD service is not active."
        critical=$((critical+1))
    fi

    printf '
MEMBERSHIP / MACHINE TRUST
'
    if grep -Fiqx "$domain" <<<"$realm_guess"; then
        ok "realmd reports membership in $domain."
        if command_exists adcli; then
            if run_probe 20 'adcli machine trust validation' adcli testjoin -D "$domain" >/dev/null 2>&1; then
                ok "Machine trust validates against AD."
            else
                local trc=$?
                if (( trc == 124 )); then
                    err "Machine-trust validation timed out. Check DC routing, DNS and firewall before touching membership."
                else
                    err "Machine-trust validation failed. The host can report membership while its secure channel is broken."
                fi
                critical=$((critical+1))
            fi
        fi
    else
        warn "realmd does not currently report membership in $domain."
        degraded=$((degraded+1))
    fi

    printf '
RECENT SSSD SIGNALS
'
    local journal=""
    journal="$(capture_probe 8 'SSSD journal read' journalctl -u sssd.service -n 120 --no-pager || true)"
    if [[ -n "$journal" ]]; then
        if grep -Eqi 'offline|timed out|timeout|cannot contact|failed to resolve|network is unreachable' <<<"$journal"; then
            warn "Recent SSSD logs contain offline/network/timeout indicators."
            degraded=$((degraded+1))
        fi
        if grep -Eqi 'krb5|preauth|clock skew|credentials|keytab' <<<"$journal"; then
            warn "Recent SSSD logs contain Kerberos/credential/keytab indicators."
            degraded=$((degraded+1))
        fi
        grep -Ei 'offline|timed out|timeout|cannot contact|failed to resolve|network is unreachable|krb5|preauth|clock skew|keytab|permission denied' <<<"$journal" | tail -n 12 | sed 's/^/  /' || true
    else
        info "No recent SSSD journal messages were returned."
    fi

    printf '
DIAGNOSTIC VERDICT
'
    if (( critical == 0 && degraded == 0 )); then
        ok "HEALTHY: no blocking AD client issue was detected."
    elif (( critical == 0 )); then
        warn "DEGRADED: no hard blocker detected, but ${degraded} warning condition(s) should be reviewed."
    else
        err "ACTION REQUIRED: ${critical} blocking condition(s) and ${degraded} warning condition(s) detected."
        info "Recommended order: DNS discovery -> route/ports -> time -> SSSD config/service -> machine trust -> user identity lookup."
    fi

    printf '
SAFE FOLLOW-UP
'
    printf '  [1] Test one domain user through SSSD/NSS (adaptive timeout)
'
    printf '  [2] Show recent SSSD journal (last 80 lines)
'
    printf '  [3] Attempt resolver convergence repair
'
    printf '  [4] Repair/publish secure AD DNS registration
'
    printf '  [5] Configure/repair remote administration readiness (OpenSSH)
'
    printf '  [0] Return without changes
'
    local action=""
    action="$(ask 'Select operation' '0')"
    case "$action" in
        1)
            local test_user=""
            test_user="$(ask 'Optional AD user for SSSD identity lookup (not Kerberos authentication; blank to skip)' '')"
            [[ -n "$test_user" ]] && validate_sssd_identity_lookup "$test_user" "$domain" || true
            ;;
        2)
            capture_probe 8 'SSSD journal read' journalctl -u sssd.service -n 80 --no-pager | sed 's/^/  /' || true
            ;;
        3)
            if validate_dns_list "$dns_csv"; then
                if confirm "Attempt safe resolver convergence repair using the supplied AD DNS?" N; then
                    repair_resolver_convergence "$domain" "$dns_csv" "$ACTIVE_IFACE" || warn "Resolver repair did not fully converge."
                fi
            else
                warn "A valid AD DNS list is required before resolver repair can run."
            fi
            ;;
        4)
            if validate_dns_list "$dns_csv"; then
                if confirm "Enable persistent SSSD dynamic DNS refresh and publish this host A record now?" Y; then
                    ensure_sssd_dynamic_dns "$domain" "" ||                         warn "Persistent SSSD dynamic DNS settings could not be applied."
                    if systemctl is-active --quiet sssd.service 2>/dev/null; then
                        run_probe 20 "SSSD restart after dynamic DNS repair" systemctl restart sssd.service ||                             warn "SSSD could not be restarted after dynamic DNS repair."
                    fi
                    register_client_ad_dns "$domain" "$dns_csv" || true
                fi
            else
                warn "A valid AD DNS list is required before secure DNS registration can run."
            fi
            ;;
        5)
            repair_remote_management_readiness || true
            ;;
        *) : ;;
    esac

    (( critical == 0 ))
}

export_diagnostic_bundle() {
    header
    local out="${LOG_ROOT}/diagnostic-${RUN_ID}.tar.gz"
    local tmp="${STATE_ROOT}/diagnostic-${RUN_ID}"
    rm -rf "$tmp" && mkdir -p "$tmp"
    {
        printf 'Generated: %s\n' "$(date -Is)"
        printf 'Host: %s\n' "$(hostname -f 2>/dev/null || hostname)"
        printf 'OS: %s\n' "$DISTRO_ID"
        printf 'Interface: %s\nDNS backend: %s\nResolver: %s\n' "$ACTIVE_IFACE" "$DNS_BACKEND" "$SYSTEM_RESOLVER_BACKEND"
        printf '\nRealm:\n'; capture_probe 10 'realm diagnostic query' realm list 2>&1 || true
        printf '\nRoutes:\n'; ip -4 route 2>&1 || true
        printf '\nAddresses:\n'; ip -4 addr 2>&1 || true
        printf '\nResolver:\n'; cat /etc/resolv.conf 2>&1 || true
    } >"$tmp/summary.txt"
    cp -a "$CURRENT_STATE" "$tmp/current.env" 2>/dev/null || true
    capture_probe 10 "SSSD journal export" journalctl -u sssd.service -n 200 --no-pager >"$tmp/sssd-journal.txt" 2>&1 || true
    command_exists sssctl && capture_probe 10 "SSSD config export" sssctl config-check >"$tmp/sssd-config-check.txt" 2>&1 || true
    {
        printf '=== resolvectl status ===\n'
        command_exists resolvectl && capture_probe 8 "resolvectl diagnostic" resolvectl status || true
        printf '\n=== NetworkManager DNS ===\n'
        command_exists nmcli && capture_probe 8 "NetworkManager diagnostic" nmcli -f GENERAL.DEVICE,GENERAL.CONNECTION,IP4.ADDRESS,IP4.GATEWAY,IP4.DNS device show || true
        printf '\n=== time ===\n'
        command_exists timedatectl && timedatectl status || true
        command_exists chronyc && capture_probe 8 "chrony diagnostic" chronyc tracking || true
        printf '\n=== keytab principals ===\n'
        command_exists klist && capture_probe 5 "keytab diagnostic" klist -k /etc/krb5.keytab || true
        printf '\n=== package versions ===\n'
        if [[ "$PKG_FAMILY" == apt ]]; then dpkg-query -W realmd sssd-ad sssd-tools adcli krb5-user 2>/dev/null || true; fi
        if [[ "$PKG_FAMILY" == dnf ]]; then rpm -q realmd sssd adcli krb5-workstation 2>/dev/null || true; fi
    } >"$tmp/platform-diagnostics.txt" 2>&1
    tar -C "$tmp" -czf "$out" . || { err "Could not create diagnostic bundle."; rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
    chmod 0600 "$out" 2>/dev/null || true
    ok "Diagnostic bundle created: $out"
    warn "Review the bundle before sharing; network/domain metadata is included. Passwords are never collected by this assistant."
}

# ---------------------------------------------------------------------------
# Audit / status / leave / restore
# ---------------------------------------------------------------------------

audit_readiness() {
    header
    printf '%bCLIENT READINESS%b\n\n' "$C_BOLD" "$C_RESET"

    printf 'Distribution    : %s\n' "$DISTRO_ID"
    printf 'Package family  : %s\n' "$PKG_FAMILY"
    printf 'Init/systemd    : %s\n' "$(command_exists systemctl && [[ -d /run/systemd/system ]] && printf supported || printf unsupported)"
    printf 'Suggested iface : %s\n' "${ACTIVE_IFACE:-unknown}"
    detect_system_resolver
    printf 'DNS config owner: %s\n' "$DNS_BACKEND"
    printf 'System resolver : %s\n' "$SYSTEM_RESOLVER_BACKEND"
    printf 'resolv.conf      : %s\n' "$RESOLV_CONF_TARGET"
    printf 'Remote session  : %s\n\n' "$REMOTE_SESSION"

    printf 'Active IPv4 interfaces:\n'
    show_network_candidates | while IFS=$'\t' read -r iface addr metric manager; do
        printf '  %-16s %-20s metric=%-6s %s\n' "$iface" "$addr" "$metric" "$manager"
    done

    printf '\nCurrent DNS:\n'
    current_dns_summary | sed 's/^/  /'
    printf '\n'

    validate_required_commands || true
    if incomplete_sssd_residue_present; then
        warn "Incomplete previous join residue detected: sss_cache is installed but SSSD is not initialized."
        info "Run the guided join again; it will offer snapshot-based recovery before continuing."
    fi
    audit_time_sync || true

    local realms=""
    realms="$(capture_probe 10 "realm membership query" realm list --name-only || true)"
    if [[ -n "$realms" ]]; then ok "Realm membership detected: $realms"; else info "No realm membership detected."; fi

    [[ -s /etc/krb5.keytab ]] && info "Existing Kerberos keytab detected: /etc/krb5.keytab"
    [[ -s /etc/sssd/sssd.conf ]] && info "Existing SSSD configuration detected."

    if [[ -f "$CURRENT_STATE" ]]; then ok "Assistant-managed state exists: $CURRENT_STATE"; else info "No assistant-managed join state exists."; fi
}

status_domain() {
    header
    printf '%bDOMAIN CLIENT STATUS%b\n\n' "$C_BOLD" "$C_RESET"

    realm list 2>/dev/null || info "No realm membership reported."

    if [[ -f "$CURRENT_STATE" ]]; then
        local SNAPSHOT_PATH="" DOMAIN="" REALM="" AD_DNS_SERVERS="" HOSTNAME_CHANGED="" PHASE="" JOIN_BOOT_ID="" COMPUTER_NAME=""
        load_state_file "$CURRENT_STATE" || true
        printf '\nAssistant state:\n'
        printf '  Phase    : %s\n' "${PHASE:-legacy/unknown}"
        printf '  Domain   : %s\n' "${DOMAIN:-unknown}"
        printf '  Realm    : %s\n' "${REALM:-unknown}"
        printf '  Computer : %s\n' "${COMPUTER_NAME:-unknown}"
        printf '  DNS      : %s\n' "${AD_DNS_SERVERS:-unknown}"
        printf '  Snapshot : %s\n' "${SNAPSHOT_PATH:-unknown}"

        if [[ "${PHASE:-}" == "JOIN_PENDING_REBOOT" && -n "${JOIN_BOOT_ID:-}" && "$(current_boot_id)" != "$JOIN_BOOT_ID" ]]; then
            info "Post-reboot lifecycle transition detected; running final acceptance."
            if postjoin_acceptance "$DOMAIN" ""; then
                set_current_phase "JOINED" || true
                PHASE="JOINED"
                ok "Post-reboot domain acceptance passed."
            else
                set_current_phase "JOINED_DEGRADED" || true
                PHASE="JOINED_DEGRADED"
                warn "Post-reboot acceptance is degraded."
            fi
        elif [[ "${PHASE:-}" == "JOIN_PENDING_REBOOT" ]]; then
            warn "Final lifecycle acceptance is pending a reboot."
        elif [[ "${PHASE:-}" == "JOINED_DEGRADED" ]]; then
            info "Re-checking previously degraded join state."
            if postjoin_acceptance "$DOMAIN" ""; then
                set_current_phase "JOINED" || true
                PHASE="JOINED"
                ok "The repaired client now passes domain acceptance."
            fi
        fi

        if [[ -n "${DOMAIN:-}" ]] && command_exists adcli; then
            run_probe 20 "adcli machine trust validation" adcli testjoin -D "$DOMAIN" >/dev/null 2>&1 \
                && ok "Secure machine join validated by adcli." \
                || warn "adcli testjoin failed or timed out."
        fi
    fi

    printf '\nResolver:\n'
    current_dns_summary | sed 's/^/  /'
    audit_time_sync || true
}

restore_identity_files() {
    local snap="$1"
    restore_snapshot_file "$snap" /etc/krb5.conf
    restore_snapshot_file "$snap" /etc/krb5.keytab
    restore_snapshot_file "$snap" /etc/realmd.conf
    restore_snapshot_file "$snap" /etc/sssd/sssd.conf
    restore_snapshot_file "$snap" /etc/sssd/conf.d
    restore_snapshot_file "$snap" /etc/nsswitch.conf
    restore_snapshot_file "$snap" /etc/pam.d/common-session
    restore_snapshot_file "$snap" /etc/pam.d/common-session-noninteractive

    if command_exists authselect && [[ -f "${snap}/snapshot.env" ]]; then
        local AUTHSELECT_BACKUP="" AUTHSELECT_HAD_MKHOMEDIR=""
        load_state_file "${snap}/snapshot.env" || true
        if [[ -n "${AUTHSELECT_BACKUP:-}" ]]; then
            authselect backup-restore "$AUTHSELECT_BACKUP" >/dev/null 2>&1 || \
                warn "authselect backup restore failed; file-level snapshot was still restored."
        elif [[ "${AUTHSELECT_HAD_MKHOMEDIR:-0}" == "0" ]]; then
            authselect disable-feature with-mkhomedir >/dev/null 2>&1 || true
        fi
    fi
}

restore_sssd_runtime_from_snapshot() {
    local snap="$1"
    local PREJOIN_SSSD_ACTIVE="0" PREJOIN_SSSD_ENABLED="0"

    [[ -f "$snap/snapshot.env" ]] || return 0
    # shellcheck disable=SC1090
    . "$snap/snapshot.env"

    local sssd_units=""
    sssd_units="$(systemctl list-unit-files sssd.service --no-legend 2>/dev/null || true)"
    if ! grep -Fq 'sssd.service' <<<"$sssd_units"; then
        return 0
    fi

    if [[ "${PREJOIN_SSSD_ENABLED:-0}" == "1" ]]; then
        systemctl enable sssd.service >/dev/null 2>&1 || true
    else
        systemctl disable sssd.service >/dev/null 2>&1 || true
    fi

    if [[ "${PREJOIN_SSSD_ACTIVE:-0}" == "1" ]]; then
        systemctl restart sssd.service >/dev/null 2>&1 || \
            warn "Pre-join SSSD service state could not be restored completely."
    else
        systemctl stop sssd.service >/dev/null 2>&1 || true
    fi
}

rollback_failed_join_local_state() {
    local snap="$1" mode="${2:-interactive}"
    [[ -n "$snap" && -d "$snap" ]] || return 1

    JOIN_TRANSACTION_ROLLBACK=1
    JOIN_TRANSACTION_ACTIVE=0
    cleanup_private_ccache

    warn "Restoring local state because AD membership was not committed."
    restore_network_from_snapshot "$snap" || warn "DNS/network rollback reported a problem."
    restore_identity_files "$snap"
    restore_hostname_from_snapshot "$snap" || warn "Hostname rollback reported a problem."
    restore_sssd_runtime_from_snapshot "$snap"
    rm -f "$CURRENT_STATE" 2>/dev/null || true
    join_transaction_mark "$snap" "LOCAL_STATE_ROLLED_BACK"

    if [[ "$mode" == "interactive" &&
          -s "$snap/packages-installed-by-assistant.txt" ]]; then
        printf '\n'
        info "The failed attempt installed AD client packages that were absent before the snapshot."
        warn "If SSSD was never configured, keeping sssd-tools can produce sss_cache/config.ldb warnings on local user operations."
        if confirm "Remove only packages added by this failed attempt and fully return to the pre-join package baseline?" Y; then
            remove_assistant_packages_now "$snap" || \
                warn "Package rollback was incomplete; review the package manager output."
        else
            warn "Packages were retained for retry. SSSD-related tools may warn until a later join configures SSSD."
        fi
    fi

    JOIN_TRANSACTION_ROLLBACK=0
}


restore_hostname_from_snapshot() {
    local snap="$1"
    local OLD_HOSTNAME=""
    load_state_file "${snap}/snapshot.env" || return 1
    [[ -n "${OLD_HOSTNAME:-}" ]] || return 0

    local current=""
    current="$(hostnamectl --static 2>/dev/null || hostname)"
    if [[ "$current" != "$OLD_HOSTNAME" ]]; then
        hostnamectl set-hostname "$OLD_HOSTNAME" || return 1
        ok "Hostname restored to $OLD_HOSTNAME."
    fi
}

leave_domain_cleanly() {
    header
    printf '%bLEAVE DOMAIN CLEANLY%b\n\n' "$C_BOLD" "$C_RESET"

    local realm_names=""
    realm_names="$(capture_probe 10 "realm membership query" realm list --name-only || true)"
    [[ -n "$realm_names" ]] || {
        info "This machine is not reporting realm membership."
        return 0
    }

    local domain=""
    domain="$(awk 'NR==1{print}' <<<"$realm_names")"

    printf 'Domain: %s\n' "$domain"
    info "Pre-leave checks will determine whether AD still has a usable computer trust before asking for credentials."

    local server_state_rc=0
    server_side_membership_state "$domain"
    server_state_rc=$?

    if (( server_state_rc == 3 )); then
        warn "The server appears to have already removed/reset this computer account."
        info "No domain administrator credential is required for the local cleanup path."
        confirm_literal \
            "Detach this client locally and restore its pre-join configuration." \
            "DETACH" || return 0
        local_detach_after_server_unlink "$domain"
        return $?
    fi

    local leave_user=""
    leave_user="$(prompt_domain_admin_account 'remove this computer from the domain' 'Administrator')"

    confirm_literal \
        "The machine will leave Active Directory. A reboot will be required." \
        "LEAVE" || return 0

    local leave_log="${LOG_ROOT}/${RUN_ID}-realm-leave.log"
    local leave_rc=0 evidence_rc=0

    run_membership_operation "$AD_CLIENT_MEMBERSHIP_TIMEOUT" "Clean realm leave" "$leave_log" \
        realm leave -v -U "$leave_user" "$domain"
    leave_rc=$?

    if (( leave_rc != 0 )); then
        membership_evidence_after_leave "$domain"
        evidence_rc=$?

        case "$evidence_rc" in
            0)
                warn "realm leave did not return cleanly, but post-operation evidence indicates that domain membership was removed."
                warn "Proceeding with local restoration because membership removal is evidenced."
                ;;
            1)
                err "Clean realm leave did not complete; the machine trust still validates."
                warn "No local rollback was forced, because doing so could create a stale or split membership state."
                leave_connectivity_diagnostics "$domain"
                warn "Detailed leave output: $leave_log"
                return 1
                ;;
            *)
                # A server-side delete may have happened while realm/adcli was
                # waiting. Re-check before declaring an ambiguous failure.
                server_side_membership_state "$domain" || server_state_rc=$?
                if [[ "${SERVER_MEMBERSHIP_STATE:-}" == "server-unlinked" ]]; then
                    warn "The authenticated leave did not finish cleanly, but AD now reports no usable machine trust."
                    warn "Treating this as a server-unlinked client and finishing local cleanup."
                    local_detach_after_server_unlink "$domain"
                    return $?
                fi

                err "Clean realm leave ended in an ambiguous state."
                warn "No DNS, SSSD, keytab or hostname rollback will be performed automatically."
                leave_connectivity_diagnostics "$domain"
                warn "Run Domain client status / Deep diagnostics before retrying or forcing local restore."
                warn "Detailed leave output: $leave_log"
                return 1
                ;;
        esac
    else
        membership_evidence_after_leave "$domain" || {
            evidence_rc=$?
            if (( evidence_rc != 0 )); then
                warn "realm leave returned success, but post-operation membership evidence is not fully converged yet."
                warn "Local restoration will continue because the membership command itself returned success."
            fi
        }
    fi

    local snap=""
    if [[ -f "$CURRENT_STATE" ]]; then
        local SNAPSHOT_PATH=""
        load_state_file "$CURRENT_STATE" || true
        snap="${SNAPSHOT_PATH:-}"
    fi

    if [[ -n "$snap" && -d "$snap" ]]; then
        restore_network_from_snapshot "$snap" || warn "DNS restore reported a problem."
        restore_identity_files "$snap"
        restore_hostname_from_snapshot "$snap" || warn "Hostname restore reported a problem."
        rm -f "$CURRENT_STATE"
        ok "Pre-join local state restored, including DNS, identity files and keytab."

        if confirm "Also offer removal of packages installed only for the AD client?" N; then
            remove_assistant_packages "$snap" || true
        fi
    else
        warn "No assistant snapshot was found. Domain membership was removed, but local DNS/config was not rewritten."
    fi

    request_reboot_now || true
}

restore_prejoin_state() {
    header
    printf '%bRESTORE PRE-JOIN STATE%b\n\n' "$C_BOLD" "$C_RESET"

    [[ -f "$CURRENT_STATE" ]] || { err "No current assistant state exists."; return 1; }

    local SNAPSHOT_PATH="" DOMAIN=""
    load_state_file "$CURRENT_STATE" || return 1
    [[ -n "${SNAPSHOT_PATH:-}" && -d "$SNAPSHOT_PATH" ]] || { err "Recorded snapshot is unavailable."; return 1; }

    local memberships=""
    memberships="$(capture_probe 10 "realm membership query" realm list --name-only || true)"
    if [[ -n "$memberships" ]]; then
        warn "The machine still reports domain membership: $memberships"
        warn "Preferred path: use Leave domain cleanly so the AD computer account is handled properly."
        confirm_literal \
            "Force-local restore may leave a stale computer account in Active Directory." \
            "FORCE-LOCAL-RESTORE" || return 0
        realm leave "${DOMAIN:-}" >/dev/null 2>&1 || true
    fi

    restore_network_from_snapshot "$SNAPSHOT_PATH" || return 1
    restore_identity_files "$SNAPSHOT_PATH"
    restore_hostname_from_snapshot "$SNAPSHOT_PATH" || true

    if [[ -s /etc/sssd/sssd.conf ]]; then
        systemctl restart sssd.service >/dev/null 2>&1 || true
    else
        systemctl stop sssd.service >/dev/null 2>&1 || true
    fi
    rm -f "$CURRENT_STATE"

    ok "Local pre-join state restored, including the pre-join Kerberos keytab state."
    warn "If a forced local restore was used, check Active Directory for a stale computer account."

    if confirm "Also offer removal of packages installed only for the AD client?" N; then
        remove_assistant_packages "$SNAPSHOT_PATH" || true
    fi
}

list_snapshots() {
    header
    printf '%bSNAPSHOTS%b\n\n' "$C_BOLD" "$C_RESET"

    local dirs=""
    dirs="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -r || true)"
    [[ -n "$dirs" ]] || {
        info "No snapshots found."
        return 0
    }

    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        printf '  %s\n' "$name"
    done <<<"$dirs"
}

# ---------------------------------------------------------------------------
# Endpoint security: Suricata + Wazuh + guarded response
# ---------------------------------------------------------------------------

security_init() {
    mkdir -p "$REMOTE_SECURITY_DIR"
    chmod 0700 "$REMOTE_SECURITY_DIR" 2>/dev/null || true
    touch "$SECURITY_TRUSTED" "$SECURITY_BLOCKS"
    chmod 0600 "$SECURITY_TRUSTED" "$SECURITY_BLOCKS" 2>/dev/null || true
    if [[ ! -f "$SECURITY_CONFIG" ]]; then
        cat >"$SECURITY_CONFIG" <<'EOF_SEC'
BUSINESS_START=08:00
BUSINESS_END=18:00
BUSINESS_HOURS_WINDOW=1
AFTER_HOURS_WINDOW=8
BLOCK_TTL_MINUTES=30
EOF_SEC
        chmod 0600 "$SECURITY_CONFIG"
    fi
}

security_load_config() {
    security_init
    BUSINESS_START=08:00; BUSINESS_END=18:00; BUSINESS_HOURS_WINDOW=1; AFTER_HOURS_WINDOW=8; BLOCK_TTL_MINUTES=30
    # shellcheck disable=SC1090
    source "$SECURITY_CONFIG" 2>/dev/null || true
}

security_is_public_ipv4() {
    local ip="$1" a b
    valid_ip "$ip" || return 1
    IFS=. read -r a b _ _ <<<"$ip"
    a=$((10#$a)); b=$((10#$b))
    ((a>=1 && a<=223)) || return 1
    ((a==10 || a==127 || a==0 || (a==169 && b==254) || (a==172 && b>=16 && b<=31) || (a==192 && b==168))) && return 1
    ((a>=224)) && return 1
    return 0
}

security_trusted() { grep -Fxq -- "$1" "$SECURITY_TRUSTED" 2>/dev/null; }
security_nft_ready() { command -v nft >/dev/null 2>&1; }
security_nft_setup() {
    security_nft_ready || { warn "nftables is not available; guarded response cannot manage blocks."; return 1; }
    nft list table inet rhel_ad_guard >/dev/null 2>&1 || nft add table inet rhel_ad_guard
    nft list set inet rhel_ad_guard blocked4 >/dev/null 2>&1 || nft 'add set inet rhel_ad_guard blocked4 { type ipv4_addr; flags timeout; }'
    nft list chain inet rhel_ad_guard input >/dev/null 2>&1 || {
        nft 'add chain inet rhel_ad_guard input { type filter hook input priority -5; policy accept; }'
        nft add rule inet rhel_ad_guard input ip saddr @blocked4 counter drop comment 'RHEL AD Assistant guarded IPS'
    }
}
security_list_blocks() {
    security_init
    printf '\n%s\n' "$(ui_text 'Blocked IP addresses')"
    if security_nft_ready && nft list set inet rhel_ad_guard blocked4 >/dev/null 2>&1; then nft list set inet rhel_ad_guard blocked4; else info "No assistant-managed nftables block set is active."; fi
}
security_block_ip() {
    security_load_config
    local ip="$1" ttl="${2:-$BLOCK_TTL_MINUTES}"
    security_is_public_ipv4 "$ip" || { warn "Only public IPv4 addresses may be blocked by this guarded workflow."; return 1; }
    security_trusted "$ip" && { warn "$ip is trusted; remove it from the trusted list first."; return 1; }
    [[ "$ttl" =~ ^[0-9]+$ ]] && ((ttl>=1 && ttl<=10080)) || { warn "TTL must be 1..10080 minutes."; return 1; }
    security_nft_setup || return 1
    nft delete element inet rhel_ad_guard blocked4 "{ $ip }" 2>/dev/null || true
    nft add element inet rhel_ad_guard blocked4 "{ $ip timeout ${ttl}m }"
    printf '%s\t%s\t%s\n' "$(date -Is)" "$ip" "$ttl" >>"$SECURITY_BLOCKS"
    ok "Temporarily blocked $ip for ${ttl} minutes."
}
security_unblock_ip() {
    local ip="$1"; security_nft_ready || return 1
    nft delete element inet rhel_ad_guard blocked4 "{ $ip }" 2>/dev/null && ok "Unblocked $ip." || warn "$ip was not present in the assistant block set."
}
security_unblock_all() {
    security_nft_ready || return 1
    confirm_literal "Emergency removal of every assistant-managed temporary network block." "UNBLOCK-ALL" || return 0
    nft flush set inet rhel_ad_guard blocked4 2>/dev/null || true
    ok "All assistant-managed temporary blocks were cleared."
}
security_trust_add() {
    local ip="$1"; [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { warn "Invalid IPv4 address."; return 1; }
    security_init; grep -Fxq "$ip" "$SECURITY_TRUSTED" || printf '%s\n' "$ip" >>"$SECURITY_TRUSTED"
    security_unblock_ip "$ip" >/dev/null 2>&1 || true
    ok "$ip is now trusted and excluded from guarded response."
}
security_trust_remove() { local ip="$1"; security_init; grep -Fxv -- "$ip" "$SECURITY_TRUSTED" >"${SECURITY_TRUSTED}.tmp" || true; mv "${SECURITY_TRUSTED}.tmp" "$SECURITY_TRUSTED"; chmod 0600 "$SECURITY_TRUSTED"; ok "Removed $ip from trusted addresses."; }
security_trust_list() { security_init; printf '\n%s\n' "$(ui_text 'Trusted IP addresses')"; if [[ -s "$SECURITY_TRUSTED" ]]; then nl -ba "$SECURITY_TRUSTED"; else info "No trusted IP addresses configured."; fi; }

security_suricata_info() {
    printf '\nSURICATA / IDS\n'
    command -v suricata >/dev/null 2>&1 && { printf '  Binary  : %s\n' "$(command -v suricata)"; suricata --build-info 2>/dev/null | head -1 | sed 's/^/  Version : /'; } || printf '  Binary  : not installed\n'
    printf '  Service : %s\n' "$(systemctl is-active suricata 2>/dev/null || true)"
    local eve="$SURICATA_EVE_DEFAULT"; [[ -r "$eve" ]] && printf '  EVE     : %s\n' "$eve" || printf '  EVE     : not detected\n'
}
security_suricata_validate() { command -v suricata >/dev/null 2>&1 || { warn "Suricata is not installed."; return 1; }; local cfg=/etc/suricata/suricata.yaml; [[ -r "$cfg" ]] || { warn "Suricata configuration was not found."; return 1; }; run_probe 30 "Suricata configuration" suricata -T -c "$cfg"; }
security_wazuh_info() {
    printf '\nWAZUH AGENT\n'; local svc=''; for x in wazuh-agent wazuh WazuhSvc; do systemctl list-unit-files "$x.service" >/dev/null 2>&1 && { svc="$x"; break; }; done
    [[ -n "$svc" ]] && printf '  Service : %s (%s)\n' "$svc" "$(systemctl is-active "$svc" 2>/dev/null || true)" || printf '  Service : not detected\n'
    [[ -r /var/ossec/etc/ossec.conf ]] && printf '  Config  : /var/ossec/etc/ossec.conf\n' || printf '  Config  : not detected\n'
}
security_wazuh_integrate() {
    local cfg=/var/ossec/etc/ossec.conf eve="$SURICATA_EVE_DEFAULT"
    [[ -r "$cfg" ]] || { warn "Wazuh agent configuration was not detected."; return 1; }
    [[ -r "$eve" ]] || { warn "Suricata EVE JSON is not available."; return 1; }
    grep -Fq "$eve" "$cfg" && { ok "Wazuh already ingests Suricata EVE JSON."; return 0; }
    confirm "Add Suricata EVE JSON as Wazuh localfile telemetry?" Y || return 0
    cp -a "$cfg" "${cfg}.rhel-ad.$(date +%s).bak"
    local tmp; tmp="$(mktemp)"
    awk -v eve="$eve" 'BEGIN{done=0} /<\/ossec_config>/ && !done {print "  <localfile>\n    <log_format>json</log_format>\n    <location>" eve "</location>\n  </localfile>"; done=1} {print}' "$cfg" >"$tmp"
    install -m 0640 "$tmp" "$cfg"; rm -f "$tmp"
    if systemctl restart wazuh-agent 2>/dev/null || systemctl restart wazuh 2>/dev/null; then ok "Wazuh now ingests Suricata EVE JSON."; else warn "Wazuh restart failed; restore the latest .bak if validation shows a problem."; return 1; fi
}
security_alert_review() {
    security_load_config; local eve="$SURICATA_EVE_DEFAULT"; [[ -r "$eve" ]] || { warn "Suricata EVE JSON is unavailable."; return 1; }
    local now hm hours="$BUSINESS_HOURS_WINDOW" label="business-hours"; hm="$(date +%H:%M)"
    if [[ "$hm" < "$BUSINESS_START" || "$hm" > "$BUSINESS_END" ]]; then hours="$AFTER_HOURS_WINDOW"; label="after-hours"; fi
    printf '\nIDS AWARENESS (%s, last %sh)\n' "$label" "$hours"
    python3 - "$eve" "$hours" <<'PY_EVE'
import json,sys,datetime,collections
p,h=sys.argv[1],int(sys.argv[2]); now=datetime.datetime.now(datetime.timezone.utc); cut=now-datetime.timedelta(hours=h); c=collections.Counter()
try: f=open(p,'r',errors='replace')
except OSError: sys.exit(0)
for line in f:
 try: e=json.loads(line)
 except: continue
 if e.get('event_type')!='alert': continue
 try:
  t=datetime.datetime.fromisoformat(str(e.get('timestamp','')).replace('Z','+00:00'))
  if t<cut: continue
 except: pass
 a=e.get('alert') or {}; src=e.get('src_ip','?'); dst=e.get('dest_ip','?'); sig=a.get('signature','unknown'); sev=a.get('severity','?'); cat=a.get('category','')
 c[(src,dst,sev,sig,cat)]+=1
for (src,dst,sev,sig,cat),n in c.most_common(40): print(f'{n:4}  sev={sev}  {src:15} -> {dst:15}  {sig}  [{cat}]')
PY_EVE
}
security_recommended_blocks() {
    local eve="$SURICATA_EVE_DEFAULT"; [[ -r "$eve" ]] || { warn "Suricata EVE JSON is unavailable."; return 1; }
    local rows; rows="$(python3 - "$eve" <<'PY_BLOCK'
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
PY_BLOCK
)"
    [[ -n "$rows" ]] || { info "No severity-1 public IPv4 source currently qualifies."; return 0; }
    printf '%s\n' "$rows" | nl -ba
    local pick; pick="$(ask 'IP to block (blank to cancel)' '')"; [[ -n "$pick" ]] || return 0; security_block_ip "$pick"
}
security_schedule_config() {
    security_load_config
    local bs be bh ah ttl
    bs="$(ask 'Business hours start (HH:MM)' "$BUSINESS_START")"; be="$(ask 'Business hours end (HH:MM)' "$BUSINESS_END")"
    bh="$(ask 'IDS lookback hours during business hours' "$BUSINESS_HOURS_WINDOW")"; ah="$(ask 'IDS lookback hours after hours' "$AFTER_HOURS_WINDOW")"; ttl="$(ask 'Default block TTL minutes' "$BLOCK_TTL_MINUTES")"
    [[ "$bs" =~ ^[0-2][0-9]:[0-5][0-9]$ && "$be" =~ ^[0-2][0-9]:[0-5][0-9]$ && "$bh" =~ ^[0-9]+$ && "$ah" =~ ^[0-9]+$ && "$ttl" =~ ^[0-9]+$ ]] || { warn "Invalid schedule values."; return 1; }
    cat >"$SECURITY_CONFIG" <<EOF_SEC
BUSINESS_START=$bs
BUSINESS_END=$be
BUSINESS_HOURS_WINDOW=$bh
AFTER_HOURS_WINDOW=$ah
BLOCK_TTL_MINUTES=$ttl
EOF_SEC
    chmod 0600 "$SECURITY_CONFIG"; ok "Awareness schedule updated."
}
security_telegram_config() {
    security_init; local token chat
    token="$(ask 'Telegram bot token (blank keeps current)' '')"; chat="$(ask 'Telegram chat/channel ID' '')"
    [[ -n "$token" || -f "$TELEGRAM_CONFIG" ]] || { warn "A bot token is required for first configuration."; return 1; }
    if [[ -z "$token" && -f "$TELEGRAM_CONFIG" ]]; then token="$(awk -F= '$1=="TOKEN"{sub(/^TOKEN=/,"");print;exit}' "$TELEGRAM_CONFIG")"; fi
    cat >"$TELEGRAM_CONFIG" <<EOF_TG
TOKEN=$token
CHAT_ID=$chat
EOF_TG
    chmod 0600 "$TELEGRAM_CONFIG"; ok "Telegram alert hook configured."
}
security_telegram_test() {
    [[ -r "$TELEGRAM_CONFIG" ]] || { warn "Telegram is not configured."; return 1; }; local TOKEN CHAT_ID; source "$TELEGRAM_CONFIG"
    [[ -n "${TOKEN:-}" && -n "${CHAT_ID:-}" ]] || return 1
    curl -fsS --max-time 12 -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" --data-urlencode "chat_id=${CHAT_ID}" --data-urlencode "text=RHEL AD Assistant security notification test on $(hostname -f 2>/dev/null || hostname)." >/dev/null && ok "Telegram test notification sent." || warn "Telegram test notification failed."
}
security_watch_once() {
    security_load_config
    local eve="$SURICATA_EVE_DEFAULT"; [[ -r "$eve" ]] || return 0
    local hm hours="$BUSINESS_HOURS_WINDOW"; hm="$(date +%H:%M)"; if [[ "$hm" < "$BUSINESS_START" || "$hm" > "$BUSINESS_END" ]]; then hours="$AFTER_HOURS_WINDOW"; fi
    local summary; summary="$(python3 - "$eve" "$hours" <<'PY_WATCH'
import sys,json,ipaddress,collections,datetime
p,h=sys.argv[1],int(sys.argv[2]); cut=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=h); c=collections.Counter()
with open(p,errors='replace') as f:
 for l in f:
  try:
   e=json.loads(l); a=e.get('alert') or {}; ip=e.get('src_ip')
   ts=str(e.get('timestamp','')).replace('Z','+00:00')
   try:
    if datetime.datetime.fromisoformat(ts)<cut: continue
   except Exception: pass
   if e.get('event_type')=='alert' and int(a.get('severity',9))<=1 and ip and ipaddress.ip_address(ip).is_global: c[(ip,a.get('signature','unknown'))]+=1
  except Exception: pass
for (ip,sig),n in c.most_common(5): print(f'{n}x {ip} {sig}')
PY_WATCH
)"
    [[ -n "$summary" && -r "$TELEGRAM_CONFIG" ]] || return 0
    local TOKEN CHAT_ID; source "$TELEGRAM_CONFIG"; [[ -n "${TOKEN:-}" && -n "${CHAT_ID:-}" ]] || return 0
    curl -fsS --max-time 12 -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" --data-urlencode "chat_id=${CHAT_ID}" --data-urlencode "text=RHEL AD endpoint attention required on $(hostname -f 2>/dev/null||hostname):\n${summary}\nReview manually in the assistant; no chat-side action was executed." >/dev/null || true
}
security_enable_watch_timer() {
    local install=/usr/local/sbin/rhel-ad-client-assistant
    install -m 0750 "$0" "$install"
    cat >/etc/systemd/system/rhel-ad-security-watch.service <<EOF
[Unit]
Description=RHEL AD Client IDS awareness check
[Service]
Type=oneshot
ExecStart=$install --security-watch
EOF
    cat >/etc/systemd/system/rhel-ad-security-watch.timer <<'EOF'
[Unit]
Description=RHEL AD Client IDS awareness timer
[Timer]
OnBootSec=5m
OnUnitActiveSec=15m
Persistent=true
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload; systemctl enable --now rhel-ad-security-watch.timer
    ok "15-minute IDS awareness notification timer enabled."
}

security_response_menu() {
    security_init
    while true; do
        printf '\n%s\n' "$(ui_text 'IDS / IPS response center')"
        printf '  [1] %s\n  [2] %s\n  [3] %s\n  [4] %s\n  [5] %s\n  [6] Remove trusted IP\n  [7] Recommended high-confidence blocks\n  [8] %s\n  [9] %s\n  [10] Enable 15-minute alert timer\n  [0] %s\n' "$(ui_text 'Blocked IP addresses')" "$(ui_text 'Unblock IP address')" "$(ui_text 'Emergency unblock all')" "$(ui_text 'Temporarily block IP')" "$(ui_text 'Trusted IP addresses')" "$(ui_text 'Awareness schedule')" "$(ui_text 'Telegram notifications')" "$(ui_text 'Exit')"
        local c ip; c="$(ask 'Select operation' '1')"
        case "$c" in
          1) security_list_blocks ;; 2) ip="$(ask 'IPv4 address' '')"; [[ -n "$ip" ]] && security_unblock_ip "$ip" ;; 3) security_unblock_all ;;
          4) ip="$(ask 'Public IPv4 address' '')"; [[ -n "$ip" ]] && security_block_ip "$ip" ;; 5) security_trust_list; ip="$(ask 'IPv4 to trust (blank to keep list)' '')"; [[ -n "$ip" ]] && security_trust_add "$ip" ;;
          6) security_trust_list; ip="$(ask 'Trusted IPv4 to remove' '')"; [[ -n "$ip" ]] && security_trust_remove "$ip" ;; 7) security_recommended_blocks ;; 8) security_schedule_config ;;
          9) printf '  [1] Configure\n  [2] Test\n'; c="$(ask 'Action' '1')"; [[ "$c" == 2 ]] && security_telegram_test || security_telegram_config ;; 10) security_enable_watch_timer ;; 0) return 0 ;; *) warn "Unknown option." ;;
        esac; pause_ui
    done
}
security_menu_client() {
    while true; do
        header; printf '%b%s%b\n\n' "$C_BOLD" "$(ui_text 'Endpoint security / Suricata + Wazuh')" "$C_RESET"
        security_suricata_info; security_wazuh_info
        printf '\n  [1] %s\n  [2] %s\n  [3] %s\n  [4] IDS alert review\n  [5] %s\n  [0] %s\n\n' "$(ui_text 'Security status')" "$(ui_text 'Validate Suricata')" "$(ui_text 'Configure Wazuh integration')" "$(ui_text 'IDS / IPS response center')" "$(ui_text 'Exit')"
        local c; c="$(ask 'Select operation' '1')"
        case "$c" in 1) security_suricata_info; security_wazuh_info ;; 2) security_suricata_validate ;; 3) security_wazuh_integrate ;; 4) security_alert_review ;; 5) security_response_menu ;; 0) return 0 ;; *) warn "Unknown option." ;; esac
        pause_ui
    done
}

# ---------------------------------------------------------------------------
# Interactive control plane
# ---------------------------------------------------------------------------

main_menu() {
    while true; do
        header
        printf '%bAD CLIENT OPERATIONS%b\n\n' "$C_BOLD" "$C_RESET"
        printf '  [1] %s\n' "$(ui_text 'Readiness audit')"
        printf '  [2] %s\n' "$(ui_text 'Guided domain join')"
        printf '  [3] %s\n' "$(ui_text 'Domain client status')"
        printf '  [4] %s\n' "$(ui_text 'Leave domain cleanly')"
        printf '  [5] %s\n' "$(ui_text 'Switch to another domain')"
        printf '  [6] %s\n' "$(ui_text 'AD connectivity test')"
        printf '  [7] %s\n' "$(ui_text 'Troubleshoot / repair')"
        printf '  [8] %s\n' "$(ui_text 'Export diagnostic bundle')"
        printf '  [9] %s\n' "$(ui_text 'Restore pre-join state')"
        printf '  [10] %s\n' "$(ui_text 'List snapshots')"
        printf '  [11] %s\n' "$(ui_text 'Endpoint security / Suricata + Wazuh')"
        printf '  [L] %s [%s]\n' "$(ui_text 'Language / Idioma')" "${UI_LANG^^}"
        printf '  [0] %s\n\n' "$(ui_text 'Exit')"

        local choice=""
        choice="$(ask 'Select operation' '1')" || return 0

        case "${choice^^}" in
            1) audit_readiness || true; pause_ui ;;
            2) join_domain_guided || warn "Join operation did not complete."; pause_ui ;;
            3) status_domain || true; pause_ui ;;
            4) leave_domain_cleanly || warn "Leave operation did not complete."; pause_ui ;;
            5) switch_domain_guided || warn "Domain switch did not complete."; pause_ui ;;
            6) ad_connectivity_test || true; pause_ui ;;
            7) troubleshoot_ad || true; pause_ui ;;
            8) export_diagnostic_bundle || true; pause_ui ;;
            9) restore_prejoin_state || warn "Restore operation did not complete."; pause_ui ;;
            10) list_snapshots || true; pause_ui ;;
            11) security_menu_client ;;
            L) toggle_ui_language ;;
            0) return 0 ;;
            *) warn "Unknown option."; pause_ui ;;
        esac

        detect_os
        detect_active_interface
        detect_dns_backend
        detect_system_resolver
    done
}

usage() {
    cat <<EOF
$PRODUCT_NAME v$SCRIPT_VERSION

--preflight: read-only launch prerequisites; no root required.

Usage:
  sudo $0 [mode]

Modes:
  --manage, --interactive   Interactive control plane
  --audit                   Readiness audit
  --join                    Guided domain join
  --status                  Domain client status
  --leave                   Clean domain leave + restore
  --switch                  Preflight target, leave source, join target
  --connectivity            AD DNS/network/time connectivity test
  --troubleshoot            Guided local AD troubleshooting
  --diagnostics             Export a local diagnostic bundle
  --restore                 Restore pre-join local state
  --snapshots               List local snapshots
  --security                Suricata + Wazuh endpoint security center
  --security-watch          Non-interactive IDS notification check
  --lang en|es              UI language
  --no-color                Disable ANSI color
  --help                    Show this help

State:
  $STATE_ROOT

Recovery snapshots:
  $BACKUP_ROOT

Logs:
  $LOG_ROOT

Administrator is the default join/leave account but can be overridden at the credential step.
DHCP addressing is supported; a static client IP is not required. AD DNS must also forward external DNS before the assistant replaces the client resolver.
No password is persisted, no third-party repository is added, and supported joins use a private Kerberos cache.
EOF
}

validate_runtime_settings() {
    local name value
    for name in AD_CLIENT_NETWORK_TIMEOUT AD_CLIENT_MEMBERSHIP_TIMEOUT AD_CLIENT_SLOW_NETWORK_TIMEOUT; do
        value="${!name}"
        if [[ ! "$value" =~ ^[1-9][0-9]{0,3}$ ]] || (( value > 3600 )); then
            printf 'Invalid %s: use integer seconds from 1 to 3600.\n' "$name" >&2
            return 2
        fi
    done
}

# Read-only launch check: no elevation, package installation or runtime state.
launch_preflight() {
    local failures=0 tool os_id=unknown
    printf 'Preflight: Linux domain client\n'
    printf 'Bash: %s | UID: %s\n' "$BASH_VERSION" "$EUID"
    if [[ "$(uname -s)" != Linux ]]; then
        printf '[FAIL] Linux is required.\n'; failures=1
    fi
    if [[ -r /etc/os-release ]]; then
        os_id="$(. /etc/os-release; printf '%s' "${ID:-unknown}")"
    fi
    printf 'Distribution: %s\n' "$os_id"
    if [[ ! -d /run/systemd/system ]]; then
        printf '[FAIL] A running systemd host is required for lifecycle operations.\n'
        failures=1
    fi
    for tool in ip systemctl hostname flock timeout; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '[OK] %s\n' "$tool"
        else
            printf '[FAIL] Missing launch prerequisite: %s\n' "$tool"; failures=1
        fi
    done
    for tool in realm adcli kinit sssctl; do
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
    local mode="manage"

    while (($#)); do
        case "$1" in
            --manage|--interactive) mode="manage" ;;
            --preflight) mode="preflight" ;;
            --audit) mode="audit" ;;
            --join) mode="join" ;;
            --status) mode="status" ;;
            --leave) mode="leave" ;;
            --switch) mode="switch" ;;
            --connectivity) mode="connectivity" ;;
            --troubleshoot) mode="troubleshoot" ;;
            --diagnostics) mode="diagnostics" ;;
            --lang)
                shift
                (($#)) || { printf "Missing value for --lang (en|es).\n" >&2; return 2; }
                set_ui_language "$1" || return 2
                ;;
            --lang=*) set_ui_language "${1#*=}" || return 2 ;;
            --restore) mode="restore" ;;
            --snapshots) mode="snapshots" ;;
            --security) mode="security" ;;
            --security-watch) mode="security-watch" ;;
            --no-color)
                USE_COLOR=0
                C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_CYAN=""
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                printf 'Unknown argument: %s\n\n' "$1" >&2
                usage >&2
                return 2
                ;;
        esac
        shift
    done

    validate_runtime_settings || return $?
    if [[ "$mode" == preflight ]]; then launch_preflight; return $?; fi
    case "$mode" in
        audit|status|snapshots|security-watch) ;;
        *) if ! (: </dev/tty) 2>/dev/null; then
               printf 'Mode %s requires a terminal. Use a local console or ssh -t.\n' "$mode" >&2
               return 2
           fi ;;
    esac
    init_runtime || return $?

    case "$mode" in
        manage) main_menu ;;
        audit) audit_readiness ;;
        join) join_domain_guided ;;
        status) status_domain ;;
        leave) leave_domain_cleanly ;;
        switch) switch_domain_guided ;;
        connectivity) ad_connectivity_test ;;
        troubleshoot) troubleshoot_ad ;;
        diagnostics) export_diagnostic_bundle ;;
        restore) restore_prejoin_state ;;
        snapshots) list_snapshots ;;
        security) security_menu_client ;;
        security-watch) security_watch_once ;;
    esac
}

main "$@"
