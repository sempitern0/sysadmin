#!/usr/bin/env bash
# Standalone, non-elevated entry point for everyday Linux operations.
# No remote downloads, runtime imports, automatic repairs or implicit sudo.
set -uo pipefail
IFS=$'\n\t'

LANGUAGE=en
FAILURES=0
SKIPS=0
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

text() { if [[ "$LANGUAGE" == es ]]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
usage() {
    cat <<'EOF'
Sysadmin Operations Console
Usage: bash sysadmin.sh [--manage|--preflight|--audit|--network|--storage|--services|--logs]
                       [--lang en|es] [--no-color]
Default: interactive menu. Read-only modes require no elevation or terminal.
--tools: guided installation of a small diagnostic toolset (requires a terminal).
The AD assistants remain standalone; this console can launch their help/preflight/menu.
No configuration, report files or external network probes are created by read-only modes.
Exit status: 0 complete, 1 failed probe/action, 2 usage/terminal error.
Missing optional tools are explicitly SKIP, not a passed health check.
EOF
}

has() { command -v "$1" >/dev/null 2>&1; }
has_tty() { (: </dev/tty) 2>/dev/null; }
systemd_host() { [[ -d /run/systemd/system ]] && has systemctl; }

# Never run an unbounded diagnostic or treat a timeout as success.
probe() {
    local title="$1" rc=0
    shift
    printf '\n-- %s --\n' "$title"
    if ! has "$1"; then printf '[SKIP] %s unavailable\n' "$1"; ((SKIPS+=1)); return 0; fi
    if ! has timeout; then printf '[SKIP] timeout unavailable; bounded probe not possible\n'; ((SKIPS+=1)); return 0; fi
    if timeout --signal=TERM --kill-after=2s 15s "$@"; then
        return 0
    else
        rc=$?
        printf '[WARN] %s: rc=%s (124/137 indicates timeout; permissions may limit visibility)\n' "$title" "$rc" >&2
        ((FAILURES+=1))
    fi
    return 0
}

inventory() {
    printf '\n%s\n' "$(text 'Host inventory' 'Inventario del equipo')"
    probe Kernel uname -srmo
    if [[ -r /etc/os-release ]]; then
        # Print data; never evaluate a host-supplied file as shell commands.
        while IFS= read -r line; do
            case "$line" in ID=*|VERSION_ID=*|PRETTY_NAME=*) printf '%s\n' "$line" ;; esac
        done </etc/os-release
    fi
    printf 'UID=%s | systemd=%s | SSH=%s\n' "$EUID" "$(systemd_host && printf yes || printf no)" "${SSH_TTY:-${SSH_CONNECTION:+remote}}"
    [[ -e /.dockerenv || -e /run/.containerenv ]] && printf '[INFO] Container detected; host visibility is restricted.\n'
    [[ -n "${WSL_DISTRO_NAME:-}" ]] && printf '[INFO] WSL: %s\n' "$WSL_DISTRO_NAME"
    probe Uptime uptime
    probe Memory free -h
    probe Clock date -Is
}

network() {
    printf '\n%s\n' "$(text 'Local network diagnostics (no external traffic)' 'Diagnóstico de red local (sin tráfico externo)')"
    probe Addresses ip -brief address show
    probe 'IPv4 routes' ip -4 route show
    probe 'IPv6 routes' ip -6 route show
    probe 'Listening sockets' ss -lntu
    if systemd_host && has resolvectl; then
        probe Resolver resolvectl status
    elif [[ -r /etc/resolv.conf ]]; then
        probe Resolver cat /etc/resolv.conf
    else
        printf '[SKIP] No readable resolver configuration\n'; ((SKIPS+=1))
    fi
    if has nmcli; then probe NetworkManager nmcli --wait 5 device status; fi
}

storage() {
    probe 'Filesystem capacity' df -hP
    probe 'Filesystem inodes' df -iP
    probe 'Block devices (no serial numbers)' lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT
    probe Mounts findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS
}

services() {
    if systemd_host; then
        probe 'Failed units' systemctl --no-pager --failed
        probe 'Running services' systemctl --no-pager --type=service --state=running
        probe Timers systemctl --no-pager list-timers
    elif has rc-status; then
        probe 'OpenRC services' rc-status --all
    elif has service; then
        probe 'SysV service status' service --status-all
    else
        printf '[SKIP] No supported running service manager (systemd/OpenRC/SysV).\n'
        ((SKIPS+=1))
    fi
}

logs() {
    if systemd_host && has journalctl; then
        probe 'Recent warning/error logs (current boot, up to 100)' journalctl --no-pager -b -p warning -n 100
    else
        printf '[SKIP] No running systemd journal; use the platform syslog/container logs.\n'; ((SKIPS+=1))
    fi
    probe 'Kernel messages (permissions may restrict access)' dmesg --level=err,warn
}

preflight() {
    local tool
    printf 'Preflight: general Linux operations\n'
    [[ "$(uname -s)" == Linux ]] || { printf '[FAIL] Linux required\n'; return 1; }
    for tool in timeout ip ss df lsblk findmnt; do
        if has "$tool"; then printf '[OK] %s\n' "$tool";
        else printf '[SKIP] %s (install through your distribution)\n' "$tool"; ((SKIPS+=1)); fi
    done
    printf 'No changes made. No root required. Optional tools missing: %s\n' "$SKIPS"
}

read_input() {
    printf '%s: ' "$1" >/dev/tty
    IFS= read -r REPLY </dev/tty
}

install_tools() {
    has_tty || { printf 'Tool installation requires a terminal.\n' >&2; return 2; }
    if [[ -e /run/ostree-booted || -r /etc/NIXOS ]] || has transactional-update; then
        printf 'Image/transactional host: use its native deployment or toolbox workflow.\n' >&2; return 1
    fi
    local -a refresh=() install=() prefix=()
    local answer
    if has apt-get; then
        refresh=(apt-get update)
        install=(apt-get install --no-install-recommends iproute2 iputils-ping dnsutils curl openssl traceroute mtr-tiny tcpdump lsof rsync tmux)
    elif has dnf; then
        install=(dnf install iproute iputils bind-utils curl openssl traceroute mtr tcpdump lsof rsync tmux)
    elif has pacman; then
        printf 'Arch requires a reviewed full system upgrade; this assistant will not perform a partial upgrade.\n'
        printf 'Review Arch news, run pacman -Syu, then install: iproute2 iputils bind curl openssl traceroute mtr tcpdump lsof rsync tmux\n'
        return 0
    elif has zypper; then
        install=(zypper install iproute2 iputils bind-utils curl openssl traceroute mtr tcpdump lsof rsync tmux)
    elif has apk; then
        install=(apk add iproute2 iputils bind-tools curl openssl traceroute mtr tcpdump lsof rsync tmux)
    else
        printf 'No supported package manager. Install diagnostic tools with your platform tooling.\n' >&2; return 1
    fi
    if (( EUID != 0 )); then
        has sudo || { printf 'sudo unavailable; ask your administrator to install the tools.\n' >&2; return 1; }
        prefix=(sudo --)
    fi
    printf '%s\n' "$(text 'Proposed package operations (configured repositories only):' 'Operaciones propuestas (solo repositorios configurados):')"
    if ((${#refresh[@]})); then printf '  '; printf '%q ' "${prefix[@]}" "${refresh[@]}"; printf '\n'; fi
    printf '  '; printf '%q ' "${prefix[@]}" "${install[@]}"; printf '\n'
    read_input "$(text 'Type INSTALL to continue; anything else cancels' 'Escribe INSTALL para continuar; otro valor cancela')" || return 2
    answer="$REPLY"
    [[ "$answer" == INSTALL ]] || { printf 'Cancelled.\n'; return 0; }
    if ((${#refresh[@]})); then "${prefix[@]}" "${refresh[@]}" || return $?; fi
    # Do not time-limit package transactions, force answers or remove lock files.
    "${prefix[@]}" "${install[@]}"
}

assistant_menu() {
    local script mode
    printf '\n1 Linux AD client\n2 Debian/Ubuntu AD controller\n3 RHEL AD controller\n0 Back / Volver\n'
    read_input "$(text 'Assistant' 'Asistente')" || return 2
    case "$REPLY" in
        1) script=linux-ad-client-assistant.sh ;;
        2) script=debian-ad-assistant.sh ;;
        3) script=rhel-ad-assistant.sh ;;
        0|'') return 0 ;;
        *) printf 'Invalid selection\n' >&2; return 2 ;;
    esac
    [[ -f "$SCRIPT_DIR/$script" ]] || { printf 'Download the full repository for %s\n' "$script" >&2; return 1; }
    printf '1 Help / Ayuda\n2 Preflight\n3 Interactive / Interactivo (sudo/root)\n'
    read_input "$(text 'Mode' 'Modo')" || return 2
    case "$REPLY" in
        1) mode=--help ;;
        2) mode=--preflight ;;
        3) mode=--manage ;;
        *) return 2 ;;
    esac
    printf 'bash %q %q --lang %q\n' "$SCRIPT_DIR/$script" "$mode" "$LANGUAGE"
    if [[ "$mode" == --manage ]] && (( EUID != 0 )); then
        has sudo || { printf 'sudo unavailable. Run this assistant as root.\n' >&2; return 1; }
        sudo -- bash "$SCRIPT_DIR/$script" "$mode" --lang "$LANGUAGE"
    else
        bash "$SCRIPT_DIR/$script" "$mode" --lang "$LANGUAGE"
    fi
}

menu() {
    has_tty || { printf 'Interactive mode requires a terminal. Use --preflight or --audit; SSH: ssh -t.\n' >&2; return 2; }
    while true; do
        printf '\n%s\n' "$(text 'SYSADMIN | Operations Console' 'SYSADMIN | Consola de operaciones')"
        printf '%s\n' "$(text '1 Inventory  2 Network  3 Storage  4 Services  5 Logs' '1 Inventario  2 Red  3 Almacenamiento  4 Servicios  5 Logs')"
        printf '%s\n' "$(text '6 Full diagnosis  7 Install tools  8 AD assistants  9 Language  0 Exit' '6 Diagnóstico completo  7 Instalar herramientas  8 Asistentes AD  9 Idioma  0 Salir')"
        read_input "$(text 'Selection' 'Selección')" || return 2
        case "$REPLY" in
            1) inventory ;; 2) network ;; 3) storage ;; 4) services ;; 5) logs ;;
            6) inventory; network; storage; services; logs ;;
            7) install_tools || ((FAILURES+=1)) ;;
            8) assistant_menu || ((FAILURES+=1)) ;;
            9) if [[ "$LANGUAGE" == en ]]; then LANGUAGE=es; else LANGUAGE=en; fi ;;
            0|q) return 0 ;;
            *) printf '%s\n' "$(text 'Invalid selection' 'Selección no válida')" ;;
        esac
        printf '\n%s\n' "$(text 'Review output before sharing: hostnames, addresses and logs may be sensitive.' 'Revisa la salida antes de compartir: puede contener nombres, direcciones y logs.')"
    done
}

main() {
    (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) )) || { printf 'Bash 4.3+ required.\n' >&2; return 2; }
    local mode=manage rc=0 previous_mode
    while (($#)); do
        previous_mode="$mode"
        case "$1" in
            --manage|--interactive) mode=manage ;;
            --preflight|--audit|--network|--storage|--services|--logs|--tools) mode="${1#--}" ;;
            --lang) shift; (($#)) || return 2; LANGUAGE="$1" ;;
            --lang=*) LANGUAGE="${1#*=}" ;;
            --no-color) : ;;
            --help|-h) usage; return 0 ;;
            *) printf 'Unknown argument: %s\n' "$1" >&2; return 2 ;;
        esac
        if [[ "$previous_mode" != manage && "$previous_mode" != "$mode" ]]; then
            printf 'Choose one mode per invocation.\n' >&2; return 2
        fi
        [[ "$LANGUAGE" == en || "$LANGUAGE" == es ]] || { printf 'Language: en|es\n' >&2; return 2; }
        shift
    done
    [[ "$(uname -s)" == Linux ]] || { printf 'Linux required. Use the standalone .ps1 assistants on Windows.\n' >&2; return 1; }
    case "$mode" in
        manage) menu || rc=$? ;;
        preflight) preflight || rc=$? ;;
        audit) inventory; network; storage; services; logs ;;
        network) network ;; storage) storage ;; services) services ;; logs) logs ;;
        tools) install_tools || rc=$? ;;
    esac
    printf '\nFailed probes/actions: %s | Optional checks skipped: %s\n' "$FAILURES" "$SKIPS"
    (( rc != 0 || FAILURES == 0 )) || rc=1
    return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    trap 'exit 130' INT
    trap 'exit 143' TERM
    main "$@"
fi
