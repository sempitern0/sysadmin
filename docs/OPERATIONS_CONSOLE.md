# Operations console / Consola de operaciones

[English overview](../README.md) · [Resumen español](../README_ES.md)

## English

`bash sysadmin.sh` opens a Linux operations menu without requiring root. It is a
standalone script; the complete checkout is only needed to launch the existing AD
assistants from its submenu. Download a reviewed revision using the
[deployment guide](DEPLOYMENT.md). Windows keeps the existing standalone PowerShell
AD, migration and workstation assistants; this Bash console is Linux-specific.

```bash
bash sysadmin.sh --preflight
bash sysadmin.sh --audit
bash sysadmin.sh --network --lang en
bash sysadmin.sh --storage
bash sysadmin.sh --services
bash sysadmin.sh --logs
bash sysadmin.sh --tools            # interactive package installation, optional
# For the interactive menu over SSH:
ssh -t user@host 'cd /path/to/sysadmin && bash sysadmin.sh --lang en'
```

| Workspace | What it shows |
|---|---|
| Inventory | OS/kernel, uptime, memory, clock and session constraints |
| Network | Addresses, IPv4/IPv6 routes, listening sockets, resolver, NetworkManager status |
| Storage | Capacity, inodes, device filesystems and mounts; no disk writes |
| Services | Failed/running units and timers, with OpenRC/SysV status fallbacks |
| Logs | Up to 100 current-boot warnings/errors; kernel warnings if permissions allow |
| Tools | Proposed diagnostic package set and explicit INSTALL confirmation |
| AD assistants | Help, preflight or existing interactive assistant; only the last requests sudo |

Read-only modes create no reports/configuration and send no external probes. Redirect
output yourself if required, protect the file, and review hostnames, addresses,
mount options and logs before sharing. Elevated execution can expose more data;
it is unnecessary for the general menu. Unlike this console, specialized AD audits
may initialize protected state and log files and require elevation.

Probes are bounded to 15 seconds, followed by up to 2 seconds to terminate a stuck
command. A failed or timed-out command returns a warning and contributes to exit
status **1**. Missing optional tools are **SKIP**, never a successful health check.
**0** means the requested available commands completed, not that the host is healthy.
**2** means invalid arguments or a missing controlling terminal. Interactive mode
shows the menu again after failures and retains the aggregate failure status on exit.

### Platforms and package operations

Linux with Bash 4.3+ and GNU `timeout` provides the diagnostic path. Minimal images
without tools remain inspectable through the available checks; missing timeout
skips bounded probes. Service checks detect a running systemd, then try OpenRC/SysV.
Containers and WSL expose their own namespace/permissions; results are not a host
certification. Logs can be unavailable to normal users.

Tool installation supports APT, DNF, Zypper and APK on mutable hosts. It prints exact
commands, uses only configured repositories, requests sudo only for installation,
and leaves native package confirmations enabled. Repository/authentication, disk,
network, lock and package failures propagate. No locks are deleted, arbitrary package
names accepted or repair commands run. Package transactions are deliberately not
killed with diagnostic timeouts. Arch prints a manual full-upgrade/install plan
instead of performing a partial upgrade. OSTree, NixOS and transactional-update
hosts are directed to native image/toolbox workflows. Air-gapped installations must
provide repository access/cache themselves; there are no remote shell installers.

The AD client's NETWORK/MEMBERSHIP/SLOW_NETWORK timeout variables accept integer
seconds **1–3600**, without leading zeros. Invalid values stop before runtime state
is created. Both Linux client variants require flock and hold one exclusive lock
through cleanup; the protected state/log directories must be writable. Automated
AD lifecycle still requires a running systemd. This does not change domain protocols
or certify all target OS combinations.

Validation: `python3 tools/verify.py --require-shellcheck`; add
`--require-powershell` for the full existing gate. New tests stub diagnostics, verify
exit statuses, invalid timeout inputs and real lock contention in temporary files.
Native package/service/AD/reboot/recovery testing on disposable hosts remains required.

## Español

`bash sysadmin.sh --lang es` abre un menú Linux sin requerir root. El script funciona
independientemente; para abrir los asistentes AD desde el submenú necesitas el
repositorio completo. Usa una revisión revisada según la [guía](DEPLOYMENT_ES.md).
Windows mantiene los asistentes PowerShell de AD, migración y estaciones de trabajo;
esta consola Bash es específica de Linux.

```bash
bash sysadmin.sh --preflight --lang es
bash sysadmin.sh --audit --lang es
bash sysadmin.sh --network --lang es
bash sysadmin.sh --storage
bash sysadmin.sh --services
bash sysadmin.sh --logs
bash sysadmin.sh --tools            # instalación guiada opcional
ssh -t usuario@equipo 'cd /ruta/sysadmin && bash sysadmin.sh --lang es'
```

| Área | Información |
|---|---|
| Inventario | SO/kernel, uptime, memoria, reloj y restricciones de sesión |
| Red | Direcciones, rutas IPv4/IPv6, puertos, DNS y estado de NetworkManager |
| Almacenamiento | Capacidad, inodos, dispositivos y montajes; sin escribir discos |
| Servicios | Unidades fallidas/activas y temporizadores; alternativas OpenRC/SysV |
| Logs | Hasta 100 avisos/errores del arranque; kernel según permisos |
| Herramientas | Lista de paquetes propuesta y confirmación literal INSTALL |
| Asistentes AD | Ayuda, preflight o menú existente; solo el último solicita sudo |

Los modos de lectura no generan informes/configuración ni tráfico hacia destinos
externos. Redirige la salida si necesitas conservarla, protege el archivo y revisa
nombres, direcciones, opciones de montaje y logs antes de compartirlos. Root aumenta
la visibilidad y no es necesario para este menú. Las auditorías especializadas AD
sí pueden crear estado protegido y logs y exigir elevación.

Cada diagnóstico tiene 15 segundos y hasta 2 adicionales para terminar procesos
atascados. Fallos y timeouts generan aviso y salida **1**. Las herramientas opcionales
ausentes son **SKIP**, no comprobaciones superadas. **0** significa que terminaron
los comandos disponibles; no certifica la salud del equipo. **2** indica argumentos
inválidos o falta de terminal de control. El menú continúa después de un fallo y
conserva el resultado acumulado al salir.

### Plataformas y paquetes

Diagnóstico Linux con Bash 4.3+ y GNU `timeout`. Las imágenes mínimas muestran las
comprobaciones disponibles; sin timeout se omiten las pruebas acotadas. Detecta
systemd activo y ofrece alternativas de estado OpenRC/SysV. En contenedores y WSL,
la visibilidad y los permisos corresponden a ese entorno, no a todo el host.
Los logs pueden estar restringidos.

Instala herramientas con APT, DNF, Zypper y APK en sistemas mutables. Muestra los
comandos, utiliza repositorios configurados, solicita sudo solo para instalar y
mantiene las confirmaciones del gestor. Propaga fallos de repositorio, permisos,
espacio, red, bloqueo y paquetes. No borra locks, acepta nombres arbitrarios ni
aplica reparaciones automáticas. No mata transacciones con timeouts de diagnóstico.
En Arch muestra un plan manual de actualización completa e instalación. En OSTree,
NixOS o transactional-update remite al flujo nativo de imagen/toolbox. En redes
aisladas debes aportar repositorios/caché. No descarga instaladores de shell remotos.

Los timeouts NETWORK/MEMBERSHIP/SLOW_NETWORK de los clientes AD admiten enteros de
**1–3600** segundos sin ceros iniciales. Los valores inválidos detienen el arranque
antes de crear estado. Ambos clientes Linux requieren flock y mantienen un bloqueo
exclusivo hasta finalizar la limpieza; los directorios de estado/log deben poder
escribirse. El ciclo AD automatizado sigue requiriendo systemd activo. No se cambian
los protocolos de dominio ni se certifican todas las combinaciones de sistemas.

Validación: `python3 tools/verify.py --require-shellcheck`; añade
`--require-powershell` para la batería existente completa. Las regresiones simulan
diagnósticos y prueban códigos de salida, timeouts inválidos y contención real de
bloqueos en temporales. Sigue siendo necesario probar paquetes, servicios, AD,
reinicios y recuperación en equipos desechables.
