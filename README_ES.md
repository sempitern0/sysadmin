# sysadmin

Asistentes autónomos de administración Windows/Linux, Active Directory, diagnóstico y recuperación.

[English](README.md) · **Español**

RabbitMole (antes Audit Workbench) tiene [su propio repositorio](https://github.com/sempitern0/RabbitMole). Aquí se mantienen los asistentes de consola, sin dependencias de la PWA.

## Elige la tarea

| Necesitas… | Empieza por… |
|---|---|
| Administrar Samba AD en Debian/Ubuntu | `debian-ad-assistant.sh --audit` |
| Administrar Samba AD en Rocky/AlmaLinux | `rhel-ad-assistant.sh --audit` |
| Diagnosticar/administrar AD DS en Windows | `windows-ad-assistant.ps1 -Mode Audit` |
| Unir, diagnosticar o recuperar clientes Linux de AD | `linux-ad-client-assistant.sh --audit` |
| Usar la variante Linux con identidad RHEL | `rhel-ad-client-assistant.sh --audit` |
| Unir, diagnosticar o recuperar clientes Windows de AD | `windows-ad-client-assistant.ps1 -Mode Audit` |
| Planificar actualizaciones o migrar archivos a Ubuntu/Nextcloud | `migration-assistant.ps1 -Mode Interactive` |

Consulta [alcance, procedimientos y recuperación de migraciones](docs/MIGRATIONS_ES.md).

## Primer uso en minutos

```bash
git clone https://github.com/sempitern0/sysadmin.git
cd sysadmin
```

**Asistentes AD:** revisa el script, consulta la ayuda y audita desde una consola elevada.

```bash
bash ./linux-ad-client-assistant.sh --help
bash ./linux-ad-client-assistant.sh --preflight
sudo bash ./linux-ad-client-assistant.sh --audit
# Para un controlador Debian/Ubuntu:
sudo bash ./debian-ad-assistant.sh --audit
```

```powershell
Get-Help .\windows-ad-client-assistant.ps1 -Detailed
# No requiere elevación:
powershell.exe -NoProfile -File .\windows-ad-client-assistant.ps1 -Mode Preflight
# En una consola elevada:
.\windows-ad-client-assistant.ps1 -Mode Audit
# Para un controlador Windows:
.\windows-ad-assistant.ps1 -Mode Audit
```

En Windows utiliza la política de ejecución/firma aprobada por tu organización.
Los scripts de la raíz son descargables y autónomos.

## Desplegar una revisión verificada

La [guía de lanzamiento](docs/DEPLOYMENT_ES.md) explica cómo elegir el asistente, descargar por commit, comprobar hashes/sintaxis, copiar por SSH y lanzar en Windows. CI genera un paquete con checksums solo tras superar las comprobaciones Linux y Windows PowerShell 5.1/7.

`--preflight` / `-Mode Preflight` no modifica el sistema. Comprueba requisitos locales; la auditoría posterior sí puede crear logs e informes. Un resultado correcto no sustituye una prueba de cambio y recuperación en laboratorio.

## Criterios de operación

- Empieza por auditoría/diagnóstico y aplica cambios con una vía de recuperación.
- Conserva backups restaurables y acceso por consola antes de cambiar DNS, SSH, firewall o pertenencia al dominio.
- El aprovisionamiento Samba AD DC en RHEL está protegido por ser un rol no soportado; consulta las [notas de plataforma](docs/OPERATIONS_ES.md#control-plane-enterprise-linux).
- Las implementaciones difieren entre plataformas. Una comprobación de sintaxis o un hardening no certifican preparación para producción ni cumplimiento completo.

## Referencia, recuperación y mantenimiento

| Consulta | Guía |
|---|---|
| Comandos AD, DNS, GPO, IDS, backups y recuperación | [Referencia operativa](docs/OPERATIONS_ES.md) |
| Diagnosticar DNS, Kerberos o unión a dominio | [Resolución de problemas](docs/OPERATIONS_ES.md#troubleshooting) |
| Localizar estado, snapshots y logs | [Rutas de estado](docs/OPERATIONS_ES.md#rutas-de-estado-y-logs) |
| Modificar código y ejecutar pruebas offline | [Mantenimiento](docs/MAINTENANCE.md) |

```bash
python3 tools/verify.py              # Sintaxis, paridad y pruebas de regresión
# CI exige también ShellCheck y PowerShell:
python3 tools/verify.py --require-shellcheck --require-powershell
```

[Licencia MIT](LICENSE).
