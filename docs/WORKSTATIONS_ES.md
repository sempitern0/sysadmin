# Preparación de puestos Windows

[English](WORKSTATIONS.md) · [Inicio](../README_ES.md)

`windows-workstation-assistant.ps1` es un único archivo autónomo en la raíz:
no descarga herramientas, no instala paquetes y no necesita el repositorio completo.
Usa las herramientas nativas de Windows. Los asistentes AD existentes siguen
siendo responsables de unión al dominio, DNS y políticas de dominio.

## Compatibilidad y alcance

| Plataforma | Requisito / tratamiento |
|---|---|
| Windows 7 | **SP1 + Windows PowerShell 5.1 (WMF 5.1)** previamente instalado; perfil Legacy |
| Windows 8 RTM | No compatible con este runtime; actualizar a una plataforma admitida antes de usarlo |
| Windows 8.1 | Windows PowerShell 5.1; perfil Legacy predeterminado |
| Windows 10 / 11 | Windows PowerShell 5.1 integrado; Home, Pro, Enterprise/Education según capacidades |
| Windows Server / controladores de dominio | Rechazados; usar los asistentes de servidor |
| PowerShell 7 / proceso de 32 bits en Windows de 64 bits | Detecta el entorno y relanza automaticamente el mismo archivo en Windows PowerShell nativo, conservando parametros y resultado |

La compatibilidad del script **no restablece el soporte del fabricante**. Windows
7/8.1 están fuera de soporte; Windows 10 terminó su soporte general el 14-10-2025
(existen excepciones LTSC/ESU que deben verificarse). Para software antiguo:
segmentación de red, salida restringida, cuentas sin privilegios, copias externas
y plan de sustitución. No se comprueba automáticamente la licencia ESU ni la
vigencia de cada build de Windows 11.

## Descargar y ejecutar

Elige un commit revisado y sustituye `COMMIT` por su SHA completo. En Windows
antiguo sin TLS compatible descarga desde otro equipo y transfiere el archivo;
no desactives la validación de certificados para descargarlo.

```powershell
# Desde un equipo con HTTPS/TLS compatible:
$url = 'https://raw.githubusercontent.com/sempitern0/sysadmin/COMMIT/windows-workstation-assistant.ps1'
Invoke-WebRequest -UseBasicParsing $url -OutFile .\windows-workstation-assistant.ps1
Get-FileHash .\windows-workstation-assistant.ps1 -Algorithm SHA256
Get-Help .\windows-workstation-assistant.ps1 -Detailed
powershell.exe -NoProfile -File .\windows-workstation-assistant.ps1 -Mode Preflight
```

Compara el hash con un artefacto/revisión verificado, revisa el archivo y utiliza
la política de ejecución/firma aprobada por tu organización. No se usa `iex`,
no se cambia la política de ejecución y no se instala WMF automáticamente.

En **PowerShell elevado** (5.1 o 7; el script adapta el motor automaticamente):

```powershell
# Sin argumentos: asistente de perfil y opciones; Enter audita.
.\windows-workstation-assistant.ps1

.\windows-workstation-assistant.ps1 -Mode Audit -Profile Academy
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Academy -WhatIf
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Academy -CreateRestorePoint
# Solo tras aprobar excepciones y probar aplicaciones antiguas:
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Legacy -DisableLegacyProtocols
```

`Apply` y `Restore` solicitan confirmación mediante `ShouldProcess`. `-WhatIf`
lee inventario y muestra el plan, sin crear logs, checkpoints, cuentas ni cambiar
configuración. `Audit` sí genera evidencia local, pero no cambia políticas.
`-Confirm:$false` sirve para un despliegue ya aprobado; no evita otras condiciones
como la revisión de equipo gestionado o la petición segura de contraseña.

## Qué cambia

| Área | Comportamiento |
|---|---|
| Seguridad | UAC y escritorio seguro, restricciones a contraseñas vacías remotas, AutoRun desactivado, tres perfiles de firewall habilitados sin borrar reglas; WDigest según versión |
| Protocolos | Corporate/Academy retiran SMBv1 cliente/servidor al reiniciar. Legacy lo conserva por defecto. `-DisableLegacyProtocols` retira además SSL 2/3 y TLS 1.0/1.1 de Schannel y habilita TLS 1.2 |
| Privacidad | Windows 10/11: mínimo nivel diagnóstico por edición, ID publicitario y sugerencias de consumo según soporte. Home/Pro no prometen diagnóstico cero. Se mantienen actualizaciones y protección |
| Arranque rápido | Desactiva **Windows Fast Startup**, desde Windows 8.1; conserva hibernación. BIOS Fast Boot es distinto y se revisa manualmente |
| Energía | Selecciona Equilibrado mediante GUID independiente del idioma. No altera tiempos de suspensión, batería, tapa ni planes OEM; se diagnostican según portátil/PC/desconocido |
| Sesiones | Corporate: bloqueo por inactividad a 15 min; Academy: 10 min (Windows 8.1+). Revisar clases, exámenes y accesibilidad |
| Animaciones | `-UserExperience` reduce animaciones de ventanas/barra y transparencia. Solo el HKCU del operador; no modifica otros perfiles ni el usuario predeterminado |
| Servicios | `-DisableOptionalServices` deshabilita el arranque de servicios Xbox/mapas presentes, con efecto tras reiniciar. No toca Defender, Update, BITS, RPC, Wi-Fi, impresión, búsqueda, SysMain, VPN ni utilidades OEM |
| Inicio de sesión | Inventaría arranque. `-DisableStartupName 'Nombre exacto'` elimina solo valores Run seleccionados (HKCU, HKLM y WOW6432Node), guardándolos para recuperación. No elimina ejecutables ni tareas |
| Restauración | `-CreateRestorePoint` solicita y comprueba un punto anterior al cambio; detecta reutilización de uno de las últimas 24 h. Si no hay punto válido, detiene la aplicación. No habilita protección automáticamente ni reduce cuotas |

La retirada de protocolos puede romper NAS, impresoras, autenticación o aplicaciones.
Las políticas Schannel no afectan implementaciones privadas de TLS (Java/OpenSSL).
`AllowTelemetry=0` no equivale a eliminar todas las comunicaciones de Microsoft.
La política de sugerencias puede no aplicarse en Home/Pro. Verificar política
efectiva, firewall y aplicaciones tras reiniciar; el registro no prueba cumplimiento.
No se promete mejora de rendimiento medida sin comparar antes/después.

## Usuarios, grupos y equipos gestionados

```powershell
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Academy -StandardUserName alumno01
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Academy -UserExperience -DisableOptionalServices
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Corporate -DisableStartupName 'Aplicacion revisada'
```

Una cuenta nueva recibe contraseña solicitada como `SecureString` (mínimo 14
caracteres y confirmación), cumple además la política de contraseña local y se
incorpora al grupo **Usuarios** mediante SID, independientemente del idioma.
No se reutilizan cuentas existentes ni se cambian sus contraseñas. Se crea
deshabilitada y se habilita después de asignar el grupo; un fallo intermedio
puede dejarla deshabilitada para revisión. La contraseña se entrega temporalmente
a la API WinNT, no se registra, no aparece en argumentos de procesos ni en archivos.

Se inventarían usuarios y grupos Administradores y Usuarios de escritorio remoto.
No se eliminan administradores automáticamente ni se concede acceso remoto.
Para clases: cuentas individuales; grupos por curso con ACL sobre sus carpetas;
profesores separados de administradores. El script no inventa carpetas compartidas,
permisos sobre datos existentes ni credenciales comunes para todo un aula.

En dominio o con indicios de inscripción MDM, Apply se bloquea salvo
`-AllowManaged`. Es una excepción explícita: **no detecta todos los gestores**
ni vence una GPO/Intune. Revisar `gpresult /r`, `dsregcmd /status` cuando exista,
LAPS, EDR, VPN y política corporativa. No usar estas excepciones para combatir
políticas centrales; publicar los ajustes apropiados desde el gestor.

## Evidencia y recuperación

Cada ejecución crea una carpeta privada para administradores/SYSTEM en
`%ProgramData%\WorkstationAssistant\fecha-id`:

- `inventory.clixml`: Windows, edición/build, fabricante/modelo/chasis, firmware,
  TPM/Secure Boot cuando se pueden consultar, usuarios, arranque y puntos existentes.
- `plan.csv`, `settings-audit.clixml`: ajustes propuestos y valores observados.
- `diagnostics.txt`: firewall efectivo, antivirus registrado, Defender cuando existe,
  servicios relevantes, espacio de discos, estado de cifrado y reinicio pendiente.
- `manual-checklist.txt`: firmware, drivers, seguridad, energía, restauración y entrega.
- `state.clixml` al aplicar: valor/tipo/ausencia original y destino, escrito **antes**
  de cada modificación y actualizado tras comprobarla. Contiene información local
  y puede contener comandos de inicio; protegerlo como documentación interna.

```powershell
.\windows-workstation-assistant.ps1 -Mode Restore -SnapshotPath 'C:\ProgramData\WorkstationAssistant\FECHA-ID\state.clixml' -WhatIf
.\windows-workstation-assistant.ps1 -Mode Restore -SnapshotPath 'C:\ProgramData\WorkstationAssistant\FECHA-ID\state.clixml'
```

Solo recuperar snapshots propios, íntegros y de confianza, del mismo equipo y
operador. Se restauran valores, tipos y ausencias originales y el plan de energía.
Las claves de registro vacías que se crearon pueden permanecer. Los cambios
posteriores de terceros se reportan como conflictos y se conservan. Si hay fallo
parcial, revisar el diario y recuperar; no se afirma atomicidad de todo el lote.
**Las cuentas nuevas y los puntos de restauración se conservan**: no se borran datos
de usuarios al recuperar ajustes. Las cuentas requieren revisión manual explícita.

## Entrega y aceptación

El checklist recomienda actualización OEM del modelo exacto, UEFI/Secure Boot,
TPM, virtualización según cursos y control del arranque externo. No escribe BIOS,
no borra TPM, no cambia AHCI/RAID/CSM y no activa BitLocker sin custodia de claves.
No usa una lista universal de servicios o programas para desinstalar.

Antes de desplegar: VM/imagen recuperable de cada versión/edición → Preflight →
Audit → WhatIf → Apply → reinicio → Audit → probar software/impresoras/VPN/AD →
Restore → reinicio → comprobar recuperación. Probar portátil con batería y AC,
Home y Pro, cuenta estándar, equipo gestionado y aplicación legado real.

El diario ayuda a evidenciar inventario, cambios y excepciones para un sistema de
gestión de calidad/seguridad. **No certifica ISO 9001, ISO 27001 ni ENS**. Políticas,
responsables, evaluación de riesgos, parches, copias y controles organizativos
requieren validación propia.

Pruebas automatizadas: planificación por versión/edición, ausencia vs valor cero,
arrays, idempotencia, diario antes de escritura, conflictos al recuperar y preflight.
No sustituyen pruebas reales en Windows: las pruebas unitarias simulan registro y
comandos administrativos; CI usa Windows Server para parser/funciones, no aplica
el endurecimiento al runner.

## Referencias

- [Baselines Microsoft](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [WMF y compatibilidad](https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf-overview)
- [Retirada de SMBv1](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Configuración TLS Schannel](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)
- [Diagnóstico por edición](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization)
- [Checkpoint-Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkpoint-computer?view=powershell-5.1)
- [Fast Startup y actualizaciones](https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/updates-not-install-with-fast-startup)

## Consola y deteccion automatica del motor

Windows 11 Pro es compatible aunque abras el script desde PowerShell 7. El
asistente detecta Core/arquitectura y continua en Windows PowerShell 5.1 usando
System32 o Sysnative. El SO se identifica despues con las API nativas. Conserva
arrays, switches, `-WhatIf`, `-Confirm:$false` y el codigo de salida del proceso.
No cambia la politica de ejecucion, no eleva privilegios automaticamente ni
instala motores; si falta Windows PowerShell muestra la ruta que falta. Hay que
usar el archivo `.ps1` guardado, no pegar su contenido en `iex`.

La consola agrupa la informacion por perfil: identidad del equipo, objetivo,
opciones, plan con valores pendientes/coincidentes y resultado. Los contadores
son comparaciones de registro, no una puntuacion de cumplimiento. La aplicacion
muestra cuatro fases; las rutas de informes y las tareas posteriores aparecen al
final. Un fallo no se presenta como una ejecucion completa.

- `-Detailed`: muestra rutas y nombres tecnicos sin imprimir valores ni comandos
  de arranque potencialmente sensibles.
- `-NoColor` o variable `NO_COLOR`: salida sin colores. La redireccion desactiva
  colores automaticamente; se usan etiquetas de texto y ancho adaptable.
- El menu acepta `s/n` y `y`, repregunta ante entradas invalidas y Enter conserva
  opciones previamente pasadas por parametros.

```powershell
.\windows-workstation-assistant.ps1 -Mode Audit -Profile Academy -NoColor
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Corporate -Detailed -WhatIf
```
