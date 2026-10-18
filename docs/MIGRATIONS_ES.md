# Centro de migraciones

`migration-assistant.ps1` es un asistente autónomo de consola en la raíz. Se ejecuta en Windows PowerShell 5.1 o PowerShell 7; las transferencias también pueden iniciarse desde PowerShell 7 en Linux con una fuente local/montada. No necesita Python ni clonar el repositorio. El menú de migración AD de Windows ofrece acceso al compañero si ambos scripts están juntos; descargarlos por la misma revisión evita mezclar versiones.

## Alcance y arquitectura

| Perfil | Implementado | Fuera de automatización |
|---|---|---|
| `Server2022To2025` | Inventario de SO, roles, volúmenes y servicios; detección de DC/clúster; procedimiento y comprobación de versión posterior | Instalación de SO, promoción/despromoción DC, FSMO, actualización de aplicaciones, aceptación y restauración |
| `UbuntuFiles` | Copia desde carpeta Windows/local/UNC a un remoto SFTP configurado; simulación y comparación del contenido | Instalar Ubuntu/Samba, traducir ACL/SID, sustituir AD/DNS/DHCP/IIS/SQL |
| `NextcloudFiles` | Copia a una carpeta de un remoto WebDAV configurado y comparación del contenido | Instalar Nextcloud, crear identidades, convertir ACL o importar versiones, enlaces compartidos y metadatos de aplicaciones |

Windows→Ubuntu es una migración por servicios. Windows Server→Nextcloud cubre el servicio de archivos/colaboración; Nextcloud no sustituye todo Windows Server. Para otros roles hay que añadir adaptadores con inventario, requisitos, ejecución, aceptación y reversión propios. Los asistentes AD existentes conservan sus herramientas de inventario, backups y migración de dominio. La PWA RabbitMole tiene otro repositorio y no se modifica aquí.

## Uso interactivo

```powershell
.\migration-assistant.ps1 -Mode Preflight
.\migration-assistant.ps1 -Mode Interactive
```

Elige perfil y carpeta de trabajo; después `Plan`, `Status`, `DryRun`, `Copy`, `Verify` o `VerifyUpgrade`. `Plan` exige una carpeta nueva y guarda `plan.json` con el procedimiento, inventario disponible e historial. `Status` muestra ese estado. No hay servidor web ni puerto de administración abierto. Los mensajes técnicos son en inglés y las preguntas del menú incluyen español.

Los ejemplos siguientes se ejecutan directamente, sin scripts de aplicación de cambios. Sigue la política de firma/ejecución de tu organización.

## Windows Server 2022 → 2025

Desde una consola elevada en el servidor origen:

```powershell
.\migration-assistant.ps1 -Mode Plan -Profile Server2022To2025 -Workspace C:\Migration\upgrade-2025
.\migration-assistant.ps1 -Mode Status -Workspace C:\Migration\upgrade-2025
```

El inventario debe completarse; los errores de acceso no se convierten en comprobaciones aprobadas. Se identifica 2022 por build 20348 y se señalan como bloqueos para la ruta in situ los roles AD DS y Failover Clustering. **No es una certificación de compatibilidad:** la lista requiere revisar edición, idioma, Core/Desktop Experience, hardware, espacio, reinicios pendientes, aplicaciones, drivers, licencia y soporte del fabricante. Los bloqueos se muestran y guardan; el programa no ejecuta Setup.

Para AD DS, crea nuevos DC 2025 y valida previamente niveles funcionales compatibles, esquema, replicación, DNS, catálogo global y restauración de estado del sistema. Transfiere FSMO de forma planificada y retira los antiguos solo después de aceptación. Usa `windows-ad-assistant.ps1 -Mode Migration` para las herramientas de dominio existentes. No automatizamos elevar niveles funcionales ni cambiar esquema.

Para un servidor miembro elegible: prueba la restauración de un backup completo, conserva evidencia fuera del servidor y acceso por consola, ensaya en laboratorio, programa una parada y detén/migra las VMs y aplicaciones. Inicia manualmente Setup desde medios aprobados; si no permite conservar archivos, configuración y aplicaciones, cancela. Azure y clústeres requieren procedimientos específicos.

Tras la actualización:

```powershell
.\migration-assistant.ps1 -Mode VerifyUpgrade -Workspace C:\Migration\upgrade-2025
```

Comprueba build 26100 y SO de servidor; guarda un inventario posterior. `OSVersionVerified` **solo confirma versión**, no salud de servicios. Prueba transacciones reales desde clientes, permisos, DNS, monitorización y backups. Ante fallo, aplica la restauración ensayada; no se promete downgrade automático.

## Archivos → Ubuntu o Nextcloud

1. Prepara el destino y sus usuarios/permisos/cuota. Instala una versión aprobada de `rclone` en el equipo que ejecutará el asistente.
2. Configura un remoto mediante `rclone config --config C:\Secure\rclone.conf`. Ubuntu: backend `sftp`, clave SSH y `known_hosts_file` validado. Nextcloud: backend `webdav`, `vendor=nextcloud`, URL HTTPS `https://cloud.example/remote.php/dav/files/USUARIO/` y contraseña de aplicación. No desactives comprobaciones TLS.
3. Protege la configuración y el workspace mediante ACL (o permisos Unix). No los pongas dentro de los datos que vas a copiar. La configuración nunca se incorpora al plan; se guarda su ruta y hash para detectar cambios. La revisión del transporte y de los permisos es responsabilidad del operador; la herramienta valida el tipo de backend, no certifica la configuración del servidor.
4. Reserva una subcarpeta exclusiva del destino. Prueba un piloto con los nombres, tamaños, sensibilidad a mayúsculas y accesos reales del entorno.

Ejemplo Nextcloud (sustituye rutas y nombre de remoto):

```powershell
.\migration-assistant.ps1 -Mode Plan -Profile NextcloudFiles -Source D:\Datos -Destination nc:Migracion/lote1 -ConfigPath C:\Secure\rclone.conf -Workspace C:\Migration\nextcloud-lote1
.\migration-assistant.ps1 -Mode DryRun -Workspace C:\Migration\nextcloud-lote1
# Revisa el log. Detén escritores o usa un snapshot consistente de solo lectura.
.\migration-assistant.ps1 -Mode Copy -Workspace C:\Migration\nextcloud-lote1 -BackupVerified -PermissionsReviewed -SourceFrozen -ConfirmDestination nc:Migracion/lote1
.\migration-assistant.ps1 -Mode Verify -Workspace C:\Migration\nextcloud-lote1 -SourceFrozen
.\migration-assistant.ps1 -Mode Status -Workspace C:\Migration\nextcloud-lote1
```

Para Ubuntu usa `-Profile UbuntuFiles -Destination ubuntu:staging/lote1`, con `ubuntu` configurado como SFTP. La carpeta destino es relativa al remoto configurado. El nombre de remoto admite letras, números, guion y guion bajo, debe empezar por letra y tener al menos dos caracteres. La ruta destino admite nombres sencillos, espacios internos y `/`; usa el piloto para detectar restricciones del servidor.

Las confirmaciones son declaraciones del administrador: el asistente no crea backups, no comprueba su restauración ni congela aplicaciones. No copies una base de datos activa como si fuera una carpeta: usa una exportación consistente específica del motor.

## Estado, reanudación y límites

- `Planned → Previewed → Copied → ContentVerified`. Cada comando guarda primero un estado `*Running`; un fallo controlado guarda `Failed`. Una interrupción brusca puede dejar `*Running`: revisa el log y repite `DryRun` y `Copy`. Un bloqueo exclusivo evita usar simultáneamente el mismo workspace. Nunca uses dos workspaces sobre la misma carpeta destino.
- `DryRun` contacta con el remoto y escribe logs locales; no copia datos. La simulación no reserva recursos ni garantiza cuota disponible cuando se ejecute la copia.
- `Copy` usa `rclone copy --immutable --checksum --create-empty-src-dirs`. No elimina el origen ni el destino, ni sobrescribe archivos detectados como distintos. Puede añadir archivos antes de fallar: no es una transacción. Para datos modificados utiliza un nuevo lote/carpeta y un nuevo plan; no es sincronización incremental mutable ni réplica continua.
- En SFTP se desactivan las sondas de shell y hashes remotos para evitar ejecutar comandos o modificar automáticamente la configuración. La comprobación fuerte se hace por descarga.
- Si un backend carece de hashes, la decisión de omitir un archivo puede basarse en tamaño. Por eso `Copied` no implica igualdad: `Verify` usa `rclone check --download` y falla ante diferencias, ausencias o archivos extra. Descarga contenido y puede consumir mucho tiempo/ancho de banda. No valida ACL, timestamps ni directorios vacíos.
- `ContentVerified` corresponde al instante de comprobación. Mantén el origen congelado hasta la aceptación/cambio de servicio; cualquier escritura posterior invalida esa evidencia. No se marca la migración empresarial como completada automáticamente.
- Los enlaces/junctions se rechazan para evitar omisiones silenciosas. No se preservan ACL NTFS, SID, ADS, semántica EFS, identidad de hard links, cuentas, GPO, comparticiones ni metadatos de Nextcloud. Exporta ACL/comparticiones aparte y define una política de permisos nueva y verificable.
- Las credenciales quedan en la configuración externa de rclone. Se rechazan variables `RCLONE_*` que alteren el comportamiento, salvo `RCLONE_CONFIG_PASS` para configuraciones cifradas. Los logs/planes contienen rutas, nombres de host y datos operativos: limita su acceso y retención.
- El estado está ligado al host origen y al hash de configuración. Si cambia el remoto/configuración, crea un plan nuevo. No se ejecutan comandos contenidos en JSON; no edites el estado para saltarte pasos. No existe un agente privilegiado que vigile cambios concurrentes del sistema de archivos.

## Aceptación y reversión

Antes del corte valida recuentos/contenido, acceso de usuarios con y sin permiso, cuotas, archivos grandes, aplicaciones cliente, DNS/URL, rendimiento, backups y restauración. Conserva el origen en solo lectura durante la ventana acordada. Antes de escrituras nuevas, puedes devolver los clientes al origen. Después de escrituras nuevas, reconcilia los cambios del destino antes de revertir para no perderlos. El asistente no borra datos ni ejecuta la reversión.

Nextcloud también permite una fase de coexistencia con almacenamiento externo SMB: conserva la dependencia del servidor Windows y no equivale a migrar los datos. Es una configuración manual alternativa, no ejecutada por este perfil.

## Pruebas y fuentes

`tools/verify_powershell.ps1` valida sintaxis y prueba destinos inválidos, bloqueos de copia, journal, exclusión mutua y reintentos sin operaciones administrativas. `tests/test_migration_transport.py` usa rclone real con SFTP/WebDAV en loopback y datos desechables: simulación, copia, corrupción del mismo tamaño, conflictos y recuperación. No sustituye ensayos con Windows Server, Ubuntu y Nextcloud reales ni valida un upgrade de SO.

Documentación consultada el 18 de octubre de 2026:

- [Actualización in situ de Windows Server](https://learn.microsoft.com/en-us/windows-server/get-started/upgrade-in-place)
- [Actualizar controladores de dominio](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/upgrade-domain-controllers)
- [Niveles funcionales AD](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/identifying-your-functional-level-upgrade)
- [rclone copy](https://rclone.org/commands/rclone_copy/), [check](https://rclone.org/commands/rclone_check/), [WebDAV/Nextcloud](https://rclone.org/webdav/), [SFTP](https://rclone.org/sftp/)
- [Nextcloud: almacenamiento externo](https://docs.nextcloud.com/server/stable/admin_manual/configuration_files/external_storage_configuration_gui.html)
