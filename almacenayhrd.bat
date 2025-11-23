@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Optimizacion de Almacenamiento y Hardware (Sin Red/GPU/Kernel)
color 0B

:: Comprobacion de permisos de Administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Este script requiere privilegios de Administrador.
    pause
    exit /b
)

echo ============================================================================
echo                INICIANDO OPTIMIZACION DE ALMACENAMIENTO Y HARDWARE
echo ============================================================================

:: ----------------------------------------------------------------------------
:: 1. OPTIMIZACION DEL SISTEMA DE ARCHIVOS (NTFS / FSUTIL)
:: ----------------------------------------------------------------------------
echo [1/6] Configurando parametros de sistema de archivos...

:: Habilitar TRIM (0 = Habilitado para borrar notificaciones)
fsutil behavior set DisableDeleteNotify 0 >nul 2>&1
:: Deshabilitar la creacion de nombres cortos 8.3 (Mejora rendimiento en carpetas grandes)
fsutil behavior set disable8dot3 1 >nul 2>&1
:: Deshabilitar actualizacion de marca de tiempo de ultimo acceso (Reduce escrituras)
fsutil behavior set DisableLastAccess 1 >nul 2>&1
:: Aumentar la reserva de la MFT (Master File Table) para evitar fragmentacion
fsutil behavior set mftzone 4 >nul 2>&1
:: Deshabilitar compresion global (Mejora latencia de IO)
fsutil behavior set DisableCompression 1 >nul 2>&1
:: Deshabilitar encriptacion global (Mejora latencia de IO)
fsutil behavior set DisableEncryption 1 >nul 2>&1
:: Aumentar el uso de memoria para el sistema de archivos (Cache)
fsutil behavior set memoryusage 2 >nul 2>&1
:: Limpiar el journal USN en C:
fsutil usn deletejournal /D C: >nul 2>&1

:: Registro: Parametros NTFS adicionales
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsAllowExtendedCharacter8dot3Rename" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "IOReadBuffer" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "4" /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 2. OPTIMIZACION DE DISCOS (NVMe, SATA, STORAHCI, STORNVME)
:: ----------------------------------------------------------------------------
echo [2/6] Optimizando controladores NVMe y SATA...

:: Deshabilitar Link Power Management (LPM) y paradas de dispositivo (Evita micro-stuttering)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "DisableDeviceStop" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v "NoLPM" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v "BusyRetryCount" /t REG_DWORD /d "1" /f >nul 2>&1

:: Configuracion de profundidad de cola (Queue Depth)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v "QueueDepth" /t REG_DWORD /d "32" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "QueueDepth" /t REG_DWORD /d "32" /f >nul 2>&1

:: Optimizaciones especificas para NVMe (Latencia y rendimiento)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "DisableThrottling" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "EnableHighPriority" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "CompletionQueueSize" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "SubmissionQueueSize" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "AutonomousPowerStateTransition" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IoQueuesPerCore" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "MaxIoQueues" /t REG_DWORD /d "16" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "EnableLatencyControl" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "LowLatencyMode" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "ThermalThrottling" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "WriteCacheEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "EnableVolatileWriteCache" /t REG_DWORD /d "1" /f >nul 2>&1
:: Alineacion de sectores forzada para NVMe (4K)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "ForcedPhysicalSectorSizeInBytes" /t REG_MULTI_SZ /d "* 4096" /f >nul 2>&1

:: Tratar dispositivos SATA como internos (Evita que aparezcan como expulsables)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "TreatAsInternalPort" /t REG_MULTI_SZ /d "0\00\01\02\03\04\05\06" /f >nul 2>&1

:: Deshabilitar gestiones de energia de puerto ocioso (StorPort)
for /f "tokens=*" %%s in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /S /F "StorPort" 2^>nul ^| findstr /e "StorPort"') do (
    reg add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "%%s" /v "IdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
)

:: Deshabilitar latencia de IO capada
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "IoLatencyCap" 2^>nul ^| FINDSTR /V "IoLatencyCap"') DO (
    REG ADD "%%a" /F /V "IoLatencyCap" /T REG_DWORD /d "0" >NUL 2>&1
)

:: ----------------------------------------------------------------------------
:: 3. OPTIMIZACION DE USB Y PERIFERICOS (Energia y Latencia)
:: ----------------------------------------------------------------------------
echo [3/6] Configurando energia para USB y dispositivos...

:: Deshabilitar suspension selectiva USB en registro
reg add "HKLM\SYSTEM\CurrentControlSet\Services\usbuhci" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\usbhub" /v "DisableSelectiveSuspend" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\hidusb\Parameters" /v "EnablePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1

:: Deshabilitar ahorro de energia para todos los HUBs USB
for /f %%a in ('WMIC PATH Win32_USBHub GET DeviceID^| FINDSTR /L "VID_"') do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /f /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d 0 >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /f /v "SelectiveSuspendOn" /t REG_DWORD /d 0 >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /f /v "DeviceSelectiveSuspended" /t REG_DWORD /d 0 >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /f /v "SelectiveSuspendEnabled" /t REG_DWORD /d 0 >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /f /v "AllowIdleIrpInD3" /t REG_DWORD /d 0 >nul 2>&1
)

:: Aplicar Message Signaled Interrupts (MSI) para controladores USB e IDE (Reduce latencia de interrupciones)
for /f %%a in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "VEN_"') do reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1

:: Deshabilitar notificaciones de errores USB en Shell
reg add "HKCU\SOFTWARE\Microsoft\Shell\USB" /v "NotifyOnUsbErrors" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Shell\USB" /v "NotifyOnWeakCharger" /t REG_DWORD /d "0" /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 4. CACHE, MEMORIA DE DISCO Y SERVICIOS RELACIONADOS
:: ----------------------------------------------------------------------------
echo [4/6] Ajustando cache de disco y servicios de indexacion...

:: LargeSystemCache: 1 (Optimiza para throughput de archivos, util para discos rapidos)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f >nul 2>&1
:: DisablePagingExecutive: 1 (Mantiene drivers en RAM, evita paginacion al disco)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >nul 2>&1
:: Limite de bloqueo de paginas IO (Buffer)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "268435456" /f >nul 2>&1
:: No verificar drivers (Acelera IO)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f >nul 2>&1

:: Deshabilitar Servicios de Indexacion y Superfetch (Reduce uso de disco en segundo plano)
:: SysMain (Superfetch)
sc config "SysMain" start= disabled >nul 2>&1
sc stop "SysMain" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: Windows Search (Indexador)
sc config "WSearch" start= disabled >nul 2>&1
sc stop "WSearch" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: Configuracion de Prefetch en registro (Deshabilitar)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f >nul 2>&1

:: Storage Sense (Sentido de almacenamiento - Deshabilitar mantenimiento automatico de disco que causa IO)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseGlobal" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense" /v "AllowedTrayType" /t REG_DWORD /d "0" /f >nul 2>&1

:: Deshabilitar FileHistory (Copias de seguridad automaticas locales)
sc config fhsvc start= disabled >nul 2>&1
net stop fhsvc >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 5. GESTION DE ENERGIA (DISCO Y HIBERNACION)
:: ----------------------------------------------------------------------------
echo [5/6] Configurando plan de energia para almacenamiento...

:: Deshabilitar Hibernacion (Libera espacio hiberfil.sys y evita escrituras al apagar)
powercfg -h off >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >nul 2>&1

:: Establecer tiempos de apagado de disco a 0 (Nunca apagar disco)
powercfg -change -disk-timeout-ac 0 >nul 2>&1
powercfg -change -disk-timeout-dc 0 >nul 2>&1

:: Configurar atributos ocultos de energia para maximo rendimiento de disco
for /f "tokens=4" %%g in ('powercfg -getactivescheme') do set "UP_GUID=%%g"
:: Hard Disk Idle -> 0
powercfg /setacvalueindex %UP_GUID% SUB_DISK 6738e2c4-e8a5-4a42-b16a-e040e7e8eb78 0 >nul 2>&1
powercfg /setdcvalueindex %UP_GUID% SUB_DISK 6738e2c4-e8a5-4a42-b16a-e040e7e8eb78 0 >nul 2>&1
:: NVMe Power Override -> 0 (Max Performance)
powercfg /setacvalueindex %UP_GUID% SUB_DISK DISKNVMEPOWERRIDE 0 >nul 2>&1
:: USB Selective Suspend -> 0 (Disabled)
powercfg /setacvalueindex %UP_GUID% SUB_USB 2a737441-1930-4402-8d77-b2bebba308a3 0 >nul 2>&1
:: PCI Express Link State Power Management -> 0 (Off/Max Performance - Vital para NVMe)
powercfg /setacvalueindex %UP_GUID% SUB_PCIEXPRESS ASPM 0 >nul 2>&1
powercfg -setactive %UP_GUID% >nul 2>&1

:: ----------------------------------------------------------------------------
:: 6. TAREAS PROGRAMADAS Y LIMPIEZA (Mantenimiento de Disco)
:: ----------------------------------------------------------------------------
echo [6/6] Gestionando tareas de mantenimiento de disco...

:: Deshabilitar Desfragmentacion Automatica (Mejor gestionarlo manualmente o dejar que el controlador del SSD lo maneje)
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledOptimize" /Disable >nul 2>&1
@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Optimizacion Avanzada de Almacenamiento y Perifericos (Extracto 2.bat)
color 0B

:: Verificacion de Permisos
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requiere permisos de Administrador.
    pause
    exit /b
)

echo ============================================================================
echo      OPTIMIZACION DE HARDWARE Y ALMACENAMIENTO (Extracto Limpio)
echo ============================================================================

:: ----------------------------------------------------------------------------
:: 1. OPTIMIZACION AVANZADA DE ALMACENAMIENTO (NVMe & SATA)
:: ----------------------------------------------------------------------------
echo [1/5] Aplicando configuraciones avanzadas para controladores de disco...

:: --- General Storage Tweaks --- [Fuente: 100, 101]
:: Deshabilitar contadores de rendimiento de disco (ligera mejora de overhead)
diskperf -N >nul 2>&1
:: No borrar el archivo de paginacion al apagar (Acelera el apagado)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f >nul 2>&1

:: --- NVMe Optimizations (stornvme) --- [Fuente: 98-99]
:: Deshabilitar transiciones de energia autonomas (Evita latencia al despertar el disco)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "AutonomousPowerStateTransition" /t REG_DWORD /d "0" /f >nul 2>&1
:: Deshabilitar modo de energia inactivo
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /t REG_DWORD /d "0" /f >nul 2>&1
:: Optimizacion de colas de E/S (Queue Depth) para SSDs modernos
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "QueueDepth" /t REG_DWORD /d "32" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IoQueuesPerCore" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "MaxIoQueues" /t REG_DWORD /d "16" /f >nul 2>&1
:: Forzar modo de baja latencia y deshabilitar control de latencia dinámico
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "EnableLatencyControl" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "LowLatencyMode" /t REG_DWORD /d "1" /f >nul 2>&1
:: Deshabilitar Thermal Throttling (PRECAUCION: Solo si tienes buena refrigeracion, mejora rendimiento sostenido)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "ThermalThrottling" /t REG_DWORD /d "0" /f >nul 2>&1
:: Habilitar cache de escritura y alineacion de sectores
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "WriteCacheEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "ForcedPhysicalSectorSizeInBytes" /t REG_MULTI_SZ /d "* 4096" /f >nul 2>&1

:: --- SATA/AHCI Optimizations (storahci) --- [Fuente: 97-98]
:: Deshabilitar parada del dispositivo
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "DisableDeviceStop" /t REG_DWORD /d "1" /f >nul 2>&1
:: Tratar puertos 0-7 como internos (Soluciona iconos de "Expulsar hardware" en discos fijos)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "TreatAsInternalPort" /t REG_MULTI_SZ /d "0\00\01\02\03\04\05\06\07" /f >nul 2>&1
:: Profundidad de cola para SATA
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v "QueueDepth" /t REG_DWORD /d "32" /f >nul 2>&1

:: --- Power Management for Storage --- [Fuente: 38, 96-97]
:: Deshabilitar HIPM, DIPM y ALPM (Ahorro de energia de enlace) para evitar micro-cortes
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "EnableHIPM" 2^>nul ^| FINDSTR /V "EnableHIPM"') DO (
    REG ADD "%%a" /F /V "EnableHIPM" /T REG_DWORD /d "0" >NUL 2>&1
    REG ADD "%%a" /F /V "EnableDIPM" /T REG_DWORD /d "0" >NUL 2>&1
    REG ADD "%%a" /F /V "EnableHDDParking" /T REG_DWORD /d "0" >NUL 2>&1
)
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "EnableALPM" 2^>nul ^| FINDSTR /V "EnableALPM"') DO (
    REG ADD "%%a" /F /V "EnableALPM" /T REG_DWORD /d "0" >NUL 2>&1
)

:: ----------------------------------------------------------------------------
:: 2. GESTION DE MEMORIA I/O (Calculo Dinamico)
:: ----------------------------------------------------------------------------
echo [2/5] Calculando y optimizando limites de I/O en RAM... [Fuente: 110]

:: LargeSystemCache (Optimiza la cache del sistema para transferencia de archivos)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f >nul 2>&1
:: DontVerifyRandomDrivers (Reduce overhead en I/O, usar con precaucion pero mejora rendimiento)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f >nul 2>&1

:: Calculo de IoPageLockLimit basado en RAM total
:: (Permite operaciones de I/O más grandes sin paginar al disco)
for /f %%i in ('powershell -Command "(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize"') do set RAM_KB=%%i
set /a IOPAGELOCKLIMIT=%RAM_KB% * 1024
if %IOPAGELOCKLIMIT% GTR 0 (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "%IOPAGELOCKLIMIT%" /f >nul 2>&1
    echo    - IoPageLockLimit establecido a: %IOPAGELOCKLIMIT% bytes
)

:: ----------------------------------------------------------------------------
:: 3. OPTIMIZACION DE USB Y PERIFERICOS DE ENTRADA
:: ----------------------------------------------------------------------------
echo [3/5] Optimizando controladores USB y dispositivos de entrada...

:: Habilitar MSI (Message Signaled Interrupts) para controladores USB [Fuente: 41]
:: Reduce la carga de CPU y latencia para dispositivos USB
for /f %%a in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "VEN_"') do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1
)

:: Habilitar MSI para controladores IDE/SATA [Fuente: 41, 97]
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID 2^>nul ^| findstr /L "PCI\VEN_"') do (
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1
    reg delete "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
)

:: Aumentar el tamaño de la cola de datos para Teclado y Mouse [Fuente: 141]
:: (Evita perdida de input bajo carga extrema de CPU)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "100" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "100" /f >nul 2>&1
:: Prioridad de hilos para controladores de entrada [Fuente: 80, 103]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\USBXHCI\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 4. SISTEMA DE ARCHIVOS (FSUTIL & REGISTRO)
:: ----------------------------------------------------------------------------
echo [4/5] Aplicando configuraciones finales de NTFS... [Fuente: 101, 189]

reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "4" /f >nul 2>&1
fsutil behavior set Disable8dot3 1 >nul 2>&1
fsutil behavior set MftZone 4 >nul 2>&1
fsutil behavior set DisableCompression 1 >nul 2>&1
fsutil behavior set DisableEncryption 1 >nul 2>&1
:: Asegurar que TRIM esta activado (0 = Activado)
fsutil behavior set DisableDeleteNotify 0 >nul 2>&1

:: ----------------------------------------------------------------------------
:: 5. SERVICIOS Y MANTENIMIENTO DE DISCO
:: ----------------------------------------------------------------------------
echo [5/5] Gestionando servicios de indexacion y mantenimiento...

:: Deshabilitar SysMain (Superfetch) - Reduce lectura/escritura de fondo [Fuente: 11]
sc config SysMain start= disabled >nul 2>&1
net stop SysMain >nul 2>&1
:: Deshabilitar Windows Search (Indexador) [Fuente: 51]
sc config WSearch start= disabled >nul 2>&1
net stop WSearch >nul 2>&1
:: Deshabilitar servicio de Rastreo de Diagnosticos (DiagTrack) - Reduce escritura de logs [Fuente: 44]
sc config DiagTrack start= disabled >nul 2>&1
net stop DiagTrack >nul 2>&1

:: Deshabilitar tareas programadas de desfragmentacion y diagnostico de disco [Fuente: 46, 170]
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledOptimize" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /Disable >nul 2>&1

@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Optimizacion DMA, Input y Almacenamiento (Extracto 3.bat)
color 0B

:: Verificacion de permisos administrativos
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo =================================================================
    echo  ERROR: Este script requiere privilegios de Administrador.
    echo  Por favor, clic derecho y "Ejecutar como administrador".
    echo =================================================================
    pause
    exit /b
)

echo ============================================================================
echo      OPTIMIZACION DE HARDWARE: DMA, INPUT Y ALMACENAMIENTO
echo ============================================================================

:: ----------------------------------------------------------------------------
:: 1. OPTIMIZACION DE CONTROLADORES DE ALMACENAMIENTO (DMA & POWER)
:: ----------------------------------------------------------------------------
echo [1/5] Configurando controladores SATA/NVMe y gestion DMA...

:: Deshabilitar la compatibilidad de reasignacion DMA (DmaRemappingCompatible)
:: Esto puede reducir la latencia en controladores que no necesitan virtualizacion I/O estricta.
:: [Fuente: 167]
reg add "HKLM\System\ControlSet001\Services\storahci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Services\stornvme\Parameters\Device" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Services\stornvme\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul 2>&1

:: Deshabilitar la gestion de energia en reposo para StorPort (Controladores de almacenamiento)
:: [Fuente: 158]
for /f "tokens=*" %%s in ('reg query "HKLM\System\CurrentControlSet\Enum" /S /F "StorPort" ^| findstr /e "StorPort"') do (
    reg add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
)

:: Deshabilitar HIPM/DIPM (Administracion de energia de enlace) y Capado de Latencia I/O
:: [Fuente: 162]
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "EnableHIPM" 2^>nul ^| FINDSTR /V "EnableHIPM"') DO (
    REG ADD "%%a" /F /V "EnableHIPM" /T REG_DWORD /d "0" >NUL 2>&1
    REG ADD "%%a" /F /V "EnableDIPM" /T REG_DWORD /d "0" >NUL 2>&1
    REG ADD "%%a" /F /V "EnableHDDParking" /T REG_DWORD /d "0" >NUL 2>&1
)
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "IoLatencyCap" 2^>nul ^| FINDSTR /V "IoLatencyCap"') DO (
    REG ADD "%%a" /F /V "IoLatencyCap" /T REG_DWORD /d "0" >NUL 2>&1
)

:: ----------------------------------------------------------------------------
:: 2. GESTION DE MEMORIA VIRTUAL Y CACHE DE ARCHIVOS
:: ----------------------------------------------------------------------------
echo [2/5] Optimizando gestion de memoria y cache de disco...

:: Deshabilitar paginacion del ejecutivo (Mantiene el kernel en RAM) [Fuente: 193]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >nul 2>&1
:: Limpiar archivo de paginacion al apagar (Seguridad y prevencion de corrupcion) [Fuente: 193]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f >nul 2>&1
:: Deshabilitar LargeSystemCache (En este script se deshabilita para priorizar apps sobre cache de archivos) [Fuente: 193]
:: Nota: El archivo 3.bat lo establece en 0, a diferencia del 1.bat. Respetamos la fuente 3.bat aqui.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f >nul 2>&1
:: Aumentar limite de bloqueo de paginas I/O [Fuente: 193]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "16710656" /f >nul 2>&1
:: Deshabilitar combinacion de paginas de memoria (Reduce overhead de CPU/Disco) [Fuente: 139]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d "1" /f >nul 2>&1
powershell -Command "Disable-MMAgent -PageCombining" >nul 2>&1
powershell -Command "Disable-MMAgent -MemoryCompression" >nul 2>&1

:: ----------------------------------------------------------------------------
:: 3. OPTIMIZACION DE DISPOSITIVOS DE ENTRADA (Teclado/Mouse) Y RESPUESTA
:: ----------------------------------------------------------------------------
echo [3/5] Ajustando latencia de perifericos y tiempos de espera...

:: Ajustes de respuesta de teclado [Fuente: 159]
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "DelayBeforeAcceptance" /t REG_SZ /d "0" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatDelay" /t REG_SZ /d "500" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatRate" /t REG_SZ /d "33" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "BounceTime" /t REG_SZ /d "0" /f >nul 2>&1

:: Deshabilitar funciones de accesibilidad que pueden causar input lag [Fuente: 159]
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1

:: Reducir tiempos de espera para cerrar aplicaciones (Mejora sensacion de rapidez) [Fuente: 200, 202]
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d "0" /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 4. OPTIMIZACION DE USB (Controladores)
:: ----------------------------------------------------------------------------
echo [4/5] Configurando controladores USB...

:: Deshabilitar compatibilidad de reasignacion DMA para USB (Mejora estabilidad/latencia en algunos sistemas)
:: [Fuente: 167]
reg add "HKLM\System\ControlSet001\Services\USBXHCI\Parameters" /v "DmaRemappingCompatibleSelfhost" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 5. SERVICIOS Y SISTEMA DE ARCHIVOS
:: ----------------------------------------------------------------------------
echo [5/5] Deshabilitando hibernacion y servicios de indexado...

:: Deshabilitar Hibernacion [Fuente: 166]
powercfg -h off >nul 2>&1

:: Deshabilitar SysMain (Superfetch) y Prefetch [Fuente: 140, 193]
:: Esto reduce la carga en disco constante por analisis de patrones de uso.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >nul 2>&1
sc config "SysMain" start= disabled >nul 2>&1
sc stop "SysMain" >nul 2>&1

:: Deshabilitar "Ultimo Acceso" en sistema de archivos (Evita escrituras innecesarias) [Fuente: 163]
fsutil behavior set disablelastaccess 1 >nul 2>&1

:: Deshabilitar servicio de rastreo de diagnosticos (Reduce I/O de logs) [Fuente: 196]
sc config "DiagTrack" start= disabled >nul 2>&1
sc stop "DiagTrack" >nul 2>&1

@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Optimizacion Hardware y Almacenamiento (Extracto 4.bat)
color 0B

:: Verificacion de Permisos
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Este script requiere permisos de Administrador.
    pause
    exit /b
)

echo ============================================================================
echo      OPTIMIZACION DE HARDWARE Y ALMACENAMIENTO (Extracto 4)
echo ============================================================================

:: ----------------------------------------------------------------------------
:: 1. OPTIMIZACION PROFUNDA DE NVMe Y CONTROLADORES
:: ----------------------------------------------------------------------------
echo [1/5] Aplicando configuraciones de baja latencia para NVMe/SATA...

:: Optimizacion de parametros del dispositivo NVMe [Fuente: 551]
:: Deshabilita el throttling (estrangulamiento) por energia o temperatura
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "DisableThrottling" /t REG_DWORD /d "1" /f >nul 2>&1
:: Fuerza alta prioridad para interrupciones del disco
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "EnableHighPriority" /t REG_DWORD /d "1" /f >nul 2>&1
:: Aumenta el tamaño de las colas de comandos (Mejora IOPS en cargas pesadas)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "CompletionQueueSize" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device" /v "SubmissionQueueSize" /t REG_DWORD /d "64" /f >nul 2>&1

:: Ajustes SATA (storahci) [Fuente: 550]
:: Tratar puertos como internos y aumentar reintentos si el disco esta ocupado
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v "TreatAsInternalPort" /t REG_MULTI_SZ /d "0\00\01\02\03\04\05" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v "BusyRetryCount" /t REG_DWORD /d "1" /f >nul 2>&1
:: Deshabilitar LPM (Link Power Management) especificamente
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v "NoLPM" /t REG_DWORD /d "1" /f >nul 2>&1

:: Aumentar tiempo de espera para discos (Evita desconexiones en spin-up lento) [Fuente: 551]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Disk" /v "TimeOutValue" /t REG_DWORD /d "200" /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 2. GESTION DE ENERGIA PCI Y USB (Latencia Cero)
:: ----------------------------------------------------------------------------
echo [2/5] Deshabilitando ahorro de energia en buses PCI y USB...

:: Deshabilitar ASPM (Active State Power Management) en PCIe [Fuente: 550]
:: Esto evita que el bus PCIe entre en reposo, reduciendo la latencia de acceso.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PnP\Pci" /v "DisablePciExpressASPM" /t REG_DWORD /d "1" /f >nul 2>&1

:: Deshabilitar sondeo "caliente" (Warm Poll) en PnP para reducir uso de CPU [Fuente: 487]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PnP" /v "DisableWarmPoll" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PnP" /v "FastDeviceDetect" /t REG_DWORD /d "1" /f >nul 2>&1

:: Bucle para deshabilitar energia en TODOS los hubs USB detectados [Fuente: 472-473, 510]
for /f "tokens=*" %%i in ('powershell -Command "Get-PnpDevice -Class 'USB' | Select-Object -ExpandProperty DeviceID" ^| findstr "USB\VID_"') do (
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f >nul 2>&1
)

:: Deshabilitar suspension selectiva en servicios de controladores USB [Fuente: 486]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\usbuhci" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\usbhub" /v "DisableSelectiveSuspend" /t REG_DWORD /d "1" /f >nul 2>&1

:: Deshabilitar suspension selectiva USB en Configuracion de Energia Global [Fuente: 417]
for /f "tokens=4" %%g in ('powercfg -getactivescheme') do set "UP_GUID=%%g"
powercfg /setacvalueindex %UP_GUID% 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >nul 2>&1
powercfg /setdcvalueindex %UP_GUID% 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >nul 2>&1
powercfg /setactive %UP_GUID% >nul 2>&1

:: ----------------------------------------------------------------------------
:: 3. OPTIMIZACION DE DISPOSITIVOS DE ENTRADA (HID)
:: ----------------------------------------------------------------------------
echo [3/5] Ajustando buffers de teclado y mouse...

:: Aumentar el tamaño de la cola de datos para Teclado y Mouse [Fuente: 552]
:: Valor 50 -> 100. Permite procesar mas eventos simultaneos sin "comerse" clicks.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "100" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "100" /f >nul 2>&1

:: Ajustar tasa de muestreo PS/2 (si aplica) [Fuente: 428]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters" /v "SampleRate" /t REG_DWORD /d "200" /f >nul 2>&1

:: Deshabilitar visualizacion de gestos/contactos (Reduce overhead grafico en input) [Fuente: 419]
reg add "HKCU\Control Panel\Cursors" /v "ContactVisualization" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Cursors" /v "GestureVisualization" /t REG_DWORD /d "0" /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 4. SISTEMA DE ARCHIVOS Y GESTION DE MEMORIA I/O
:: ----------------------------------------------------------------------------
echo [4/5] Configurando sistema de archivos NTFS y Buffers...

:: Aumentar Buffer de Lectura I/O [Fuente: 593]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "IOReadBuffer" /t REG_DWORD /d "256" /f >nul 2>&1

:: Configuraciones NTFS estandar optimizadas [Fuente: 558-559]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsAllowExtendedCharacter8dot3Rename" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
:: Deshabilitar compresion de memoria (Mejora latencia a costa de usar mas RAM) [Fuente: 559]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisableCompression" /t REG_DWORD /d "1" /f >nul 2>&1
:: Deshabilitar recorte de archivo de paginacion (Reduce operaciones de disco) [Fuente: 551]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageFileTrims" /t REG_DWORD /d "1" /f >nul 2>&1

:: Configuraciones FSUTIL [Fuente: 559, 478]
fsutil behavior set DisableDeleteNotify 0 >nul 2>&1
fsutil behavior set disable8dot3 1 >nul 2>&1
fsutil behavior set disablelastaccess 1 >nul 2>&1
fsutil behavior set memoryusage 2 >nul 2>&1
fsutil resource setautoreset true C: >nul 2>&1

:: ----------------------------------------------------------------------------
:: 5. MANTENIMIENTO Y SERVICIOS DE DISCO
:: ----------------------------------------------------------------------------
echo [5/5] Deshabilitando servicios innecesarios de disco...

:: Deshabilitar SysMain (Superfetch) [Fuente: 367]
sc config "SysMain" start= disabled >nul 2>&1
sc stop "SysMain" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: Deshabilitar Windows Search [Fuente: 368]
sc config "WSearch" start= disabled >nul 2>&1
sc stop "WSearch" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: Deshabilitar Storage Sense (Sentido de almacenamiento) [Fuente: 589]
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseGlobal" /t REG_DWORD /d "0" /f >nul 2>&1

:: Deshabilitar Power Throttling (Estrangulamiento de energia) [Fuente: 585]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >nul 2>&1

:: Deshabilitar Hibernacion [Fuente: 359]
powercfg -h off >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >nul 2>&1

:: Limpieza de cache de iconos y thumbnails (Soluciona problemas graficos menores en explorador) [Fuente: 452]
del /f /q "%LocalAppData%\Microsoft\Windows\Explorer\iconcache*" >nul 2>&1
del /f /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache*" >nul 2>&1

echo.
echo ============================================================================
echo           OPTIMIZACION DE HARDWARE (Extracto 4) COMPLETADA
echo ============================================================================
echo Por favor, reinicia tu sistema.
pause
exit