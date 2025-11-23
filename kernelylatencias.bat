@echo off
title Optimizador de Latencia y Kernel (Low Level Tweaks)
color 0b

echo ==================================================
echo    APLICANDO AJUSTES DE KERNEL Y LATENCIA
echo    (Excluyendo Red y GPU)
echo ==================================================
echo.

:: --- SECCION 1: GESTION DE MEMORIA Y KERNEL ---
echo [1/6] Configurando Memoria y Kernel...

:: Deshabilita la paginacion del ejecutivo (Kernel en RAM fisica)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f

:: Deshabilita la cache grande del sistema (Prioridad a Apps)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f

:: Deshabilita mitigaciones de Spectre/Meltdown para recuperar rendimiento (ADVERTENCIA DE SEGURIDAD)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f

:: Deshabilita aleatorizacion de memoria del kernel (ASLR) y protecciones extra
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f

:: --- SECCION 2: PRIORIDADES DEL PROCESADOR Y SCHEDULER ---
echo [2/6] Ajustando Prioridades de CPU y Hilos...

:: Win32PrioritySeparation (Valor 26 hexadecimal = 38 decimal, balance agresivo para foreground)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f

:: SystemResponsiveness (Reservar 0% CPU para sistema, 100% para juegos/media)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "0xffffffff" /f

:: Prioridades de Juegos y Multimedia
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f

:: Prioridad Critica para CSRSS (Subsistema visual)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f

:: --- SECCION 3: GESTION DE ENERGIA (C-STATES Y THROTTLING) ---
echo [3/6] Desactivando Ahorro de Energia Profundo...

:: Desactivar C-States y Power Throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "Attributes" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec" /v "Attributes" /t REG_DWORD /d "2" /f

:: Forzar maximo rendimiento en registro
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Cstates" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f

:: Desaparcar Nucleos (Core Parking OFF)
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
powercfg -setacvalueindex scheme_current sub_processor CPMAXCORES 100
powercfg -setactive scheme_current

:: --- SECCION 4: BCDEDIT Y TEMPORIZADORES (BOOT) ---
echo [4/6] Ajustando BCD y Temporizadores de Plataforma...

:: Usar temporizador de plataforma y desactivar tick dinamico (Crucial para latencia estable)
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
bcdedit /set tscsyncpolicy legacy
bcdedit /deletevalue useplatformclock 2>nul

:: Deshabilitar protecciones de arranque que causan latencia
bcdedit /set nx AlwaysOff
bcdedit /set bootux disabled

:: --- SECCION 5: DISPOSITIVOS Y MSI MODE ---
echo [5/6] Habilitando MSI Mode para dispositivos compatibles...

:: Bucle para forzar MSI Mode en controladores USB, AHCI, NVME, etc.
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\PCI" /s /f "PCI\VEN_" ^| findstr "HKEY"') do (
    reg add "%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1
)

:: Eliminar prioridades de dispositivo preestablecidas para permitir gestion nativa o manual
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "DevicePriority" /f >nul 2>&1

:: --- SECCION 6: SISTEMA DE ARCHIVOS Y SERVICIOS VARIOS ---
echo [6/6] Ajustes finales de Sistema de Archivos...

:: Evitar escritura en disco al solo leer archivos
fsutil behavior set disablelastaccess 1

:: Temporizador de alta resolucion global
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f

:: Desactivar DCOM (Comunicacion distribuida, reduce overhead)
reg add "HKLM\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f

:: Desactivar Mitigaciones via Powershell
powershell -Command "Set-ProcessMitigation -System -Disable DEP, StrictHandle, SEHOP" >nul 2>&1

@echo off
title Optimizador de Servicios y Telemetria (Archivo 3)
color 0e

echo ==================================================
echo    OPTIMIZACION DE SERVICIOS Y LIMPIEZA
echo    (Reduccion de procesos en segundo plano)
echo ==================================================
echo.

:: --- SECCION 1: DESHABILITAR TELEMETRIA Y RASTREO ---
echo [1/4] Desactivando Telemetria y Data Collection...

:: Deshabilitar servicio de seguimiento de diagnostico
sc stop DiagTrack >nul 2>&1
sc config DiagTrack start= disabled >nul 2>&1

:: Deshabilitar servicio de enrutamiento de mensajes push (WAP)
sc stop dmwappushservice >nul 2>&1
sc config dmwappushservice start= disabled >nul 2>&1

:: Deshabilitar Experiencias del usuario y Telemetria asociada
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f

:: --- SECCION 2: SERVICIOS INNECESARIOS (BLOATWARE) ---
echo [2/4] Deshabilitando servicios pesados e innecesarios...

:: SysMain (Superfetch) - A veces causa stuttering en SSDs rapidos o uso alto de CPU
sc stop SysMain >nul 2>&1
sc config SysMain start= disabled >nul 2>&1

:: Windows Search (Indexado) - Consume disco en segundo plano
sc stop WSearch >nul 2>&1
sc config WSearch start= disabled >nul 2>&1

:: Servicio de Mapas Descargados
sc stop MapsBroker >nul 2>&1
sc config MapsBroker start= disabled >nul 2>&1

:: Asistente de compatibilidad de programas (PcaSvc) - Reduce overhead al ejecutar juegos
sc stop PcaSvc >nul 2>&1
sc config PcaSvc start= disabled >nul 2>&1

:: Cliente de seguimiento de enlaces distribuidos (TrkWks) - Innecesario en PC domestico
sc stop TrkWks >nul 2>&1
sc config TrkWks start= disabled >nul 2>&1

:: Servicio de Informe de Errores de Windows (WerSvc)
sc stop WerSvc >nul 2>&1
sc config WerSvc start= disabled >nul 2>&1

:: Servicio de Geolocalizacion
sc stop lfsvc >nul 2>&1
sc config lfsvc start= disabled >nul 2>&1

:: --- SECCION 3: SERVICIOS DE XBOX Y JUEGO (OPCIONAL) ---
echo [3/4] Optimizando Servicios de Xbox (Manteniendo Auth)...

:: Se desactivan solo las grabaciones en segundo plano (GameDVR) que bajan FPS
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f

:: Mantener XboxGipSvc y XblAuthManager habilitados para que funcione el login y el mando
sc config XboxGipSvc start= demand >nul 2>&1
sc config XblAuthManager start= demand >nul 2>&1

:: --- SECCION 4: LIMPIEZA DE ARCHIVOS TEMPORALES ---
echo [4/4] Limpiando archivos basura del sistema...

:: Limpiar carpeta Temp de usuario
del /s /f /q "%temp%\*.*" >nul 2>&1
rd /s /q "%temp%" >nul 2>&1
mkdir "%temp%" >nul 2>&1

:: Limpiar carpeta Temp de Windows
del /s /f /q "C:\Windows\Temp\*.*" >nul 2>&1
rd /s /q "C:\Windows\Temp" >nul 2>&1
mkdir "C:\Windows\Temp" >nul 2>&1

:: Limpiar Prefetch (Reconstruye cache de inicio limpia)
del /s /f /q "C:\Windows\Prefetch\*.*" >nul 2>&1

@echo off
title Optimizador de Input Lag y UI (Archivo 4)
color 0a

echo ==================================================
echo    OPTIMIZACION DE INPUT LAG (RATON/TECLADO)
echo    Y RESPUESTA DE INTERFAZ (UI)
echo ==================================================
echo.

:: --- SECCION 1: RESPUESTA DE PERIFERICOS (BUFFER) ---
echo [1/4] Aumentando el buffer de datos de entrada...

:: Aumentar el tamaño de la cola de datos del teclado (Evita inputs perdidos si pulsas muchas teclas)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "100" /f

:: Aumentar el tamaño de la cola de datos del raton (Movimiento mas suave)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "100" /f

:: Ajustar prioridades de controladores de entrada (Si existen)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f

:: --- SECCION 2: RESPUESTA DEL ESCRITORIO (UI) ---
echo [2/4] Acelerando menus y ventanas...

:: MenuShowDelay: Tiempo que tarda un menu en aparecer al pasar el mouse (0 = instantaneo)
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f

:: Reducir tiempos de espera para matar aplicaciones colgadas (Cierre rapido)
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f

:: MouseHoverTime: Tiempo de respuesta al pasar el cursor sobre elementos
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "10" /f

:: --- SECCION 3: DESHABILITAR AYUDAS DE ACCESIBILIDAD (LAG) ---
echo [3/4] Desactivando Sticky Keys y Filter Keys (Causan input lag)...

:: Desactivar Sticky Keys (Teclas especiales)
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f

:: Desactivar Toggle Keys (Teclas de conmutacion)
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f

:: Desactivar Filter Keys (Teclas filtro) - Importante para evitar retraso al teclear rapido
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f

:: --- SECCION 4: EFECTOS VISUALES (REDUCIR CARGA GPU/CPU) ---
echo [4/4] Optimizando efectos visuales basicos...

:: Desactivar Transparencia de Windows (Ahorra recursos de GPU)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f

:: Desactivar "Agitar ventanas para minimizar" (Aero Shake)
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoWindowMinimizingShortcuts" /t REG_DWORD /d "1" /f

:: Deshabilitar optimizaciones de pantalla completa globales (A veces ayuda, a veces no - Configuración segura)
:: Esto evita que el "Game Bar" se superponga de forma agresiva
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f

echo.
echo ==================================================
echo    OPTIMIZACION DE INPUT COMPLETADA
echo    Reinicia para asegurar que el registro se actualice.
echo ==================================================
pause