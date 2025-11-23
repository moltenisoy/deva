:: ============================================================================
:: EXTRACTO DE AJUSTES DE GPU Y GRÁFICOS - ARCHIVO: 1.BAT
:: ============================================================================

:: ----------------------------------------------------------------------------
:: 1. PLANIFICACIÓN DE GPU Y PRIORIDADES (MULTIMEDIA SYSTEM PROFILE)
:: ----------------------------------------------------------------------------
:: Estas claves indican a Windows que dedique la mayor cantidad de ciclos de GPU a los juegos.

:: Establece la prioridad de la GPU a 8 (alta) para juegos
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1

:: Ajustes similares para otros perfiles multimedia para asegurar que no roben prioridad,
:: o para asegurar rendimiento en streaming (Capture/Distribution)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul 2>&1

:: Configuración de preferencias de GPU de usuario (Alto rendimiento)
reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "GpuPreference" /t REG_DWORD /d 2 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 2. CONFIGURACIÓN DE CONTROLADORES Y HARDWARE SCHEDULING
:: ----------------------------------------------------------------------------

:: Habilita "Hardware Accelerated GPU Scheduling" (HAGS)
:: Valor 2 = Activado
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f >nul 2>&1

:: Configuración TDR (Timeout Detection and Recovery)
:: ADVERTENCIA: Esto evita que Windows reinicie el driver si la GPU deja de responder. 
:: Puede causar congelamientos totales del sistema en lugar de un parpadeo de pantalla.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d 60 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDdiDelay" /t REG_DWORD /d 60 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitTime" /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitCount" /t REG_DWORD /d 0 /f >NUL 2>&1

:: Deshabilitar Preemption (Interrupción de tareas gráficas)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "EnablePreemption" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f >nul 2>&1

:: Prioridad de hilos (Threads) para drivers específicos
:: NVIDIA
reg add "HKLM\SYSTEM\CurrentControlSet\services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
:: AMD
reg add "HKLM\SYSTEM\CurrentControlSet\services\amdkmdap\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
:: DirectX Kernel
reg add "HKLM\SYSTEM\CurrentControlSet\services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
:: Intel Graphics (igfx) - Ajustes específicos
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "IncreaseFixedSegment" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f >nul 2>&1

:: Deshabilitar aceleración de hardware en frameworks antiguos (WPF/Avalon) para evitar conflictos
reg add "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "MaxMultisampleType" /t REG_DWORD /d "0" /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 3. DESKTOP WINDOW MANAGER (DWM) Y EFECTOS VISUALES
:: ----------------------------------------------------------------------------
:: Reducción de carga en la GPU eliminando efectos de escritorio.

:: Prioridad del proceso DWM (Gestor de ventanas)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 0 /f >nul 2>&1

:: Desactivar transparencias, Aero Peek y animaciones
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAnimations" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableTransparency" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OneCoreNoComposition" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "5" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "ForceDoubleBuffer" /t REG_DWORD /d "1" /f >nul 2>&1

:: Ajustes de rendimiento visual (Ajustar para mejor rendimiento)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 2 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 4. GAMEDVR Y GAMEBAR (GRABACIÓN EN SEGUNDO PLANO)
:: ----------------------------------------------------------------------------
:: Deshabilitar estas funciones libera VRAM y ciclos de GPU.

reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 1 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 5. ENERGÍA Y INTERFAZ (PCIe/MSI Mode)
:: ----------------------------------------------------------------------------

:: Desactivar ASPM (Active State Power Management) para PCIe - Evita latencia al cambiar estados de energía
powercfg -setacvalueindex %UP_GUID% SUB_PCIEXPRESS ASPM 0 >nul 2>&1
powercfg -setdcvalueindex %UP_GUID% SUB_PCIEXPRESS ASPM 0 >nul 2>&1

:: Desactivar apagado de video/pantalla
powercfg -setacvalueindex %UP_GUID% SUB_VIDEO VIDEOIDLE 0 >nul 2>&1

:: Intentar activar MSI Mode (Message Signaled Interrupts) para controladores de video
for /f %%a in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "VEN_"') do reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1

:: ============================================================================
:: EXTRACTO DE AJUSTES DE GPU Y GRÁFICOS - ARCHIVO: 2.BAT
:: ============================================================================

:: ----------------------------------------------------------------------------
:: 1. CONFIGURACIÓN ESPECÍFICA DE DRIVERS (NVIDIA / AMD / INTEL / DXGK)
:: ----------------------------------------------------------------------------

:: NVIDIA: Desactivar Write Combining (Puede mejorar rendimiento en ciertas cargas, riesgo de artifacts)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d 1 /f >nul 2>&1

:: NVIDIA: Desactivar Preemption (Evita que el sistema interrumpa a la GPU para otras tareas)
:: ADVERTENCIA: Esto reduce la latencia pero si un juego exige el 100%, el escritorio se congelará.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d 1 /f >nul 2>&1

:: NVIDIA: Prioridad de hilos del driver
reg add "HKLM\SYSTEM\CurrentControlSet\services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d 31 /f >nul 2>&1

:: AMD: Prioridad de hilos del driver
reg add "HKLM\SYSTEM\CurrentControlSet\services\amdkmdap\Parameters" /v "ThreadPriority" /t REG_DWORD /d 31 /f >nul 2>&1

:: DIRECTX KERNEL: Prioridad de hilos
reg add "HKLM\SYSTEM\CurrentControlSet\services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d 31 /f >nul 2>&1

:: INTEL (IGFX): Ajustes de Overlay y segmentos de memoria
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "IncreaseFixedSegment" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AdaptiveVsyncEnable" /t REG_DWORD /d 0 /f >nul 2>&1

:: SCHEDULER: Desactivar Preemption a nivel de sistema
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d 0 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 2. PLANIFICACIÓN DE GPU (HAGS) Y TDR (ESTABILIDAD)
:: ----------------------------------------------------------------------------

:: Habilitar Hardware Accelerated GPU Scheduling (HAGS)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f >nul 2>&1

:: Desactivar soporte para Miracast (Liberar recursos de proyección inalámbrica)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t REG_DWORD /d 0 /f >nul 2>&1

:: Ajustes de Tolerancia de Latencia de Monitor
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d 0 /f >nul 2>&1

:: Configuración TDR (Timeout Detection and Recovery)
:: Riesgoso: Evita el reinicio del driver en caso de fallo.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d 10 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDdiDelay" /t REG_DWORD /d 60 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 3. PRIORIDAD DE PROCESOS MULTIMEDIA (REGISTRO)
:: ----------------------------------------------------------------------------

:: Perfil "Games": Prioridad Alta y GPU Priority 8 (Máxima para juegos)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f >nul 2>&1

:: Preferencia de GPU de usuario a "Alto Rendimiento" (Valor 2)
reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "GpuPreference" /t REG_DWORD /d 2 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 4. DESKTOP WINDOW MANAGER (DWM) Y COMPOSICIÓN
:: ----------------------------------------------------------------------------

:: Prioridad del proceso DWM en el sistema
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 5 /f >nul 2>&1

:: Ajustes de composición y Overlay
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OneCoreNoComposition" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "MaxQueuedBuffers" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "ForceDoubleBuffer" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "EnablePerProcessSystemScheduling" /t REG_DWORD /d 1 /f >nul 2>&1

:: Desactivar aceleración de hardware en frameworks antiguos (WPF/Avalon)
reg add "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "MaxMultisampleType" /t REG_DWORD /d 0 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 5. ENERGÍA Y HARDWARE (MSI MODE / PCIe)
:: ----------------------------------------------------------------------------

:: Intentar activar MSI Mode (Message Signaled Interrupts) para la controladora de video
for /f %%a in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "VEN_"') do reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d 1 /f >nul 2>&1

:: Desactivar afinidad predeterminada para la controladora de video
for /f %%i in ('powershell -Command "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty PNPDeviceID" ^| findstr /L "PCI\VEN_"') do (
    reg delete "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
)

:: Desactivar ahorro de energía en el puerto PCIe (ASPM)
powercfg -setacvalueindex %UP_GUID% SUB_PCIEXPRESS ASPM 0 >nul 2>&1

:: ============================================================================
:: EXTRACTO DE AJUSTES DE GPU Y GRÁFICOS - ARCHIVO: 3.BAT
:: ============================================================================

:: ----------------------------------------------------------------------------
:: 1. CONTROLADORES Y LATENCIA (NVIDIA & SCHEDULER)
:: ----------------------------------------------------------------------------

[cite_start]:: Deshabilitar el servicio de Energía de la GPU (GpuEnergyDrv) [cite: 193]
:: Evita que el sistema gestione dinámicamente la energía de la tarjeta gráfica.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1

:: NVIDIA: Desactivar Write Combining
:: Puede aumentar el rendimiento en buffers de video específicos, pero causar errores visuales.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d 1 /f >nul 2>&1

:: NVIDIA: Desactivar Preemption (Interrupción)
:: Fuerza a la GPU a terminar tareas sin interrupción. Reduce latencia, riesgo de congelamiento.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d 1 /f >nul 2>&1

:: SYSTEM SCHEDULER: Desactivar Preemption globalmente
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d 0 /f >nul 2>&1

:: Desactivar soporte Miracast (Proyección inalámbrica)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t REG_DWORD /d 0 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 2. PRIORIDADES MULTIMEDIA (SYSTEM PROFILE)
:: ----------------------------------------------------------------------------

[cite_start]:: Perfil de Juegos: Prioridad de GPU Máxima [cite: 199]
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f >nul 2>&1

[cite_start]:: Desactivar Throttling de Red para no limitar la GPU en juegos online [cite: 199]
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 0xffffffff /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 3. GAMEDVR Y GRABACIÓN (GAMEBAR)
:: ----------------------------------------------------------------------------

[cite_start]:: Desactivar todo el subsistema de grabación de juegos de Windows [cite: 156, 158, 199]
reg add "HKEY_USERS\.DEFAULT\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_USERS\.DEFAULT\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul 2>&1

[cite_start]:: Deshabilitar la barra de juegos Nexus/GameBar [cite: 159]
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 4. HARDWARE E INTERRUPCIONES (MSI MODE)
:: ----------------------------------------------------------------------------

[cite_start]:: Activar MSI Mode (Message Signaled Interrupts) para la controladora de video [cite: 227]
:: Busca específicamente controladores de video (VideoController) y activa MSISupported.
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do (
    reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d 1 /f >nul 2>&1
)

[cite_start]:: Eliminar afinidad de CPU específica para dejar que el sistema decida (o el driver) [cite: 227]
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do (
    reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>&1
)

:: ----------------------------------------------------------------------------
:: 5. SERVICIOS Y COMPONENTES VISUALES
:: ----------------------------------------------------------------------------

[cite_start]:: Desactivar servicio de monitor de rendimiento de gráficos [cite: 198]
:: "GraphicsPerfSvc" no es esencial para jugar y consume ciclos de fondo.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1

[cite_start]:: Ajustes visuales: Desactivar transparencias y efectos [cite: 201]
:: Aunque estos son estéticos, liberan composición en el DWM.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 3 /f >nul 2>&1

:: ============================================================================
:: EXTRACTO DE AJUSTES DE GPU Y GRÁFICOS - ARCHIVO: 4.BAT
:: ============================================================================

:: ----------------------------------------------------------------------------
:: 1. DIRECT3D Y LATENCIA DE RENDERIZADO (DX9/DX11/DX12)
:: ----------------------------------------------------------------------------

:: Desactivar Multihilo en Direct3D (Reduce overhead en CPU, baja latencia, pero puede bajar FPS)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "DisableMultithreading" /t REG_DWORD /d 1 /f >nul 2>&1

:: Limitar frames pre-renderizados a 1 (Máxima reducción de Input Lag)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "MaxPreRenderedFrames" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "MaxFrameLatency" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DxMaxFrameLatency" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MaxFrameLatency" /t REG_DWORD /d 1 /f >nul 2>&1

:: Activar "Modo de Latencia Ultra Baja" (Similar al ajuste del Panel NVIDIA)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "EnableUltralowLatencyMode" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "LowLatencyMode" /t REG_DWORD /d 1 /f >nul 2>&1

:: Desactivar V-Sync forzado y detecciones de tiempo de espera
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "ForceVSYNC" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "DisableTimeoutDetection" /t REG_DWORD /d 1 /f >nul 2>&1

:: Desactivar optimización enhebrada (Threaded Optimization)
:: Nota: En juegos modernos esto suele ser contraproducente, pero reduce latencia en antiguos.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "DisableThreadedOptimization" /t REG_DWORD /d 0 /f >nul 2>&1

:: Habilitar GPU de Alta Prioridad en DX
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "HighPriorityGPU" /t REG_DWORD /d 1 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 2. CONFIGURACIÓN DE CONTROLADORES Y SCHEDULER
:: ----------------------------------------------------------------------------

:: Habilitar Hardware Accelerated GPU Scheduling (HAGS)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f >nul 2>&1

:: Forzar renderizado en hilos (Force Threading)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "ForceThreadedRendering" /t REG_DWORD /d 1 /f >nul 2>&1

:: Desactivar multihilo a nivel de driver (conflictivo con ajustes anteriores, testear)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisableMultithreading" /t REG_DWORD /d 1 /f >nul 2>&1

:: Desactivar aceleración por hardware (Valor 0 = HW Acceleration ACTIVADA, nombre confuso)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisableHWAcceleration" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectDraw" /v "DisableHardwareAcceleration" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t REG_DWORD /d 0 /f >nul 2>&1

:: TDR (Evitar reinicio del driver en cargas pesadas)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d 10 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitCount" /t REG_DWORD /d 256 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitTime" /t REG_DWORD /d 60 /f >nul 2>&1

:: Preemption (Interrupción de tareas gráficas)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "GraphicsPreemption" /t REG_DWORD /d 2 /f >nul 2>&1

:: ----------------------------------------------------------------------------
:: 3. PRIORIZACIÓN DE PROCESOS (WMIC & REGISTRO)
:: ----------------------------------------------------------------------------

:: Multimedia System Profile (Juegos = Prioridad GPU 8)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1

:: INYECCIÓN DE PRIORIDAD EN TIEMPO REAL (Lista de juegos específicos)
:: Valor 256 = Realtime (Tiempo Real) | Valor 128 = High (Alta)
[cite_start]wmic process where "name='valorant.exe'" CALL setpriority 256 [cite: 313]
[cite_start]wmic process where "name='csgo.exe'" CALL setpriority 256 [cite: 313]
[cite_start]wmic process where "name='fortnite.exe'" CALL setpriority 256 [cite: 313]
[cite_start]wmic process where "name='eldenring.exe'" CALL setpriority 256 [cite: 315]
[cite_start]wmic process where "name='warzone.exe'" CALL setpriority 256 [cite: 315]
[cite_start]wmic process where "name='apex.exe'" CALL setpriority 256 [cite: 315]
[cite_start]wmic process where "name='r6s.exe'" CALL setpriority 256 [cite: 316]
[cite_start]wmic process where "name='gta5.exe'" CALL setpriority 256 [cite: 316]
[cite_start]wmic process where "name='overwatch.exe'" CALL setpriority 256 [cite: 316]
[cite_start]wmic process where "name='game.exe'" CALL setpriority 256 [cite: 309]

:: Prioridad para DWM (Gestor de ventanas) - Crítico para evitar stuttering
[cite_start]wmic process where "name='dwm.exe'" CALL setpriority 256 [cite: 304]

:: Prioridad para aplicaciones secundarias (Discord/OBS)
[cite_start]wmic process where "name='discord.exe'" CALL setpriority 128 [cite: 312]
[cite_start]wmic process where "name='obs64.exe'" CALL setpriority 128 [cite: 312]

:: ----------------------------------------------------------------------------
:: 4. IMAGE FILE EXECUTION OPTIONS (PERFOPTIONS)
:: ----------------------------------------------------------------------------
:: Esto configura la prioridad de CPU y E/S de forma persistente en el registro para juegos específicos.

:: Lista de juegos a optimizar
for %%g in ("EscapeFromTarkov.exe" "FortniteClient-Win64-Shipping.exe" "Valorant.exe" "cs2.exe" "RainbowSix.exe" "PUBG.exe" "ApexLegends.exe" "Overwatch.exe" "League of Legends.exe" "LeagueClient.exe" "VALORANT-Win64-Shipping.exe" "r5apex.exe") do (
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~g\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f >nul 2>&1
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~g\PerfOptions" /v "IoPriority" /t REG_DWORD /d 3 /f >nul 2>&1
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~g\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f >nul 2>&1
)

:: ----------------------------------------------------------------------------
:: 5. GAMEDVR Y OPTIMIZACIÓN VISUAL
:: ----------------------------------------------------------------------------

:: Desactivar GameDVR, GameBar y Capturas
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: Reducir efectos visuales del explorador para liberar GPU
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 2 /f >nul 2>&1

