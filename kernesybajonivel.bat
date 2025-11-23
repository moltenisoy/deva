@echo off
title Optimizacion de Kernel y Bajo Nivel

:: ============================================================================
:: KERNEL
:: ============================================================================

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableAutoBoost" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f

reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f

reg add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f

:: ============================================================================
:: BCDEDIT
:: ============================================================================

bcdedit /set disabledynamictick yes
bcdedit /set useplatformtick yes
bcdedit /deletevalue useplatformclock
bcdedit /set tscsyncpolicy legacy
bcdedit /set nx AlwaysOff
bcdedit /set bootux disabled

:: ============================================================================
:: AHORRO DE ENERGIA Y C-STATES
:: ============================================================================

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "Attributes" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec" /v "Attributes" /t REG_DWORD /d "2" /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Cstates" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f

powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
powercfg -setacvalueindex scheme_current sub_processor CPMAXCORES 100
powercfg -setactive scheme_current

:: ============================================================================
:: MSI MODE DISPOSITIVOS PCI
:: ============================================================================

for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\PCI" /s /f "PCI\VEN_" ^| findstr "HKEY"') do (
    reg add "%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
)

reg delete "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "DevicePriority" /f

:: ============================================================================
:: USB POWER MANAGEMENT
:: ============================================================================

for /f "Delims=" %%k in ('wmic path Win32_USBHub get DeviceID^| findstr /L "VID_"') do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%k\Device Parameters" /f /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0"
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%k\Device Parameters" /f /v "AllowIdleIrpInD3" /t REG_DWORD /d "0"
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%k\Device Parameters" /f /v "SelectiveSuspendOn" /t REG_DWORD /d "0"
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%k\Device Parameters" /f /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0"
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%k\Device Parameters" /f /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0"
)

for /f %%a in ('wmic path Win32_PnPEntity get DeviceID ^| findstr /l "USB\VID_"') do (
    reg add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
    reg add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_BINARY /d "00" /f
    reg add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
    reg add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
)

:: ============================================================================
:: PROCESS MITIGATION
:: ============================================================================

powershell -Command "Set-ProcessMitigation -System -Disable DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, SEHOP, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess"

:: ============================================================================
:: TIMER RESOLUTION SERVICE
:: ============================================================================

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f

:: ============================================================================
:: PRIORIDADES BAJO NIVEL PROCESOS SISTEMA
:: ============================================================================

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEngCP.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f

for %%p in ("TiWorker.exe" "TrustedInstaller.exe" "wuauclt.exe" "WuSoCoreWorker.exe" "MoUsoCoreWorker.exe" "diagtrack.exe") do (
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~p\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
)

:: ============================================================================
:: MAINTENANCE
:: ============================================================================

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f

:: ============================================================================
:: DCOM
:: ============================================================================

reg add "HKLM\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f

:: ============================================================================
:: FTH (FAULT TOLERANT HEAP)
:: ============================================================================

reg add "HKLM\SOFTWARE\FTH" /v "Enabled" /t REG_DWORD /d "0" /f
