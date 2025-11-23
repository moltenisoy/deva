@Echo Off
Title DE3NAKE PRIVATE PC Optimizer

echo Applying bcdedit tweaks

timeout 1 >nul 
bcdedit /set disabledynamictick yes
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
ipconfig /release
ipconfig /renew
ipconfig /flushdns
netsh winsock reset
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1




:: OPTIMIZACIONES DIRECTX Y GRAFICOS (DirectDraw/Direct3D)
:: =========================================================

:: Habilitar soporte AGP y memoria no local
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableAGPSupport" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableAGPSupport" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "UseNonLocalVidMem" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "UseNonLocalVidMem" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "UseNonLocalVidMem" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "UseNonLocalVidMem" /t reg_DWORD /d "1" /f

:: Configurar PrintScreen y Buffer VGA
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EnablePrintScreen" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EnablePrintScreen" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "VGABuffer" /t reg_DWORD /d "21181233" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "VGABuffer" /t reg_DWORD /d "21181233" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "VGABuffer" /t reg_DWORD /d "21181233" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "VGABuffer" /t reg_DWORD /d "21181233" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectMusic" /v "VGABuffer" /t reg_DWORD /d "21181233" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectMusic" /v "VGABuffer" /t reg_DWORD /d "21181233" /f

:: Aceleracion de Hardware y Superficies
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableDDSCAPSInDDSD" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableDDSCAPSInDDSD" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulationOnly" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectMusic" /v "DisableHWAcceleration" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectMusic" /v "DisableHWAcceleration" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulatePointSprites" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulatePointSprites" /t reg_DWORD /d "0" /f

:: Rasterizacion y Bloques de estado
reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "ForceRgbRasterizer" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "ForceRgbRasterizer" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulateStateBlocks" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulateStateBlocks" /t reg_DWORD /d "0" /f

:: Bibliotecas DirectX adicionales y MMX
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableDP2" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "DisableDP2" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "D3DXDoNotMute" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "D3DXDoNotMute" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableMMX" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableMMX" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableMMX" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "DisableMMX" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "MMX Fast Path" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMXFastPath" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "MMXFastPath" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "UseMMXForRGB" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "UseMMXForRGB" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "UseMMXForRGB" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "UseMMXForRGB" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t reg_DWORD /d "1" /f

:: Configuración de VSync y Depuración (Debug)
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "FlipNoVsync" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "EnableDebugging" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FullDebug" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableDM" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "EnableMultimonDebugging" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "LoadDebugRuntime" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "ForceNoSysLock" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "ForceNoSysLock" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "ModeXOnly" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "ModeXOnly" /t reg_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FewVertices" /t reg_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "FewVertices" /t reg_DWORD /d "1" /f

:: OPTIMIZACIONES DE KERNEL Y LATENCIA
:: =========================================================

:: IoLatencyCap
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "IoLatencyCap"^| FINDSTR /V "IoLatencyCap"') DO (
	REG ADD "%%a" /F /V "IoLatencyCap" /T REG_DWORD /d 0 >NUL 2>&1
)

:: Process Mitigation (Desactivar mitigaciones para rendimiento)
powershell set-ProcessMitigation -System -Disable DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, SEHOP, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess

:: Ajustes de DXGKrnl y Kernel Manager
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableAutoBoost" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f

:: Timer Resolution Service
Sc create TRS_500 binPath=C:\Windows\Microsoft.NET\Framework\v4.0.30319\SetTimerResolutionService.exe DisplayName=TRS_500 type=own start=auto
fltmc >nul 2>&1 || (
    echo Permisos de administrador requeridos para continuar.
)


:: ELIMINACION DE BLOATWARE (PowerShell Avanzado)
:: =========================================================



PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Print3D' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Windows.Print3D' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.3DBuilder' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Microsoft3DViewer' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingWeather' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingSports' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingNews' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingFinance' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.HEIFImageExtension' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.VP9VideoExtensions' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WebMediaExtensions' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WebpImageExtension' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.HEVCVideoExtension' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.RawImageExtension' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MicrosoftOfficeHub' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Office.OneNote' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Office.Sway' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxGamingOverlay' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxGameOverlay' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxSpeechToTextOverlay' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsPhone' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.CommsPhone' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.YourPhone' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.CallingShellApp' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'king.com.CandyCrushSaga' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'king.com.CandyCrushSodaSaga' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'ShazamEntertainmentLtd.Shazam' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Flipboard.Flipboard' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'ClearChannelRadioDigital.iHeartRadio' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'D5EA27B7.Duolingo-LearnLanguagesforFree' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'AdobeSystemsIncorporated.AdobePhotoshopExpress' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'PandoraMediaInc.29680B314EFC2' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage '46928bounde.EclipseManager' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'ActiproSoftwareLLC.562882FEEB491' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'SpotifyAB.SpotifyMusic' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.PeopleExperienceHost' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.ParentalControls' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.Holographic.FirstRun' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.GetHelp' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Getstarted' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Messaging' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MixedReality.Portal' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsFeedbackHub' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsAlarms' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsMaps' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MinecraftUWP' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.People' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Wallet' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.OneConnect' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MicrosoftSolitaireCollection' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MicrosoftStickyNotes' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'microsoft.windowscommunicationsapps' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.RemoteDesktop' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.NetworkSpeedTest' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Todos' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.GroupMe10' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Appconnector' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Windows.CBSPreview' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.ZuneMusic' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.ZuneVideo' | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.SecureAssessmentBrowser' | Remove-AppxPackage"


:: ENERGIA Y USB (Desactivar Ahorro de Energia)
:: =========================================================

FOR /F %%a in ('WMIC PATH Win32_USBHub GET DeviceID^| FINDSTR /L "VID_"') DO (
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "EnhancedPowerManagementEnabled" /T REG_DWORD /d 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "AllowIdleIrpInD3" /T REG_DWORD /d 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "SelectiveSuspendOn" /T REG_DWORD /d 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "DeviceSelectiveSuspended" /T REG_DWORD /d 0 >NUL 2>&1
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "SelectiveSuspendEnabled" /T REG_DWORD /d 0 >NUL 2>&1
)
for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr /l "USB\VID_"') do (
    reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 00000000 /f
    reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
    reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 00000000 /f
    reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 00000000 /f
)


:: RED, SEGURIDAD Y PRIVACIDAD 
:: =========================================================

SC STOP edgeupdate
SC CONFIG edgeupdate start= disabled
SC DELETE edgeupdate
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ConfigureDoNotTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f

:: Seguridad de Red
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v "ServerMinKeyBitLength" /t "REG_DWORD" /d "2048" /f
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' /v 'ClientMinKeyBitLength' /t 'REG_DWORD' /d '2048' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' /v 'ClientMinKeyBitLength' /t 'REG_DWORD' /d '2048' /f"
:: Deshabilitar Cifrados inseguros (RC2, RC4, DES, MD5, SHA-1)
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
:: Deshabilitar SMBv1 y NetBios
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v 'SMBv1' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "$key = 'HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces'; Get-ChildItem $key | ForEach {; Set-ItemProperty -Path \"$key\$($_.PSChildName)\" -Name NetbiosOptions -Value 2 -Verbose; }"
:: Deshabilitar Protocolos Viejos (SSL 2.0/3.0, TLS 1.0/1.1)
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v 'Enabled' /t 'REG_DWORD' /d '0' /f"
:: Habilitar Protocolos Seguros (TLS 1.2/1.3)
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' /v 'Enabled' /t 'REG_DWORD' /d '1' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' /v 'Enabled' /t 'REG_DWORD' /d '1' /f"
:: Seguridad .NET
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d '1' /f"
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d '1' /f"
:: Deshabilitar Servicios Inseguros
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f



