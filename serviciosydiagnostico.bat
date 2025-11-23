@echo off
title Optimizaciones de Telemetria y Servicios
color 0A

:: ============================================
:: TELEMETRÍA Y DIAGNÓSTICOS
:: ============================================

:: Deshabilitar telemetría de Windows
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f

:: Deshabilitar DiagTrack (Connected User Experiences and Telemetry)
sc config "DiagTrack" start=disabled
sc stop "DiagTrack"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f

:: Deshabilitar dmwappushservice
sc config "dmwappushservice" start=disabled
sc stop "dmwappushservice"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f

:: Deshabilitar servicios de diagnóstico
sc config "diagsvc" start=disabled
sc stop "diagsvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f

sc config "DPS" start=disabled
sc stop "DPS"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f

sc config "diagnosticshub.standardcollector.service" start=disabled
sc stop "diagnosticshub.standardcollector.service"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f

sc config "WdiServiceHost" start=disabled
sc stop "WdiServiceHost"

sc config "WdiSystemHost" start=disabled
sc stop "WdiSystemHost"

:: Deshabilitar Windows Error Reporting
sc config "WerSvc" start=disabled
sc stop "WerSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f

:: Deshabilitar telemetría de compatibilidad
taskkill /f /im CompatTelRunner.exe >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f

:: Deshabilitar PcaSvc (Program Compatibility Assistant)
sc config "PcaSvc" start=disabled
sc stop "PcaSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f

:: ============================================
:: NOTIFICACIONES Y CARACTERÍSTICAS DE WINDOWS
:: ============================================

:: Deshabilitar notificaciones
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f

:: Deshabilitar Windows Consumer Features
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f

:: Deshabilitar Content Delivery Manager
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f

:: Deshabilitar publicidad
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f

:: ============================================
:: SERVICIOS DE WINDOWS
:: ============================================

:: Windows Defender
sc config "WinDefend" start=disabled
sc stop "WinDefend"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f

sc config "SecurityHealthService" start=disabled
sc stop "SecurityHealthService"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f

sc config "WdNisSvc" start=disabled
sc stop "WdNisSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f

sc config "Sense" start=disabled
sc stop "Sense"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f

sc config "wscsvc" start=disabled
sc stop "wscsvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f

:: Políticas de Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f

:: Servicios de búsqueda y indexación
sc config "WSearch" start=disabled
sc stop "WSearch"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f

:: Windows Biometric Service
sc config "WbioSrvc" start=disabled
sc stop "WbioSrvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f

:: Font Cache Services
sc config "FontCache" start=disabled
sc stop "FontCache"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f

sc config "FontCache3.0.0.0" start=disabled
sc stop "FontCache3.0.0.0"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f

:: Graphics Performance Monitor
sc config "GraphicsPerfSvc" start=disabled
sc stop "GraphicsPerfSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "4" /f

:: Windows Image Acquisition
sc config "stisvc" start=disabled
sc stop "stisvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f

:: Windows Event Collector
sc config "Wecsvc" start=disabled
sc stop "Wecsvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f

:: Maps Services
sc config "MapsBroker" start=disabled
sc stop "MapsBroker"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f

:: Print Services
sc config "Spooler" start=disabled
sc stop "Spooler"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f

sc config "PrintNotify" start=disabled
sc stop "PrintNotify"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f

:: Xbox Services
sc config "XblGameSave" start=disabled
sc stop "XblGameSave"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f

sc config "XboxNetApiSvc" start=disabled
sc stop "XboxNetApiSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f

sc config "XboxGipSvc" start=disabled
sc stop "XboxGipSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f

sc config "XblAuthManager" start=disabled
sc stop "XblAuthManager"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f

:: Windows Update Services
sc config "wuauserv" start=disabled
sc stop "wuauserv"

sc config "UsoSvc" start=disabled
sc stop "UsoSvc"

sc config "BITS" start=disabled
sc stop "BITS"

sc config "DoSvc" start=disabled
sc stop "DoSvc"

:: Otros servicios
sc config "SysMain" start=disabled
sc stop "SysMain"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f

sc config "TabletInputService" start=disabled
sc stop "TabletInputService"

sc config "Fax" start=disabled
sc stop "Fax"

sc config "PhoneSvc" start=disabled
sc stop "PhoneSvc"

sc config "RetailDemo" start=disabled
sc stop "RetailDemo"

sc config "RemoteAccess" start=disabled
sc stop "RemoteAccess"

sc config "RemoteRegistry" start=disabled
sc stop "RemoteRegistry"

sc config "SharedAccess" start=disabled
sc stop "SharedAccess"

sc config "TrkWks" start=disabled
sc stop "TrkWks"

sc config "WpnService" start=disabled
sc stop "WpnService"

sc config "WpnUserService" start=disabled
sc stop "WpnUserService"

:: ============================================
:: CONFIGURACIÓN DE PRIVACIDAD
:: ============================================

:: Deshabilitar ubicación
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f

:: Deshabilitar Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f

:: Deshabilitar búsqueda web
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f

:: ============================================
:: LIMPIEZA DE LOGS Y EVENTOS
:: ============================================

:: Limpiar logs de eventos
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

:: Eliminar archivos de log
del *.log /a /s /q /f
@echo off
title Telemetry, Privacy and Services Optimization
color 0A

echo Disabling Telemetry and Data Collection...

:: Telemetry and Data Collection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f >nul 2>&1

:: Disable DiagTrack Service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config "DiagTrack" start= disabled >nul 2>&1
sc stop "DiagTrack" >nul 2>&1

echo Disabling Diagnostic Services...

:: Diagnostic Services
sc config "diagnosticshub.standardcollector.service" start= disabled >nul 2>&1
sc config "diagsvc" start= disabled >nul 2>&1
sc config "DPS" start= disabled >nul 2>&1
sc config "WdiServiceHost" start= disabled >nul 2>&1
sc config "WdiSystemHost" start= disabled >nul 2>&1
sc stop "diagnosticshub.standardcollector.service" >nul 2>&1
sc stop "diagsvc" >nul 2>&1
sc stop "DPS" >nul 2>&1
sc stop "WdiServiceHost" >nul 2>&1
sc stop "WdiSystemHost" >nul 2>&1

echo Disabling Notifications and Push Services...

:: Notifications
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
sc config "WpnService" start= disabled >nul 2>&1
sc stop "WpnService" >nul 2>&1

:: dmwappushservice
sc config "dmwappushservice" start= disabled >nul 2>&1
sc stop "dmwappushservice" >nul 2>&1

echo Disabling Content Delivery and Advertising...

:: Content Delivery Manager
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f >nul 2>&1

:: Advertising Info
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1

echo Disabling Activity Feed and Privacy Settings...

:: Activity Feed
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1

:: Privacy Settings
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >nul 2>&1

:: SIUF Settings
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1

echo Disabling Location Services...

:: Location Services
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >nul 2>&1
sc config "lfsvc" start= disabled >nul 2>&1
sc stop "lfsvc" >nul 2>&1

echo Disabling Windows Error Reporting...

:: Windows Error Reporting
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1
sc config "WerSvc" start= disabled >nul 2>&1
sc stop "WerSvc" >nul 2>&1

echo Disabling Windows Search and Cortana...

:: Windows Search
sc config "WSearch" start= disabled >nul 2>&1
sc stop "WSearch" >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >nul 2>&1

echo Disabling Compatibility Services...

:: Application Compatibility
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePropPage" /t REG_DWORD /d "1" /f >nul 2>&1
sc config "PcaSvc" start= disabled >nul 2>&1
sc stop "PcaSvc" >nul 2>&1

echo Disabling Other Services...

:: Superfetch/SysMain
sc config "SysMain" start= disabled >nul 2>&1
sc stop "SysMain" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f >nul 2>&1

:: Font Cache Services
sc config "FontCache" start= disabled >nul 2>&1
sc config "FontCache3.0.0.0" start= disabled >nul 2>&1
sc stop "FontCache" >nul 2>&1
sc stop "FontCache3.0.0.0" >nul 2>&1

:: Shell Hardware Detection
sc config "ShellHWDetection" start= disabled >nul 2>&1
sc stop "ShellHWDetection" >nul 2>&1

:: Themes Service
sc config "Themes" start= disabled >nul 2>&1
sc stop "Themes" >nul 2>&1

:: Windows Biometric Service
sc config "WbioSrvc" start= disabled >nul 2>&1
sc stop "WbioSrvc" >nul 2>&1

:: Print Spooler
sc config "Spooler" start= demand >nul 2>&1

:: Maps Services
sc config "MapsBroker" start= disabled >nul 2>&1
sc stop "MapsBroker" >nul 2>&1

:: Remote Services
sc config "RemoteRegistry" start= disabled >nul 2>&1
sc config "RemoteAccess" start= disabled >nul 2>&1
sc stop "RemoteRegistry" >nul 2>&1
sc stop "RemoteAccess" >nul 2>&1

:: Windows Update Services
sc config "wuauserv" start= disabled >nul 2>&1
sc config "UsoSvc" start= disabled >nul 2>&1
sc config "DoSvc" start= disabled >nul 2>&1
sc config "bits" start= disabled >nul 2>&1
sc stop "wuauserv" >nul 2>&1
sc stop "UsoSvc" >nul 2>&1
sc stop "DoSvc" >nul 2>&1
sc stop "bits" >nul 2>&1

:: Xbox Services
sc config "XblAuthManager" start= disabled >nul 2>&1
sc config "XblGameSave" start= disabled >nul 2>&1
sc config "XboxGipSvc" start= disabled >nul 2>&1
sc config "XboxNetApiSvc" start= disabled >nul 2>&1
sc stop "XblAuthManager" >nul 2>&1
sc stop "XblGameSave" >nul 2>&1
sc stop "XboxGipSvc" >nul 2>&1
sc stop "XboxNetApiSvc" >nul 2>&1

:: Windows Defender Services
sc config "WinDefend" start= disabled >nul 2>&1
sc config "SecurityHealthService" start= disabled >nul 2>&1
sc config "WdNisSvc" start= disabled >nul 2>&1
sc config "Sense" start= disabled >nul 2>&1
sc config "wscsvc" start= disabled >nul 2>&1
sc stop "WinDefend" >nul 2>&1
sc stop "SecurityHealthService" >nul 2>&1
sc stop "WdNisSvc" >nul 2>&1
sc stop "Sense" >nul 2>&1
sc stop "wscsvc" >nul 2>&1

echo Disabling Scheduled Tasks...

:: Disable telemetry and diagnostic scheduled tasks
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Location\Notifications" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Location\WindowsActionDialog" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable >nul 2>&1

@echo off
title Optimizacion de Telemetria, Diagnosticos y Servicios
cd /d "%~dp0"

:: ============================================
:: TELEMETRIA Y DIAGNOSTICOS
:: ============================================

:: Deshabilitar telemetria y recopilacion de datos
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1

:: Deshabilitar servicios de telemetria
sc config DiagTrack start=disabled >nul 2>&1
sc stop DiagTrack >nul 2>&1
sc config dmwappushservice start=disabled >nul 2>&1
sc stop dmwappushservice >nul 2>&1
sc config diagnosticshub.standardcollector.service start=disabled >nul 2>&1
sc stop diagnosticshub.standardcollector.service >nul 2>&1

:: Deshabilitar servicios de diagnostico
sc config diagsvc start=disabled >nul 2>&1
sc stop diagsvc >nul 2>&1
sc config DPS start=disabled >nul 2>&1
sc stop DPS >nul 2>&1
sc config WdiServiceHost start=disabled >nul 2>&1
sc stop WdiServiceHost >nul 2>&1
sc config WdiSystemHost start=disabled >nul 2>&1
sc stop WdiSystemHost >nul 2>&1

:: Deshabilitar Windows Error Reporting
sc config WerSvc start=disabled >nul 2>&1
sc stop WerSvc >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1

:: Deshabilitar Program Compatibility Assistant
sc config PcaSvc start=disabled >nul 2>&1
sc stop PcaSvc >nul 2>&1

:: Deshabilitar Windows Event Collector
sc config Wecsvc start=disabled >nul 2>&1
sc stop Wecsvc >nul 2>&1

:: ============================================
:: WINDOWS DEFENDER Y SEGURIDAD
:: ============================================

:: Deshabilitar Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >nul 2>&1

:: Deshabilitar Real-Time Protection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul 2>&1

:: Deshabilitar notificaciones de Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul 2>&1

:: Deshabilitar servicios de Windows Defender
sc config WinDefend start=disabled >nul 2>&1
sc stop WinDefend >nul 2>&1
sc config SecurityHealthService start=disabled >nul 2>&1
sc stop SecurityHealthService >nul 2>&1
sc config WdNisSvc start=disabled >nul 2>&1
sc stop WdNisSvc >nul 2>&1
sc config Sense start=disabled >nul 2>&1
sc stop Sense >nul 2>&1
sc config wscsvc start=disabled >nul 2>&1
sc stop wscsvc >nul 2>&1

:: ============================================
:: NOTIFICACIONES Y TOASTS
:: ============================================

:: Deshabilitar notificaciones push
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f >nul 2>&1

:: ============================================
:: SERVICIOS BIOMETRICOS Y FUENTES
:: ============================================

:: Deshabilitar Windows Biometric Service
sc config WbioSrvc start=disabled >nul 2>&1
sc stop WbioSrvc >nul 2>&1

:: Deshabilitar servicios de cache de fuentes
sc config FontCache start=disabled >nul 2>&1
sc stop FontCache >nul 2>&1
sc config FontCache3.0.0.0 start=disabled >nul 2>&1
sc stop FontCache3.0.0.0 >nul 2>&1

:: ============================================
:: SERVICIOS DE MONITOREO Y RENDIMIENTO
:: ============================================

:: Deshabilitar Graphics performance monitor
sc config GraphicsPerfSvc start=disabled >nul 2>&1
sc stop GraphicsPerfSvc >nul 2>&1

:: ============================================
:: SERVICIOS DE IMAGENES Y ESCANEO
:: ============================================

:: Deshabilitar Windows Image Acquisition
sc config stisvc start=disabled >nul 2>&1
sc stop stisvc >nul 2>&1

:: ============================================
:: SERVICIOS DE MAPAS
:: ============================================

:: Deshabilitar servicios de mapas
sc config MapsBroker start=disabled >nul 2>&1
sc stop MapsBroker >nul 2>&1

:: ============================================
:: SERVICIOS DE IMPRESION
:: ============================================

:: Deshabilitar servicios de impresion
sc config Spooler start=disabled >nul 2>&1
sc stop Spooler >nul 2>&1
sc config PrintNotify start=disabled >nul 2>&1
sc stop PrintNotify >nul 2>&1

:: ============================================
:: SERVICIOS XBOX
:: ============================================

:: Configurar servicios Xbox como manuales
sc config XblGameSave start=demand >nul 2>&1
sc config XboxNetApiSvc start=demand >nul 2>&1
sc config XboxGipSvc start=demand >nul 2>&1
sc config XblAuthManager start=demand >nul 2>&1

:: ============================================
:: SERVICIOS ADICIONALES
:: ============================================

:: Deshabilitar Windows Search
sc config WSearch start=disabled >nul 2>&1
sc stop WSearch >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: Deshabilitar SysMain (Superfetch)
sc config SysMain start=disabled >nul 2>&1
sc stop SysMain >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: Deshabilitar servicios de fax
sc config Fax start=disabled >nul 2>&1
sc stop Fax >nul 2>&1



:: ============================================
:: SERVICIOS DE GOOGLE
:: ============================================

:: Eliminar servicios de Google Update
net stop gupdate >nul 2>&1
sc delete gupdate >nul 2>&1
net stop googlechromeelevationservice >nul 2>&1
sc delete googlechromeelevationservice >nul 2>&1
net stop gupdatem >nul 2>&1
sc delete gupdatem >nul 2>&1

:: ============================================
:: SERVICIOS DE BRAVE
:: ============================================

:: Detener servicios de Brave
net stop brave >nul 2>&1
net stop bravem >nul 2>&1
rmdir "C:\Program Files (x86)\BraveSoftware\Update" /s /q >nul 2>&1

:: ============================================
:: MOZILLA FIREFOX
:: ============================================

:: Eliminar servicios de mantenimiento de Firefox
taskkill /f /im maintenanceservice.exe >nul 2>&1
taskkill /f /im uninstall.exe >nul 2>&1
net stop MozillaMaintenance >nul 2>&1
sc delete MozillaMaintenance >nul 2>&1
wmic product where name="Mozilla Maintenance Service" call uninstall /nointeractive >nul 2>&1
rmdir "C:\Program Files (x86)\Mozilla Maintenance Service" /s /q >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\maintenanceservice_installer.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\maintenanceservice.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\updater.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\crashreporter.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\crashreporter.ini" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\minidump-analyzer.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\pingsender.exe" >nul 2>&1

:: Deshabilitar actualizaciones de Firefox
reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableAppUpdate" /t REG_DWORD /d "1" /f >nul 2>&1

@echo off
title Ajustes de telemetría, notificaciones y diagnóstico
color 0A

:: --- TELEMETRÍA / DIAGNÓSTICO / CEIP / DATOS DE USO ---

:: Telemetría general de Windows
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f >nul 2>&1

:: Telemetría de Office
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: CEIP / SQM / Experiencias personalizadas
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: Experiencias personalizadas y anuncios / publicidad
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: Desactivar publicidad / ID de publicidad
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f >nul 2>&1

:: AppCompat / Experiencia de compatibilidad
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePropPage" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f >nul 2>&1

:: Diagnóstico de telemetría de usuario
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f >nul 2>&1

:: Input / recopilación predictiva
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f >nul 2>&1

:: Siuf / feedback de usuario
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f >nul 2>&1

:: Desactivar Activity History / Timeline
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f >nul 2>&1

:: Desactivar Location & sensores (telemetría de localización)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f >nul 2>&1

:: DiagTrack / Telemetry Service (servicio)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1

:: Experiencias personalizadas en la nube / CloudContent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f >nul 2>&1

:: Windows Error Reporting
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v "DumpFolder" /t REG_EXPAND_SZ /d "%%LOCALAPPDATA%%\CrashDumps" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v "DumpCount" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v "DumpType" /t REG_DWORD /d 0 /f >nul 2>&1

:: Windows Feeds / Noticias e intereses
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f >nul 2>&1

:: Servicios de mapas / localización
reg add "HKLM\SYSTEM\Maps\AutoUpdateEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration\Status" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\Maps\AutoUpdateEnabled" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: WindowsAI / análisis de datos
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f >nul 2>&1


:: --- NOTIFICACIONES Y CENTRO DE ACTIVIDADES / PUSH / GAMEBAR ---

:: Desactivar centro de notificaciones
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d 1 /f >nul 2>&1

:: Notificaciones / feeds / Meet Now
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement\ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: GameBar / GameDVR notificaciones y capturas
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 1 /f >nul 2>&1

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1

reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: Preferencias de audio (ducking)
reg add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d 3 /f >nul 2>&1

:: Desactivar Storage Sense visual (no almacenamiento en sí)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseGlobal" /t REG_DWORD /d 0 /f >nul 2>&1


:: --- SERVICIOS RELACIONADOS CON TELEMETRÍA / NOTIFICACIONES / EXPERIENCIAS ---

:: Servicios de notificaciones
sc config "WpnService" start= disabled >nul 2>&1
sc stop "WpnService" >nul 2>&1
sc config "WpnUserService" start= disabled >nul 2>&1
sc stop "WpnUserService" >nul 2>&1

:: Seguridad / centro de seguridad (solo interfaz, no motor bajo nivel)
sc config "wscsvc" start= disabled >nul 2>&1
sc stop "wscsvc" >nul 2>&1
sc config "SecurityHealthService" start= disabled >nul 2>&1
sc stop "SecurityHealthService" >nul 2>&1

:: Mapas / localización
sc config "MapsBroker" start= disabled >nul 2>&1
sc stop "MapsBroker" >nul 2>&1
sc config "lfsvc" start= disabled >nul 2>&1
sc stop "lfsvc" >nul 2>&1

:: OneDrive (telemetría/sync en segundo plano; no es almacenamiento de bajo nivel)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d 1 /f >nul 2>&1
IF EXIST "%SystemRoot%\SysWOW64\OneDriveSetup.exe" ("%SystemRoot%\SysWOW64\OneDriveSetup.exe" /uninstall >nul 2>&1)
IF EXIST "%SystemRoot%\System32\OneDriveSetup.exe" ("%SystemRoot%\System32\OneDriveSetup.exe" /uninstall >nul 2>&1)

:: Desactivar Clipboard History
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d 0 /f >nul 2>&1

:: Servicios de experiencia de usuario / scheduled diagnostics
reg add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d 1 /f >nul 2>&1


:: --- CONTENIDO ONLINE, BUSCADOR, EDGE, CORTANA, FEEDS ---

:: Cortana / Búsqueda online / Bing
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: Desactivar recomendaciones en el menú Inicio / barra
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f >nul 2>&1

:: Políticas Edge (recomendaciones, telemetría, sugerencias)
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate\CreateDesktopShortcutDefault" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HideFirstRunExperience" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ConfigureDoNotTrack" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeCollectionsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "MicrosoftEdgeInsiderPromotionEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ShowMicrosoftRewards" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "WebWidgetAllowed" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "DiagnosticData" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeAssetDeliveryServiceEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "CryptoWalletEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "WalletDonationEnabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: Cortana (policymanager)
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1

:: CloudContent Recommended / Start menú
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f >nul 2>&1


:: --- TAREAS PROGRAMADAS RELACIONADAS CON TELEMETRÍA / CEIP / EXPERIENCIAS ---

schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\WSCSecurityAudit" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable >nul 2>&1

:: Algunas otras tareas de diagnóstico / experiencia (ligado a CEIP/telemetría)
schtasks /Change /TN "\Microsoft\Windows\PI\Sqm-Tasks" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable >nul 2>&1

echo.
echo Ajustes de telemetria, notificaciones y diagnostico aplicados.
pause