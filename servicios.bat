@echo off
title Optimizacion de Servicios

:: ============================================================================
:: TELEMETRIA Y DIAGNOSTICOS
:: ============================================================================

sc config "DiagTrack" start= disabled
sc stop "DiagTrack"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f

sc config "dmwappushservice" start= disabled
sc stop "dmwappushservice"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f

sc config "diagnosticshub.standardcollector.service" start= disabled
sc stop "diagnosticshub.standardcollector.service"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f

sc config "diagsvc" start= disabled
sc stop "diagsvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f

sc config "DPS" start= disabled
sc stop "DPS"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f

sc config "WdiServiceHost" start= disabled
sc stop "WdiServiceHost"

sc config "WdiSystemHost" start= disabled
sc stop "WdiSystemHost"

sc config "PcaSvc" start= disabled
sc stop "PcaSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f

sc config "Wecsvc" start= disabled
sc stop "Wecsvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f

:: ============================================================================
:: WINDOWS ERROR REPORTING
:: ============================================================================

sc config "WerSvc" start= disabled
sc stop "WerSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f

:: ============================================================================
:: WINDOWS DEFENDER
:: ============================================================================

sc config "WinDefend" start= disabled
sc stop "WinDefend"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f

sc config "SecurityHealthService" start= disabled
sc stop "SecurityHealthService"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f

sc config "WdNisSvc" start= disabled
sc stop "WdNisSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f

sc config "Sense" start= disabled
sc stop "Sense"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f

sc config "wscsvc" start= disabled
sc stop "wscsvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f

:: ============================================================================
:: BUSQUEDA E INDEXACION
:: ============================================================================

sc config "WSearch" start= disabled
sc stop "WSearch"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f

:: ============================================================================
:: SUPERFETCH Y PREFETCH
:: ============================================================================

sc config "SysMain" start= disabled
sc stop "SysMain"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f

powershell -NoProfile -ExecutionPolicy Bypass -Command "Disable-MMAgent -mc" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "Disable-MMAgent -ApplicationLaunchPrefetching -OperationAPI -PageCombining -ApplicationPreLaunch" 2>nul

:: ============================================================================
:: SERVICIOS DE FONT CACHE
:: ============================================================================

sc config "FontCache" start= disabled
sc stop "FontCache"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f

sc config "FontCache3.0.0.0" start= disabled
sc stop "FontCache3.0.0.0"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f

:: ============================================================================
:: SERVICIOS BIOMETRICOS
:: ============================================================================

sc config "WbioSrvc" start= disabled
sc stop "WbioSrvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f

:: ============================================================================
:: SERVICIOS DE IMPRESION
:: ============================================================================

sc config "Spooler" start= demand

sc config "PrintNotify" start= disabled
sc stop "PrintNotify"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f

:: ============================================================================
:: SERVICIOS DE MAPAS
:: ============================================================================

sc config "MapsBroker" start= disabled
sc stop "MapsBroker"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f

sc config "lfsvc" start= disabled
sc stop "lfsvc"

:: ============================================================================
:: SERVICIOS DE IMAGENES
:: ============================================================================

sc config "stisvc" start= disabled
sc stop "stisvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f

:: ============================================================================
:: SERVICIOS XBOX
:: ============================================================================

sc config "XblGameSave" start= demand
sc config "XboxNetApiSvc" start= demand
sc config "XboxGipSvc" start= demand
sc config "XblAuthManager" start= demand

:: ============================================================================
:: SERVICIOS DE ACTUALIZACION
:: ============================================================================

sc config "wuauserv" start= demand
sc stop "wuauserv"

sc config "UsoSvc" start= demand
sc stop "UsoSvc"

sc config "BITS" start= demand
sc stop "BITS"

sc config "DoSvc" start= demand
sc stop "DoSvc"

sc config "WaaSMedicSvc" start= demand

:: ============================================================================
:: SERVICIOS DE HYPER-V Y VIRTUALIZACION
:: ============================================================================

sc config "hvservice" start= disabled
sc config "HvHost" start= demand

dism /online /disable-feature /featurename:Microsoft-Hyper-V /norestart

:: ============================================================================
:: SERVICIOS DE TELEFONIA Y TELEFONO
:: ============================================================================

sc config "PhoneSvc" start= disabled
sc stop "PhoneSvc"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f

sc config "TapiSrv" start= disabled

:: ============================================================================
:: SERVICIOS ADICIONALES DESHABILITADOS
:: ============================================================================

sc config "AppVClient" start= disabled
sc config "AssignedAccessManagerSvc" start= disabled
sc config "AxInstSV" start= demand
sc config "BDESVC" start= demand
sc config "CertPropSvc" start= demand
sc config "CloudBackup" start= disabled
sc config "CDPSvc" start= disabled
sc config "CDPUserSvc" start= disabled
sc config "defragsvc" start= demand
sc config "DisplayEnhancementService" start= demand
sc config "FrameServer" start= demand
sc config "OneSyncSvc" start= disabled
sc config "PimIndexMaintenanceSvc" start= disabled
sc config "PolicyAgent" start= disabled
sc config "QWAVE" start= disabled
sc config "RetailDemo" start= disabled
sc config "SCardSvr" start= demand
sc config "ScDeviceEnum" start= demand
sc config "SCPolicySvc" start= demand
sc config "SEMgrSvc" start= disabled
sc config "SensorDataService" start= disabled
sc config "SensorService" start= disabled
sc config "SensrSvc" start= demand
sc config "Server" start= disabled
sc config "SmsRouter" start= disabled
sc config "TermService" start= disabled
sc config "UmRdpService" start= disabled
sc config "vds" start= demand
sc config "vss" start= disabled
sc config "WalletService" start= disabled
sc config "wbengine" start= demand
sc config "WinRM" start= disabled
sc config "WMPNetworkSvc" start= disabled
sc config "workfolderssvc" start= disabled
sc config "WPCSvc" start= disabled
sc config "pla" start= disabled
sc config "PerfHost" start= disabled
sc config "SessionEnv" start= disabled
sc config "ClickToRunSvc" start= disabled
sc config "TrkWks" start= disabled
sc config "sppsvc" start= demand
sc config "wlidsvc" start= demand
sc config "NcdAutoSetup" start= disabled
sc config "seclogon" start= disabled
sc config "spectrum" start= disabled
sc config "ALG" start= disabled
sc config "COMSysApp" start= disabled
sc config "DeviceAssociationService" start= demand
sc config "EFS" start= demand
sc config "fhsvc" start= disabled
sc config "HomeGroupListener" start= disabled
sc config "HomeGroupProvider" start= disabled
sc config "IKEEXT" start= disabled
sc config "keyiso" start= disabled
sc config "lltdsvc" start= disabled
sc config "SNMPTRAP" start= disabled
sc config "SSDPSRV" start= disabled
sc config "StorSvc" start= disabled
sc config "TroubleshootingSvc" start= disabled
sc config "upnphost" start= disabled
sc config "VaultSvc" start= disabled
sc config "Wcmsvc" start= disabled
sc config "WEPHOSTSVC" start= disabled
sc config "WiaRpc" start= disabled
sc config "WinHttpAutoProxySvc" start= disabled
sc config "WPDBusEnum" start= disabled
sc config "WpnService" start= disabled
sc config "TimeBrokerSvc" start= disabled
sc config "CscService" start= disabled
sc config "SDRSVC" start= demand
sc config "AppMgmt" start= disabled
sc config "PeerDistSvc" start= disabled
sc config "Browser" start= disabled
sc config "edgeupdate" start= disabled
sc config "edgeupdatem" start= disabled
sc config "cbdhsvc" start= disabled
sc config "AJRouter" start= demand
sc config "RmSvc" start= demand
sc config "SystemUsageReportSvc_QUEENCREEK" start= disabled
sc config "SgrmAgent" start= disabled
sc config "uhssvc" start= disabled
sc config "Fax" start= disabled
sc config "Themes" start= disabled
sc config "ShellHWDetection" start= disabled
sc config "TabletInputService" start= disabled

:: ============================================================================
:: SERVICIOS ADICIONALES MODO DEMANDA
:: ============================================================================

sc config "AppIDSvc" start= demand
sc config "Appinfo" start= demand
sc config "ConsentUxUserSvc_*" start= demand
sc config "CredentialEnrollmentManagerUserSvc_*" start= demand
sc config "DcpSvc" start= demand
sc config "DevQueryBroker" start= demand
sc config "DeviceAssociationBrokerSvc_*" start= demand
sc config "DeviceInstall" start= demand
sc config "DevicePickerUserSvc_*" start= demand
sc config "DevicesFlowUserSvc_*" start= demand
sc config "DmEnrollmentSvc" start= demand
sc config "DsSvc" start= demand
sc config "DsmSvc" start= demand
sc config "EapHost" start= demand
sc config "EntAppSvc" start= demand
sc config "FDResPub" start= demand
sc config "FrameServerMonitor" start= demand
sc config "IEEtwCollectorService" start= demand
sc config "InventorySvc" start= demand
sc config "IpxlatCfgSvc" start= demand
sc config "KtmRm" start= demand
sc config "LxpSvc" start= demand
sc config "MSDTC" start= demand
sc config "MSiSCSI" start= demand
sc config "McpManagementService" start= demand
sc config "MessagingService_*" start= demand
sc config "MicrosoftEdgeElevationService" start= demand
sc config "MixedRealityOpenXRSvc" start= demand
sc config "NPSMSvc_*" start= demand
sc config "NaturalAuthentication" start= demand
sc config "NcaSvc" start= demand
sc config "NcbService" start= demand
sc config "NetSetupSvc" start= demand
sc config "NgcCtnrSvc" start= demand
sc config "NgcSvc" start= demand
sc config "P9RdrService_*" start= demand
sc config "PNRPAutoReg" start= demand
sc config "PNRPsvc" start= demand
sc config "PenService_*" start= demand
sc config "PlugPlay" start= demand
sc config "PrintWorkflowUserSvc_*" start= demand
sc config "PushToInstall" start= demand
sc config "RpcLocator" start= demand
sc config "SharedRealitySvc" start= demand
sc config "SstpSvc" start= demand
sc config "StiSvc" start= demand
sc config "TieringEngineService" start= demand
sc config "TimeBroker" start= demand
sc config "TokenBroker" start= demand
sc config "TrustedInstaller" start= demand
sc config "UI0Detect" start= demand
sc config "UdkUserSvc_*" start= demand
sc config "UnistoreSvc_*" start= demand
sc config "UserDataSvc_*" start= demand
sc config "VSS" start= demand
sc config "VacSvc" start= demand
sc config "W32Time" start= demand
sc config "WFDSConMgrSvc" start= demand
sc config "WManSvc" start= demand
sc config "WSService" start= demand
sc config "WarpJITSvc" start= demand
sc config "WcsPlugInService" start= demand
sc config "WebClient" start= demand
sc config "autotimesvc" start= demand
sc config "camsvc" start= demand
sc config "cloudidsvc" start= demand
sc config "dcsvc" start= demand
sc config "embeddedmode" start= demand
sc config "fdPHost" start= demand
sc config "hidserv" start= demand
sc config "msiserver" start= demand
sc config "p2pimsvc" start= demand
sc config "p2psvc" start= demand
sc config "perceptionsimulation" start= demand
sc config "smphost" start= demand
sc config "svsvc" start= demand
sc config "swprv" start= demand
sc config "vmicguestinterface" start= demand
sc config "vmicheartbeat" start= demand
sc config "vmickvpexchange" start= demand
sc config "vmicrdv" start= demand
sc config "vmicshutdown" start= demand
sc config "vmictimesync" start= demand
sc config "vmicvmsession" start= demand
sc config "vmicvss" start= demand
sc config "vmvss" start= demand
sc config "webthreatdefsvc" start= demand
sc config "wercplsupport" start= demand
sc config "wisvc" start= demand
sc config "wlpasvc" start= demand
sc config "wmiApSrv" start= demand
sc config "wudfsvc" start= demand

:: ============================================================================
:: ELIMINACION DE SERVICIOS GOOGLE
:: ============================================================================

net stop gupdate
sc delete gupdate
net stop googlechromeelevationservice
sc delete googlechromeelevationservice
net stop gupdatem
sc delete gupdatem

:: ============================================================================
:: ELIMINACION DE SERVICIOS BRAVE
:: ============================================================================

net stop brave
net stop bravem

:: ============================================================================
:: MOZILLA FIREFOX
:: ============================================================================

taskkill /f /im maintenanceservice.exe
taskkill /f /im uninstall.exe
net stop MozillaMaintenance
sc delete MozillaMaintenance

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f

:: ============================================================================
:: EDGE
:: ============================================================================

SC STOP edgeupdate
SC CONFIG edgeupdate start= disabled
SC DELETE edgeupdate
