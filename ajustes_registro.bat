@echo off

REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d 4294967295 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d 3 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d 32 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "ThreadPriority" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d 4 /f
sc config "AppVClient" start=disabled >nul
sc config "AssignedAccessManagerSvc" start=disabled >nul
sc config "AxInstSV" start=disabled >nul
sc config "BDESVC" start=disabled >nul
sc config "CertPropSvc" start=disabled >nul
sc config "CloudBackup" start=disabled >nul
sc config "CDPSvc" start=disabled >nul
sc config "CDPUserSvc" start=disabled >nul
sc config "defragsvc" start=disabled >nul
sc config "DisplayEnhancementService" start=disabled >nul
sc config "FrameServer" start=disabled >nul
sc config "lfsvc" start=disabled >nul
sc config "lmhosts" start=disabled >nul
sc config "MapsBroker" start=disabled >nul
sc config "NetTcpPortSharing" start=disabled >nul
sc config "OneSyncSvc" start=disabled >nul
sc config "PhoneSvc" start=disabled >nul
sc config "PimIndexMaintenanceSvc" start=disabled >nul
sc config "PolicyAgent" start=disabled >nul
sc config "QWAVE" start=disabled >nul
sc config "RasMan" start=disabled >nul
sc config "RemoteAccess" start=disabled >nul
sc config "RemoteRegistry" start=disabled >nul
sc config "RetailDemo" start=disabled >nul
sc config "SCardSvr" start=disabled >nul
sc config "ScDeviceEnum" start=disabled >nul
sc config "SCPolicySvc" start=disabled >nul
sc config "SEMgrSvc" start=disabled >nul
sc config "SensorDataService" start=disabled >nul
sc config "SensorService" start=disabled >nul
sc config "SensrSvc" start=disabled >nul
sc config "Server" start=disabled >nul
sc config "SmsRouter" start=disabled >nul
sc config "stisvc" start=disabled >nul
sc config "SysMain" start=disabled >nul
sc config "TapiSrv" start=disabled >nul
sc config "TermService" start=disabled >nul
sc config "UmRdpService" start=disabled >nul
sc config "vds" start=manual >nul
sc config "vss" start=disabled >nul
sc config "WalletService" start=disabled >nul
sc config "wbengine" start=disabled >nul
sc config "WbioSrvc" start=disabled >nul
sc config "WinRM" start=disabled >nul
sc config "WMPNetworkSvc" start=disabled >nul
sc config "workfolderssvc" start=disabled >nul
sc config "WPCSvc" start=disabled >nul
sc config "WSearch" start=disabled >nul
sc config "XblAuthManager" start=disabled >nul
sc config "XblGameSave" start=disabled >nul
sc config "XboxNetApiSvc" start=disabled >nul
sc config "diagnosticshub.standardcollector.service" start=disabled >nul
sc config "DPS" start=disabled >nul
sc config "WdiServiceHost" start=disabled >nul
sc config "WdiSystemHost" start=disabled >nul
sc config "WerSvc" start=disabled >nul
sc config "pla" start=disabled >nul
sc config "PerfHost" start=disabled >nul
sc config "PcaSvc" start=disabled >nul
sc config "hvservice" start=disabled >nul
sc config "SessionEnv" start=disabled >nul
sc config "ClickToRunSvc" start=disabled >nul
sc config "TrkWks" start=disabled >nul
sc config "sppsvc" start=demand >nul
sc config "wlidsvc" start=disabled >nul
sc config "WaaSMedicSvc" start=disabled >nul
sc config "NcdAutoSetup" start=disabled >nul
sc config "seclogon" start=disabled >nul
sc config "XboxGipSvc" start=disabled >nul
sc config "spectrum" start=disabled >nul
sc config "ALG" start=disabled >nul
sc config "COMSysApp" start=disabled >nul
sc config "DeviceAssociationService" start=disabled >nul
sc config "diagsvc" start=disabled >nul
sc config "EFS" start=disabled >nul
sc config "fhsvc" start=disabled >nul
sc config "HomeGroupListener" start=disabled >nul
sc config "HomeGroupProvider" start=disabled >nul
sc config "IKEEXT" start=disabled >nul
sc config "keyiso" start=disabled >nul
sc config "lltdsvc" start=disabled >nul
sc config "RasAuto" start=disabled >nul
sc config "SNMPTRAP" start=disabled >nul
sc config "SSDPSRV" start=disabled >nul
sc config "StorSvc" start=disabled >nul
sc config "TroubleshootingSvc" start=disabled >nul
sc config "upnphost" start=disabled >nul
sc config "VaultSvc" start=disabled >nul
sc config "Wcmsvc" start=disabled >nul
sc config "WEPHOSTSVC" start=disabled >nul
scL config "WiaRpc" start=disabled >nul
sc config "WinHttpAutoProxySvc" start=disabled >nul
sc config "WPDBusEnum" start=disabled >nul
sc config "wscsvc" start=disabled >nul
sc config "WpnService" start=disabled >nul
sc config "TimeBrokerSvc" start=disabled >nul
sc config "CscService" start=disabled >nul
sc config "SDRSVC" start=disabled >nul
sc config "Wecsvc" start=disabled >nul
sc config "AppMgmt" start=disabled >nul
sc config "PeerDistSvc" start=disabled >nul
sc config "Browser" start=disabled >nul
sc config "edgeupdate" start=disabled >nul
sc config "edgeupdatem" start=disabled >nul


sc config "FontCache" start=disabled >nul
sc config "FontCache3.0.0.0" start=disabled >nul
sc config "cbdhsvc" start=disabled >nul
sc config "AJRouter" start=auto >nul
sc config "RmSvc" start=auto >nul
sc config "SystemUsageReportSvc_QUEENCREEK" start=disabled >nul
sc config "GpuEnergyDrv" start=disabled >nul
sc config "SgrmAgent" start=disabled >nul
sc config "uhssvc" start=disabled >nul
sc config "wuauserv" start=demand >nul
sc config "UsoSvc" start=demand >nul
sc config "BITS" start=demand >nul
sc config "DoSvc" start=demand >nul
sc config "AJRouter" start=demand >nul
sc config "ALG" start=demand >nul
sc config "AppIDSvc" start=demand >nul
sc config "AppMgmt" start=demand >nul
sc config "Appinfo" start=demand >nul
sc config "AssignedAccessManagerSvc" start=demand >nul
sc config "AxInstSV" start=demand >nul
sc config "BDESVC" start=demand >nul
sc config "Browser" start=demand >nul
sc config "CertPropSvc" start=demand >nul
sc config "ConsentUxUserSvc_*" start=demand >nul
sc config "CredentialEnrollmentManagerUserSvc_*" start=demand >nul
sc config "CscService" start=demand >nul
sc config "DcpSvc" start=demand >nul
sc config "DevQueryBroker" start=demand >nul
sc config "DeviceAssociationBrokerSvc_*" start=demand >nul
sc config "DeviceAssociationService" start=demand >nul
sc config "DeviceInstall" start=demand >nul
sc config "DevicePickerUserSvc_*" start=demand >nul
sc config "DevicesFlowUserSvc_*" start=demand >nul
sc config "DisplayEnhancementService" start=demand >nul
sc config "DmEnrollmentSvc" start=demand >nul
sc config "DsSvc" start=demand >nul
sc config "DsmSvc" start=demand >nul
sc config "EFS" start=demand >nul
sc config "EapHost" start=demand >nul
sc config "EntAppSvc" start=demand >nul
sc config "FDResPub" start=demand >nul
sc config "Fax" start=demand >nul
sc config "FrameServer" start=demand >nul
sc config "FrameServerMonitor" start=demand >nul
sc config "GraphicsPerfSvc" start=demand >nul
sc config "HomeGroupListener" start=demand >nul
sc config "HomeGroupProvider" start=demand >nul
sc config "HvHost" start=demand >nul
sc config "IEEtwCollectorService" start=demand >nul
sc config "IKEEXT" start=demand >nul
sc config "InventorySvc" start=demand >nul
sc config "IpxlatCfgSvc" start=demand >nul
sc config "KtmRm" start=demand >nul
sc config "LxpSvc" start=demand >nul
sc config "MSDTC" start=demand >nul
sc config "MSiSCSI" start=demand >nul
sc config "McpManagementService" start=demand >nul
sc config "MessagingService_*" start=demand >nul
sc config "MicrosoftEdgeElevationService" start=demand >nul
sc config "MixedRealityOpenXRSvc" start=demand >nul
sc config "NPSMSvc_*" start=demand >nul
sc config "NaturalAuthentication" start=demand >nul
sc config "NcaSvc" start=demand >nul
sc config "NcbService" start=demand >nul
sc config "NcdAutoSetup" start=demand >nul
sc config "NetSetupSvc" start=demand >nul
sc config "NgcCtnrSvc" start=demand >nul
sc config "NgcSvc" start=demand >nul
sc config "P9RdrService_*" start=demand >nul
sc config "PNRPAutoReg" start=demand >nul
sc config "PNRPsvc" start=demand >nul
sc config "PeerDistSvc" start=demand >nul
sc config "PenService_*" start=demand >nul
sc config "PerfHost" start=demand >nul
sc config "PhoneSvc" start=demand >nul
sc config "PimIndexMaintenanceSvc_*" start=demand >nul
sc config "PlugPlay" start=demand >nul
sc config "PolicyAgent" start=demand >nul
sc config "PrintNotify" start=demand >nul
sc config "PrintWorkflowUserSvc_*" start=demand >nul
sc config "PushToInstall" start=demand >nul
sc config "QWAVE" start=demand >nul
sc config "RasAuto" start=demand >nul
sc config "RasMan" start=demand >nul
sc config "RetailDemo" start=demand >nul
sc config "RmSvc" start=demand >nul
sc config "RpcLocator" start=demand >nul
sc config "SCPolicySvc" start=demand >nul
sc config "SCardSvr" start=demand >nul
sc config "SDRSVC" start=demand >nul
sc config "SEMgrSvc" start=demand >nul
sc config "SNMPTRAP" start=demand >nul
sc config "SNMPTrap" start=demand >nul
sc config "SSDPSRV" start=demand >nul
sc config "ScDeviceEnum" start=demand >nul
sc config "SecurityHealthService" start=demand >nul
sc config "Sense" start=demand >nul
sc config "SensorDataService" start=demand >nul
sc config "SensorService" start=demand >nul
sc config "SensrSvc" start=demand >nul
sc config "SessionEnv" start=demand >nul
sc config "SharedAccess" start=demand >nul
sc config "SharedRealitySvc" start=demand >nul
sc config "SmsRouter" start=demand >nul
sc config "SstpSvc" start=demand >nul
sc config "StiSvc" start=demand >nul
sc config "TabletInputService" start=demand >nul
sc config "TapiSrv" start=demand >nul
sc config "TieringEngineService" start=demand >nul
sc config "TimeBroker" start=demand >nul
sc config "TimeBrokerSvc" start=demand >nul
sc config "TokenBroker" start=demand >nul
sc config "TroubleshootingSvc" start=demand >nul
sc config "TrustedInstaller" start=demand >nul
sc config "UI0Detect" start=demand >nul
sc config "UdkUserSvc_*" start=demand >nul
sc config "UmRdpService" start=demand >nul
sc config "UnistoreSvc_*" start=demand >nul
sc config "UserDataSvc_*" start=demand >nul
sc config "VSS" start=demand >nul
sc config "VacSvc" start=demand >nul
sc config "W32Time" start=demand >nul
sc config "WEPHOSTSVC" start=demand >nul
sc config "WFDSConMgrSvc" start=demand >nul
sc config "WMPNetworkSvc" start=demand >nul
sc config "WManSvc" start=demand >nul
sc config "WPDBusEnum" start=demand >nul
sc config "WSService" start=demand >nul
sc config "WaaSMedicSvc" start=demand >nul
sc config "WalletService" start=demand >nul
sc config "WarpJITSvc" start=demand >nul
sc config "WbioSrvc" start=demand >nul
sc config "WcsPlugInService" start=demand >nul
sc config "WdNisSvc" start=demand >nul
sc config "WebClient" start=demand >nul
sc config "Wecsvc" start=demand >nul
sc config "WerSvc" start=demand >nul
sc config "WiaRpc" start=demand >nul
sc config "WinHttpAutoProxySvc" start=demand >nul
sc config "WinRM" start=demand >nul
sc config "WpcMonSvc" start=demand >nul
sc config "XblAuthManager" start=demand >nul
sc config "XblGameSave" start=demand >nul
sc config "XboxGipSvc" start=demand >nul
sc config "XboxNetApiSvc" start=demand >nul
sc config "autotimesvc" start=demand >nul
sc config "camsvc" start=demand >nul
sc config "cloudidsvc" start=demand >nul
sc config "dcsvc" start=demand >nul
sc config "defragsvc" start=demand >nul
sc config "dmwappushservice" start=demand >nul
sc config "embeddedmode" start=demand >nul
sc config "fdPHost" start=demand >nul
sc config "fhsvc" start=demand >nul
sc config "hidserv" start=demand >nul
sc config "lltdsvc" start=demand >nul
sc config "lmhosts" start=demand >nul
sc config "msiserver" start=demand >nul
sc config "p2pimsvc" start=demand >nul
sc config "p2psvc" start=demand >nul
sc config "perceptionsimulation" start=demand >nul
sc config "pla" start=demand >nul
sc config "seclogon" start=demand >nul
sc config "smphost" start=demand >nul
sc config "spectrum" start=demand >nul
sc config "svsvc" start=demand >nul
sc config "swprv" start=demand >nul
sc config "upnphost" start=demand >nul
sc config "vds" start=demand >nul
sc config "vmicguestinterface" start=demand >nul
sc config "vmicheartbeat" start=demand >nul
sc config "vmickvpexchange" start=demand >nul
sc config "vmicrdv" start=demand >nul
scL "vmicshutdown" start=demand >nul
sc config "vmictimesync" start=demand >nul
sc config "vmicvmsession" start=demand >nul
sc config "vmicvss" start=demand >nul
sc config "vmvss" start=demand >nul
sc config "wbengine" start=demand >nul
sc config "webthreatdefsvc" start=demand >nul
sc config "wercplsupport" start=demand >nul
sc config "wisvc" start=demand >nul
sc config "wlidsvc" start=demand >nul
sc config "wlpasvc" start=demand >nul
sc config "wmiApSrv" start=demand >nul
sc config "workfolderssvc" start=demand >nul
scD "wuauserv" start=demand >nul
sc config "wudfsvc" start=demand >nul
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\HelloFace\FODCleanupTask" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClient" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Device Information\Device" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Device Information\Device User" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /DISABLE >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\Scheduled Start" /Disable >nul 2>&1
schtasks /end /tn "\Microsoft\XblGameSave\XblGameSaveTask" >nul 2>&1
schtasks /change /tn "\Microsoft\XblGameSave\XblGameSaveTask" /disable >nul 2>&1
schtasks /end /tn "\Microsoft\XblGameSave\XblGameSaveTaskLogon" >nul 2>&1
schtasks /change /tn "\Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Performance\PerfTrack" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Defrag\ScheduledDefrag" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Defrag\ScheduledOptimize" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\RAID Recovery\Scheduled" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Servicing\StartComponentCleanup" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Recovery Environment\VerifyWinRE" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\EDP\StorageCardEncryption Task" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\BitLocker\BitLocker MDM policy Refresh" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\TaskScheduler\Maintenance Configurator" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\TaskScheduler\Regular Maintenance" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\TaskScheduler\Idle Maintenance" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Maps\MapsUpdateTask" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (triggered backup)" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\QueueReader" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ScheduledTask | Where-Object {$_.TaskName -match 'Diag|Telemetry|Customer Experience|OfficeClickToRun'} | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue" >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Application Experience\AITAgent" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Maintenance\Regular Maintenance" /disable >nul 2>&1


schtasks /change /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\*" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\UpdateAssistant\*" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\WaaSMedic\*" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\WindowsUpdate\*" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\MareBackup" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Control Panel\International\UserProfile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceMFT" /v "DisableCodecs" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MSDeploy\3" /v "EnableTelemetry" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "EnableCdp" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\SOFTWARE Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackStatus" /t REG_DWORD /d "2" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "UploadPermissionReceived" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackAuthorization" /t REG_DWORD /d "775" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ClearRecentDocsOnExit" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "AllowLinguisticDataCollection" /t REG_DWORD /d 0 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f >nul
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d 31 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f >nul
fsutil behavior set disablecompression 1 >nul
fsutil behavior set disableencryption 1 >nul
fsutil behavior set encryptpagingfile 0 >nul
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "2000" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEngCP.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "50" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize " /t REG_DWORD /d "50" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters" /v "SampleRate" /t REG_DWORD /d 200 /f >nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "Disable-MMAgent -mc" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "Disable-MMAgent -ApplicationLaunchPrefetching -OperationAPI -PageCombining -ApplicationPreLaunch" 2>nul
bcdedit /set disabledynamictick yes 2>nul
bcdedit /set useplatformclock true 2>nul
bcdedit /set tscsyncpolicy Enhanced 2>nul
bcdedit /set useplatformtick yes 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Telemetry" /v Affinity /t REG_DWORD /d !mask! /f >nul 2>&1
set "processes=TiWorker.exe TrustedInstaller.exe wuauclt.exe WuSoCoreWorker.exe MoUsoCoreWorker.exe diagtrack.exe"
for %%p in (%processes%) do (
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%p\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%p" /v AffinityMask /t REG_DWORD /d !mask! /f >nul 2>&1
)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableSR" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSense" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SpellCheck" /v "DisableSpellchecking" /t REG_DWORD /d 1 /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotIncludeDriversWithWindowsUpdate" /t REG_DWORD /d 1 /f 2>nul
dism /online /disable-feature /featurename:Microsoft-Hyper-V /norestart >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_SZ /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_SZ /d 6 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul 2>&1
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /format:value') do set MEM=%%i
set /a RAM=%MEM% + 1024000
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%RAM%" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v "Start" /t REG_DWORD /d 2 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "2" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f >nul
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "BorderWidth" /t REG_SZ /d "-15" /f >nul
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "CaptionHeight" /t REG_SZ /d "-330" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\DefaultColors\Standard" /v "HotTrackingColor" /t REG_DWORD /d "13395456" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\DefaultColors\HighContrast" /v "HotTrackingColor" /t REG_DWORD /d "65535" /f >nul
reg add "HKCU\Control Panel\Cursors" /v "ContactVisualization" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\Control Panel\Cursors" /v "GestureVisualization" /t REG_DWORD /d "0" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 2 /f 2>nul
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d 0 /f 2>nul
reg add "HKCU\Control Panel\Desktop" /v "MenuAnimate" /t REG_SZ /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "Animations" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCU\AppEvents\Schemes" /ve /d ".None" /f 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d 1 /f 2>nul
reg add "HKCU\Control Panel\Sound" /v "Beep" /t REG_SZ /d "no" /f 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f 2>nul
reg add "HKCR\DesktopBackground\shell\Shutdown" /ve /t REG_SZ /d "Apagar equipo" /f >nul 2>&1
reg add "HKCR\DesktopBackground\shell\Shutdown\command" /ve /t REG_SZ /d "shutdown /s /t 0" /f >nul 2>&1
reg add "HKCR\DesktopBackground\shell\Restart" /ve /t REG_SZ /d "Reiniciar equipo" /f >nul 2>&1
reg add "HKCR\DesktopBackground\shell\Restart\command" /ve /t REG_SZ /d "shutdown /r /t 0" /f >nul 2>&1
reg add "HKCR\DesktopBackground\shell\Settings" /ve /t REG_SZ /d "Configuracion" /f >nul 2>&1
reg add "HKCR\DesktopBackground\shell\Settings\command" /ve /t REG_SZ /d "ms-settings:" /f >nul 2>&1
reg add "HKCR\DesktopBackground\shell\ControlPanel" /ve /t REG_SZ /d "Panel de control" /f >nul 2>&1
reg add "HKCR\DesktopBackground\shell\ControlPanel\command" /ve /t REG_SZ /d "control" /f >nul 2>&1
reg add "HKCR\DesktopBackground\shell\TaskManager" /ve /t REG_SZ /d "Gestor de tareas" /f >nul 2>&1
reg add "HKCR\DesktopBackground\shell\TaskManager\command" /ve /t REG_SZ /d "taskmgr" /f >nul 2>&1
reg add "HKCR\*\shell\TakeOwnership" /ve /t REG_SZ /d "Tomar propiedad" /f >nul 2>&1
reg add "HKCR\*\shell\TakeOwnership\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l' -Verb runAs\"" /f >nul 2>&1
reg add "HKCR\Directory\shell\TakeOwnership" /ve /t REG_SZ /d "Tomar propiedad" /f >nul 2>&1
reg add "HKCR\Directory\shell\TakeOwnership\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%1\\\" /r /d y && icacls \\\"%1\\\" /grant *S-1-3-4:F /t /c /l /q' -Verb runAs\"" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Clipboard" /v "EnableClipboardHistory" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d 0 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d 0 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 3 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d 0 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d 200 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "MinAnimate" /t REG_SZ /d 0 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "KeyboardDelay" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "ListviewAlphaSelect" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "ListviewShadow" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 3 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "400" /f >nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "1" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >nul


powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true" >nul 2>&1
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true" >nul 2>&1
powershell -Command "Set-MpPreference -DisableBlockAtFirstSeen $true" >nul 2>&1
powershell -Command "Set-MpPreference -DisablePrivacyMode $true" >nul 2>&1
powershell -Command "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" >nul 2>&1
powershell -Command "Set-MpPreference -DisableArchiveScanning $true" >nul 2>&1
powershell -Command "Set-MpPreference -DisableIntrusionPreventionSystem $true" >nul 2>&1
powershell -Command "Set-MpPreference -DisableScriptScanning $true" >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Acrobat.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AcrobatInfo.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AcroCEF.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AcroRd32.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AcroServicesUpdater.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ExtExport.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ie4uinit.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ieinstal.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ielowutil.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ieUnatt.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\iexplore.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mscorsvw.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msfeedssync.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mshta.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngen.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngentask.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PresentationHost.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PrintDialog.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PrintIsolationHost.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\runtimebroker.exe" /v "MitigationOptions" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\splwow64.exe" /v "MitigationOptions" /f >nul 2>&1




reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
netsh interface ipv6 set global randomizeidentifiers=disabled store=persistent >nul 2>&1
netsh interface tcp set global initialrto=2000 >nul 2>&1
netsh advfirewall set allprofiles state off >nul 2>&1
powershell -NoLogo -NoProfile -NonInteractive -Command "Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip,ms_pacer" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-NetTCPSetting -SettingName InternetCustom,DatacenterCustom,Compat -ForceWS Disabled -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CTCP -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Get-NetAdapter | Enable-NetAdapterRss -ErrorAction SilentlyContinue; Get-NetAdapter | ForEach-Object { try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Receive Buffers' -RegistryValue 512 -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Transmit Buffers' -RegistryValue 512 -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Energy Efficient Ethernet' -RegistryValue '0' -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Interrupt Moderation' -RegistryValue 'Disabled' -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Flow Control' -RegistryValue 'Disabled' -ErrorAction SilentlyContinue } catch {} } }" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Get-NetAdapter | ForEach-Object { Disable-NetAdapterChecksumOffload -Name $_.Name -IpIPv4 -TcpIPv4 -TcpIPv6 -UdpIPv4 -UdpIPv6 -ErrorAction SilentlyContinue; Disable-NetAdapterLso -Name $_.Name -IPv4 -IPv6 -ErrorAction SilentlyContinue } }" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetAdapter | Disable-NetAdapterPowerManagement -WakeOnMagicPacket:$false -WakeOnPattern:$false -DeviceSleepOnDisconnect:$false -SelectiveSuspend:$false -ArpOffload:$false -NSOffload:$false -D0PacketCoalescing:$false -RsnRekeyOffload:$false -NoRestart -ErrorAction SilentlyContinue" >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNicBuffers" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v "NodeType" /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableDHCPMediaSenseEventLog" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d 2 /f >nul
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "accesssolution" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "olksolution" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "onenotesolution" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "pptsolution" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "projectsolution" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "publishersolution" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "visiosolution" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "wdsolution" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "xlsolution" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "agave" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "verbosestatus" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout" /v "EnableAutoLayout" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "N" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\DefragPath" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "WebControlStatus" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "WebControlSecondaryStatus" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d 3 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v "DisableBranchCache" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\BITS" /v "DisableBranchCache" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsMenu" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d 1 /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentDocsOnExit" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HidePeopleBar" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoResolveTrack" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoRecentDocsMenu" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LastActiveClick" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f
REG ADD "HKEY_USERS\.DEFAULT\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_USERS\.DEFAULT\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f
REG ADD "HKEY_USERS\.DEFAULT\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d 1 /f
REG ADD "HKEY_USERS\.DEFAULT\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 1 /f
REG ADD "HKEY_USERS\.DEFAULT\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d 0 /f
REG ADD "HKEY_USERS\.DEFAULT\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d 2 /f
REG ADD "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility" /v "DynamicScrollbars" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\Maps" /v "UpdateOnlyOnWifi" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Maps\AllowOfflineMapsDownloadOverMeteredConnection" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Maps\EnableOfflineMapsAutoUpdate" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d 3 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\ConfigureChatIcon" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "Capabilities" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "PreventAutoRun" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "PaddedBorderWidth" /t REG_SZ /d "0" /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "MaxAnimate" /t REG_SZ /d "0" /f
REG ADD "HKEY_USERS\.DEFAULT\Control Panel\Desktop\WindowMetrics" /v "PaddedBorderWidth" /t REG_SZ /d "0" /f
REG ADD "HKEY_USERS\.DEFAULT\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
REG ADD "HKEY_USERS\.DEFAULT\Control Panel\Desktop\WindowMetrics" /v "MaxAnimate" /t REG_SZ /d "0" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v "AnimationAttributionEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v "AnimationAttributionHashingEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v "AnimationAttributionEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v "AnimationAttributionHashingEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VSCommon\17.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VSCommon\17.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DiskQuota" /v "Enforce" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DiskQuota" /v "Enable" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DiskQuota" /v "LogEventOverLimit" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DiskQuota" /v "LogEventOverThreshold" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d 0 /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular" /v "TracingDisabled" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\DeviceHealthAttestationService" /v "EnableDeviceHealthAttestationService" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarContentUpdateMode" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarOpenOnHover" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowThirdPartySuggestionsInWindowsSpotlight" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsSpotlight" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowSpotlightCollection" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsSpotlightOnActionCenter" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsSpotlightOnSettings" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsSpotlightWindowsWelcomeExperience" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsTips" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\ConfigureWindowsSpotlightOnLockScreen" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EditionOverrides" /v "UserSetting_DisableStartupSound" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Boot" /v "DisableStartupSound" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Stickers\EnableStickers" /v "value" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HidePeopleBar" /v "value" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People\ShoulderTap" /v "ShoulderTapAudio" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d 0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d 0000000000000000000038000000000000007000000000000000a800000000000000e00000000000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 4294967295 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Catergory" /t REG_SZ /d "High" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Priority" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "AwayModeEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "CoreParkingDisabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "FastBoot" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "VirtualizationEnabled" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d 0 /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "FreezeThawTimeoutInSeconds" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenu.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenu.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenu.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sppsvc.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sppsvc.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sppsvc.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d 31 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d 8 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "High" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d 31 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d 8 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "High" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MoUsoCoreWorker.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MoUsoCoreWorker.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MoUsoCoreWorker.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MoUsoCoreWorker.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Compattelrunner.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Compattelrunner.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Compattelrunner.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Compattelrunner.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d 3 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnablePrefetcher" /t REG_DWORD /d 3 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableSuperfetch" /t REG_DWORD /d 3 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "100" /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpDelAckTicks" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d 65534 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d 65535 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d 65535 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Network" /v "GPU Priority" /t REG_DWORD /d 8 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Network" /v "Priority" /t REG_DWORD /d 8 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Network" /v "Scheduling Category" /t REG_SZ /d "High" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Network" /v "SFIO Priority" /t REG_SZ /d "High" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSettings" /t REG_DWORD /d 2 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d 0 /f
REG ADD "HKEY_CURRENT_USER\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\System\TurnOffFileHistory" /v "value" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d 1 /f
for /l %%i in (0,1,10) do (
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}\000%%i" /v "IdleEnable" /t REG_DWORD /d 0 /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1fb2a002-4c6c-4de7-85c2-cb8db9a4f728}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{7988B571-EC89-11cf-9C00-00AA00A14F56}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{7988B573-EC89-11cf-9C00-00AA00A14F56}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{1fb2a002-4c6c-4de7-85c2-cb8db9a4f728}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7988B571-EC89-11cf-9C00-00AA00A14F56}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7988B573-EC89-11cf-9C00-00AA00A14F56}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Microsoft.DiskQuota" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Microsoft.DiskQuota.1" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{BB0DB60E-FFA0-4756-9F04-A0FCE6A97809}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{BBD5AFE4-1417-40f7-94B3-A10719535CB4}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{4D728E35-16FA-4320-9E8B-BFD7100A8846}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{614C2902-8C8F-4D8F-90A2-FB9017B19FF9}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{6A5FEA5B-BF8F-4EE5-B8C3-44D8A0D7331C}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{A4F2A5C9-979A-4EC6-851F-341F15D3F67D}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{B164BCEE-41B3-4F70-A53C-2ACA322DCCCB}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{98859A6C-02F2-43FC-ADB0-CE6D10F1A1AA}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{C5388469-F816-40D2-9E6B-D6C68986996E}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7AA809F6-C072-11DF-AC23-18A90531A85A}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7AA809F7-C072-11DF-AC23-18A90531A85A}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7AA809F8-C072-11DF-AC23-18A90531A85A}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{E49F7E50-C070-11DF-AC23-18A90531A85A}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{168F4281-EC0D-46D3-951D-FBCB2F7C9079}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{90511715-D0AD-4DAA-A18B-254BD3AE1CF2}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{A7AA4814-7479-4047-BC99-32E757C8B850}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{59C88A5A-702B-4DAB-9FBE-F53140BA899B}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{B5A123C0-3893-4F1C-8599-00F4B82F2C99}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{0F563B5F-8EE2-4516-BA0A-544DE058C75B}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{F6B6E965-E9B2-444B-9286-10C9152EDBC5}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f
REG DELETE "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\PropertySheetHandlers\{7EFA68C6-086B-43e1-A2D2-55A113531240}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.CscWorkOfflineOnline" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.CscSync" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{0F563B5F-8EE2-4516-BA0A-544DE058C75B}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{F6B6E965-E9B2-444B-9286-10C9152EDBC5}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{0F563B5F-8EE2-4516-BA0A-544DE058C75B}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{F6B6E965-E9B2-444B-9286-10C9152EDBC5}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{F6B6E965-E9B2-444B-9286-10C9152EDBC5}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_41040327" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DeviceUpdateLocations" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.RibbonSync.WorkOfflineOnline" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.RibbonSync.SyncThisFolder" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.RibbonSync.MakeAvailableOffline" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\FileHistory" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E61FEADD-31CB-4052-8A16-1F4336764D10}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{E61FEADD-31CB-4052-8A16-1F4336764D10}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{E61FEADD-31CB-4052-8A16-1F4336764D10}" /f
REG DELETE "HKEY_CLASSES_ROOT\ms-meetnow" /f
REG DELETE "HKEY_CLASSES_ROOT\ms-meetnowflyout" /f
REG DELETE "HKEY_CURRENT_USER\Software\Classes\ms-meetnow" /f
REG DELETE "HKEY_CURRENT_USER\Software\Classes\ms-meetnowflyout" /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-meetnowflyout" /f
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-meetnowflyout" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-meetnowflyout" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\JumpViewUI.TaskbarMeetNowFrame" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\JumpViewUI.TaskbarMeetNow2Frame" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.MicrosoftEdge.ContentProcessComponent" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.FamilySafety.AppTimeLimits" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpatialGraphFilter" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{880B9D61-BF97-4850-97D8-CD9EBFC4488A}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{880B9D61-BF97-4850-97D8-CD9EBFC4488A}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{880B9D61-BF97-4850-97D8-CD9EBFC4488A}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\RetailDemo" /f
REG DELETE "HKEY_CLASSES_ROOT\AppXjj5q94522tr3azgc4pv1grpyk9t831ve" /f
REG DELETE "HKEY_CLASSES_ROOT\AppID\{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}" /f
REG DELETE "HKEY_CLASSES_ROOT\AppID\{C2EA2356-994C-45AF-BDAE-10796F73BC47}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{1e46246f-b2ad-4a86-9e08-d0f9e01ee05d}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{61f77d5e-afe9-400b-a5e6-e9e80fc8e601}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{94FBC195-CB86-4142-9A6A-8E9CCF0D4F4D}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{a6e02196-c1bf-4989-8a94-144eee4a9bb2}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{FB046C65-10C7-4994-ABE4-E3F7FD710B2E}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{15D8726E-26CE-495A-817E-3AD7B022FCFA}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{1FD12909-E6DD-4983-A4C6-50B395961110}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{8ba5a5ed-e0c5-4ce6-a1e8-9263e099746f}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{faedbd4d-20b6-43a9-b67c-577127c8d12b}" /f
REG DELETE "HKEY_CLASSES_ROOT\ms-retaildemo-launchbioenrollment" /f
REG DELETE "HKEY_CLASSES_ROOT\ms-retaildemo-launchstart" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\AppID\{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\AppID\{C2EA2356-994C-45AF-BDAE-10796F73BC47}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{FB046C65-10C7-4994-ABE4-E3F7FD710B2E}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\Interface\{15D8726E-26CE-495A-817E-3AD7B022FCFA}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\Interface\{1FD12909-E6DD-4983-A4C6-50B395961110}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\Interface\{8ba5a5ed-e0c5-4ce6-a1e8-9263e099746f}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\Interface\{faedbd4d-20b6-43a9-b67c-577127c8d12b}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{C2EA2356-994C-45AF-BDAE-10796F73BC47}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{1e46246f-b2ad-4a86-9e08-d0f9e01ee05d}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{61f77d5e-afe9-400b-a5e6-e9e80fc8e601}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{94FBC195-CB86-4142-9A6A-8E9CCF0D4F4D}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{a6e02196-c1bf-4989-8a94-144eee4a9bb2}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{FB046C65-10C7-4994-ABE4-E3F7FD710B2E}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{15D8726E-26CE-495A-817E-3AD7B022FCFA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{1FD12909-E6DD-4983-A4C6-50B395961110}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{8ba5a5ed-e0c5-4ce6-a1e8-9263e099746f}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{faedbd4d-20b6-43a9-b67c-577127c8d12b}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-retaildemo-launchstart" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-retaildemo-launchbioenrollment" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\{C2EA2356-994C-45AF-BDAE-10796F73BC47}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{FB046C65-10C7-4994-ABE4-E3F7FD710B2E}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{15D8726E-26CE-495A-817E-3AD7B022FCFA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{1FD12909-E6DD-4983-A4C6-50B395961110}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{8ba5a5ed-e0c5-4ce6-a1e8-9263e099746f}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{faedbd4d-20b6-43a9-b67c-577127c8d12b}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\ProtocolExecute\ms-retaildemo-launchbioenrollment" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\ProtocolExecute\ms-retaildemo-launchstart" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{12D4C69E-24AD-4923-BE19-31321C43A767}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{0886dae5-13ba-49d6-a6ef-d0922e502d96}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{0886dae5-13ba-49d6-a6ef-d0922e502d96}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\RetailDemo.Internal.RetailDemoSetup" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\RetailDemo.Internal.RetailInfoSetter" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\RetailDemo.Internal.WindowsHelloHelper" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\CloudExperienceHostBroker.RetailDemo.ConfigureRetailDemo" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{119b14a0-eb11-40c7-9a3c-e6a8904827d2}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1a9ca6d5-2488-46b1-b439-218f2314a059}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{A5890610-900C-4115-BAFF-767E05E10F1F}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{CD607C8B-17CA-4D2E-BA26-B748553BB0B2}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{DE8DEA9C-CC35-4A6E-8A17-F0C611F249A4}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{EBB236B1-F57F-480D-9DE9-B15A87298EEC}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\AppID\{0886dae5-13ba-49d6-a6ef-d0922e502d96}" /f
REG DELETE "HKEY_CLASSES_ROOT\AppID\{0886dae5-13ba-49d6-a6ef-d0922e502d96}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{119b14a0-eb11-40c7-9a3c-e6a8904827d2}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{1a9ca6d5-2488-46b1-b439-218f2314a059}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{A5890610-900C-4115-BAFF-767E05E10F1F}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{CD607C8B-17CA-4D2E-BA26-B748553BB0B2}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{DE8DEA9C-CC35-4A6E-8A17-F0C611F249A4}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{EBB236B1-F57F-480D-9DE9-B15A87298EEC}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{AAEC1DAE-CC06-4DA4-B762-56A76FD4B2FF}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{0DEE55E7-1157-4FBD-865E-80D4E151DD74}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{75185BE8-64A9-4E35-9B42-EA422CB7D854}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{445AB715-5154-42F6-9DAF-71C05428DF4E}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{76192C2C-2F55-45DF-B1BF-2ADA479F399C}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{8201C8D6-A9A9-41EA-877D-6D29FEE52732}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{8E17139B-5D9A-4EE3-96A1-F9455D55ED34}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{A03D1421-B1EC-11D0-8C3A-00C04FC31D2F}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{B6A55658-AD62-4133-A1D7-C9073361763B}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{BB328424-067F-45AF-8485-C7389ED64A54}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{BED46A0F-EFF2-4EA3-A201-337BE6828F42}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{D5FE7E1F-7473-4D6E-8BD5-3F72B1DB02BE}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{DCABF59E-AF88-41D5-92E8-905680968039}" /f
REG DELETE "HKEY_CLASSES_ROOT\Interface\{F2CC526B-08C7-4E0E-BA62-74A53C4AB446}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{AAEC1DAE-CC06-4DA4-B762-56A76FD4B2FF}" /f
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{0DEE55E7-1157-4FBD-865E-80D4E151DD74}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{445AB715-5154-42F6-9DAF-71C05428DF4E}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{75185BE8-64A9-4E35-9B42-EA422CB7D854}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{76192C2C-2F55-45DF-B1BF-2ADA479F399C}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{8201C8D6-A9A9-41EA-877D-6D29FEE52732}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{8E17139B-5D9A-4EE3-96A1-F9455D55ED34}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{A03D1421-B1EC-11D0-8C3A-00C04FC31D2F}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{B6A55658-AD62-4133-A1D7-C9073361763B}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{BB328424-067F-45AF-8485-C7389ED64A54}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{BED46A0F-EFF2-4EA3-A201-337BE6828F42}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{D5FE7E1F-7473-4D6E-8BD5-3F72B1DB02BE}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{DCABF59E-AF88-41D5-92E8-905680968039}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{F2CC526B-08C7-4E0E-BA62-74A53C4AB446}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\OCHelper.BrowserHelper" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\OCHelper.BrowserHelper.1" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\AppVMachineRegistryStore\Integration\Ownership\Software\Microsoft\Windows\CurrentVersion\App Paths\SKYPESERVER.EXE" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\CLSID\{AAEC1DAE-CC06-4DA4-B762-56A76FD4B2FF}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\OCHelper.BrowserHelper" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\OCHelper.BrowserHelper.1" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\Wow6432Node\CLSID\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\SocialNetworks\ABCH-SKYPE" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\SKYPESERVER.EXE" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\microphone\Apps\Microsoft.Windows.PPISkype_cw5n1h2txyewy" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\microphone\Apps\WhatsNew_cw5n1h2txyewy" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\webcam\Apps\Microsoft.Windows.PPISkype_cw5n1h2txyewy" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Messaging_8wekyb3d8bbweSkypeVide" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.MessagingSkype_8wekyb3d8bbweApp" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.MessagingSkype_8wekyb3d8bbweSkypeVideo" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.MessagingSkype_8wekyb3d8bbwex27e26f40ye031y48a6yb130yd1f20388991ax" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Winners\amd64_microsoft-windows-skype-ortc_31bf3856ad364e35_none_e1fa6582c679b1b3" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extension Compatibility\{22BF413B-C6D2-4D91-82A9-A0F997BA588C}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extension Compatibility\{77BF5300-1474-4EC7-9980-D32B190E9B07}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extension Compatibility\{AE805869-2E5C-4ED4-8F7B-F1F7851A4497}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\WcmSvc\wifinetworkmanager\SocialNetworks\ABCH-SKYPE" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\SKYPESERVER.EXE" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\ROOT\IMAGE\0000\Device Parameters\Processes\skype.exe" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration\Devices\ROOT\IMAGE\0000\Device\Processes\skype.exe" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\diagnostics" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\wercplsupport" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AeLookupSvc" /f
REG DELETE "HKEY_CLASSES_ROOT\AppXkndb5xvk0v1ka1efnjajnamxcd3sfae1" /f
REG DELETE "HKEY_CLASSES_ROOT\ms-desktopsearchbox" /f
REG DELETE "HKEY_CLASSES_ROOT\ms-stickereditor" /f
REG DELETE "HKEY_CLASSES_ROOT\AppXy37j8m4r12mkyg6recvrn8r32ean0kjm" /f
REG DELETE "HKEY_CURRENT_USER\Software\Classes\AppXy37j8m4r12mkyg6recvrn8r32ean0kjm" /f
REG DELETE "HKEY_CURRENT_USER\Software\Classes\AppXkndb5xvk0v1ka1efnjajnamxcd3sfae1" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXy37j8m4r12mkyg6recvrn8r32ean0kjm" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXkndb5xvk0v1ka1efnjajnamxcd3sfae1" /f
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXy37j8m4r12mkyg6recvrn8r32ean0kjm" /f
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXkndb5xvk0v1ka1efnjajnamxcd3sfae1" /f
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-desktopsearchbox" /f
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-stickereditor" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-desktopsearchbox" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-stickereditor" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Protocol\Data\17" /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-desktopsearchbox" /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-stickereditor" /f
REG DELETE "HKEY_CLASSES_ROOT\DesktopBackground\Shell\EditStickers" /f
REG DELETE "HKEY_CLASSES_ROOT\DesktopBackground\Shell\ShowDesktopSearch" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\DiskDiagnostic" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7F2DA095-D54F-4B13-B246-9B6F33A50E83}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{CDF54DC6-6DCD-410E-A3F0-003BB1289F40}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{CDF54DC6-6DCD-410E-A3F0-003BB1289F40}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{7F2DA095-D54F-4B13-B246-9B6F33A50E83}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{CDF54DC6-6DCD-410E-A3F0-003BB1289F40}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{7F2DA095-D54F-4B13-B246-9B6F33A50E83}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{1677ABA1-4346-442F-A74A-D8B9A713B964}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1677ABA1-4346-442F-A74A-D8B9A713B964}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{1677ABA1-4346-442F-A74A-D8B9A713B964}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{1677ABA1-4346-442F-A74A-D8B9A713B964}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\Server\BcastDVRUserService" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{053C9CB8-5BA1-4F47-A6F1-D1D748C7DA93}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{053C9CB8-5BA1-4F47-A6F1-D1D748C7DA93}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{053C9CB8-5BA1-4F47-A6F1-D1D748C7DA93}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{053C9CB8-5BA1-4F47-A6F1-D1D748C7DA93}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{817F98C4-C9D9-4B8F-B8D0-413C8E5DBBB7}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.fax" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.fax" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{0b6d74fe-ad29-4c92-ac06-f06bc2f238a7}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{34e6abfe-e9f4-4ddf-895a-7350e198f26e}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{a7c922a0-a197-4ae4-8fcd-2236bb4cf515}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{F4D36777-EAED-4cc5-9FE7-827BE5190B20}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{faeb54c4-f66f-4806-83a0-805299f5e3ad}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{FE6B11C3-C72E-4061-86C6-9D163121F229}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{0b6d74fe-ad29-4c92-ac06-f06bc2f238a7}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{34e6abfe-e9f4-4ddf-895a-7350e198f26e}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{a7c922a0-a197-4ae4-8fcd-2236bb4cf515}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{F4D36777-EAED-4cc5-9FE7-827BE5190B20}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{faeb54c4-f66f-4806-83a0-805299f5e3ad}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{FE6B11C3-C72E-4061-86C6-9D163121F229}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Microsoft.FeedsManager" /f
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{9CDCD9C9-BC40-41C6-89C5-230466DB0BD0}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_FEEDS" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{9CDCD9C9-BC40-41C6-89C5-230466DB0BD0}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{4C6470A6-3F91-4f41-850B-DB9BCD074537}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{55b70dec-4b3b-4e26-ae9c-9e8d131843a1}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{C8059EB6-D2FC-4ecf-A15F-AF427F5E4DB6}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{0316BBC2-92D9-4E2E-8345-3609C6B5C167}" /f
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{56D04F5D-964F-4DBF-8D23-B97989E53418}" /f
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{7D868ACD-1A5D-4A47-A247-F39741353012}" /f
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{D7CA032C-B7D0-429E-9FD7-82241C356B4A}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{56D04F5D-964F-4DBF-8D23-B97989E53418}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{7D868ACD-1A5D-4A47-A247-F39741353012}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{D7CA032C-B7D0-429E-9FD7-82241C356B4A}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.SocialFeedChildItem" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.SocialFeedItem" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.SocialFeedSharedItem" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.Provider.SocialInfoProviderManager" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.SocialItemThumbnail" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\WellKnownContracts" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Lock Screen\FeedManager" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\FeedManager" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{3E73C6F7-8937-4C07-85D9-D4447A4BE072}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{3E73C6F7-8937-4C07-85D9-D4447A4BE072}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\GameOverlay" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\GameOverlay" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Gaming_GameBar_LearnMore" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Gaming_GameBar_NexusButton" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Gaming_GameBar_Toggle" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Gaming_GameDVR_HardwareEncoder" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Gaming_GameDVRHeader_LearnMore" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Gaming_GameDVRHeader_OpenFolder" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameBar" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\WindowsUdk.Gaming.UI.GameMru" /f
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{8cec5857-07a1-11d9-b15e-000d56bfe6ee}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{8cec58e7-07a1-11d9-b15e-000d56bfe6ee}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{8cec5857-07a1-11d9-b15e-000d56bfe6ee}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{E5B8E079-EE6D-4E33-A438-C87F2E959254}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{B9033E87-33CF-4D77-BC9B-895AFBBA72E4}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{B9033E87-33CF-4D77-BC9B-895AFBBA72E4}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{9885AEF2-BD9F-41E0-B15E-B3141395E803}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{9885AEF2-BD9F-41E0-B15E-B3141395E803}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{27016870-8E02-11D1-924E-00C04FBBBFB3}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{754A73E3-B0A5-4305-A45A-428186716507}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\{EB521D7D-4095-4E61-88FB-BF25700F142A}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{241D7C96-F8BF-4F85-B01F-E2B043341A4B}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{27016870-8E02-11D1-924E-00C04FBBBFB3}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{754A73E3-B0A5-4305-A45A-428186716507}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{EB521D7D-4095-4E61-88FB-BF25700F142A}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{241D7C96-F8BF-4F85-B01F-E2B043341A4B}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxa.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxc.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxd.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxe.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxf.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxh.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxi.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxk.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxq.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxr.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxs.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxt.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxv.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxw.2.5" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\HelpAndSupport" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Hints" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\HelpAndSupport" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Hints" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.help" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{9127081a-04b5-4044-b4c5-c7a9718e8795}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.help" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{9127081a-04b5-4044-b4c5-c7a9718e8795}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{06946266-393A-456E-92BC-91DDDBF6893C}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{07DC68FA-A15D-4E44-93DE-645060C7B469}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{06946266-393A-456E-92BC-91DDDBF6893C}" /f
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{07DC68FA-A15D-4E44-93DE-645060C7B469}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Maps" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{2409B88C-473B-428B-8795-4C32D7822C9F}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{C9D09D2D-8C0A-4A0F-A699-4125AD19EF9C}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Auto_Update_Setting" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_CopyrightAttribution" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_DeleteAll" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Download_Add_Package" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Download_Available_Packages_Collection" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Download_User_Packages_Collection" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Downloads_Activation" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_MapDataOld_Update" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Storage_Manage" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Service_Error" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Storage_Migration" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Storage_Migration_Cancel" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Storage_Migration_Confirmation" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Storage_Migration_Error" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Storage_Options" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Updates_Actions" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Updates_State_Installing" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Wifi_Only_Setting" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\AppID\{5C03E1B1-EB13-4DF1-8943-2FE8E7D5F309}" /f
REG DELETE "HKEY_CLASSES_ROOT\AppID\{5C03E1B1-EB13-4DF1-8943-2FE8E7D5F309}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\MemoryDiagnostic" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{74F6069B-3D81-479E-AA67-42CE80F16799}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B97E9B4F-4348-4D52-8204-5EB3B9E3351C}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{74F6069B-3D81-479E-AA67-42CE80F16799}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{74F6069B-3D81-479E-AA67-42CE80F16799}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{B97E9B4F-4348-4D52-8204-5EB3B9E3351C}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{B97E9B4F-4348-4D52-8204-5EB3B9E3351C}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WacomPen" /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PenService" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\RemoteApp and Desktop Connections Update" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\RemoteAssistance" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{10B3DD77-3048-41E7-A34D-5FF120D33FA4}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{10B3DD77-3048-41E7-A34D-5FF120D33FA4}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{10B3DD77-3048-41E7-A34D-5FF120D33FA4}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{A3BC03A0-041D-42E3-AD22-882B7865C9C5}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{115e13cf-cfe8-4821-b0da-e06aa4d51426}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1B462D7B-72D8-4544-ACC1-D84E5B9A8A14}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1DF7C823-B2D4-4B54-975A-F2AC5D7CF8B8}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{22A7E88C-5BF5-4DE6-B687-60F7331DF190}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{301B94BA-5D25-4A12-BFFE-3B6E7A616585}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{32be5ed2-5c86-480f-a914-0ff8885a1b3f}" /f
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{3523c2fb-4031-44e4-9a3b-f1e94986ee7f}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\WebCheck" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WebCheck" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\{6de5dc63-3c0c-4dda-9220-1028a37298ba}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{c1f85ef8-bcc2-4606-bb39-70c523715eb3}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{C424F25A-6774-48BC-9F1E-02CCA8C1BE62}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{C58C4893-3BE0-4B45-ABB5-A63E4B8C8651}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{6de5dc63-3c0c-4dda-9220-1028a37298ba}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{c1f85ef8-bcc2-4606-bb39-70c523715eb3}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{C424F25A-6774-48BC-9F1E-02CCA8C1BE62}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{C58C4893-3BE0-4B45-ABB5-A63E4B8C8651}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{58E3C745-D971-4081-9034-86E34B30836A}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{58E3C745-D971-4081-9034-86E34B30836A}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Foundation.Diagnostics.ErrorDetails" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Device Setup" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\DeviceDirectoryClient" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Device Information" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Feedback" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WDI" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Servicing" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4C5BCB25-2C1D-40F3-A779-FDE6280DB867}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Management\Provisioning" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0E511F8F-D1BF-49C8-B1B9-A6C784A17EDA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{1D3D9B10-30A4-459E-8B32-248CAD0EB7EF}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{3EFB737D-965A-4364-8CBA-CCDA345B1C71}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{76300FA9-9EB5-4A2C-8087-029276F64728}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{825F76D6-EA34-4133-BF96-B416888766A3}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8D567D13-E3B8-4273-84F4-C743E60872CC}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{BAE9F0C3-0DB3-494E-BC0B-42703170C272}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{C6D0FF06-5886-4924-93EB-851D6F3CBD06}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{81272F44-D745-4699-8216-955865606EAC}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{9FFC9FC7-ACE3-434F-A78C-43BBD0C1B871}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8B551B42-E746-49C9-A6F3-D9B988AE0914}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{BE7B1C85-5B05-49EE-A887-1F23FF59A1EA}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{68AB1C40-FB5C-490E-9513-733CCED864C1}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FB9EE28D-D0CA-4B6E-B47A-201C830C7006}" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{CD3A454B-E619-4AA6-85B5-B2D98ABC43A1}" /f
sc config "AarSvc" start= demand
sc config "AJRouter" start= demand
sc config "ALG" start= demand
sc config "AppIDSvc" start= demand
sc config "AppMgmt" start= demand
sc config "AppReadiness" start= demand
sc config "AppVClient" start= demand
sc config "AssignedAccessManagerSvc" start= demand
sc config "AutomaticBytesignature" start= demand
sc config "BcastDVRUserService" start= demand
sc config "BthAvctpSvc" start= demand
sc config "CaptureService" start= demand
sc config "cbdhsvc" start= demand
sc config "CDPUserSvc" start= demand
sc config "CertPropSvc" start= demand
sc config "ClipSVC" start= demand
sc config "CloudExperienceHost" start= demand
sc config "ConsentUxUserSvc" start= demand
sc config "CredentialEnrollmentManagerUserSvc" start= demand
sc config "camsvc" start= demand
sc config "Dbupdate" start= demand
sc config "Dbupdatem" start= demand
sc config "DeviceAssociationService" start= demand
sc config "DevicePickerUserSvc" start= demand
sc config "DevicesFlowUserSvc" start= demand
sc config "DeviceUpdateAgent" start= demand
sc config "DmEnrollmentSvc" start= demand
sc config "dmwappushservice" start= demand
sc config "DolbyDAXAPI" start= demand
sc config "DsmSvc" start= demand
sc config "DusmSvc" start= demand
sc config "EapHost" start= demand
sc config "EntAppSvc" start= demand
sc config "Fax" start= demand
sc config "FrameServer" start= demand
sc config "GraphBuilder" start= demand
sc config "HvHost" start= demand
sc config "icssvc" start= demand
sc config "InstallService" start= demand
sc config "IpxlatCfgSvc" start= demand
sc config "KeyIso" start= demand
sc config "KtmRm" start= demand
sc config "LanmanWorkstation" start= demand
sc config "lfsvc" start= demand
sc config "LicenseManager" start= demand
sc config "lltdsvc" start= demand
sc config "LSM" start= demand
sc config "MapsBroker" start= demand
sc config "MessagingService" start= demand
sc config "MixedRealityOpenXRSvc" start= demand
sc config "MpsSvc" start= demand
sc config "MsKeyboardFilter" start= demand
sc config "NaturalAuthentication" start= demand
sc config "NcaSvc" start= demand
sc config "NcbService" start= demand
sc config "NcdAutoSetup" start= demand
sc config "Netlogon" start= demand
sc config "Netman" start= demand
sc config "NetSetupSvc" start= demand
sc config "NgcCtnrSvc" start= demand
sc config "NgcSvc" start= demand
sc config "NlaSvc" start= demand
sc config "nsi" start= demand
sc config "OfflineFiles" start= demand
sc config "OneSyncSvc" start= demand
sc config "P9RdrService" start= demand
sc config "p2pimsvc" start= demand
sc config "p2psvc" start= demand
sc config "PerfHost" start= demand
sc config "PhoneSvc" start= demand
sc config "PimIndexMaintenanceSvc" start= demand
sc config "PlugPlay" start= demand
sc config "PNRPAutoReg" start= demand
sc config "PNRPsvc" start= demand
sc config "PolicyAgent" start= demand
sc config "Power" start= demand
sc config "PrintNotify" start= demand
sc config "PrintWorkflowUserSvc" start= demand
sc config "ProfSvc" start= demand
sc config "PushToInstall" start= demand
sc config "QWAVE" start= demand
sc config "RasAuto" start= demand
sc config "RasMan" start= demand
sc config "RemoteAccess" start= demand
sc config "RemoteRegistry" start= disabled
sc config "RetailDemo" start= demand
sc config "RmSvc" start= demand
sc config "RpcEptMapper" start= demand
sc config "RpcLocator" start= demand
sc config "SCardSvr" start= demand
sc config "ScDeviceEnum" start= demand
sc config "Schedule" start= demand
sc config "SCPolicySvc" start= demand
sc config "SDRSVC" start= demand
sc config "SensorDataService" start= demand
sc config "SensorService" start= demand
sc config "SensrSvc" start= demand
sc config "SessionEnv" start= demand
sc config "SgrmBroker" start= demand
sc config "SharedRealitySvc" start= demand
sc config "ShellHWDetection" start= demand
sc config "smphost" start= demand
sc config "SmsRouter" start= demand
sc config "SNMPTRAP" start= demand
sc config "Spectrum" start= demand
sc config "Spooler" start= demand
sc config "sppsvc" start= demand
sc config "SSDPSRV" start= demand
sc config "SstpSvc" start= demand
sc config "StateRepository" start= demand
sc config "StiSvc" start= demand
sc config "StorSvc" start= demand
sc config "svsvc" start= demand
sc config "SwPrv" start= demand
sc config "TabletInputService" start= demand
sc config "TapiSrv" start= demand
sc config "TermService" start= demand
sc config "Themes" start= demand
sc config "TieringEngineService" start= demand
sc config "TimeBrokerSvc" start= demand
sc config "TokenBroker" start= demand
sc config "TrkWks" start= demand
sc config "TroubleshootingSvc" start= demand
sc config "TscGate" start= demand
sc config "UevAgentService" start= demand
sc config "UmRdpService" start= demand
sc config "UnistoreSvc" start= demand
sc config "Upnphost" start= demand
sc config "UserDataSvc" start= demand
sc config "UserManager" start= demand
sc config "UsoSvc" start= demand
sc config "VaultSvc" start= demand
sc config "vds" start= demand
sc config "VirtualDisk" start= demand
sc config "VSS" start= demand
sc config "W32Time" start= demand
sc config "WaaSMedicSvc" start= demand
sc config "WalletService" start= demand
sc config "War" start= demand
sc config "WarpJITSvc" start= demand
sc config "WbioSrvc" start= demand
sc config "Wcmsvc" start= demand
sc config "wcncsvc" start= demand
sc config "WdiServiceHost" start= demand
sc config "WdiSystemHost" start= demand
sc config "WdNisSvc" start= demand
sc config "WebClient" start= demand
sc config "Wecsvc" start= demand
sc config "WEPHOSTSVC" start= demand
sc config "wercplsupport" start= demand
sc config "WerSvc" start= demand
sc config "WFDSConMgrSvc" start= demand
sc config "WiaRpc" start= demand
sc config "WinHttpAutoProxySvc" start= demand
sc config "Winmad" start= demand
sc config "Winmgmt" start= demand
sc config "WinRM" start= demand
sc config "WlanSvc" start= demand
sc config "wlcrasvc" start= demand
sc config "wlidsvc" start= demand
sc config "WManSvc" start= demand
sc config "wmiApSrv" start= demand
sc config "WMPNetworkSvc" start= demand
sc config "workfolderssvc" start= demand
sc config "WpcMonSvc" start= demand
sc config "WPDBusEnum" start= demand
sc config "WpnService" start= demand
sc config "WpnUserService" start= demand
sc config "wscsvc" start= demand
sc config "WSearch" start= demand
sc config "WSService" start= demand
sc config "wuauserv" start= demand
sc config "WwanSvc" start= demand
sc config "XboxGipSvc" start= disabled
sc config "XboxNetApiSvc" start= disabled
sc config "TabletInputService" start= disabled
sc config "WSearch" start= disabled
sc config "DiagTrack" start= disabled
sc config "dmwappushservice" start= disabled
sc config "MapsBroker" start= disabled
sc config "lfsvc" start= disabled
sc config "SharedAccess" start= disabled
sc config "lltdsvc" start= disabled
sc config "FTPSVC" start= disabled
sc config "SCardSvr" start= disabled
sc config "TroubleshootingSvc" start= disabled
pauseecho Aplicando optimizaciones de red y latencia...
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global dca=enabled
netsh int tcp set global congestionprovider=ctcp
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d 65535 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d 65535 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "SwapEffectUpgradeEnable=1;VRROptionEnable=1;" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerThrottling" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d 0 /f
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
sc config "AarSvc" start= demand >nul 2>&1
sc config "AJRouter" start= demand >nul 2>&1
sc config "ALG" start= demand >nul 2>&1
sc config "AppIDSvc" start= demand >nul 2>&1
sc config "AppMgmt" start= demand >nul 2>&1
sc config "AppReadiness" start= demand >nul 2>&1
sc config "AppVClient" start= demand >nul 2>&1
sc config "AssignedAccessManagerSvc" start= demand >nul 2>&1
sc config "AutomaticBytesignature" start= demand >nul 2>&1
sc config "BcastDVRUserService" start= demand >nul 2>&1
sc config "BthAvctpSvc" start= demand >nul 2>&1
sc config "CaptureService" start= demand >nul 2>&1
sc config "cbdhsvc" start= demand >nul 2>&1
sc config "CDPUserSvc" start= demand >nul 2>&1
sc config "CertPropSvc" start= demand >nul 2>&1
sc config "ClipSVC" start= demand >nul 2>&1
sc config "CloudExperienceHost" start= demand >nul 2>&1
sc config "ConsentUxUserSvc" start= demand >nul 2>&1
sc config "CredentialEnrollmentManagerUserSvc" start= demand >nul 2>&1
sc config "camsvc" start= demand >nul 2>&1
sc config "XboxGipSvc" start= disabled >nul 2>&1
sc config "XboxNetApiSvc" start= disabled >nul 2>&1
sc config "TabletInputService" start= disabled >nul 2>&1
sc config "WSearch" start= disabled >nul 2>&1
sc config "DiagTrack" start= disabled >nul 2>&1
sc config "dmwappushservice" start= disabled >nul 2>&1
sc config "MapsBroker" start= disabled >nul 2>&1
sc config "lfsvc" start= disabled >nul 2>&1
sc config "SharedAccess" start= disabled >nul 2>&1
sc config "lltdsvc" start= disabled >nul 2>&1
sc config "FTPSVC" start= disabled >nul 2>&1
sc config "SCardSvr" start= disabled >nul 2>&1
sc config "TroubleshootingSvc" start= disabled >nul 2>&1
net stop "XboxGipSvc" >nul 2>&1
net stop "XboxNetApiSvc" >nul 2>&1
net stop "DiagTrack" >nul 2>&1
net stop "dmwappushservice" >nul 2>&1
net stop "MapsBroker" >nul 2>&1
net stop "WSearch" >nul 2>&1
sc config "DcomLaunch" start= auto >nul 2>&1
sc config "RpcSs" start= auto >nul 2>&1
sc config "CryptSvc" start= auto >nul 2>&1
sc config "LanmanWorkstation" start= auto >nul 2>&1
sc config "LanmanServer" start= auto >nul 2>&1
netsh int tcp set global autotuninglevel=disabled
netsh int tcp set global rss=disabled
netsh int tcp set global initialwindowsize=65535
netsh int tcp set global numack=2
netsh int tcp set global ackdelay=0
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableNetDMA" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 255 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\AppEvents\Schemes" /v ".Current" /t REG_SZ /d ".None" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 38 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionSeconds" /t REG_DWORD /d 1 /f
bcdedit /deletevalue useplatformclock
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "AffinityPolicy" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f
powercfg -setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 0
powercfg -setdcvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 0
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" /v "Attributes" /t REG_DWORD /d 0 /f
powercfg -setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 2
powercfg -setdcvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 2
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableULPS" /t REG_DWORD /d 0 /f
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 000
powercfg -setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 000
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "Scheduler Response (ms)" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
bcdedit /set disabledynamictick yes
[cite_start]reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f [cite: 1971, 2108, 2295]
[cite_start]reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f [cite: 2116, 2309, 2384, 2520]
[cite_start]reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f [cite: 1968, 2028, 2421]
[cite_start]reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f [cite: 1965, 1968, 2028]
[cite_start]reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f [cite: 2116, 2269, 2422]
[cite_start]reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f [cite: 1966, 1976, 2029, 2116]
[cite_start]reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f [cite: 2270, 2297, 2381, 3059, 3335, 3687, 3867]
[cite_start]bcdedit /set disabledynamictick yes [cite: 2303, 2760, 3334]
[cite_start]reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f [cite: 2116, 2259, 2310, 2421, 3356, 3646, 3705]
[cite_start]netsh int tcp set global autotuninglevel=normal [cite: 2311, 2461, 3340, 3431]
[cite_start]netsh int tcp set global congestionprovider=ctcp [cite: 2231, 2293, 2312, 3340, 3426, 3705, 3866]
[cite_start]netsh int tcp set global ecncapability=disabled [cite: 2279, 2293, 2312, 3340, 3431, 3700]
[cite_start]netsh int tcp set global timestamps=disabled [cite: 2231, 2293, 2312, 3340, 3431]
[cite_start]netsh interface teredo set state disabled [cite: 2152, 2279, 3490]
[cite_start]reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f [cite: 2132, 2310, 2375, 3340, 3430, 3450]
[cite_start]reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f [cite: 2133, 2310, 2376, 3340, 3430, 3451]
[cite_start]reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f [cite: 2232, 2255, 2257, 2602, 3280, 3340, 3354, 3414]
[cite_start]powercfg /h off [cite: 2134, 2257, 2300, 2417, 3213, 3331]
[cite_start]reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f [cite: 2270, 2297, 2425, 3283, 3333, 3468]
[cite_start]powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100 [cite: 2117, 3096, 3417, 3694]
[cite_start]powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0 [cite: 2195, 2302]
[cite_start]powercfg /setacvalueindex SCHEME_CURRENT SUB_USB USBSELECTIVESUSPEND 0 [cite: 2195, 2302]
[cite_start]reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v "EnableDIPM" /t REG_DWORD /d "0" /f [cite: 2124, 2235, 2334, 2437, 2446, 2746, 3334]
[cite_start]reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /v "EnableHIPM" /t REG_DWORD /d "0" /f [cite: 2124, 2235, 2333, 2437, 2445, 2745, 3333]
[cite_start]sc config "DiagTrack" start= disabled [cite: 2267, 2442, 2884, 3073, 3079, 3314, 3360, 3400, 3416, 3462, 3841]
[cite_start]sc config "dmwappushservice" start= disabled [cite: 2266, 2273, 2285, 3073, 3079, 3315, 3400, 3462, 3472, 3481]
[cite_start]sc config "WerSvc" start= disabled [cite: 2167, 2286, 2442, 2448, 3001, 3082, 3315, 3400, 3462, 3481]
[cite_start]sc config "SysMain" start= disabled [cite: 2100, 2447, 2448, 3073, 3317, 3416, 3922]
[cite_start]reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f [cite: 2245, 2276, 2385, 3056, 3176, 3262, 3268, 3320, 3360, 3400, 3419, 3439, 3463, 3480, 3601, 3643, 3800, 3902]
setlocal enabledelayedexpansion
sc config AppVClient start=disabled >nul 2>&1
sc stop AppVClient >nul 2>&1
sc config AssignedAccessManagerSvc start=disabled >nul 2>&1
sc stop AssignedAccessManagerSvc >nul 2>&1
sc config AxInstSV start=disabled >nul 2>&1
sc stop AxInstSV >nul 2>&1
sc config BDESVC start=disabled >nul 2>&1
sc stop BDESVC >nul 2>&1
sc config CertPropSvc start=disabled >nul 2>&1
sc stop CertPropSvc >nul 2>&1
sc config CloudBackup start=disabled >nul 2>&1
sc stop CloudBackup >nul 2>&1
sc config CDPSvc start=disabled >nul 2>&1
sc stop CDPSvc >nul 2>&1
sc config CDPUserSvc start=disabled >nul 2>&1
sc stop CDPUserSvc >nul 2>&1
sc config defragsvc start=disabled >nul 2>&1
sc stop defragsvc >nul 2>&1
sc config DisplayEnhancementService start=disabled >nul 2>&1
sc stop DisplayEnhancementService >nul 2>&1
sc config FrameServer start=disabled >nul 2>&1
sc stop FrameServer >nul 2>&1
sc config icssvc start=disabled >nul 2>&1
sc stop icssvc >nul 2>&1
sc config iphlpsvc start=disabled >nul 2>&1
sc stop iphlpsvc >nul 2>&1
sc config lfsvc start=disabled >nul 2>&1
sc stop lfsvc >nul 2>&1
sc config lmhosts start=disabled >nul 2>&1
sc stop lmhosts >nul 2>&1
sc config MapsBroker start=disabled >nul 2>&1
sc stop MapsBroker >nul 2>&1
sc config NetTcpPortSharing start=disabled >nul 2>&1
sc stop NetTcpPortSharing >nul 2>&1
sc config OneSyncSvc start=disabled >nul 2>&1
sc stop OneSyncSvc >nul 2>&1
sc config PhoneSvc start=disabled >nul 2>&1
sc stop PhoneSvc >nul 2>&1
sc config PimIndexMaintenanceSvc start=disabled >nul 2>&1
sc stop PimIndexMaintenanceSvc >nul 2>&1
sc config PolicyAgent start=disabled >nul 2>&1
sc stop PolicyAgent >nul 2>&1
sc config QWAVE start=disabled >nul 2>&1
sc stop QWAVE >nul 2>&1
sc config RasMan start=disabled >nul 2>&1
sc stop RasMan >nul 2>&1
sc config RemoteAccess start=disabled >nul 2>&1
sc stop RemoteAccess >nul 2>&1
sc config RemoteRegistry start=disabled >nul 2>&1
sc stop RemoteRegistry >nul 2>&1
sc config RetailDemo start=disabled >nul 2>&1
sc stop RetailDemo >nul 2>&1
sc config SCardSvr start=disabled >nul 2>&1
sc stop SCardSvr >nul 2>&1
sc config ScDeviceEnum start=disabled >nul 2>&1
sc stop ScDeviceEnum >nul 2>&1
sc config SCPolicySvc start=disabled >nul 2>&1
sc stop SCPolicySvc >nul 2>&1
sc config SEMgrSvc start=disabled >nul 2>&1
sc stop SEMgrSvc >nul 2>&1
sc config SensorDataService start=disabled >nul 2>&1
sc stop SensorDataService >nul 2>&1
sc config SensorService start=disabled >nul 2>&1
sc stop SensorService >nul 2>&1
sc config SensrSvc start=disabled >nul 2>&1
sc stop SensrSvc >nul 2>&1
sc config Server start=disabled >nul 2>&1
sc stop Server >nul 2>&1
sc config SmsRouter start=disabled >nul 2>&1
sc stop SmsRouter >nul 2>&1
sc config stisvc start=disabled >nul 2>&1
sc stop stisvc >nul 2>&1
sc config SysMain start=disabled >nul 2>&1
sc config TapiSrv start=disabled >nul 2>&1
sc stop TapiSrv >nul 2>&1
sc config TermService start=disabled >nul 2>&1
sc stop TermService >nul 2>&1
sc config UmRdpService start=disabled >nul 2>&1
sc stop UmRdpService >nul 2>&1
sc config vds start=manual >nul
sc stop vds >nul 2>&1
sc config vss start=disabled >nul 2>&1
sc stop vss >nul 2>&1
sc config WalletService start=disabled >nul 2>&1
sc stop WalletService >nul 2>&1
sc config wbengine start=disabled >nul 2>&1
sc stop wbengine >nul 2>&1
sc config WbioSrvc start=disabled >nul 2>&1
sc stop WbioSrvc >nul 2>&1
sc config wcncsvc start=disabled >nul 2>&1
sc stop wcncsvc >nul 2>&1
sc config WinRM start=disabled >nul 2>&1
sc stop WinRM >nul 2>&1
sc config WMPNetworkSvc start=disabled >nul 2>&1
sc stop WMPNetworkSvc >nul 2>&1
sc config workfolderssvc start=disabled >nul 2>&1
sc stop workfolderssvc >nul 2>&1
sc config WPCSvc start=disabled >nul 2>&1
sc stop WPCSvc >nul 2>&1
sc config WSearch start=disabled >nul
sc config wwansvc start=disabled >nul 2>&1
sc stop wwansvc >nul 2>&1
sc config XblAuthManager start=disabled >nul 2>&1
sc stop XblAuthManager >nul 2>&1
sc config XblGameSave start=disabled >nul 2>&1
sc stop XblGameSave >nul 2>&1
sc config XboxNetApiSvc start=disabled >nul 2>&1
sc stop XboxNetApiSvc >nul 2>&1
sc config diagnosticshub.standardcollector.service start=disabled >nul
sc stop diagnosticshub.standardcollector.service >nul 2>&1
sc config DPS start=disabled >nul
sc stop DPS >nul 2>&1
sc config WdiServiceHost start=disabled >nul
sc stop WdiServiceHost >nul 2>&1
sc config WdiSystemHost start=disabled >nul
sc stop WdiSystemHost >nul 2>&1
sc config wuauserv start=demand >nul
sc stop wuauserv >nul 2>&1
sc config UsoSvc start=demand >nul
sc stop UsoSvc >nul 2>&1
sc config BITS start=demand >nul
sc stop BITS >nul 2>&1
sc config DoSvc start=demand >nul
sc stop DoSvc >nul 2>&1
sc config WerSvc start=disabled >nul
sc config pla start=disabled >nul
sc stop pla >nul 2>&1
sc config PerfHost start=disabled >nul
sc stop PerfHost >nul 2>&1
sc config PcaSvc start=disabled >nul
sc stop PcaSvc >nul 2>&1
sc config hvservice start=disabled >nul
sc stop hvservice >nul 2>&1
sc config SessionEnv start=disabled >nul
sc stop SessionEnv >nul 2>&1
sc config ClickToRunSvc start=disabled >nul
sc stop ClickToRunSvc >nul 2>&1
sc config TrkWks start=disabled >nul
sc config InstallService start=demand >nul
sc config LicenseManager start=demand >nul
sc config sppsvc start=demand >nul
sc config Dhcp start=auto >nul
sc config Dnscache start=auto >nul
sc config NlaSvc start=auto >nul
sc config nsi start=auto >nul
sc config WlanSvc start=auto >nul
sc config netprofm start=demand >nul
sc config bthserv start=demand >nul
sc config BTAGService start=demand >nul
sc config BluetoothUserService start=demand >nul
sc config wlidsvc start=disabled >nul
sc stop wlidsvc >nul 2>&1
sc config WaaSMedicSvc start=disabled >nul
sc stop WaaSMedicSvc >nul 2>&1
sc config NcdAutoSetup start=disabled >nul
sc stop NcdAutoSetup >nul 2>&1
sc config seclogon start=disabled >nul
sc stop seclogon >nul 2>&1
sc config XboxGipSvc start=disabled >nul
sc config spectrum start=disabled >nul
sc config ALG start=disabled >nul
sc config BrokerInfrastructure start=disabled >nul
sc config COMSysApp start=disabled >nul
sc config DeviceAssociationService start=disabled >nul
sc config diagsvc start=disabled >nul
sc config EFS start=disabled >nul
sc config fhsvc start=disabled >nul
sc config HomeGroupListener start=disabled >nul
sc config HomeGroupProvider start=disabled >nul
sc config IKEEXT start=disabled >nul
sc config keyiso start=disabled >nul
sc config lltdsvc start=disabled >nul
sc config RasAuto start=disabled >nul
sc config SNMPTRAP start=disabled >nul
sc config SSDPSRV start=disabled >nul
sc config StorSvc start=disabled >nul
sc config TroubleshootingSvc start=disabled >nul
sc config upnphost start=disabled >nul
sc config VaultSvc start=disabled >nul
sc config Wcmsvc start=disabled >nul
sc config WEPHOSTSVC start=disabled >nul
sc config WiaRpc start=disabled >nul
sc config WinHttpAutoProxySvc start=disabled >nul
sc config WPDBusEnum start=disabled >nul
sc config wscsvc start=disabled >nul
sc config WpnService start=disabled >nul
sc config TimeBrokerSvc start=disabled >nul
sc config CscService start=disabled >nul
sc config dot3svc start=disabled >nul
sc config SDRSVC start=disabled >nul
sc config Wecsvc start=disabled >nul
sc config AppMgmt start=disabled >nul
sc config PeerDistSvc start=disabled >nul
sc config Browser start=disabled >nul
sc config AppReadiness start=disabled >nul
sc config edgeupdate start=disabled >nul
sc config edgeupdatem start=disabled >nul
sc config AJRouter start=disabled >nul 2>&1
sc config AppMgmt start=disabled >nul 2>&1
sc config BcastDVRUserService start=disabled >nul 2>&1
sc config BthAvctpSvc start=disabled >nul 2>&1
sc config BthHFSrv start=disabled >nul 2>&1
sc config BTAGService start=disabled >nul 2>&1
sc config ClipSVC start=disabled >nul 2>&1
sc config cloudidsvc start=disabled >nul 2>&1
sc config COMSysApp start=disabled >nul 2>&1
sc config ConsentUxUserSvc start=disabled >nul 2>&1
sc config CscService start=disabled >nul 2>&1
sc config DeviceAssociationBrokerSvc start=disabled >nul 2>&1
sc config DeviceAssociationService start=disabled >nul 2>&1
sc config DeviceInstall start=disabled >nul 2>&1
sc config DevicePickerUserSvc start=disabled >nul 2>&1
sc config DevicesFlowUserSvc start=disabled >nul 2>&1
sc config DevQueryBroker start=disabled >nul 2>&1
sc config diagnosticshub.standardcollector.service start=disabled >nul 2>&1
sc config diagsvc start=disabled >nul 2>&1
sc config DialogBlockingService start=disabled >nul 2>&1
sc config DispBrokerDesktopSvc start=disabled >nul 2>&1
sc config DmEnrollmentSvc start=disabled >nul 2>&1
sc config dmwappushservice start=disabled >nul 2>&1
sc config DoSvc start=disabled >nul 2>&1
sc config DPS start=disabled >nul 2>&1
sc config DsmSvc start=disabled >nul 2>&1
sc config DsSvc start=disabled >nul 2>&1
sc config DusmSvc start=disabled >nul 2>&1
sc config Eaphost start=disabled >nul 2>&1
sc config EFS start=disabled >nul 2>&1
sc config embeddedmode start=disabled >nul 2>&1
sc config EntAppSvc start=disabled >nul 2>&1
sc config Fax start=disabled >nul 2>&1
sc config fdPHost start=disabled >nul 2>&1
sc config fhsvc start=disabled >nul 2>&1
sc config FontCache start=disabled >nul 2>&1
sc config GraphicsPerfSvc start=disabled >nul 2>&1
sc config hidserv start=disabled >nul 2>&1
sc config HvHost start=disabled >nul 2>&1
sc config IKEEXT start=disabled >nul 2>&1
sc config InstallService start=disabled >nul 2>&1
sc config IpxlatCfgSvc start=disabled >nul 2>&1
sc config irmon start=disabled >nul 2>&1
sc config KtmRm start=disabled >nul 2>&1
sc config LicenseManager start=disabled >nul 2>&1
sc config lltdsvc start=disabled >nul 2>&1
sc config LxpSvc start=disabled >nul 2>&1
sc config MessagingService start=disabled >nul 2>&1
sc config MicrosoftEdgeElevationService start=disabled >nul 2>&1
sc config MixedRealityOpenXRSvc start=disabled >nul 2>&1
sc config MSDTC start=disabled >nul 2>&1
sc config MSiSCSI start=disabled >nul 2>&1
sc config NaturalAuthentication start=disabled >nul 2>&1
sc config NcaSvc start=disabled >nul 2>&1
sc config NcbService start=disabled >nul 2>&1
sc config NcdAutoSetup start=disabled >nul 2>&1
sc config Netlogon start=disabled >nul 2>&1
sc config Netman start=disabled >nul 2>&1
sc config NetSetupSvc start=disabled >nul 2>&1
sc config NgcCtnrSvc start=disabled >nul 2>&1
sc config NgcSvc start=disabled >nul 2>&1
sc config NvContainerLocalSystem start=disabled >nul 2>&1
sc config p2pimsvc start=disabled >nul 2>&1
sc config p2psvc start=disabled >nul 2>&1
sc config P9RdrService start=disabled >nul 2>&1
sc config PcaSvc start=disabled >nul 2>&1
sc config PeerDistSvc start=disabled >nul 2>&1
sc config perceptionsimulation start=disabled >nul 2>&1
sc config PerfHost start=disabled >nul 2>&1
sc config pla start=disabled >nul 2>&1
sc config PNRPAutoReg start=disabled >nul 2>&1
sc config PNRPsvc start=disabled >nul 2>&1
sc config PrintNotify start=disabled >nul 2>&1
sc config PrintWorkflowUserSvc start=disabled >nul 2>&1
sc config PushToInstall start=disabled >nul 2>&1
sc config RasAuto start=disabled >nul 2>&1
sc config RmSvc start=disabled >nul 2>&1
sc config RpcLocator start=disabled >nul 2>&1
sc config SDRSVC start=disabled >nul 2>&1
sc config seclogon start=disabled >nul 2>&1
sc config SessionEnv start=disabled >nul 2>&1
sc config SgrmBroker start=disabled >nul 2>&1
sc config shpamsvc start=disabled >nul 2>&1
sc config SharedAccess start=disabled >nul 2>&1
sc config SharedRealitySvc start=disabled >nul 2>&1
sc config SNMPTRAP start=disabled >nul 2>&1
sc config spectrum start=disabled >nul 2>&1
sc config SSDPSRV start=disabled >nul 2>&1
sc config StorSvc start=disabled >nul 2>&1
sc config svsvc start=disabled >nul 2>&1
sc config swprv start=disabled >nul 2>&1
sc config TabletInputService start=disabled >nul 2>&1
sc config TieringEngineService start=disabled >nul 2>&1
sc config TimeBrokerSvc start=disabled >nul 2>&1
sc config TokenBroker start=disabled >nul 2>&1
sc config TrkWks start=disabled >nul 2>&1
sc config TroubleshootingSvc start=disabled >nul 2>&1
sc config tzautoupdate start=disabled >nul 2>&1
sc config UevAgentService start=disabled >nul 2>&1
sc config upnphost start=disabled >nul 2>&1
sc config UserDataSvc start=disabled >nul 2>&1
sc config UsoSvc start=disabled >nul 2>&1
sc config VacSvc start=disabled >nul 2>&1
sc config VaultSvc start=disabled >nul 2>&1
sc config vds start=disabled >nul 2>&1
sc config vmicguestinterface start=disabled >nul 2>&1
sc config vmicheartbeat start=disabled >nul 2>&1
sc config vmickvpexchange start=disabled >nul 2>&1
sc config vmicrdv start=disabled >nul 2>&1
sc config vmicshutdown start=disabled >nul 2>&1
sc config vmictimesync start=disabled >nul 2>&1
sc config vmicvmsession start=disabled >nul 2>&1
sc config vmicvss start=disabled >nul 2>&1
sc config VSS start=disabled >nul 2>&1
sc config W32Time start=disabled >nul 2>&1
sc config WaaSMedicSvc start=disabled >nul 2>&1
sc config WarpJITSvc start=disabled >nul 2>&1
sc config Wcmsvc start=disabled >nul 2>&1
sc config WdiServiceHost start=disabled >nul 2>&1
sc config WdiSystemHost start=disabled >nul 2>&1
sc config WdNisSvc start=disabled >nul 2>&1
sc config WebClient start=disabled >nul 2>&1
sc config Wecsvc start=disabled >nul 2>&1
sc config WEPHOSTSVC start=disabled >nul 2>&1
sc config wercplsupport start=disabled >nul 2>&1
sc config WerSvc start=disabled >nul 2>&1
sc config WiaRpc start=disabled >nul 2>&1
sc config WindowsTrustedRT start=disabled >nul 2>&1
sc config WindowsTrustedRTProxy start=disabled >nul 2>&1
sc config WinHttpAutoProxySvc start=disabled >nul 2>&1
sc config wisvc start=disabled >nul 2>&1
sc config wlidsvc start=disabled >nul 2>&1
sc config wlpasvc start=disabled >nul 2>&1
sc config WManSvc start=disabled >nul 2>&1
sc config wmiApSrv start=disabled >nul 2>&1
sc config WPDBusEnum start=disabled >nul 2>&1
sc config WpcMonSvc start=disabled >nul 2>&1
sc config WpnService start=disabled >nul 2>&1
sc config WpnUserService start=disabled >nul 2>&1
sc config wscsvc start=disabled >nul 2>&1
sc config WSearch start=disabled >nul 2>&1
sc config wuauserv start=disabled >nul 2>&1
sc config WwanSvc start=disabled >nul 2>&1
sc config XboxGipSvc start=disabled >nul 2>&1
sc config SysMain start= disabled >nul 2>&1
net stop SysMain >nul 2>&1
sc config WerSvc start= disabled >nul 2>&1
net stop WerSvc >nul 2>&1
sc config RemoteRegistry start= disabled >nul 2>&1
net stop RemoteRegistry >nul 2>&1
sc config TermService start= disabled >nul 2>&1
net stop TermService >nul 2>&1
sc config SharedAccess start= disabled >nul 2>&1
net stop SharedAccess >nul 2>&1
sc config RasMan start= disabled >nul 2>&1
net stop RasMan >nul 2>&1
sc config BITS start= disabled >nul 2>&1
net stop BITS >nul 2>&1
sc config BthAvctpSvc start= disabled >nul 2>&1
net stop BthAvctpSvc >nul 2>&1
sc config FrameServer start= disabled >nul 2>&1
net stop FrameServer >nul 2>&1
sc config Spectrum start= disabled >nul 2>&1
net stop Spectrum >nul 2>&1
sc config lfsvc start= disabled >nul 2>&1
net stop lfsvc >nul 2>&1
sc config fhsvc start= disabled >nul 2>&1
net stop fhsvc >nul 2>&1
sc config AudioSrv start= disabled >nul 2>&1
net stop AudioSrv >nul 2>&1
sc config TabletInputService start= disabled >nul 2>&1
net stop TabletInputService >nul 2>&1
sc config DiagTrack start= disabled >nul 2>&1
sc config dmwappushservice start= disabled >nul 2>&1
sc config diagnosticshub.standardcollector.service start= disabled >nul 2>&1
sc config WdiServiceHost start= disabled >nul 2>&1
sc config WdiSystemHost start= disabled >nul 2>&1
net stop DiagTrack >nul 2>&1
net stop dmwappushservice >nul 2>&1
net stop diagnosticshub.standardcollector.service >nul 2>&1
net stop WdiServiceHost >nul 2>&1
net stop WdiSystemHost >nul 2>&1
sc config WSearch start= disabled >nul 2>&1
net stop WSearch >nul 2>&1
sc config FontCache3.0.0.0 start=disabled >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\HelloFace\FODCleanupTask" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClient" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Device Information\Device" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Device Information\Device User" >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Application Experience\AITAgent" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Autochk\Proxy" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\PI\Sqm-Tasks" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\AppID\EDP Policy Manager" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\AppID\PolicyConverter" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\appuriverifierinstall" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Clip\License Validation" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleCommand" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleWnsCommand" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\IntegrityCheck" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\LocateCommandUserSession" /disable >nul 2>&1
