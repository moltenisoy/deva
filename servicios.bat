@echo off

:: ============================================================================
:: GESTION COMPLETA DE SERVICIOS Y TAREAS PROGRAMADAS
:: ============================================================================

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineUA" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\currentcontrolset\services\XboxNetApiSvc"  /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableAppUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /V "ShowedToastAtLevel" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /V "EnableEventTranscript" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config ALG start=disabled >nul 2>&1
sc config AJRouter start=disabled >nul 2>&1
sc config XblAuthManager start=disabled >nul 2>&1
sc config XblGameSave start=disabled >nul 2>&1
sc config XboxNetApiSvc start=disabled >nul 2>&1
sc config WSearch start=disabled >nul 2>&1
sc config lfsvc start=disabled >nul 2>&1
sc config RemoteRegistry start=disabled >nul 2>&1
sc config WpcMonSvc start=disabled >nul 2>&1
sc config SEMgrSvc start=disabled >nul 2>&1
sc config SCardSvr start=disabled >nul 2>&1
sc config Netlogon start=disabled >nul 2>&1
sc config CscService start=disabled >nul 2>&1
sc config icssvc start=disabled >nul 2>&1
sc config wisvc start=disabled >nul 2>&1
sc config RetailDemo start=disabled >nul 2>&1
sc config WalletService start=disabled >nul 2>&1
sc config Fax start=disabled >nul 2>&1
sc config WbioSrvc start=disabled >nul 2>&1
sc config iphlpsvc start=disabled >nul 2>&1
sc config wcncsvc start=disabled >nul 2>&1
sc config fhsvc start=disabled >nul 2>&1
sc config PhoneSvc start=disabled >nul 2>&1
sc config seclogon start=disabled >nul 2>&1
sc config FrameServer start=disabled >nul 2>&1
sc config StiSvc start=disabled >nul 2>&1
sc config PcaSvc start=disabled >nul 2>&1
sc config DPS start=disabled >nul 2>&1
sc config MapsBroker start=disabled >nul 2>&1
sc config bthserv start=disabled >nul 2>&1
sc config BDESVC start=disabled >nul 2>&1
sc config BthAvctpSvc start=disabled >nul 2>&1
sc config DiagTrack start=disabled >nul 2>&1
sc config CertPropSvc start=disabled >nul 2>&1
sc config WdiServiceHost start=disabled >nul 2>&1
sc config WdiSystemHost start=disabled >nul 2>&1
sc config TrkWks start=disabled >nul 2>&1
sc config WerSvc start=disabled >nul 2>&1
sc config TabletInputService start=disabled >nul 2>&1
sc config EntAppSvc start=disabled >nul 2>&1
sc config Spooler start=disabled >nul 2>&1
sc config BcastDVRUserService start=disabled >nul 2>&1
sc config diagnosticshub.standardcollector.service start=disabled >nul 2>&1
sc config DmEnrollmentSvc start=disabled >nul 2>&1
sc config PNRPAutoReg start=disabled >nul 2>&1
sc config wlidsvc start=disabled >nul 2>&1
sc config AXInstSV start=disabled >nul 2>&1
sc config wlidsvc start= disabled >nul 2>&1
sc config DisplayEnhancementService start= disabled >nul 2>&1
sc config DiagTrack start= disabled >nul 2>&1
sc config DusmSvc start= disabled >nul 2>&1
sc config TabletInputService start= disabled >nul 2>&1
sc config RetailDemo start= disabled >nul 2>&1
sc config Fax start= disabled >nul 2>&1
sc config lfsvc start= disabled >nul 2>&1
sc config WpcMonSvc start= disabled >nul 2>&1
sc config SessionEnv start= disabled >nul 2>&1
sc config MicrosoftEdgeElevationService start= disabled >nul 2>&1
sc config edgeupdate start= disabled >nul 2>&1
sc config edgeupdatem start= disabled >nul 2>&1
sc config autotimesvc start= disabled >nul 2>&1
sc config CscService start= disabled >nul 2>&1
sc config TermService start= disabled >nul 2>&1
sc config SensorDataService start= disabled >nul 2>&1
sc config SensorService start= disabled >nul 2>&1
sc config SensrSvc start= disabled >nul 2>&1
sc config shpamsvc start= disabled >nul 2>&1
sc config diagnosticshub.standardcollector.service start= disabled >nul 2>&1
sc config PhoneSvc start= disabled >nul 2>&1
sc config TapiSrv start= disabled >nul 2>&1
sc config UevAgentService start= disabled >nul 2>&1
sc config WalletService start= disabled >nul 2>&1
sc config TokenBroker start= disabled >nul 2>&1
sc config WebClient start= disabled >nul 2>&1
sc config MixedRealityOpenXRSvc start= disabled >nul 2>&1
sc config stisvc start= disabled >nul 2>&1
sc config WbioSrvc start= disabled >nul 2>&1
sc config icssvc start= disabled >nul 2>&1
sc config Wecsvc start= disabled >nul 2>&1
sc config XboxGipSvc start= disabled >nul 2>&1
sc config XblAuthManager start= disabled >nul 2>&1
sc config XboxNetApiSvc start= disabled >nul 2>&1
sc config XblGameSave start= disabled >nul 2>&1
sc config SEMgrSvc start= disabled >nul 2>&1
sc config iphlpsvc start= disabled >nul 2>&1
sc config Backupper Service" start= disabled >nul 2>&1
sc config BthAvctpSvc start= disabled >nul 2>&1
sc config BDESVC start= disabled >nul 2>&1
sc config cbdhsvc start= disabled >nul 2>&1
sc config CDPSvc start= disabled >nul 2>&1
sc config CDPUserSvc start= disabled >nul 2>&1
sc config DevQueryBroker start= disabled >nul 2>&1
sc config DevicesFlowUserSvc start= disabled >nul 2>&1
sc config dmwappushservice start= disabled >nul 2>&1
sc config DispBrokerDesktopSvc start= disabled >nul 2>&1
sc config TrkWks start= disabled >nul 2>&1
sc config dLauncherLoopback start= disabled >nul 2>&1
sc config EFS start= disabled >nul 2>&1
sc config fdPHost start= disabled >nul 2>&1
sc config FDResPub start= disabled >nul 2>&1
sc config IKEEXT start= disabled >nul 2>&1
sc config NPSMSvc start= disabled >nul 2>&1
sc config WPDBusEnum start= disabled >nul 2>&1
sc config PcaSvc start= disabled >nul 2>&1
sc config SstpSvc start=disabled >nul 2>&1
sc config ShellHWDetection start= disabled >nul 2>&1
sc config SSDPSRV start= disabled >nul 2>&1
sc config SysMain start= disabled >nul 2>&1
sc config OneSyncSvc start= disabled >nul 2>&1
sc config UserDataSvc start= disabled >nul 2>&1
sc config UnistoreSvc start= disabled >nul 2>&1
sc config Wcmsvc start= disabled >nul 2>&1
sc config FontCache start= disabled >nul 2>&1
sc config W32Time start= disabled >nul 2>&1
sc config tzautoupdate start= disabled >nul 2>&1
sc config DsSvc start= disabled >nul 2>&1
sc config DevicesFlowUserSvc_5f1ad start= disabled >nul 2>&1
sc config diagsvc start= disabled >nul 2>&1
sc config DialogBlockingService start= disabled >nul 2>&1
sc config PimIndexMaintenanceSvc_5f1ad start= disabled >nul 2>&1
sc config MessagingService_5f1ad start= disabled >nul 2>&1
sc config AppVClient start= disabled >nul 2>&1
sc config NetTcpPortSharing start= disabled >nul 2>&1
sc config ssh-agent start= disabled >nul 2>&1
sc config SstpSvc start= disabled >nul 2>&1
sc config OneSyncSvc_5f1ad start= disabled >nul 2>&1
sc config wercplsupport start= disabled >nul 2>&1
sc config WerSvc start= disabled >nul 2>&1
sc config WpnUserService_5f1ad start= disabled >nul 2>&1
sc config WinHttpAutoProxySvc start= disabled >nul 2>&1
schtasks /DELETE /TN "AMDInstallLauncher" /f >nul 2>&1
schtasks /DELETE /TN "AMDLinkUpdate" /f >nul 2>&1
schtasks /DELETE /TN "AMDRyzenMasterSDKTask" /f >nul 2>&1
schtasks /DELETE /TN "Driver Easy Scheduled Scan" /f >nul 2>&1
schtasks /DELETE /TN "ModifyLinkUpdate" /f >nul 2>&1
schtasks /DELETE /TN "SoftMakerUpdater" /f >nul 2>&1
schtasks /DELETE /TN "StartCN" /f >nul 2>&1
schtasks /DELETE /TN "StartDVR" /f >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable >nul 2>&1
sc stop uhssvc >nul 2>&1
sc stop upfc >nul 2>&1
sc stop PushToInstall >nul 2>&1
sc stop BITS >nul 2>&1
sc stop InstallService >nul 2>&1
sc stop UsoSvc >nul 2>&1
sc stop wuauserv >nul 2>&1
sc config BITS start= disabled >nul 2>&1
sc config InstallService start= disabled >nul 2>&1
sc config uhssvc start= disabled >nul 2>&1
sc config UsoSvc start= disabled >nul 2>&1
sc config wuauserv start= disabled >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v Start /t reg_dword /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc" /v Start /t reg_dword /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v Start /t reg_dword /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v Start /t reg_dword /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS" /v Start /t reg_dword /d 4 /f >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdates" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdatesAsUser" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\InstallService\SmartRetry" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndContinueUpdates" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndScanForUpdates" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Report policies" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WaaSMedic\PerformRemediation" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable >nul 2>&1
sc config PrintNotify start= disabled >nul 2>&1
sc config Spooler start= disabled >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable >nul 2>&1
sc config BTAGService start= disabled >nul 2>&1
sc config bthserv start= disabled >nul 2>&1
sc config NcbService start=disabled >nul 2>&1
sc config jhi_service start=disabled >nul 2>&1
sc config WMIRegistrationService start=disabled >nul 2>&1
sc config "Intel(R) TPM Provisioning Service" start=disabled >nul 2>&1
sc config DeviceAssociationService start=disabled >nul 2>&1
sc config StorSvc start=disabled >nul 2>&1
sc config TieringEngineService start=disabled >nul 2>&1
sc config Themes start=disabled >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v "EnableBITSMaxBandwidth" /t REG_DWORD /d "0" /f >nul 2>&1
sc config "BITS" start= auto >nul 2>&1
sc start "BITS" >nul 2>&1
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
sc config "AppVClient" start=disabled >nul 2>&1
sc config "AssignedAccessManagerSvc" start=disabled >nul 2>&1
sc config "AxInstSV" start=disabled >nul 2>&1
sc config "BDESVC" start=disabled >nul 2>&1
sc config "CertPropSvc" start=disabled >nul 2>&1
sc config "CloudBackup" start=disabled >nul 2>&1
sc config "CDPSvc" start=disabled >nul 2>&1
sc config "CDPUserSvc" start=disabled >nul 2>&1
sc config "defragsvc" start=disabled >nul 2>&1
sc config "DisplayEnhancementService" start=disabled >nul 2>&1
sc config "FrameServer" start=disabled >nul 2>&1
sc config "lfsvc" start=disabled >nul 2>&1
sc config "MapsBroker" start=disabled >nul 2>&1
sc config "NetTcpPortSharing" start=disabled >nul 2>&1
sc config "OneSyncSvc" start=disabled >nul 2>&1
sc config "PhoneSvc" start=disabled >nul 2>&1
sc config "PimIndexMaintenanceSvc" start=disabled >nul 2>&1
sc config "PolicyAgent" start=disabled >nul 2>&1
sc config "QWAVE" start=disabled >nul 2>&1
sc config "RemoteRegistry" start=disabled >nul 2>&1
sc config "RetailDemo" start=disabled >nul 2>&1
sc config "SCardSvr" start=disabled >nul 2>&1
sc config "ScDeviceEnum" start=disabled >nul 2>&1
sc config "SCPolicySvc" start=disabled >nul 2>&1
sc config "SEMgrSvc" start=disabled >nul 2>&1
sc config "SensorDataService" start=disabled >nul 2>&1
sc config "SensorService" start=disabled >nul 2>&1
sc config "SensrSvc" start=disabled >nul 2>&1
sc config "Server" start=disabled >nul 2>&1
sc config "SmsRouter" start=disabled >nul 2>&1
sc config "stisvc" start=disabled >nul 2>&1
sc config "SysMain" start=disabled >nul 2>&1
sc config "TapiSrv" start=disabled >nul 2>&1
sc config "TermService" start=disabled >nul 2>&1
sc config "UmRdpService" start=disabled >nul 2>&1
sc config "vds" start=manual >nul 2>&1
sc config "vss" start=disabled >nul 2>&1
sc config "WalletService" start=disabled >nul 2>&1
sc config "wbengine" start=disabled >nul 2>&1
sc config "WbioSrvc" start=disabled >nul 2>&1
sc config "WinRM" start=disabled >nul 2>&1
sc config "workfolderssvc" start=disabled >nul 2>&1
sc config "WPCSvc" start=disabled >nul 2>&1
sc config "WSearch" start=disabled >nul 2>&1
sc config "XblAuthManager" start=disabled >nul 2>&1
sc config "XblGameSave" start=disabled >nul 2>&1
sc config "XboxNetApiSvc" start=disabled >nul 2>&1
sc config "diagnosticshub.standardcollector.service" start=disabled >nul 2>&1
sc config "DPS" start=disabled >nul 2>&1
sc config "WdiServiceHost" start=disabled >nul 2>&1
sc config "WdiSystemHost" start=disabled >nul 2>&1
sc config "WerSvc" start=disabled >nul 2>&1
sc config "pla" start=disabled >nul 2>&1
sc config "PerfHost" start=disabled >nul 2>&1
sc config "PcaSvc" start=disabled >nul 2>&1
sc config "hvservice" start=disabled >nul 2>&1
sc config "SessionEnv" start=disabled >nul 2>&1
sc config "ClickToRunSvc" start=disabled >nul 2>&1
sc config "TrkWks" start=disabled >nul 2>&1
sc config "sppsvc" start=demand >nul 2>&1
sc config "wlidsvc" start=disabled >nul 2>&1
sc config "WaaSMedicSvc" start=disabled >nul 2>&1
sc config "NcdAutoSetup" start=disabled >nul 2>&1
sc config "seclogon" start=disabled >nul 2>&1
sc config "XboxGipSvc" start=disabled >nul 2>&1
sc config "spectrum" start=disabled >nul 2>&1
sc config "ALG" start=disabled >nul 2>&1
sc config "COMSysApp" start=disabled >nul 2>&1
sc config "DeviceAssociationService" start=disabled >nul 2>&1
sc config "diagsvc" start=disabled >nul 2>&1
sc config "EFS" start=disabled >nul 2>&1
sc config "fhsvc" start=disabled >nul 2>&1
sc config "HomeGroupListener" start=disabled >nul 2>&1
sc config "HomeGroupProvider" start=disabled >nul 2>&1
sc config "IKEEXT" start=disabled >nul 2>&1
sc config "keyiso" start=disabled >nul 2>&1
sc config "lltdsvc" start=disabled >nul 2>&1
sc config "SNMPTRAP" start=disabled >nul 2>&1
sc config "SSDPSRV" start=disabled >nul 2>&1
sc config "StorSvc" start=disabled >nul 2>&1
sc config "TroubleshootingSvc" start=disabled >nul 2>&1
sc config "upnphost" start=disabled >nul 2>&1
sc config "VaultSvc" start=disabled >nul 2>&1
sc config "Wcmsvc" start=disabled >nul 2>&1
sc config "WEPHOSTSVC" start=disabled >nul 2>&1
sc config "WinHttpAutoProxySvc" start=disabled >nul 2>&1
sc config "WPDBusEnum" start=disabled >nul 2>&1
sc config "wscsvc" start=disabled >nul 2>&1
sc config "WpnService" start=disabled >nul 2>&1
sc config "TimeBrokerSvc" start=disabled >nul 2>&1
sc config "CscService" start=disabled >nul 2>&1
sc config "SDRSVC" start=disabled >nul 2>&1
sc config "Wecsvc" start=disabled >nul 2>&1
sc config "AppMgmt" start=disabled >nul 2>&1
sc config "PeerDistSvc" start=disabled >nul 2>&1
sc config "Browser" start=disabled >nul 2>&1
sc config "edgeupdate" start=disabled >nul 2>&1
sc config "edgeupdatem" start=disabled >nul 2>&1
sc config "FontCache" start=disabled >nul 2>&1
sc config "FontCache3.0.0.0" start=disabled >nul 2>&1
sc config "cbdhsvc" start=disabled >nul 2>&1
sc config "AJRouter" start=auto >nul 2>&1
sc config "RmSvc" start=auto >nul 2>&1
sc config "SystemUsageReportSvc_QUEENCREEK" start=disabled >nul 2>&1
sc config "SgrmAgent" start=disabled >nul 2>&1
sc config "uhssvc" start=disabled >nul 2>&1
sc config "wuauserv" start=demand >nul 2>&1
sc config "UsoSvc" start=demand >nul 2>&1
sc config "BITS" start=demand >nul 2>&1
sc config "DoSvc" start=demand >nul 2>&1
sc config "AJRouter" start=demand >nul 2>&1
sc config "ALG" start=demand >nul 2>&1
sc config "AppIDSvc" start=demand >nul 2>&1
sc config "AppMgmt" start=demand >nul 2>&1
sc config "Appinfo" start=demand >nul 2>&1
sc config "AssignedAccessManagerSvc" start=demand >nul 2>&1
sc config "AxInstSV" start=demand >nul 2>&1
sc config "BDESVC" start=demand >nul 2>&1
sc config "Browser" start=demand >nul 2>&1
sc config "CertPropSvc" start=demand >nul 2>&1
sc config "ConsentUxUserSvc_*" start=demand >nul 2>&1
sc config "CredentialEnrollmentManagerUserSvc_*" start=demand >nul 2>&1
sc config "CscService" start=demand >nul 2>&1
sc config "DcpSvc" start=demand >nul 2>&1
sc config "DevQueryBroker" start=demand >nul 2>&1
sc config "DeviceAssociationBrokerSvc_*" start=demand >nul 2>&1
sc config "DeviceAssociationService" start=demand >nul 2>&1
sc config "DeviceInstall" start=demand >nul 2>&1
sc config "DevicePickerUserSvc_*" start=demand >nul 2>&1
sc config "DevicesFlowUserSvc_*" start=demand >nul 2>&1
sc config "DisplayEnhancementService" start=demand >nul 2>&1
sc config "DmEnrollmentSvc" start=demand >nul 2>&1
sc config "DsSvc" start=demand >nul 2>&1
sc config "DsmSvc" start=demand >nul 2>&1
sc config "EFS" start=demand >nul 2>&1
sc config "EapHost" start=demand >nul 2>&1
sc config "EntAppSvc" start=demand >nul 2>&1
sc config "FDResPub" start=demand >nul 2>&1
sc config "Fax" start=demand >nul 2>&1
sc config "FrameServer" start=demand >nul 2>&1
sc config "FrameServerMonitor" start=demand >nul 2>&1
sc config "HomeGroupListener" start=demand >nul 2>&1
sc config "HomeGroupProvider" start=demand >nul 2>&1
sc config "HvHost" start=demand >nul 2>&1
sc config "IEEtwCollectorService" start=demand >nul 2>&1
sc config "IKEEXT" start=demand >nul 2>&1
sc config "InventorySvc" start=demand >nul 2>&1
sc config "IpxlatCfgSvc" start=demand >nul 2>&1
sc config "KtmRm" start=demand >nul 2>&1
sc config "LxpSvc" start=demand >nul 2>&1
sc config "MSDTC" start=demand >nul 2>&1
sc config "MSiSCSI" start=demand >nul 2>&1
sc config "McpManagementService" start=demand >nul 2>&1
sc config "MessagingService_*" start=demand >nul 2>&1
sc config "MicrosoftEdgeElevationService" start=demand >nul 2>&1
sc config "MixedRealityOpenXRSvc" start=demand >nul 2>&1
sc config "NPSMSvc_*" start=demand >nul 2>&1
sc config "NaturalAuthentication" start=demand >nul 2>&1
sc config "NcaSvc" start=demand >nul 2>&1
sc config "NcbService" start=demand >nul 2>&1
sc config "NcdAutoSetup" start=demand >nul 2>&1
sc config "NetSetupSvc" start=demand >nul 2>&1
sc config "NgcCtnrSvc" start=demand >nul 2>&1
sc config "NgcSvc" start=demand >nul 2>&1
sc config "P9RdrService_*" start=demand >nul 2>&1
sc config "PNRPAutoReg" start=demand >nul 2>&1
sc config "PNRPsvc" start=demand >nul 2>&1
sc config "PeerDistSvc" start=demand >nul 2>&1
sc config "PenService_*" start=demand >nul 2>&1
sc config "PerfHost" start=demand >nul 2>&1
sc config "PhoneSvc" start=demand >nul 2>&1
sc config "PimIndexMaintenanceSvc_*" start=demand >nul 2>&1
sc config "PlugPlay" start=demand >nul 2>&1
sc config "PolicyAgent" start=demand >nul 2>&1
sc config "PrintNotify" start=demand >nul 2>&1
sc config "PrintWorkflowUserSvc_*" start=demand >nul 2>&1
sc config "PushToInstall" start=demand >nul 2>&1
sc config "QWAVE" start=demand >nul 2>&1
sc config "RetailDemo" start=demand >nul 2>&1
sc config "RmSvc" start=demand >nul 2>&1
sc config "RpcLocator" start=demand >nul 2>&1
sc config "SCPolicySvc" start=demand >nul 2>&1
sc config "SCardSvr" start=demand >nul 2>&1
sc config "SDRSVC" start=demand >nul 2>&1
sc config "SEMgrSvc" start=demand >nul 2>&1
sc config "SNMPTRAP" start=demand >nul 2>&1
sc config "SSDPSRV" start=demand >nul 2>&1
sc config "ScDeviceEnum" start=demand >nul 2>&1
sc config "SecurityHealthService" start=demand >nul 2>&1
sc config "Sense" start=demand >nul 2>&1
sc config "SensorDataService" start=demand >nul 2>&1
sc config "SensorService" start=demand >nul 2>&1
sc config "SensrSvc" start=demand >nul 2>&1
sc config "SessionEnv" start=demand >nul 2>&1
sc config "SharedRealitySvc" start=demand >nul 2>&1
sc config "SmsRouter" start=demand >nul 2>&1
sc config "SstpSvc" start=demand >nul 2>&1
sc config "StiSvc" start=demand >nul 2>&1
sc config "TabletInputService" start=demand >nul 2>&1
sc config "TapiSrv" start=demand >nul 2>&1
sc config "TieringEngineService" start=demand >nul 2>&1
sc config "TimeBroker" start=demand >nul 2>&1
sc config "TimeBrokerSvc" start=demand >nul 2>&1
sc config "TokenBroker" start=demand >nul 2>&1
sc config "TroubleshootingSvc" start=demand >nul 2>&1
sc config "TrustedInstaller" start=demand >nul 2>&1
sc config "UI0Detect" start=demand >nul 2>&1
sc config "UdkUserSvc_*" start=demand >nul 2>&1
sc config "UmRdpService" start=demand >nul 2>&1
sc config "UnistoreSvc_*" start=demand >nul 2>&1
sc config "UserDataSvc_*" start=demand >nul 2>&1
sc config "VSS" start=demand >nul 2>&1
sc config "VacSvc" start=demand >nul 2>&1
sc config "W32Time" start=demand >nul 2>&1
sc config "WEPHOSTSVC" start=demand >nul 2>&1
sc config "WFDSConMgrSvc" start=demand >nul 2>&1
sc config "WManSvc" start=demand >nul 2>&1
sc config "WPDBusEnum" start=demand >nul 2>&1
sc config "WSService" start=demand >nul 2>&1
sc config "WaaSMedicSvc" start=demand >nul 2>&1
sc config "WalletService" start=demand >nul 2>&1
sc config "WarpJITSvc" start=demand >nul 2>&1
sc config "WbioSrvc" start=demand >nul 2>&1
sc config "WcsPlugInService" start=demand >nul 2>&1
sc config "WdNisSvc" start=demand >nul 2>&1
sc config "WebClient" start=demand >nul 2>&1
sc config "Wecsvc" start=demand >nul 2>&1
sc config "WerSvc" start=demand >nul 2>&1
sc config "WiaRpc" start=demand >nul 2>&1
sc config "WinHttpAutoProxySvc" start=demand >nul 2>&1
sc config "WinRM" start=demand >nul 2>&1
sc config "WpcMonSvc" start=demand >nul 2>&1
sc config "XblAuthManager" start=demand >nul 2>&1
sc config "XblGameSave" start=demand >nul 2>&1
sc config "XboxGipSvc" start=demand >nul 2>&1
sc config "XboxNetApiSvc" start=demand >nul 2>&1
sc config "autotimesvc" start=demand >nul 2>&1
sc config "camsvc" start=demand >nul 2>&1
sc config "cloudidsvc" start=demand >nul 2>&1
sc config "dcsvc" start=demand >nul 2>&1
sc config "defragsvc" start=demand >nul 2>&1
sc config "dmwappushservice" start=demand >nul 2>&1
sc config "embeddedmode" start=demand >nul 2>&1
sc config "fdPHost" start=demand >nul 2>&1
sc config "fhsvc" start=demand >nul 2>&1
sc config "hidserv" start=demand >nul 2>&1
sc config "lltdsvc" start=demand >nul 2>&1
sc config "msiserver" start=demand >nul 2>&1
sc config "p2pimsvc" start=demand >nul 2>&1
sc config "p2psvc" start=demand >nul 2>&1
sc config "perceptionsimulation" start=demand >nul 2>&1
sc config "pla" start=demand >nul 2>&1
sc config "seclogon" start=demand >nul 2>&1
sc config "smphost" start=demand >nul 2>&1
sc config "spectrum" start=demand >nul 2>&1
sc config "svsvc" start=demand >nul 2>&1
sc config "swprv" start=demand >nul 2>&1
sc config "upnphost" start=demand >nul 2>&1
sc config "vds" start=demand >nul 2>&1
sc config "vmicguestinterface" start=demand >nul 2>&1
sc config "vmicheartbeat" start=demand >nul 2>&1
sc config "vmickvpexchange" start=demand >nul 2>&1
sc config "vmicrdv" start=demand >nul 2>&1
sc config "vmictimesync" start=demand >nul 2>&1
sc config "vmicvmsession" start=demand >nul 2>&1
sc config "vmicvss" start=demand >nul 2>&1
sc config "vmvss" start=demand >nul 2>&1
sc config "wbengine" start=demand >nul 2>&1
sc config "webthreatdefsvc" start=demand >nul 2>&1
sc config "wercplsupport" start=demand >nul 2>&1
sc config "wisvc" start=demand >nul 2>&1
sc config "wlidsvc" start=demand >nul 2>&1
sc config "wlpasvc" start=demand >nul 2>&1
sc config "wmiApSrv" start=demand >nul 2>&1
sc config "workfolderssvc" start=demand >nul 2>&1
sc config "wudfsvc" start=demand >nul 2>&1
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
schtasks /change /tn "\Microsoft\Windows\Maintenance\Regular Maintenance" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /disable >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\*" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\UpdateAssistant\*" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\WaaSMedic\*" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\WindowsUpdate\*" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\MareBackup" /Disable >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackStatus" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "UploadPermissionReceived" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackAuthorization" /t REG_DWORD /d "775" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSense" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\BITS" /v "DisableBranchCache" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d 3 /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /f >nul 2>&1
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
sc config "Dbupdate" start= demand >nul 2>&1
sc config "Dbupdatem" start= demand >nul 2>&1
sc config "DeviceAssociationService" start= demand >nul 2>&1
sc config "DevicePickerUserSvc" start= demand >nul 2>&1
sc config "DevicesFlowUserSvc" start= demand >nul 2>&1
sc config "DeviceUpdateAgent" start= demand >nul 2>&1
sc config "DmEnrollmentSvc" start= demand >nul 2>&1
sc config "dmwappushservice" start= demand >nul 2>&1
sc config "DolbyDAXAPI" start= demand >nul 2>&1
sc config "DsmSvc" start= demand >nul 2>&1
sc config "DusmSvc" start= demand >nul 2>&1
sc config "EapHost" start= demand >nul 2>&1
sc config "EntAppSvc" start= demand >nul 2>&1
sc config "Fax" start= demand >nul 2>&1
sc config "FrameServer" start= demand >nul 2>&1
sc config "GraphBuilder" start= demand >nul 2>&1
sc config "HvHost" start= demand >nul 2>&1
sc config "icssvc" start= demand >nul 2>&1
sc config "InstallService" start= demand >nul 2>&1
sc config "IpxlatCfgSvc" start= demand >nul 2>&1
sc config "KeyIso" start= demand >nul 2>&1
sc config "KtmRm" start= demand >nul 2>&1
sc config "lfsvc" start= demand >nul 2>&1
sc config "LicenseManager" start= demand >nul 2>&1
sc config "lltdsvc" start= demand >nul 2>&1
sc config "LSM" start= demand >nul 2>&1
sc config "MapsBroker" start= demand >nul 2>&1
sc config "MessagingService" start= demand >nul 2>&1
sc config "MixedRealityOpenXRSvc" start= demand >nul 2>&1
sc config "MpsSvc" start= demand >nul 2>&1
sc config "NaturalAuthentication" start= demand >nul 2>&1
sc config "NcaSvc" start= demand >nul 2>&1
sc config "NcbService" start= demand >nul 2>&1
sc config "NcdAutoSetup" start= demand >nul 2>&1
sc config "Netlogon" start= demand >nul 2>&1
sc config "Netman" start= demand >nul 2>&1
sc config "NetSetupSvc" start= demand >nul 2>&1
sc config "NgcCtnrSvc" start= demand >nul 2>&1
sc config "NgcSvc" start= demand >nul 2>&1
sc config "NlaSvc" start= demand >nul 2>&1
sc config "nsi" start= demand >nul 2>&1
sc config "OfflineFiles" start= demand >nul 2>&1
sc config "OneSyncSvc" start= demand >nul 2>&1
sc config "P9RdrService" start= demand >nul 2>&1
sc config "p2pimsvc" start= demand >nul 2>&1
sc config "p2psvc" start= demand >nul 2>&1
sc config "PerfHost" start= demand >nul 2>&1
sc config "PhoneSvc" start= demand >nul 2>&1
sc config "PimIndexMaintenanceSvc" start= demand >nul 2>&1
sc config "PlugPlay" start= demand >nul 2>&1
sc config "PNRPAutoReg" start= demand >nul 2>&1
sc config "PNRPsvc" start= demand >nul 2>&1
sc config "PolicyAgent" start= demand >nul 2>&1
sc config "Power" start= demand >nul 2>&1
sc config "PrintNotify" start= demand >nul 2>&1
sc config "PrintWorkflowUserSvc" start= demand >nul 2>&1
sc config "ProfSvc" start= demand >nul 2>&1
sc config "PushToInstall" start= demand >nul 2>&1
sc config "QWAVE" start= demand >nul 2>&1
sc config "RemoteRegistry" start= disabled >nul 2>&1
sc config "RetailDemo" start= demand >nul 2>&1
sc config "RmSvc" start= demand >nul 2>&1
sc config "RpcEptMapper" start= demand >nul 2>&1
sc config "RpcLocator" start= demand >nul 2>&1
sc config "SCardSvr" start= demand >nul 2>&1
sc config "ScDeviceEnum" start= demand >nul 2>&1
sc config "Schedule" start= demand >nul 2>&1
sc config "SCPolicySvc" start= demand >nul 2>&1
sc config "SDRSVC" start= demand >nul 2>&1
sc config "SensorDataService" start= demand >nul 2>&1
sc config "SensorService" start= demand >nul 2>&1
sc config "SensrSvc" start= demand >nul 2>&1
sc config "SessionEnv" start= demand >nul 2>&1
sc config "SgrmBroker" start= demand >nul 2>&1
sc config "SharedRealitySvc" start= demand >nul 2>&1
sc config "ShellHWDetection" start= demand >nul 2>&1
sc config "smphost" start= demand >nul 2>&1
sc config "SmsRouter" start= demand >nul 2>&1
sc config "SNMPTRAP" start= demand >nul 2>&1
sc config "Spectrum" start= demand >nul 2>&1
sc config "Spooler" start= demand >nul 2>&1
sc config "sppsvc" start= demand >nul 2>&1
sc config "SSDPSRV" start= demand >nul 2>&1
sc config "SstpSvc" start= demand >nul 2>&1
sc config "StateRepository" start= demand >nul 2>&1
sc config "StiSvc" start= demand >nul 2>&1
sc config "StorSvc" start= demand >nul 2>&1
sc config "svsvc" start= demand >nul 2>&1
sc config "SwPrv" start= demand >nul 2>&1
sc config "TabletInputService" start= demand >nul 2>&1
sc config "TapiSrv" start= demand >nul 2>&1
sc config "TermService" start= demand >nul 2>&1
sc config "Themes" start= demand >nul 2>&1
sc config "TieringEngineService" start= demand >nul 2>&1
sc config "TimeBrokerSvc" start= demand >nul 2>&1
sc config "TokenBroker" start= demand >nul 2>&1
sc config "TrkWks" start= demand >nul 2>&1
sc config "TroubleshootingSvc" start= demand >nul 2>&1
sc config "TscGate" start= demand >nul 2>&1
sc config "UevAgentService" start= demand >nul 2>&1
sc config "UmRdpService" start= demand >nul 2>&1
sc config "UnistoreSvc" start= demand >nul 2>&1
sc config "Upnphost" start= demand >nul 2>&1
sc config "UserDataSvc" start= demand >nul 2>&1
sc config "UserManager" start= demand >nul 2>&1
sc config "UsoSvc" start= demand >nul 2>&1
sc config "VaultSvc" start= demand >nul 2>&1
sc config "vds" start= demand >nul 2>&1
sc config "VirtualDisk" start= demand >nul 2>&1
sc config "VSS" start= demand >nul 2>&1
sc config "W32Time" start= demand >nul 2>&1
sc config "WaaSMedicSvc" start= demand >nul 2>&1
sc config "WalletService" start= demand >nul 2>&1
sc config "War" start= demand >nul 2>&1
sc config "WarpJITSvc" start= demand >nul 2>&1
sc config "WbioSrvc" start= demand >nul 2>&1
sc config "Wcmsvc" start= demand >nul 2>&1
sc config "wcncsvc" start= demand >nul 2>&1
sc config "WdiServiceHost" start= demand >nul 2>&1
sc config "WdiSystemHost" start= demand >nul 2>&1
sc config "WdNisSvc" start= demand >nul 2>&1
sc config "WebClient" start= demand >nul 2>&1
sc config "Wecsvc" start= demand >nul 2>&1
sc config "WEPHOSTSVC" start= demand >nul 2>&1
sc config "wercplsupport" start= demand >nul 2>&1
sc config "WerSvc" start= demand >nul 2>&1
sc config "WFDSConMgrSvc" start= demand >nul 2>&1
sc config "WiaRpc" start= demand >nul 2>&1
sc config "WinHttpAutoProxySvc" start= demand >nul 2>&1
sc config "Winmad" start= demand >nul 2>&1
sc config "Winmgmt" start= demand >nul 2>&1
sc config "WinRM" start= demand >nul 2>&1
sc config "WlanSvc" start= demand >nul 2>&1
sc config "wlcrasvc" start= demand >nul 2>&1
sc config "wlidsvc" start= demand >nul 2>&1
sc config "WManSvc" start= demand >nul 2>&1
sc config "wmiApSrv" start= demand >nul 2>&1
sc config "workfolderssvc" start= demand >nul 2>&1
sc config "WpcMonSvc" start= demand >nul 2>&1
sc config "WPDBusEnum" start= demand >nul 2>&1
sc config "WpnService" start= demand >nul 2>&1
sc config "WpnUserService" start= demand >nul 2>&1
sc config "wscsvc" start= demand >nul 2>&1
sc config "WSearch" start= demand >nul 2>&1
sc config "WSService" start= demand >nul 2>&1
sc config "wuauserv" start= demand >nul 2>&1
sc config "WwanSvc" start= demand >nul 2>&1
sc config "XboxGipSvc" start= disabled >nul 2>&1
sc config "XboxNetApiSvc" start= disabled >nul 2>&1
sc config "TabletInputService" start= disabled >nul 2>&1
sc config "WSearch" start= disabled >nul 2>&1
sc config "DiagTrack" start= disabled >nul 2>&1
sc config "dmwappushservice" start= disabled >nul 2>&1
sc config "MapsBroker" start= disabled >nul 2>&1
sc config "lfsvc" start= disabled >nul 2>&1
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
[cite_start]sc config "DiagTrack" start= disabled [cite: 2267, 2442, 2884, 3073, 3079, 3314, 3360, 3400, 3416, 3462, 3841] >nul 2>&1
[cite_start]sc config "dmwappushservice" start= disabled [cite: 2266, 2273, 2285, 3073, 3079, 3315, 3400, 3462, 3472, 3481] >nul 2>&1
[cite_start]sc config "WerSvc" start= disabled [cite: 2167, 2286, 2442, 2448, 3001, 3082, 3315, 3400, 3462, 3481] >nul 2>&1
[cite_start]sc config "SysMain" start= disabled [cite: 2100, 2447, 2448, 3073, 3317, 3416, 3922] >nul 2>&1
sc config AppVClient start=disabled >nul 2>&1
sc stop AppVClient >nul 2>&1
sc config AssignedAccessManagerSvc start=disabled >nul 2>&1
sc stop AssignedAccessManagerSvc >nul 2>&1
sc stop AxInstSV >nul 2>&1
sc stop BDESVC >nul 2>&1
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
sc stop FrameServer >nul 2>&1
sc stop icssvc >nul 2>&1
sc stop iphlpsvc >nul 2>&1
sc stop lfsvc >nul 2>&1
sc stop MapsBroker >nul 2>&1
sc config NetTcpPortSharing start=disabled >nul 2>&1
sc stop NetTcpPortSharing >nul 2>&1
sc config OneSyncSvc start=disabled >nul 2>&1
sc stop OneSyncSvc >nul 2>&1
sc stop PhoneSvc >nul 2>&1
sc config PimIndexMaintenanceSvc start=disabled >nul 2>&1
sc stop PimIndexMaintenanceSvc >nul 2>&1
sc config PolicyAgent start=disabled >nul 2>&1
sc stop PolicyAgent >nul 2>&1
sc config QWAVE start=disabled >nul 2>&1
sc stop QWAVE >nul 2>&1
sc stop RemoteRegistry >nul 2>&1
sc stop RetailDemo >nul 2>&1
sc stop SCardSvr >nul 2>&1
sc config ScDeviceEnum start=disabled >nul 2>&1
sc stop ScDeviceEnum >nul 2>&1
sc config SCPolicySvc start=disabled >nul 2>&1
sc stop SCPolicySvc >nul 2>&1
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
sc stop stisvc >nul 2>&1
sc config SysMain start=disabled >nul 2>&1
sc config TapiSrv start=disabled >nul 2>&1
sc stop TapiSrv >nul 2>&1
sc config TermService start=disabled >nul 2>&1
sc stop TermService >nul 2>&1
sc config UmRdpService start=disabled >nul 2>&1
sc stop UmRdpService >nul 2>&1
sc config vds start=manual >nul 2>&1
sc stop vds >nul 2>&1
sc config vss start=disabled >nul 2>&1
sc stop vss >nul 2>&1
sc stop WalletService >nul 2>&1
sc config wbengine start=disabled >nul 2>&1
sc stop wbengine >nul 2>&1
sc stop WbioSrvc >nul 2>&1
sc stop wcncsvc >nul 2>&1
sc config WinRM start=disabled >nul 2>&1
sc stop WinRM >nul 2>&1
sc config workfolderssvc start=disabled >nul 2>&1
sc stop workfolderssvc >nul 2>&1
sc config WPCSvc start=disabled >nul 2>&1
sc stop WPCSvc >nul 2>&1
sc config wwansvc start=disabled >nul 2>&1
sc stop wwansvc >nul 2>&1
sc stop XblAuthManager >nul 2>&1
sc stop XblGameSave >nul 2>&1
sc stop XboxNetApiSvc >nul 2>&1
sc stop diagnosticshub.standardcollector.service >nul 2>&1
sc stop DPS >nul 2>&1
sc stop WdiServiceHost >nul 2>&1
sc stop WdiSystemHost >nul 2>&1
sc config wuauserv start=demand >nul 2>&1
sc config UsoSvc start=demand >nul 2>&1
sc config BITS start=demand >nul 2>&1
sc config DoSvc start=demand >nul 2>&1
sc stop DoSvc >nul 2>&1
sc config pla start=disabled >nul 2>&1
sc stop pla >nul 2>&1
sc config PerfHost start=disabled >nul 2>&1
sc stop PerfHost >nul 2>&1
sc stop PcaSvc >nul 2>&1
sc config hvservice start=disabled >nul 2>&1
sc stop hvservice >nul 2>&1
sc config SessionEnv start=disabled >nul 2>&1
sc stop SessionEnv >nul 2>&1
sc config ClickToRunSvc start=disabled >nul 2>&1
sc stop ClickToRunSvc >nul 2>&1
sc config InstallService start=demand >nul 2>&1
sc config LicenseManager start=demand >nul 2>&1
sc config sppsvc start=demand >nul 2>&1
sc config Dhcp start=auto >nul 2>&1
sc config NlaSvc start=auto >nul 2>&1
sc config nsi start=auto >nul 2>&1
sc config WlanSvc start=auto >nul 2>&1
sc config netprofm start=demand >nul 2>&1
sc config bthserv start=demand >nul 2>&1
sc config BTAGService start=demand >nul 2>&1
sc config BluetoothUserService start=demand >nul 2>&1
sc stop wlidsvc >nul 2>&1
sc config WaaSMedicSvc start=disabled >nul 2>&1
sc stop WaaSMedicSvc >nul 2>&1
sc config NcdAutoSetup start=disabled >nul 2>&1
sc stop NcdAutoSetup >nul 2>&1
sc stop seclogon >nul 2>&1
sc config XboxGipSvc start=disabled >nul 2>&1
sc config spectrum start=disabled >nul 2>&1
sc config BrokerInfrastructure start=disabled >nul 2>&1
sc config COMSysApp start=disabled >nul 2>&1
sc config diagsvc start=disabled >nul 2>&1
sc config EFS start=disabled >nul 2>&1
sc config HomeGroupListener start=disabled >nul 2>&1
sc config HomeGroupProvider start=disabled >nul 2>&1
sc config IKEEXT start=disabled >nul 2>&1
sc config keyiso start=disabled >nul 2>&1
sc config lltdsvc start=disabled >nul 2>&1
sc config SNMPTRAP start=disabled >nul 2>&1
sc config SSDPSRV start=disabled >nul 2>&1
sc config TroubleshootingSvc start=disabled >nul 2>&1
sc config upnphost start=disabled >nul 2>&1
sc config VaultSvc start=disabled >nul 2>&1
sc config Wcmsvc start=disabled >nul 2>&1
sc config WEPHOSTSVC start=disabled >nul 2>&1
sc config WiaRpc start=disabled >nul 2>&1
sc config WinHttpAutoProxySvc start=disabled >nul 2>&1
sc config WPDBusEnum start=disabled >nul 2>&1
sc config wscsvc start=disabled >nul 2>&1
sc config WpnService start=disabled >nul 2>&1
sc config TimeBrokerSvc start=disabled >nul 2>&1
sc config dot3svc start=disabled >nul 2>&1
sc config SDRSVC start=disabled >nul 2>&1
sc config Wecsvc start=disabled >nul 2>&1
sc config AppMgmt start=disabled >nul 2>&1
sc config PeerDistSvc start=disabled >nul 2>&1
sc config Browser start=disabled >nul 2>&1
sc config AppReadiness start=disabled >nul 2>&1
sc config edgeupdate start=disabled >nul 2>&1
sc config edgeupdatem start=disabled >nul 2>&1
sc config BthHFSrv start=disabled >nul 2>&1
sc config BTAGService start=disabled >nul 2>&1
sc config ClipSVC start=disabled >nul 2>&1
sc config cloudidsvc start=disabled >nul 2>&1
sc config ConsentUxUserSvc start=disabled >nul 2>&1
sc config DeviceAssociationBrokerSvc start=disabled >nul 2>&1
sc config DeviceInstall start=disabled >nul 2>&1
sc config DevicePickerUserSvc start=disabled >nul 2>&1
sc config DevicesFlowUserSvc start=disabled >nul 2>&1
sc config DevQueryBroker start=disabled >nul 2>&1
sc config DialogBlockingService start=disabled >nul 2>&1
sc config DispBrokerDesktopSvc start=disabled >nul 2>&1
sc config dmwappushservice start=disabled >nul 2>&1
sc config DoSvc start=disabled >nul 2>&1
sc config DsmSvc start=disabled >nul 2>&1
sc config DsSvc start=disabled >nul 2>&1
sc config DusmSvc start=disabled >nul 2>&1
sc config Eaphost start=disabled >nul 2>&1
sc config embeddedmode start=disabled >nul 2>&1
sc config fdPHost start=disabled >nul 2>&1
sc config FontCache start=disabled >nul 2>&1
sc config hidserv start=disabled >nul 2>&1
sc config HvHost start=disabled >nul 2>&1
sc config InstallService start=disabled >nul 2>&1
sc config IpxlatCfgSvc start=disabled >nul 2>&1
sc config irmon start=disabled >nul 2>&1
sc config KtmRm start=disabled >nul 2>&1
sc config LicenseManager start=disabled >nul 2>&1
sc config LxpSvc start=disabled >nul 2>&1
sc config MessagingService start=disabled >nul 2>&1
sc config MicrosoftEdgeElevationService start=disabled >nul 2>&1
sc config MixedRealityOpenXRSvc start=disabled >nul 2>&1
sc config MSDTC start=disabled >nul 2>&1
sc config MSiSCSI start=disabled >nul 2>&1
sc config NaturalAuthentication start=disabled >nul 2>&1
sc config NcaSvc start=disabled >nul 2>&1
sc config Netman start=disabled >nul 2>&1
sc config NetSetupSvc start=disabled >nul 2>&1
sc config NgcCtnrSvc start=disabled >nul 2>&1
sc config NgcSvc start=disabled >nul 2>&1
sc config NvContainerLocalSystem start=disabled >nul 2>&1
sc config p2pimsvc start=disabled >nul 2>&1
sc config p2psvc start=disabled >nul 2>&1
sc config P9RdrService start=disabled >nul 2>&1
sc config perceptionsimulation start=disabled >nul 2>&1
sc config PNRPsvc start=disabled >nul 2>&1
sc config PrintNotify start=disabled >nul 2>&1
sc config PrintWorkflowUserSvc start=disabled >nul 2>&1
sc config PushToInstall start=disabled >nul 2>&1
sc config RmSvc start=disabled >nul 2>&1
sc config RpcLocator start=disabled >nul 2>&1
sc config SgrmBroker start=disabled >nul 2>&1
sc config shpamsvc start=disabled >nul 2>&1
sc config SharedRealitySvc start=disabled >nul 2>&1
sc config svsvc start=disabled >nul 2>&1
sc config swprv start=disabled >nul 2>&1
sc config TokenBroker start=disabled >nul 2>&1
sc config tzautoupdate start=disabled >nul 2>&1
sc config UevAgentService start=disabled >nul 2>&1
sc config UserDataSvc start=disabled >nul 2>&1
sc config UsoSvc start=disabled >nul 2>&1
sc config VacSvc start=disabled >nul 2>&1
sc config vds start=disabled >nul 2>&1
sc config vmicguestinterface start=disabled >nul 2>&1
sc config vmicheartbeat start=disabled >nul 2>&1
sc config vmickvpexchange start=disabled >nul 2>&1
sc config vmicrdv start=disabled >nul 2>&1
sc config vmicshutdown start=disabled >nul 2>&1
sc config vmictimesync start=disabled >nul 2>&1
sc config vmicvmsession start=disabled >nul 2>&1
sc config vmicvss start=disabled >nul 2>&1
sc config W32Time start=disabled >nul 2>&1
sc config WarpJITSvc start=disabled >nul 2>&1
sc config WdNisSvc start=disabled >nul 2>&1
sc config WebClient start=disabled >nul 2>&1
sc config wercplsupport start=disabled >nul 2>&1
sc config WindowsTrustedRT start=disabled >nul 2>&1
sc config WindowsTrustedRTProxy start=disabled >nul 2>&1
sc config wlpasvc start=disabled >nul 2>&1
sc config WManSvc start=disabled >nul 2>&1
sc config wmiApSrv start=disabled >nul 2>&1
sc config WpnUserService start=disabled >nul 2>&1
sc config wuauserv start=disabled >nul 2>&1
net stop SysMain >nul 2>&1
net stop WerSvc >nul 2>&1
sc config RemoteRegistry start= disabled >nul 2>&1
net stop BITS >nul 2>&1
sc config FrameServer start= disabled >nul 2>&1
sc config Spectrum start= disabled >nul 2>&1
net stop lfsvc >nul 2>&1
sc config fhsvc start= disabled >nul 2>&1
sc config AudioSrv start= disabled >nul 2>&1
sc config WdiServiceHost start= disabled >nul 2>&1
sc config WdiSystemHost start= disabled >nul 2>&1
net stop DiagTrack >nul 2>&1
net stop dmwappushservice >nul 2>&1
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
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\HelloFace\FODCleanupTask" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClient" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Device Information\Device" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Device Information\Device User" >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\AppID\EDP Policy Manager" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\AppID\PolicyConverter" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\appuriverifierinstall" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Clip\License Validation" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleCommand" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\HandleWnsCommand" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\IntegrityCheck" /disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\DeviceDirectoryClient\LocateCommandUserSession" /disable >nul 2>&1
sc config "SysMain" start= disabled >nul 2>&1
sc stop "SysMain" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "WSearch" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseGlobal" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense" /v "AllowedTrayType" /t REG_DWORD /d "0" /f >nul 2>&1
sc stop "DiagTrack" >nul 2>&1
sc stop DiagTrack >nul 2>&1
sc stop dmwappushservice >nul 2>&1
sc stop SysMain >nul 2>&1
sc stop WSearch >nul 2>&1
sc config MapsBroker start= disabled >nul 2>&1
sc stop TrkWks >nul 2>&1
sc stop WerSvc >nul 2>&1
sc config XboxGipSvc start= demand >nul 2>&1
sc config XblAuthManager start= demand >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >nul 2>&1
sc config DPS start= Disabled >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d "0" /f >nul 2>&1
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" >nul 2>&1
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /Disable >nul 2>&1
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" >nul 2>&1
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /Disable >nul 2>&1
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn" >nul 2>&1
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable >nul 2>&1
schtasks /end /tn "\Microsoftd\Office\OfficeTelemetryAgentFallBack" >nul 2>&1
schtasks /change /TN "\Microsoftd\Office\OfficeTelemetryAgentFallBack" /Disable >nul 2>&1
schtasks /end /tn "\Microsoft\Office\Office 15 Subscription Heartbeat" >nul 2>&1
schtasks /change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /Disable >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\SynchronizeTime" >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\WindowsUpdate\Automatic App Update" >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "DoSvc" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask" > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" > nul >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /Disable > nul >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT" > nul >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config xbgm start= Disabled >nul 2>&1
sc stop DiagTrack > nul >nul 2>&1
sc config DiagTrack start= Disabled > nul >nul 2>&1
sc stop dmwappushservice > nul >nul 2>&1
sc config dmwappushservice start= Disabled > nul >nul 2>&1
sc stop diagnosticshub.standardcollector.service > nul >nul 2>&1
sc config diagnosticshub.standardcollector.service start= Disabled > nul >nul 2>&1
schtasks /change /Disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /Disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /Disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /Disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /Disable /tn "NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /Disable /tn "NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /Disable /tn "NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
SC STOP edgeupdate >nul 2>&1
sc config "DiagTrack" start=disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config "dmwappushservice" start=disabled >nul 2>&1
sc stop "dmwappushservice" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "diagsvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "DPS" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "diagnosticshub.standardcollector.service" >nul 2>&1
sc stop "WdiServiceHost" >nul 2>&1
sc stop "WdiSystemHost" >nul 2>&1
sc stop "WerSvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "PcaSvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config "WinDefend" start=disabled >nul 2>&1
sc stop "WinDefend" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config "SecurityHealthService" start=disabled >nul 2>&1
sc stop "SecurityHealthService" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config "WdNisSvc" start=disabled >nul 2>&1
sc stop "WdNisSvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config "Sense" start=disabled >nul 2>&1
sc stop "Sense" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "wscsvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "WbioSrvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "FontCache" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "FontCache3.0.0.0" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "stisvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "Wecsvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "MapsBroker" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config "Spooler" start=disabled >nul 2>&1
sc stop "Spooler" >nul 2>&1
sc config "PrintNotify" start=disabled >nul 2>&1
sc stop "PrintNotify" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "XblGameSave" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "XboxNetApiSvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "XboxGipSvc" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc stop "XblAuthManager" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config "wuauserv" start=disabled >nul 2>&1
sc stop "wuauserv" >nul 2>&1
sc config "UsoSvc" start=disabled >nul 2>&1
sc stop "UsoSvc" >nul 2>&1
sc config "BITS" start=disabled >nul 2>&1
sc stop "BITS" >nul 2>&1
sc config "DoSvc" start=disabled >nul 2>&1
sc stop "DoSvc" >nul 2>&1
sc config "TabletInputService" start=disabled >nul 2>&1
sc stop "TabletInputService" >nul 2>&1
sc config "Fax" start=disabled >nul 2>&1
sc stop "Fax" >nul 2>&1
sc stop "PhoneSvc" >nul 2>&1
sc stop "RetailDemo" >nul 2>&1
sc stop "RemoteRegistry" >nul 2>&1
sc stop "TrkWks" >nul 2>&1
sc stop "WpnService" >nul 2>&1
sc config "WpnUserService" start=disabled >nul 2>&1
sc stop "WpnUserService" >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f >nul 2>&1
sc config "diagnosticshub.standardcollector.service" start= disabled >nul 2>&1
sc config "diagsvc" start= disabled >nul 2>&1
sc config "DPS" start= disabled >nul 2>&1
sc config "WdiServiceHost" start= disabled >nul 2>&1
sc config "WdiSystemHost" start= disabled >nul 2>&1
sc config "WpnService" start= disabled >nul 2>&1
sc stop "lfsvc" >nul 2>&1
sc config "WerSvc" start= disabled >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >nul 2>&1
sc config "PcaSvc" start= disabled >nul 2>&1
sc config "FontCache" start= disabled >nul 2>&1
sc config "FontCache3.0.0.0" start= disabled >nul 2>&1
sc config "ShellHWDetection" start= disabled >nul 2>&1
sc stop "ShellHWDetection" >nul 2>&1
sc config "Themes" start= disabled >nul 2>&1
sc stop "Themes" >nul 2>&1
sc config "WbioSrvc" start= disabled >nul 2>&1
sc config "wuauserv" start= disabled >nul 2>&1
sc config "UsoSvc" start= disabled >nul 2>&1
sc config "DoSvc" start= disabled >nul 2>&1
sc config "bits" start= disabled >nul 2>&1
sc config "XblAuthManager" start= disabled >nul 2>&1
sc config "XblGameSave" start= disabled >nul 2>&1
sc config "WinDefend" start= disabled >nul 2>&1
sc config "SecurityHealthService" start= disabled >nul 2>&1
sc config "WdNisSvc" start= disabled >nul 2>&1
sc config "Sense" start= disabled >nul 2>&1
sc config "wscsvc" start= disabled >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Location\Notifications" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Location\WindowsActionDialog" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable >nul 2>&1
sc stop diagsvc >nul 2>&1
sc stop Wecsvc >nul 2>&1
sc config WinDefend start=disabled >nul 2>&1
sc stop WinDefend >nul 2>&1
sc config SecurityHealthService start=disabled >nul 2>&1
sc stop SecurityHealthService >nul 2>&1
sc stop WdNisSvc >nul 2>&1
sc config Sense start=disabled >nul 2>&1
sc stop Sense >nul 2>&1
sc stop wscsvc >nul 2>&1
sc stop FontCache >nul 2>&1
sc stop FontCache3.0.0.0 >nul 2>&1
sc stop Spooler >nul 2>&1
sc stop PrintNotify >nul 2>&1
sc config XblGameSave start=demand >nul 2>&1
sc config XboxNetApiSvc start=demand >nul 2>&1
sc config XboxGipSvc start=demand >nul 2>&1
sc config XblAuthManager start=demand >nul 2>&1
sc stop Fax >nul 2>&1
net stop gupdate >nul 2>&1
net stop googlechromeelevationservice >nul 2>&1
net stop gupdatem >nul 2>&1
net stop MozillaMaintenance >nul 2>&1
wmic product where name="Mozilla Maintenance Service" call uninstall /nointeractive >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\maintenanceservice_installer.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\maintenanceservice.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\updater.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\crashreporter.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\crashreporter.ini" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\minidump-analyzer.exe" >nul 2>&1
del /f "C:\Program Files\Mozilla Firefox\pingsender.exe" >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /v "DisableAppUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration\Status" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v "AllowStorageSenseGlobal" /t REG_DWORD /d 0 /f >nul 2>&1
sc config "WpnUserService" start= disabled >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate\CreateDesktopShortcutDefault" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d 0 /f >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\WSCSecurityAudit" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /Disable >nul 2>&1

