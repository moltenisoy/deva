@echo off

:: ============================================================================
:: PRIVACIDAD, TELEMETRIA, BLOATWARE Y OPTIMIZACIONES VARIAS
:: ============================================================================

powershell "Set-ExecutionPolicy Unrestricted" >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DoReport" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "UseDpiScaling" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ctfmon" /t REG_SZ /d "C:\Windows\System32\ctfmon.exe" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\VideoSettings" /v "VideoQualityOnBattery" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "TelemetrySalt" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "FirstRunTelemetryComplete" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AppReadinessLogonComplete" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "EdgeDesktopShortcutCreated" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "PostAppInstallTasksCompleted" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338394Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338396Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AccessibilityTemp" /v "narrator" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "RunningState" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /v "AllUpView" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /v "Remove TaskView" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "196608" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tiff" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".bmp" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".dib" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".gif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jfif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpe" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpeg" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpg" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jxr" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".png" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v ContentEvaluation /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\SYSTEM\GameConfigStore\Children\fefe78e0-cf54-411d-9154-04b8f488bea2" /v "Flags" /t REG_DWORD /d "529" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "InstalledWin32AppsRevision" /t REG_SZ /d "{E00F4E01-A5F6-488E-A733-D341606BBD99}" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "InstalledPackagedAppsRevision" /t REG_SZ /d "{EE5761AF-9340-40EE-AFFB-D3F7ECEC59BD}" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaMUID" /t REG_SZ /d "MUID=62b4e7c3c0a24010b4c5abdfe4f2b796" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaStateLastRun" /t REG_BINARY /d "3247f55f00000000" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "IsAssignedAccess" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "NamespaceSettingsRevision" /t REG_SZ /d "{EBDF1464-A4D5-443C-ACE8-21C7FCDF002F}" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AnyAboveLockAppsActive" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_SZ /d "1" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /V "SystemResponsiveness" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V "DisableNotificationCenter" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /V "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /V "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /V "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /V "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /V "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /V "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /V "EnableTransparency" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /V "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /V "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_TrackProgs" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /V "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /V "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /V "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /V "HarvestContacts" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /V "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /V "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /V "PeriodInNanoSeconds" /t REG_SZ /d "-" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "PublishUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "UploadUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /V "Value" /t REG_SZ /d "Deny" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /V "Value" /t REG_SZ /d "Deny" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /V "Value" /t REG_SZ /d "Deny" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /V "Value" /t REG_SZ /d "Deny" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /V "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService" /V "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /V "MinAnimate" /t REG_SZ /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /V "MaxAnimate" /t REG_SZ /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ExtendedUIHoverTime" /t REG_DWORD /d "30000" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "DontPrettyPath" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewShadow" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /V "EnableAeroPeek" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DWM" /V "DWMWA_TRANSITIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DWM" /V "DisallowAnimations" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /V "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /V "TelemetryMaxApplication" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /V "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /V "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "FontSmoothing" /t REG_SZ /d "2" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "FontSmoothingType" /t REG_DWORD /d "2" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /V "AllUpView" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /V "Remove TaskView" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /V "AltTabSettings" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "DragFullWindows" /t REG_SZ /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "Win8DpiScaling" /t REG_DWORD /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "DpiScalingVer" /t REG_DWORD /d "1000" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "LastUpdated" /t REG_DWORD /d "0xffffffff" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "ForegroundLockTimeout" /t REG_DWORD /d "150000" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "AutoEndTasks" /t REG_SZ /d "1" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "HungAppTimeout" /t REG_SZ /d "4000" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "MenuShowDelay" /t REG_SZ /d "0" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "Pattern Upgrade" /t REG_SZ /d "TRUE" /f >nul 2>&1
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /V "MaintenanceDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ClouedContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" >nul 2>&1
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MaxAnimate" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DWMWA_TRANSITIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "2000" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnloadDLL" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnloadDLL" /v "Default" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AltTabSettings" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TranslateEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TaskManagerEndProcessEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SpellCheckServiceEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SpellcheckEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MediaRouterCastAllowAllIPs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowDinosaurEasterEgg" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultGeolocationSetting" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultCookiesSetting" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultFileHandlingGuardSetting" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultImagesSetting" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultPopupsSetting" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultSensorsSetting" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultSerialGuardSetting" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultWebBluetoothGuardSetting" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "EnableMediaRouter" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ShowCastIconInToolbar" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PrintRasterizationMode" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PrintingEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultPluginsSetting" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SafeBrowsingExtendedReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HomepageIsNewTabPage" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HomepageLocation" /t REG_SZ /d "google.com" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "NewTabPageLocation" /t REG_SZ /d "google.com" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome\Recommended" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome\Recommended" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome\Recommended" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome\Recommended" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "Install{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_DWORD /d "5" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "TargetChannel{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_SZ /d "stable" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "Install{4CCED17F-7852-4AFC-9E9E-C89D8795BDD2}" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "AutoUpdateCheckPeriodMinutes" /t REG_DWORD /d "43200" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "DownloadPreference" /t REG_SZ /d "cacheable" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdatesSuppressedStartHour" /t REG_DWORD /d "23" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdatesSuppressedStartMin" /t REG_DWORD /d "48" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdatesSuppressedDurationMin" /t REG_DWORD /d "55" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableVceSwClockGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUvdClockGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableVCEPowerGating" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisablePowerGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSAMUPowerGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableFBCForFullScreenApp" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableFBCSupport" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableEarlySamuInit" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ActivityTarget" /t REG_DWORD /d "30" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ODNFeatureEnable" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "GCOOPTION_DisableGPIOPowerSaveMode" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_AllGraphicLevel_DownHyst" /t REG_DWORD /d "20" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_AllGraphicLevel_UpHyst" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_FRTEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_MaxUVDSessions" /t REG_DWORD /d "32" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalAllowDirectMemoryAccessTrig" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalAllowDPrefSwitchingForGLSync" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "WmAgpMaxIdleClk" /t REG_DWORD /d "32" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_MCLKStutterModeThreshold" /t REG_DWORD /d "4096" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TVEnableOverscan" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "5" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "MLF" /t REG_BINARY /d "3000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "EQAA" /t REG_BINARY /d "3000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "PowerState" /t REG_BINARY /d "3000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AreaAniso_DEF" /t REG_SZ /d "8" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SurfaceFormatReplacements_DEF" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_DEF" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoType_DEF" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoDegree_DEF" /t REG_SZ /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceTripleBuffering" /t REG_BINARY /d "3000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceTripleBuffering_DEF" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt_DEF" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureLod_DEF" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TruformMode_DEF" /t REG_SZ /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "LodAdj" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_DEF" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION_DEF" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "NoOSPowerOptions" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth" /t REG_BINARY /d "3100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_DEF" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoType" /t REG_BINARY /d "32000000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisotropyOptimise" /t REG_BINARY /d "3100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TrilinearOptimise" /t REG_BINARY /d "3100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoDegree" /t REG_BINARY /d "3400" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureLod" /t REG_BINARY /d "31000000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt" /t REG_BINARY /d "31000000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TruformMode_NA" /t REG_BINARY /d "3200" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION" /t REG_BINARY /d "3200" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation" /t REG_BINARY /d "3100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_SET" /t REG_BINARY /d "302031203220332034203500" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_SET" /t REG_BINARY /d "3020313620323400" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "FlipQueueSize" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SurfaceFormatReplacements" /t REG_BINARY /d "3000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ" /t REG_BINARY /d "3200" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ_DEF" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ZFormats_NA" /t REG_BINARY /d "3100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AntiStuttering" /t REG_BINARY /d "3000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TurboSync" /t REG_BINARY /d "3000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "HighQualityAF" /t REG_BINARY /d "3300" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ShaderCache" /t REG_BINARY /d "3200" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "DisplayPowerSaving" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DesktopStereoShortcuts" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "FeatureControl" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "NVDeviceSupportKFilter" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmCacheLoc" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmDisableInst2Sys" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmFbsrPagedDMA" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmProfilingAdminOnly" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TCCSupported" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TrackResetEngine" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "UseBestResolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ValidateBlitSubRects" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AcpiFirmwareWatchDog" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AmliWatchdogAction" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AmliWatchdogTimeout" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "WatchdogTimeout" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Throttle" /v "PerfEnablePackageIdle" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablePreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ComputePreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAsyncMidBufferPreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableSCGMidBufferPreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PerfAnalyzeMidBufferPreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableMidGfxPreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableMidBufferPreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableCEPreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisablePreemptionOnS3S4" /t REG_DWORD /d "1" /f >nul 2>&1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f > nul >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f > nul >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbxhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D1Latency" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D2Latency" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D3Latency" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "82" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f >nul 2>&1
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PassiveIntRealTimeWorkerPriority" /t REG_DWORD /d "18" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ConvertibleSlateMode" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Attributes" /t REG_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Affinity" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Background Only" /t REG_SZ /d "False" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Clock Rate" /t REG_DWORD /d "10000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Priority" /t REG_DWORD /d "6" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "BackgroundPriority" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Latency Sensitive" /t REG_SZ /d "True" /f >nul 2>&1
del /s /f /q c:\windows\temp\*.* >nul 2>&1
del /s /f /q %temp%\*.* >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService" /v Start /t reg_dword /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upfc" /v Start /t reg_dword /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\uhssvc" /v Start /t reg_dword /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ossrs" /v Start /t reg_dword /d 4 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t Reg_DWORD /d "28" /f >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f >nul 2>&1
Reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f >nul 2>&1
Reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\OCMsetup" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\Security" /v "SecureDSCommunication" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\setup" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Setup" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "PeerCachingLatencyThreshold" /t REG_DWORD /d "268435456" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service" /v "Enable" /t REG_DWORD /d "1" /f >nul 2>&1
wmic process where ProcessId=%pid% CALL setpriority "idle" >nul 2>&1
wmic process where ProcessId=%pid% CALL setpriority "realtime" >nul 2>&1
wmic process where name="mqsvc.exe" CALL setpriority "high priority" >nul 2>&1
wmic process where name="mqtgsvc.exe" CALL setpriority "high priority" >nul 2>&1
wmic process where name="javaw.exe" CALL setpriority "realtime" >nul 2>&1
wmic process where name="svchost.exe" CALL setpriority "realtime" >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
PowerShell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *Cortana* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *people* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *xbox* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *zune* | Remove-AppxPackage" >nul 2>&1
REM PowerShell -Command "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage" >nul 2>&1
REM PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *Sway* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *ContentDeliveryManager* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingWeather' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingSports' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingNews' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.BingFinance' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.HEIFImageExtension' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.VP9VideoExtensions' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WebMediaExtensions' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WebpImageExtension' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Office.OneNote' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Office.Sway' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsStore' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.StorePurchaseApp' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxApp' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Xbox.TCUI' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxGamingOverlay' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxGameOverlay' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxIdentityProvider' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.XboxSpeechToTextOverlay' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsPhone' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.Phone' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.CommsPhone' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.YourPhone' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Appconnector' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.GetHelp' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Getstarted' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MixedReality.Portal' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsFeedbackHub' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MinecraftUWP' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Wallet' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.OneConnect' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MicrosoftSolitaireCollection' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MicrosoftStickyNotes' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'microsoft.windowscommunicationsapps' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.ZuneMusic' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.ZuneVideo' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsCalculator' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.SkypeApp' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.GroupMe10' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsSoundRecorder' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'king.com.CandyCrushSaga' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'king.com.CandyCrushSodaSaga' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'ShazamEntertainmentLtd.Shazam' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Flipboard.Flipboard' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage '9E2F88E3.Twitter' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'ClearChannelRadioDigital.iHeartRadio' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'D5EA27B7.Duolingo-LearnLanguagesforFree' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'AdobeSystemsIncorporated.AdobePhotoshopExpress' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'PandoraMediaInc.29680B314EFC2' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage '46928bounde.EclipseManager' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'ActiproSoftwareLLC.562882FEEB491' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'SpotifyAB.SpotifyMusic' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Advertising.Xaml' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.RemoteDesktop' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Todos' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.BioEnrollment'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.ECApp'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Win32WebViewHost'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.PPIProjection'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.Apprep.ChxApp'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.AssignedAccessLockApp'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.CapturePicker'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.ContentDeliveryManager'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.Cortana'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.Search' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.Holographic.FirstRun'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.ParentalControls'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.SecondaryTileExperience'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.Windows.SecureAssessmentBrowser'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Microsoft.XboxGameCallableUI'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Windows.CBSPreview'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Windows.Print3D'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$package = Get-AppxPackage -AllUsers 'Windows.PrintDialog'; if (!$package) {; Write-Host 'Not installed'; exit 0; }; $directories = @($package.InstallLocation, "^""$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)"^""); foreach($dir in $directories) {; if ( !$dir -Or !(Test-Path "^""$dir"^"") ) { continue }; cmd /c ('takeown /f "^""' + $dir + '"^"" /r /d y 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; cmd /c ('icacls "^""' + $dir + '"^"" /grant administrators:F /t 1> nul'); if($LASTEXITCODE) { throw 'Failed to take ownership' }; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) {; if($file.Name.EndsWith('.OLD')) { continue }; $newName = $file.FullName + '.OLD'; Write-Host "^""Rename '$($file.FullName)' to '$newName'"^""; Move-Item -LiteralPath "^""$($file.FullName)"^"" -Destination "^""$newName"^"" -Force; }; }" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Print3D' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.3DBuilder' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Microsoft3DViewer' | Remove-AppxPackage" >nul 2>&1
taskkill /F /IM Teams.exe >nul 2>&1
powershell -Command "Get-AppxPackage -AllUsers | Where-Object { $_.PackageFullName -eq 'MicrosoftTeams_23285.3703.2471.4627_x64__8wekyb3d8bbwe' } | Remove-AppxPackage" >nul 2>&1
taskkill /f /im msedge.exe >nul 2>&1
taskkill /f /im msedge.exe /fi "IMAGENAME eq msedge.exe" >nul 2>&1
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/844006676457848902/1175873715037286550/Full_Power_plan.pow' -OutFile %HOMEPATH%\AppData\Local\Temp\Full_Power_plan.pow >nul 2>&1
powercfg -SETACTIVE "44444444-4444-4444-4444-444444444448" >nul 2>&1
powercfg -import "%HOMEPATH%\AppData\Local\Temp\Full_Power_plan.pow" >nul 2>&1
POWERSHELL "Disable-MMAgent -MemoryCompression" >nul 2>&1
POWERSHELL Disable-MMAgent -MemoryCompression -ApplicationPreLaunch -ErrorAction SilentlyContinue >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ScheduledTask | Where-Object {$_.TaskName -match 'Diag|Telemetry|Customer Experience|OfficeClickToRun'} | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue" >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Control Panel\International\UserProfile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceMFT" /v "DisableCodecs" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MSDeploy\3" /v "EnableTelemetry" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "EnableCdp" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\SOFTWARE Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul 2>&1
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f 2 >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f 2 >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ClearRecentDocsOnExit" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f 2 >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "AllowLinguisticDataCollection" /t REG_DWORD /d 0 /f 2 >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f 2 >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f 2 >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d 8 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "2000" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEngCP.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Disable-MMAgent -mc" 2 >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Telemetry" /v Affinity /t REG_DWORD /d !mask! /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%p\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%p" /v AffinityMask /t REG_DWORD /d !mask! /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableSR" /t REG_DWORD /d 1 /f 2 >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SpellCheck" /v "DisableSpellchecking" /t REG_DWORD /d 1 /f 2 >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotIncludeDriversWithWindowsUpdate" /t REG_DWORD /d 1 /f 2 >nul 2>&1
dism /online /disable-feature /featurename:Microsoft-Hyper-V /norestart >nul 2>&1
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /format:value') do set MEM=%%i
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%RAM%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v "Start" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_SZ /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "BorderWidth" /t REG_SZ /d "-15" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "CaptionHeight" /t REG_SZ /d "-330" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\DefaultColors\Standard" /v "HotTrackingColor" /t REG_DWORD /d "13395456" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\DefaultColors\HighContrast" /v "HotTrackingColor" /t REG_DWORD /d "65535" /f >nul 2>&1
reg add "HKCU\Control Panel\Cursors" /v "ContactVisualization" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Cursors" /v "GestureVisualization" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d 0 /f 2 >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "MenuAnimate" /t REG_SZ /d 0 /f 2 >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f 2 >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "Animations" /t REG_DWORD /d 0 /f 2 >nul 2>&1
reg add "HKCU\AppEvents\Schemes" /ve /d ".None" /f 2 >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d 1 /f 2 >nul 2>&1
reg add "HKCU\Control Panel\Sound" /v "Beep" /t REG_SZ /d "no" /f 2 >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f 2 >nul 2>&1
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
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d 200 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "MinAnimate" /t REG_SZ /d 0 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "ListviewAlphaSelect" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "ListviewShadow" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
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
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-NetTCPSetting -SettingName InternetCustom,DatacenterCustom,Compat -ForceWS Disabled -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CTCP -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Get-NetAdapter | Enable-NetAdapterRss -ErrorAction SilentlyContinue; Get-NetAdapter | ForEach-Object { try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Receive Buffers' -RegistryValue 512 -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Transmit Buffers' -RegistryValue 512 -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Energy Efficient Ethernet' -RegistryValue '0' -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Interrupt Moderation' -RegistryValue 'Disabled' -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Flow Control' -RegistryValue 'Disabled' -ErrorAction SilentlyContinue } catch {} } }" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "accesssolution" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "olksolution" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "onenotesolution" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "pptsolution" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "projectsolution" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "publishersolution" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "visiosolution" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "wdsolution" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" /v "xlsolution" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "agave" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "verbosestatus" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout" /v "EnableAutoLayout" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "N" /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "WebControlStatus" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "WebControlSecondaryStatus" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d 3 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v "DisableBranchCache" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsMenu" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d 1 /f >nul 2>&1
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentDocsOnExit" /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HidePeopleBar" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoResolveTrack" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoRecentDocsMenu" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "NoRecentDocsNetHood" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LastActiveClick" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility" /v "DynamicScrollbars" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\Maps" /v "UpdateOnlyOnWifi" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Maps\AllowOfflineMapsDownloadOverMeteredConnection" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Maps\EnableOfflineMapsAutoUpdate" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d 3 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\ConfigureChatIcon" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "Capabilities" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "PreventAutoRun" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "PaddedBorderWidth" /t REG_SZ /d "0" /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "MaxAnimate" /t REG_SZ /d "0" /f >nul 2>&1
REG ADD "HKEY_USERS\.DEFAULT\Control Panel\Desktop\WindowMetrics" /v "PaddedBorderWidth" /t REG_SZ /d "0" /f >nul 2>&1
REG ADD "HKEY_USERS\.DEFAULT\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul 2>&1
REG ADD "HKEY_USERS\.DEFAULT\Control Panel\Desktop\WindowMetrics" /v "MaxAnimate" /t REG_SZ /d "0" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v "AnimationAttributionEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v "AnimationAttributionHashingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v "AnimationAttributionEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v "AnimationAttributionHashingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VSCommon\17.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VSCommon\17.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d 0 /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\SCM\Regular" /v "TracingDisabled" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\DeviceHealthAttestationService" /v "EnableDeviceHealthAttestationService" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarContentUpdateMode" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarOpenOnHover" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowThirdPartySuggestionsInWindowsSpotlight" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsSpotlight" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowSpotlightCollection" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsSpotlightOnActionCenter" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsSpotlightOnSettings" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsSpotlightWindowsWelcomeExperience" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowWindowsTips" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\ConfigureWindowsSpotlightOnLockScreen" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EditionOverrides" /v "UserSetting_DisableStartupSound" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Boot" /v "DisableStartupSound" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Stickers\EnableStickers" /v "value" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d 2 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d 2 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HidePeopleBar" /v "value" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People\ShoulderTap" /v "ShoulderTapAudio" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "AwayModeEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "CoreParkingDisabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "FastBoot" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "VirtualizationEnabled" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d 0 /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "FreezeThawTimeoutInSeconds" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenu.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenu.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenu.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sppsvc.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sppsvc.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sppsvc.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d 8 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d 8 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MoUsoCoreWorker.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MoUsoCoreWorker.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MoUsoCoreWorker.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MoUsoCoreWorker.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Compattelrunner.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Compattelrunner.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Compattelrunner.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Compattelrunner.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuAffinityMask" /t REG_QWORD /d 0x8000000000000000 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "100" /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_CURRENT_USER\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\System\TurnOffFileHistory" /v "value" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}\000%%i" /v "IdleEnable" /t REG_DWORD /d 0 /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1fb2a002-4c6c-4de7-85c2-cb8db9a4f728}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{7988B571-EC89-11cf-9C00-00AA00A14F56}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{7988B573-EC89-11cf-9C00-00AA00A14F56}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{1fb2a002-4c6c-4de7-85c2-cb8db9a4f728}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7988B571-EC89-11cf-9C00-00AA00A14F56}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7988B573-EC89-11cf-9C00-00AA00A14F56}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{BB0DB60E-FFA0-4756-9F04-A0FCE6A97809}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{BBD5AFE4-1417-40f7-94B3-A10719535CB4}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{4D728E35-16FA-4320-9E8B-BFD7100A8846}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{614C2902-8C8F-4D8F-90A2-FB9017B19FF9}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{6A5FEA5B-BF8F-4EE5-B8C3-44D8A0D7331C}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{A4F2A5C9-979A-4EC6-851F-341F15D3F67D}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{B164BCEE-41B3-4F70-A53C-2ACA322DCCCB}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{98859A6C-02F2-43FC-ADB0-CE6D10F1A1AA}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{C5388469-F816-40D2-9E6B-D6C68986996E}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7AA809F6-C072-11DF-AC23-18A90531A85A}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7AA809F7-C072-11DF-AC23-18A90531A85A}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{7AA809F8-C072-11DF-AC23-18A90531A85A}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{E49F7E50-C070-11DF-AC23-18A90531A85A}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{168F4281-EC0D-46D3-951D-FBCB2F7C9079}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{90511715-D0AD-4DAA-A18B-254BD3AE1CF2}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{A7AA4814-7479-4047-BC99-32E757C8B850}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{59C88A5A-702B-4DAB-9FBE-F53140BA899B}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{B5A123C0-3893-4F1C-8599-00F4B82F2C99}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{0F563B5F-8EE2-4516-BA0A-544DE058C75B}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{F6B6E965-E9B2-444B-9286-10C9152EDBC5}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f >nul 2>&1
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.CscWorkOfflineOnline" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.CscSync" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{0F563B5F-8EE2-4516-BA0A-544DE058C75B}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{F6B6E965-E9B2-444B-9286-10C9152EDBC5}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{0F563B5F-8EE2-4516-BA0A-544DE058C75B}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{F6B6E965-E9B2-444B-9286-10C9152EDBC5}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{F6B6E965-E9B2-444B-9286-10C9152EDBC5}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_41040327" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DeviceUpdateLocations" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.RibbonSync.WorkOfflineOnline" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.RibbonSync.SyncThisFolder" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.RibbonSync.MakeAvailableOffline" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\FileHistory" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E61FEADD-31CB-4052-8A16-1F4336764D10}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{E61FEADD-31CB-4052-8A16-1F4336764D10}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{E61FEADD-31CB-4052-8A16-1F4336764D10}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\ms-meetnow" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\ms-meetnowflyout" /f >nul 2>&1
REG DELETE "HKEY_CURRENT_USER\Software\Classes\ms-meetnow" /f >nul 2>&1
REG DELETE "HKEY_CURRENT_USER\Software\Classes\ms-meetnowflyout" /f >nul 2>&1
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-meetnowflyout" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-meetnowflyout" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-meetnowflyout" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\JumpViewUI.TaskbarMeetNowFrame" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\JumpViewUI.TaskbarMeetNow2Frame" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.MicrosoftEdge.ContentProcessComponent" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.FamilySafety.AppTimeLimits" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpatialGraphFilter" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{880B9D61-BF97-4850-97D8-CD9EBFC4488A}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{880B9D61-BF97-4850-97D8-CD9EBFC4488A}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{880B9D61-BF97-4850-97D8-CD9EBFC4488A}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\RetailDemo" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\AppXjj5q94522tr3azgc4pv1grpyk9t831ve" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\AppID\{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\AppID\{C2EA2356-994C-45AF-BDAE-10796F73BC47}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{1e46246f-b2ad-4a86-9e08-d0f9e01ee05d}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{61f77d5e-afe9-400b-a5e6-e9e80fc8e601}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{94FBC195-CB86-4142-9A6A-8E9CCF0D4F4D}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{a6e02196-c1bf-4989-8a94-144eee4a9bb2}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{FB046C65-10C7-4994-ABE4-E3F7FD710B2E}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{15D8726E-26CE-495A-817E-3AD7B022FCFA}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{1FD12909-E6DD-4983-A4C6-50B395961110}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{8ba5a5ed-e0c5-4ce6-a1e8-9263e099746f}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{faedbd4d-20b6-43a9-b67c-577127c8d12b}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\ms-retaildemo-launchbioenrollment" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\ms-retaildemo-launchstart" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\AppID\{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\AppID\{C2EA2356-994C-45AF-BDAE-10796F73BC47}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{FB046C65-10C7-4994-ABE4-E3F7FD710B2E}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\Interface\{15D8726E-26CE-495A-817E-3AD7B022FCFA}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\Interface\{1FD12909-E6DD-4983-A4C6-50B395961110}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\Interface\{8ba5a5ed-e0c5-4ce6-a1e8-9263e099746f}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\Interface\{faedbd4d-20b6-43a9-b67c-577127c8d12b}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{C2EA2356-994C-45AF-BDAE-10796F73BC47}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{1e46246f-b2ad-4a86-9e08-d0f9e01ee05d}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{61f77d5e-afe9-400b-a5e6-e9e80fc8e601}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{94FBC195-CB86-4142-9A6A-8E9CCF0D4F4D}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{a6e02196-c1bf-4989-8a94-144eee4a9bb2}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{FB046C65-10C7-4994-ABE4-E3F7FD710B2E}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{15D8726E-26CE-495A-817E-3AD7B022FCFA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{1FD12909-E6DD-4983-A4C6-50B395961110}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{8ba5a5ed-e0c5-4ce6-a1e8-9263e099746f}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{faedbd4d-20b6-43a9-b67c-577127c8d12b}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-retaildemo-launchstart" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\ms-retaildemo-launchbioenrollment" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\{C2EA2356-994C-45AF-BDAE-10796F73BC47}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{FB046C65-10C7-4994-ABE4-E3F7FD710B2E}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{15D8726E-26CE-495A-817E-3AD7B022FCFA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{1FD12909-E6DD-4983-A4C6-50B395961110}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{8ba5a5ed-e0c5-4ce6-a1e8-9263e099746f}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\Interface\{faedbd4d-20b6-43a9-b67c-577127c8d12b}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\ProtocolExecute\ms-retaildemo-launchbioenrollment" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\ProtocolExecute\ms-retaildemo-launchstart" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{12D4C69E-24AD-4923-BE19-31321C43A767}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{0886dae5-13ba-49d6-a6ef-d0922e502d96}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{0886dae5-13ba-49d6-a6ef-d0922e502d96}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\RetailDemo.Internal.RetailDemoSetup" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\RetailDemo.Internal.RetailInfoSetter" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\RetailDemo.Internal.WindowsHelloHelper" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\CloudExperienceHostBroker.RetailDemo.ConfigureRetailDemo" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{119b14a0-eb11-40c7-9a3c-e6a8904827d2}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1a9ca6d5-2488-46b1-b439-218f2314a059}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{A5890610-900C-4115-BAFF-767E05E10F1F}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{CD607C8B-17CA-4D2E-BA26-B748553BB0B2}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{DE8DEA9C-CC35-4A6E-8A17-F0C611F249A4}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{EBB236B1-F57F-480D-9DE9-B15A87298EEC}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\AppID\{0886dae5-13ba-49d6-a6ef-d0922e502d96}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\AppID\{0886dae5-13ba-49d6-a6ef-d0922e502d96}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{119b14a0-eb11-40c7-9a3c-e6a8904827d2}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{1a9ca6d5-2488-46b1-b439-218f2314a059}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{A5890610-900C-4115-BAFF-767E05E10F1F}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{CD607C8B-17CA-4D2E-BA26-B748553BB0B2}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{DE8DEA9C-CC35-4A6E-8A17-F0C611F249A4}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{EBB236B1-F57F-480D-9DE9-B15A87298EEC}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{AAEC1DAE-CC06-4DA4-B762-56A76FD4B2FF}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{0DEE55E7-1157-4FBD-865E-80D4E151DD74}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{75185BE8-64A9-4E35-9B42-EA422CB7D854}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{445AB715-5154-42F6-9DAF-71C05428DF4E}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{76192C2C-2F55-45DF-B1BF-2ADA479F399C}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{8201C8D6-A9A9-41EA-877D-6D29FEE52732}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{8E17139B-5D9A-4EE3-96A1-F9455D55ED34}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{A03D1421-B1EC-11D0-8C3A-00C04FC31D2F}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{B6A55658-AD62-4133-A1D7-C9073361763B}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{BB328424-067F-45AF-8485-C7389ED64A54}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{BED46A0F-EFF2-4EA3-A201-337BE6828F42}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{D5FE7E1F-7473-4D6E-8BD5-3F72B1DB02BE}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{DCABF59E-AF88-41D5-92E8-905680968039}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Interface\{F2CC526B-08C7-4E0E-BA62-74A53C4AB446}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{AAEC1DAE-CC06-4DA4-B762-56A76FD4B2FF}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{0DEE55E7-1157-4FBD-865E-80D4E151DD74}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{445AB715-5154-42F6-9DAF-71C05428DF4E}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{75185BE8-64A9-4E35-9B42-EA422CB7D854}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{76192C2C-2F55-45DF-B1BF-2ADA479F399C}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{8201C8D6-A9A9-41EA-877D-6D29FEE52732}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{8E17139B-5D9A-4EE3-96A1-F9455D55ED34}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{A03D1421-B1EC-11D0-8C3A-00C04FC31D2F}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{B6A55658-AD62-4133-A1D7-C9073361763B}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{BB328424-067F-45AF-8485-C7389ED64A54}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{BED46A0F-EFF2-4EA3-A201-337BE6828F42}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{D5FE7E1F-7473-4D6E-8BD5-3F72B1DB02BE}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{DCABF59E-AF88-41D5-92E8-905680968039}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{F2CC526B-08C7-4E0E-BA62-74A53C4AB446}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\OCHelper.BrowserHelper" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\OCHelper.BrowserHelper.1" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\AppVMachineRegistryStore\Integration\Ownership\Software\Microsoft\Windows\CurrentVersion\App Paths\SKYPESERVER.EXE" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\CLSID\{AAEC1DAE-CC06-4DA4-B762-56A76FD4B2FF}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\OCHelper.BrowserHelper" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\OCHelper.BrowserHelper.1" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Classes\Wow6432Node\CLSID\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\SKYPESERVER.EXE" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\microphone\Apps\Microsoft.Windows.PPISkype_cw5n1h2txyewy" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\microphone\Apps\WhatsNew_cw5n1h2txyewy" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\webcam\Apps\Microsoft.Windows.PPISkype_cw5n1h2txyewy" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Messaging_8wekyb3d8bbweSkypeVide" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.MessagingSkype_8wekyb3d8bbweApp" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.MessagingSkype_8wekyb3d8bbweSkypeVideo" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.MessagingSkype_8wekyb3d8bbwex27e26f40ye031y48a6yb130yd1f20388991ax" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Winners\amd64_microsoft-windows-skype-ortc_31bf3856ad364e35_none_e1fa6582c679b1b3" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\TypeLib\{F1CBBA3D-683A-4612-97EB-AF035E3B6218}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extension Compatibility\{22BF413B-C6D2-4D91-82A9-A0F997BA588C}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extension Compatibility\{77BF5300-1474-4EC7-9980-D32B190E9B07}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extension Compatibility\{AE805869-2E5C-4ED4-8F7B-F1F7851A4497}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\SKYPESERVER.EXE" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\ROOT\IMAGE\0000\Device Parameters\Processes\skype.exe" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\diagnostics" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\wercplsupport" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AeLookupSvc" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\AppXkndb5xvk0v1ka1efnjajnamxcd3sfae1" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\ms-desktopsearchbox" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\ms-stickereditor" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\AppXy37j8m4r12mkyg6recvrn8r32ean0kjm" /f >nul 2>&1
REG DELETE "HKEY_CURRENT_USER\Software\Classes\AppXy37j8m4r12mkyg6recvrn8r32ean0kjm" /f >nul 2>&1
REG DELETE "HKEY_CURRENT_USER\Software\Classes\AppXkndb5xvk0v1ka1efnjajnamxcd3sfae1" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXy37j8m4r12mkyg6recvrn8r32ean0kjm" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXkndb5xvk0v1ka1efnjajnamxcd3sfae1" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXy37j8m4r12mkyg6recvrn8r32ean0kjm" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXkndb5xvk0v1ka1efnjajnamxcd3sfae1" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-desktopsearchbox" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-stickereditor" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-desktopsearchbox" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.protocol\ms-stickereditor" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Protocol\Data\17" /f >nul 2>&1
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-desktopsearchbox" /f >nul 2>&1
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-stickereditor" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\DesktopBackground\Shell\EditStickers" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\DesktopBackground\Shell\ShowDesktopSearch" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{7F2DA095-D54F-4B13-B246-9B6F33A50E83}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{CDF54DC6-6DCD-410E-A3F0-003BB1289F40}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{CDF54DC6-6DCD-410E-A3F0-003BB1289F40}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{7F2DA095-D54F-4B13-B246-9B6F33A50E83}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{CDF54DC6-6DCD-410E-A3F0-003BB1289F40}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{7F2DA095-D54F-4B13-B246-9B6F33A50E83}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{1677ABA1-4346-442F-A74A-D8B9A713B964}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1677ABA1-4346-442F-A74A-D8B9A713B964}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{1677ABA1-4346-442F-A74A-D8B9A713B964}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{1677ABA1-4346-442F-A74A-D8B9A713B964}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\Server\BcastDVRUserService" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{053C9CB8-5BA1-4F47-A6F1-D1D748C7DA93}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{053C9CB8-5BA1-4F47-A6F1-D1D748C7DA93}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{053C9CB8-5BA1-4F47-A6F1-D1D748C7DA93}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{053C9CB8-5BA1-4F47-A6F1-D1D748C7DA93}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{817F98C4-C9D9-4B8F-B8D0-413C8E5DBBB7}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.fax" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.fax" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{0b6d74fe-ad29-4c92-ac06-f06bc2f238a7}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{34e6abfe-e9f4-4ddf-895a-7350e198f26e}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{a7c922a0-a197-4ae4-8fcd-2236bb4cf515}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{F4D36777-EAED-4cc5-9FE7-827BE5190B20}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{faeb54c4-f66f-4806-83a0-805299f5e3ad}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{FE6B11C3-C72E-4061-86C6-9D163121F229}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{0b6d74fe-ad29-4c92-ac06-f06bc2f238a7}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{34e6abfe-e9f4-4ddf-895a-7350e198f26e}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{a7c922a0-a197-4ae4-8fcd-2236bb4cf515}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{F4D36777-EAED-4cc5-9FE7-827BE5190B20}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{faeb54c4-f66f-4806-83a0-805299f5e3ad}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{FE6B11C3-C72E-4061-86C6-9D163121F229}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Microsoft.FeedsManager" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{9CDCD9C9-BC40-41C6-89C5-230466DB0BD0}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_FEEDS" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{9CDCD9C9-BC40-41C6-89C5-230466DB0BD0}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{4C6470A6-3F91-4f41-850B-DB9BCD074537}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{55b70dec-4b3b-4e26-ae9c-9e8d131843a1}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{C8059EB6-D2FC-4ecf-A15F-AF427F5E4DB6}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{0316BBC2-92D9-4E2E-8345-3609C6B5C167}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{56D04F5D-964F-4DBF-8D23-B97989E53418}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{7D868ACD-1A5D-4A47-A247-F39741353012}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{D7CA032C-B7D0-429E-9FD7-82241C356B4A}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{56D04F5D-964F-4DBF-8D23-B97989E53418}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{7D868ACD-1A5D-4A47-A247-F39741353012}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{D7CA032C-B7D0-429E-9FD7-82241C356B4A}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.SocialFeedChildItem" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.SocialFeedItem" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.SocialFeedSharedItem" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.Provider.SocialInfoProviderManager" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.ApplicationModel.SocialInfo.SocialItemThumbnail" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\WellKnownContracts" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Lock Screen\FeedManager" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\FeedManager" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{3E73C6F7-8937-4C07-85D9-D4447A4BE072}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{3E73C6F7-8937-4C07-85D9-D4447A4BE072}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\GameOverlay" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\GameOverlay" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\WindowsUdk.Gaming.UI.GameMru" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\TypeLib\{8cec5857-07a1-11d9-b15e-000d56bfe6ee}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{8cec58e7-07a1-11d9-b15e-000d56bfe6ee}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\TypeLib\{8cec5857-07a1-11d9-b15e-000d56bfe6ee}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{E5B8E079-EE6D-4E33-A438-C87F2E959254}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{B9033E87-33CF-4D77-BC9B-895AFBBA72E4}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{B9033E87-33CF-4D77-BC9B-895AFBBA72E4}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{9885AEF2-BD9F-41E0-B15E-B3141395E803}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{9885AEF2-BD9F-41E0-B15E-B3141395E803}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{27016870-8E02-11D1-924E-00C04FBBBFB3}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{754A73E3-B0A5-4305-A45A-428186716507}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\{EB521D7D-4095-4E61-88FB-BF25700F142A}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{241D7C96-F8BF-4F85-B01F-E2B043341A4B}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{27016870-8E02-11D1-924E-00C04FBBBFB3}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{754A73E3-B0A5-4305-A45A-428186716507}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{EB521D7D-4095-4E61-88FB-BF25700F142A}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{241D7C96-F8BF-4F85-B01F-E2B043341A4B}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxa.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxc.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxd.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxe.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxf.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxh.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxi.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxk.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxq.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxr.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxs.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxt.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxv.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\MSHelp.hxw.2.5" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\HelpAndSupport" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Hints" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\HelpAndSupport" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Hints" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.help" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{9127081a-04b5-4044-b4c5-c7a9718e8795}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.help" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{9127081a-04b5-4044-b4c5-c7a9718e8795}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{06946266-393A-456E-92BC-91DDDBF6893C}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{07DC68FA-A15D-4E44-93DE-645060C7B469}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{06946266-393A-456E-92BC-91DDDBF6893C}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{07DC68FA-A15D-4E44-93DE-645060C7B469}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Maps" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{2409B88C-473B-428B-8795-4C32D7822C9F}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{C9D09D2D-8C0A-4A0F-A699-4125AD19EF9C}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Auto_Update_Setting" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_CopyrightAttribution" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_DeleteAll" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Download_Add_Package" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Download_Available_Packages_Collection" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Download_User_Packages_Collection" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Downloads_Activation" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_MapDataOld_Update" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Service_Error" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Updates_Actions" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Updates_State_Installing" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemSettings\SettingId\SystemSettings_Maps_Wifi_Only_Setting" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\AppID\{5C03E1B1-EB13-4DF1-8943-2FE8E7D5F309}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\AppID\{5C03E1B1-EB13-4DF1-8943-2FE8E7D5F309}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\MemoryDiagnostic" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{74F6069B-3D81-479E-AA67-42CE80F16799}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B97E9B4F-4348-4D52-8204-5EB3B9E3351C}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{74F6069B-3D81-479E-AA67-42CE80F16799}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{74F6069B-3D81-479E-AA67-42CE80F16799}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{B97E9B4F-4348-4D52-8204-5EB3B9E3351C}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{B97E9B4F-4348-4D52-8204-5EB3B9E3351C}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WacomPen" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PenService" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\RemoteApp and Desktop Connections Update" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\RemoteAssistance" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{10B3DD77-3048-41E7-A34D-5FF120D33FA4}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Logon\{10B3DD77-3048-41E7-A34D-5FF120D33FA4}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Plain\{10B3DD77-3048-41E7-A34D-5FF120D33FA4}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{A3BC03A0-041D-42E3-AD22-882B7865C9C5}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{115e13cf-cfe8-4821-b0da-e06aa4d51426}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1B462D7B-72D8-4544-ACC1-D84E5B9A8A14}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{1DF7C823-B2D4-4B54-975A-F2AC5D7CF8B8}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{22A7E88C-5BF5-4DE6-B687-60F7331DF190}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{301B94BA-5D25-4A12-BFFE-3B6E7A616585}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{32be5ed2-5c86-480f-a914-0ff8885a1b3f}" /f >nul 2>&1
REG DELETE "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{3523c2fb-4031-44e4-9a3b-f1e94986ee7f}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\WebCheck" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WebCheck" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\AppID\{6de5dc63-3c0c-4dda-9220-1028a37298ba}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{c1f85ef8-bcc2-4606-bb39-70c523715eb3}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{C424F25A-6774-48BC-9F1E-02CCA8C1BE62}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{C58C4893-3BE0-4B45-ABB5-A63E4B8C8651}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{6de5dc63-3c0c-4dda-9220-1028a37298ba}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{c1f85ef8-bcc2-4606-bb39-70c523715eb3}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{C424F25A-6774-48BC-9F1E-02CCA8C1BE62}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{C58C4893-3BE0-4B45-ABB5-A63E4B8C8651}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{58E3C745-D971-4081-9034-86E34B30836A}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{58E3C745-D971-4081-9034-86E34B30836A}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Foundation.Diagnostics.ErrorDetails" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Device Setup" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\DeviceDirectoryClient" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Device Information" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Feedback" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\WDI" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Servicing" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4C5BCB25-2C1D-40F3-A779-FDE6280DB867}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Management\Provisioning" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0E511F8F-D1BF-49C8-B1B9-A6C784A17EDA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{1D3D9B10-30A4-459E-8B32-248CAD0EB7EF}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{3EFB737D-965A-4364-8CBA-CCDA345B1C71}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{76300FA9-9EB5-4A2C-8087-029276F64728}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{825F76D6-EA34-4133-BF96-B416888766A3}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8D567D13-E3B8-4273-84F4-C743E60872CC}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{BAE9F0C3-0DB3-494E-BC0B-42703170C272}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{C6D0FF06-5886-4924-93EB-851D6F3CBD06}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{81272F44-D745-4699-8216-955865606EAC}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{9FFC9FC7-ACE3-434F-A78C-43BBD0C1B871}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{8B551B42-E746-49C9-A6F3-D9B988AE0914}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{BE7B1C85-5B05-49EE-A887-1F23FF59A1EA}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{68AB1C40-FB5C-490E-9513-733CCED864C1}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FB9EE28D-D0CA-4B6E-B47A-201C830C7006}" /f >nul 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{CD3A454B-E619-4AA6-85B5-B2D98ABC43A1}" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d 0 /f >nul 2>&1
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul 2>&1
reg add "HKEY_CURRENT_USER\AppEvents\Schemes" /v ".Current" /t REG_SZ /d ".None" /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 38 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f >nul 2>&1
powercfg -setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 0 >nul 2>&1
powercfg -setdcvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 0 >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" /v "Attributes" /t REG_DWORD /d 0 /f >nul 2>&1
powercfg -setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 2 >nul 2>&1
powercfg -setdcvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 2 >nul 2>&1
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >nul 2>&1
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 000 >nul 2>&1
powercfg -setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 000 >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "Scheduler Response (ms)" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f  >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f  >nul 2>&1
powercfg /h off  >nul 2>&1
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100  >nul 2>&1
powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0  >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f  >nul 2>&1
net stop RemoteRegistry >nul 2>&1
net stop TermService >nul 2>&1
net stop BthAvctpSvc >nul 2>&1
net stop FrameServer >nul 2>&1
net stop Spectrum >nul 2>&1
net stop fhsvc >nul 2>&1
net stop AudioSrv >nul 2>&1
net stop TabletInputService >nul 2>&1
net stop diagnosticshub.standardcollector.service >nul 2>&1
for /f "tokens=*" %%s in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /S /F "StorPort" 2^
reg add "%%s" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "%%s" /v "IdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\hidusb\Parameters" /v "EnablePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
for /f %%a in ('WMIC PATH Win32_USBHub GET DeviceID^| FINDSTR /L "VID_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /f /v "AllowIdleIrpInD3" /t REG_DWORD /d 0 >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Shell\USB" /v "NotifyOnUsbErrors" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Shell\USB" /v "NotifyOnWeakCharger" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
powercfg -h off >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "tokens=4" %%g in ('powercfg -getactivescheme') do set "UP_GUID=%%g"
powercfg /setacvalueindex %UP_GUID% SUB_USB 2a737441-1930-4402-8d77-b2bebba308a3 0 >nul 2>&1
powercfg /setacvalueindex %UP_GUID% SUB_PCIEXPRESS ASPM 0 >nul 2>&1
powercfg -setactive %UP_GUID% >nul 2>&1
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "EnableHIPM" 2^
REG ADD "%%a" /F /V "EnableHIPM" /T REG_DWORD /d "0" >NUL
REG ADD "%%a" /F /V "EnableDIPM" /T REG_DWORD /d "0" >NUL
REG ADD "%%a" /F /V "EnableHDDParking" /T REG_DWORD /d "0" >NUL
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services" /S /F "EnableALPM" 2^
REG ADD "%%a" /F /V "EnableALPM" /T REG_DWORD /d "0" >NUL
for /f %%i in ('powershell -Command "(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize"') do set RAM_KB=%%i
for /f %%a in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "VEN_"') do (
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID 2^
reg add "HKLM\SYSTEM\CurrentControlSet\services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\services\USBXHCI\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "tokens=*" %%s in ('reg query "HKLM\System\CurrentControlSet\Enum" /S /F "StorPort" ^| findstr /e "StorPort"') do (
powershell -Command "Disable-MMAgent -PageCombining" >nul 2>&1
powershell -Command "Disable-MMAgent -MemoryCompression" >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Services\USBXHCI\Parameters" /v "DmaRemappingCompatibleSelfhost" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\System\ControlSet001\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PnP" /v "DisableWarmPoll" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PnP" /v "FastDeviceDetect" /t REG_DWORD /d "1" /f >nul 2>&1
for /f "tokens=*" %%i in ('powershell -Command "Get-PnpDevice -Class 'USB' | Select-Object -ExpandProperty DeviceID" ^| findstr "USB\VID_"') do (
reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f >nul 2>&1
powercfg /setacvalueindex %UP_GUID% 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >nul 2>&1
powercfg /setdcvalueindex %UP_GUID% 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >nul 2>&1
powercfg /setactive %UP_GUID% >nul 2>&1
del /f /q "%LocalAppData%\Microsoft\Windows\Explorer\iconcache*" >nul 2>&1
del /f /q "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache*" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "IncreaseFixedSegment" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAnimations" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableTransparency" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "5" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "ForceDoubleBuffer" /t REG_DWORD /d "1" /f >nul 2>&1
powercfg -setacvalueindex %UP_GUID% SUB_PCIEXPRESS ASPM 0 >nul 2>&1
powercfg -setdcvalueindex %UP_GUID% SUB_PCIEXPRESS ASPM 0 >nul 2>&1
powercfg -setacvalueindex %UP_GUID% SUB_VIDEO VIDEOIDLE 0 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "IncreaseFixedSegment" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AdaptiveVsyncEnable" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "MaxQueuedBuffers" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "ForceDoubleBuffer" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "EnablePerProcessSystemScheduling" /t REG_DWORD /d 1 /f >nul 2>&1
wmic process where "name='valorant.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='csgo.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='fortnite.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='eldenring.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='warzone.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='apex.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='r6s.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='gta5.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='overwatch.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='game.exe'" CALL setpriority 256  >nul 2>&1
wmic process where "name='discord.exe'" CALL setpriority 128  >nul 2>&1
wmic process where "name='obs64.exe'" CALL setpriority 128  >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~g\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~g\PerfOptions" /v "IoPriority" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~g\PerfOptions" /v "PagePriority" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "Attributes" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec" /v "Attributes" /t REG_DWORD /d "2" /f >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 >nul 2>&1
powercfg -setacvalueindex scheme_current sub_processor CPMAXCORES 100 >nul 2>&1
powercfg -setactive scheme_current >nul 2>&1
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\PCI" /s /f "PCI\VEN_" ^| findstr "HKEY"') do (
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
del /s /f /q "%temp%\*.*" >nul 2>&1
del /s /f /q "C:\Windows\Temp\*.*" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoWindowMinimizingShortcuts" /t REG_DWORD /d "1" /f >nul 2>&1
powershell "&  {Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('!WARNING! You can only use this if you are on ethernet, if you are on wifi, press "N" on the next page', 'Exm Tweaking Utility', 'Ok', [System.Windows.Forms.MessageBoxIcon]::Information);}" >nul 2>&1
for /f %%n in '('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (
Reg.exe add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "*EEE" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "EEE" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "DisabledelayedPowerUp" /t REG_SZ /d "2" /f >nul 2>&1
Reg.exe add "%%n" /v "AutoDisablingGigabit" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f >nul 2>&1
Reg.exe add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "EnabledynamicPowerGating" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >nul 2>&1
Reg.exe add "%%n" /v "JumboPacket" /t REG_SZ /d "1514" /f >nul 2>&1
Reg.exe add "%%n" /v "TransmitBuffers" /t REG_SZ /d "2048" /f >nul 2>&1
Reg.exe add "%%n" /v "ReceiveBuffers" /t REG_SZ /d "1024" /f >nul 2>&1
Reg.exe add "%%n" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "LsoV1IPv4" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "LsoV2IPv4" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "LsoV2IPv6" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "PMARPOffload" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "PMNSOffload" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "RSS" /t REG_SZ /d "1" /f >nul 2>&1
Reg.exe add "%%n" /v "*NumRssQueues" /t REG_SZ /d "2" /f >nul 2>&1
Reg.exe add "%%n" /v "RSSProfile" /t REG_SZ /d "3" /f >nul 2>&1
Reg.exe add "%%n" /v "*FlowControl" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "FlowControlCap" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "RxAbsIntDelay" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "TxIntDelay" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "TxAbsIntDelay" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "%%n" /v "FatChannelIntolerant" /t REG_SZ /d "0" /f >nul 2>&1
powershell -NoProfile -Command "Enable-NetAdapterBinding -Name "*" -ComponentID ms_pacer" >nul 2>&1
powershell "&  {Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('You have to restart your pc after this', 'Exm Tweaking Utility', 'Ok', [System.Windows.Forms.MessageBoxIcon]::Information);}" >nul 2>&1
For /f "Delims=" %%k in ('Reg.exe Query HKLM\SYSTEM\CurrentControlSet\Enum /f "{4d36e967-e325-11ce-bfc1-08002be10318}" /d /s^|Find "HKEY"') do (
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaCapabilities" /t REG_SZ /d "" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsWindowsHelloActive" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d 3 /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\SearchCompanion" /v "DisableContentFileUpdates" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DoNotUseWebResults" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnablingFeeds" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnablingActivityFeed" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\QuietHours" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Print.Notification" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DoReport" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t Reg_DWORD /d "5" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t Reg_DWORD /d ""0"" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t Reg_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t Reg_DWORD /d "1" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t Reg_DWORD /d "2" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnablingSmartScreen" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f >nul 2>&1
Reg.exe add "HKU\!USER_SID!\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnablingWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKU\!USER_SID!\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKU\!USER_SID!\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\bam" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dam" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnablingTransparency" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance" /v "DisablediagnosticTracing" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnabling" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "DisableOptinExperience" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common" /v "sendcustomerdata" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common\Feedback" /v "includescreenshot" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\Common\ClientTelemetry" /v "SendTelemetry" /t REG_DWORD /d "3" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common" /v "qmEnable" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common" /v "updatereliabilitydata" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common\General" /v "shownfirstrunoptin" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common\General" /v "skydrivesigninoption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Common\ptwatson" /v "ptwoptin" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\Firstrun" /v "Disablemovie" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM" /v "Enablelogging" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM" /v "EnableFileObfuscation" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications" /v "accesssolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications" /v "olksolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications" /v "onenotesolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications" /v "pptsolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications" /v "projectsolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications" /v "publishersolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications" /v "visiosolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications" /v "wdsolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedapplications" /v "xlsolution" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "agave" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKCU\Software\Microsoft\Office\16.0\OSM\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d "1" /f >nul 2>&1
taskkill/im msedge.exe >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisablegWebSearch" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "1" /f >nul 2>&1
for /f "tokens=3" %%a in ('Reg.exe query "HKLM\SYSTEM\ControlSet001\Enum\%%m" /v "Driver"') do (
for /f %%m in ('echo %w%- %%a ^| findstr "{"') do (
Reg.exe add "HKLM\System\ControlSet001\Control\Class\%%m" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d "20" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d "1" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t REG_BINARY /d "0100000001000000" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "3D_Refresh_Rate_Override_DEF" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSnapshot" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AAF_NA" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AntiAlias_NA" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ASTT_NA" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSubscription" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AreaAniso_NA" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowRSOverlay" /t REG_SZ /d "false" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Adaptive De-interlacing" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSkins" /t REG_SZ /d "false" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AutoColorDepthReduction_NA" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableVCEPowerGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablingVceSwClockGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablingUvdClockGating" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablingAspmL0s" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablingAspmL1" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablingUlps" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnablingUlps_NA" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableComputePreemption" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "FlipQueueSize" /t REG_BINARY /d "3100" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\amdlog" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f >nul 2>&1
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID') do set "str=%%i" & (
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Windows.Print3D' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.HEVCVideoExtension' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.RawImageExtension' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.MicrosoftOfficeHub' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.CallingShellApp' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.PeopleExperienceHost' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.ParentalControls' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.Holographic.FirstRun' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Messaging' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsAlarms' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.WindowsMaps' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.People' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Windows.CBSPreview' | Remove-AppxPackage" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage 'Microsoft.Windows.SecureAssessmentBrowser' | Remove-AppxPackage" >nul 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /F /V "AllowIdleIrpInD3" /T REG_DWORD /d 0 >NUL
for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr /l "USB\VID_"') do (
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 00000000 /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ConfigureDoNotTrack" /t REG_DWORD /d "1" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d '1' /f" >nul 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' /v 'SchUseStrongCrypto' /t 'REG_DWORD' /d '1' /f" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
taskkill /f /im CompatTelRunner.exe >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePropPage" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f >nul 2>&1
net stop brave >nul 2>&1
net stop bravem >nul 2>&1
taskkill /f /im maintenanceservice.exe >nul 2>&1
taskkill /f /im uninstall.exe >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePropPage" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v "DumpFolder" /t REG_EXPAND_SZ /d "%%LOCALAPPDATA%%\CrashDumps" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v "DumpCount" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v "DumpType" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\Maps\AutoUpdateEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\Maps\AutoUpdateEnabled" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement\ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f >nul 2>&1
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
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f >nul 2>&1

