@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Optimizacion de Red - Extraccion 1.BAT
color 0A

echo [!] Iniciando optimizacion de pila de red y adaptadores...
echo [!] Extraccion de ajustes de 1.BAT...

:: ----------------------------------------------------------------
:: 1. CONFIGURACIONES NETSH (Global TCP/IP)
:: ----------------------------------------------------------------
echo [*] Aplicando configuraciones NETSH...

:: Desactivar heuristica y ajustes automaticos conservadores
netsh int tcp set heuristics disabled
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global chimney=enabled
netsh int tcp set global rss=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global dca=enabled
netsh int tcp set global ecncapability=enabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global rsc=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set security mpp=disabled
netsh int tcp set security profiles=disabled

:: Configurar proveedor de congestion (CTCP o BBR2 si esta disponible)
netsh int tcp set supplemental internet congestionprovider=ctcp
netsh int tcp set supplemental custom congestionprovider=ctcp

:: Ajustes de IP y vecinos (ARP cache)
netsh interface ipv4 set global neighborcachelimit=4096
netsh interface ipv4 set global routecachelimit=4096
netsh interface ipv4 set global dhcpmediasense=disabled
netsh interface ipv4 set global redirect=disabled
netsh interface ipv4 set global taskoffload=disabled

:: IPv6 (Desactivacion parcial y ajustes)
netsh interface ipv6 set global neighborcachelimit=4096
netsh interface ipv6 set global routecachelimit=4096
netsh interface ipv6 set global dhcpmediasense=disabled
netsh interface ipv6 set global redirect=disabled
netsh interface ipv6 set global mldlevel=none
netsh interface ipv6 set global randomizeidentifiers=disabled
netsh interface ipv6 set global taskoffload=disabled
netsh interface teredo set state disabled
netsh interface isatap set state disabled
netsh interface 6to4 set state disabled

:: Reinicio de parametros de timeouts TCP (RTO)
netsh int tcp set global initialRto=2000
netsh int tcp set global maxsynretransmissions=2

:: ----------------------------------------------------------------
:: 2. AJUSTES DE REGISTRO (TCP/IP Parameters)
:: ----------------------------------------------------------------
echo [*] Aplicando ajustes de Registro (HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters)...

:: Optimizaciones de Ventana TCP y Conexiones
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "131072" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "131072" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "16777214" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f

:: Desactivar Nagle y Retrasos (Latencia)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f

:: Optimizaciones Generales y Seguridad TCP
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableDHCPMediaSense" /t REG_DWORD /d "1" /f

:: Prioridades de Proveedor de Servicio
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "Class" /t REG_DWORD /d "8" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f

:: MSMQ Latency
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f

:: ----------------------------------------------------------------
:: 3. AJUSTES DE ADAPTADORES ESPECIFICOS (Interfaces)
:: ----------------------------------------------------------------
echo [*] Configurando interfaces individuales...

:: Aplicar TcpAckFrequency y TCPNoDelay a todas las interfaces listadas en el registro
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" ^| findstr "HKEY"') do (
    reg add "%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f >nul 2>&1
    reg add "%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1
    reg add "%%i" /v "TCPInitialRtt" /t REG_DWORD /d "300" /f >nul 2>&1
)

:: Desactivar NetBIOS
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" ^| findstr "HKEY"') do (
    reg add "%%i" /v "NetbiosOptions" /t REG_DWORD /d "2" /f >nul 2>&1
)

:: ----------------------------------------------------------------
:: 4. GESTION DE ANCHO DE BANDA Y QOS (Throttling)
:: ----------------------------------------------------------------
echo [*] Eliminando limites de ancho de banda y throttling...

:: Network Throttling Index (FF para desactivar)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f

:: Desactivar Packet Scheduler Limit
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f

:: Lanman Workstation/Server Tweaks
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "UseLargeMTU" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "50" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "50" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f

:: ----------------------------------------------------------------
:: 5. OPTIMIZACION DE HARDWARE DE RED (PowerShell Avanzado)
:: ----------------------------------------------------------------
echo [*] Optimizando configuraciones avanzadas de adaptador via PowerShell...

powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Get-NetAdapter | Enable-NetAdapterRss -ErrorAction SilentlyContinue }"
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Get-NetAdapter | ForEach-Object { Disable-NetAdapterChecksumOffload -Name $_.Name -IpIPv4 -TcpIPv4 -TcpIPv6 -UdpIPv4 -UdpIPv6 -ErrorAction SilentlyContinue } }"
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Get-NetAdapter | ForEach-Object { Disable-NetAdapterLso -Name $_.Name -IPv4 -IPv6 -ErrorAction SilentlyContinue } }"
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Get-NetAdapter | ForEach-Object { Disable-NetAdapterRsc -Name $_.Name -ErrorAction SilentlyContinue } }"

:: Desactivar Ahorro de Energia en Adaptadores (Green Ethernet, EEE, Suspensión Selectiva)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetAdapter | Disable-NetAdapterPowerManagement -WakeOnMagicPacket:$false -WakeOnPattern:$false -DeviceSleepOnDisconnect:$false -SelectiveSuspend:$false -ArpOffload:$false -NSOffload:$false -D0PacketCoalescing:$false -RsnRekeyOffload:$false -NoRestart -ErrorAction SilentlyContinue"

:: Ajuste de Buffers y Propiedades Avanzadas (Iteracion compleja de 1.BAT simplificada)
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Get-NetAdapter | ForEach-Object { try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Receive Buffers' -RegistryValue 2048 -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Transmit Buffers' -RegistryValue 2048 -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Flow Control' -RegistryValue 'Disabled' -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Interrupt Moderation' -RegistryValue 'Disabled' -ErrorAction SilentlyContinue } catch {}; try { Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName 'Energy Efficient Ethernet' -RegistryValue 'Disabled' -ErrorAction SilentlyContinue } catch {} } }"

:: ----------------------------------------------------------------
:: 6. SERVICIOS DE RED (Deshabilitar innecesarios)
:: ----------------------------------------------------------------
echo [*] Ajustando servicios de red...

:: Desactivar LMHOSTS (Obsoleto)
sc config "lmhosts" start= disabled
sc stop "lmhosts"

:: Desactivar TCP Port Sharing (Riesgo de seguridad/Latencia)
sc config "NetTcpPortSharing" start= disabled
sc stop "NetTcpPortSharing"

:: Desactivar Remote Registry y Remote Access
sc config "RemoteRegistry" start= disabled
sc config "RemoteAccess" start= disabled
sc stop "RemoteRegistry"
sc stop "RemoteAccess"

:: Network Connectivity Status Indicator (Sondas activas)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f

:: DNS Cache Tweaks
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "86400" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f

:: Winsock Reset
netsh winsock reset
netsh int ip reset

@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Optimizacion de Red Avanzada - Extraccion 2.BAT
color 0B

echo [!] Iniciando configuracion avanzada de red (Enfoque QoS y AFD)...

:: ----------------------------------------------------------------
:: 1. OPTIMIZACION DE PRIORIDADES DEL SISTEMA Y MULTIMEDIA
:: ----------------------------------------------------------------
echo [*] Ajustando prioridades de sistema y Network Throttling...

:: Desactivar el estrangulamiento de red (Network Throttling)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f >nul 2>&1 [cite: 368]
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 10 /f >nul 2>&1 [cite: 368]
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d 15000 /f >nul 2>&1 [cite: 368]
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 368]

:: Ajustar la separacion de prioridades para favorecer procesos activos
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 38 /f >nul 2>&1 [cite: 368]

:: Prioridad de IRQ (Interrupciones) para componentes de red y sistema
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ1Priority" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 368]
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 369]

:: ----------------------------------------------------------------
:: 2. AJUSTES AFD (Ancillary Function Driver for Winsock)
:: ----------------------------------------------------------------
echo [*] Optimizando buffers AFD y transmision de datagramas...

:: Aumentar ventanas de recepcion y envio por defecto
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d 131072 /f >nul 2>&1 [cite: 441]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d 131072 /f >nul 2>&1 [cite: 442]

:: Optimizacion de envio rapido
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d 1500 /f >nul 2>&1 [cite: 442]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d 1500 /f >nul 2>&1 [cite: 442]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d 0 /f >nul 2>&1 [cite: 442]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "IgnorePushBitOnReceives" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 442]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "NonBlockingSendSpecialBuffering" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 442]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNICBuffers" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 442]

:: ----------------------------------------------------------------
:: 3. OPTIMIZACION TCP/IP GLOBAL (Registro)
:: ----------------------------------------------------------------
echo [*] Aplicando configuracion TCP/IP Global...

:: Parametros de descarga y MTU
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 439]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 436]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MTU" /t REG_DWORD /d 1500 /f >nul 2>&1 [cite: 437]

:: Ventanas TCP y conexiones
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d 131072 /f >nul 2>&1 [cite: 437]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d 131072 /f >nul 2>&1 [cite: 437]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d 16777214 /f >nul 2>&1 [cite: 437]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d 65534 /f >nul 2>&1 [cite: 422]

:: Reduccion de latencia y retransmisiones
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d 3 /f >nul 2>&1 [cite: 437]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /t REG_DWORD /d 5 /f >nul 2>&1 [cite: 437]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d 32 /f >nul 2>&1 [cite: 437]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 421]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d 1 /f >nul 2>&1 [cite: 421]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpDelAckTicks" /t REG_DWORD /d 0 /f >nul 2>&1 [cite: 421]

:: Prioridades de Proveedor de Servicios (Winsock)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "Class" /t REG_DWORD /d 8 /f >nul 2>&1 [cite: 439]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d 6 /f >nul 2>&1 [cite: 440]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d 5 /f >nul 2>&1 [cite: 440]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d 4 /f >nul 2>&1 [cite: 440]
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d 7 /f >nul 2>&1 [cite: 440]

:: ----------------------------------------------------------------
:: 4. CONFIGURACION LANMAN (Workstation & Server)
:: ----------------------------------------------------------------
echo [*] Optimizando LanmanWorkstation para evitar cuellos de botella...

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d 1 /f >nul 2>&1 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d 0 /f >nul 2>&1 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d 8192 /f >nul 2>&1 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d 32 /f >nul 2>&1 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d 17424 /f >nul 2>&1 

:: ----------------------------------------------------------------
:: 5. NETSH TWEAKS
:: ----------------------------------------------------------------
echo [*] Aplicando comandos Netsh...

:: En 2.BAT, el autotuning se establece en DISABLED (diferente al 1.bat)
netsh int tcp set global autotuninglevel=disabled >nul 2>&1 [cite: 368]
netsh int tcp set supplemental Internet congestionprovider=ctcp >nul 2>&1 [cite: 368]
netsh int tcp set global rss=enabled >nul 2>&1 [cite: 368]
netsh int tcp set global chimney=disabled >nul 2>&1 [cite: 422]
netsh int tcp set global netdma=enabled >nul 2>&1 [cite: 422]
netsh int ip set global taskoffload=disabled >nul 2>&1 [cite: 435]
netsh int ip set global icmpredirects=disabled >nul 2>&1 [cite: 435]
netsh int ipv4 set dynamicport tcp start=1025 num=64510 >nul 2>&1 [cite: 435]
netsh winsock set autotuning on >nul 2>&1 [cite: 436]

:: ----------------------------------------------------------------
:: 6. POWERSHELL - CONFIGURACION DE ADAPTADORES
:: ----------------------------------------------------------------
echo [*] Configurando adaptadores fisicos via PowerShell (Buffers y Offload)...

:: Deshabilita Offloads para que la CPU maneje la red (Mejor latencia en CPUs modernas)
powershell -NoProfile -Command "& { Get-NetAdapter | ForEach-Object { Disable-NetAdapterChecksumOffload -Name $_.Name -IpIPv4 -TcpIPv4 -TcpIPv6 -UdpIPv4 -UdpIPv6 -ErrorAction SilentlyContinue } }" >nul 2>&1 [cite: 445]
powershell -NoProfile -Command "& { Get-NetAdapter | ForEach-Object { Disable-NetAdapterLso -Name $_.Name -IPv4 -IPv6 -ErrorAction SilentlyContinue } }" >nul 2>&1 [cite: 445]
powershell -NoProfile -Command "& { Get-NetAdapter | ForEach-Object { Disable-NetAdapterRsc -Name $_.Name -ErrorAction SilentlyContinue } }" >nul 2>&1 [cite: 445]

:: Ajuste agresivo de Buffers
powershell -NoProfile -Command "Set-NetAdapterAdvancedProperty -Name '*' -RegistryKeyword '*ReceiveBuffers' -RegistryValue 2048 -ErrorAction SilentlyContinue" >nul 2>&1 [cite: 446]
powershell -NoProfile -Command "Set-NetAdapterAdvancedProperty -Name '*' -RegistryKeyword '*TransmitBuffers' -RegistryValue 2048 -ErrorAction SilentlyContinue" >nul 2>&1 [cite: 446]
powershell -NoProfile -Command "Set-NetAdapterAdvancedProperty -Name '*' -RegistryKeyword '*FlowControl' -RegistryValue 0 -ErrorAction SilentlyContinue" >nul 2>&1 [cite: 446]
powershell -NoProfile -Command "Set-NetAdapterAdvancedProperty -Name '*' -RegistryKeyword '*InterruptModeration' -RegistryValue 0 -ErrorAction SilentlyContinue" >nul 2>&1 [cite: 446]

:: Deshabilitar IPv6 en el adaptador
powershell -NoProfile -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue" >nul 2>&1 [cite: 447]

:: ----------------------------------------------------------------
:: 7. POLITICAS QoS DE APLICACION (DSCP)
:: ----------------------------------------------------------------
echo [*] Aplicando politicas QoS para aplicaciones especificas...

:: Funcion para crear politica QoS en el registro
goto :APPLY_POLICIES

:CREATE_QOS_POLICY_REG
:: Argumentos: %1=NombrePolitica %2=RutaAplicacion
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Version" /t REG_SZ /d "1.0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Application Name" /t REG_SZ /d "%~2" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Protocol" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Local Port" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Local IP" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Remote Port" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Remote IP" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "DSCP Value" /t REG_SZ /d "5" /f >nul 2>&1 [cite: 573]
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Throttle Rate" /t REG_SZ /d "-1" /f >nul 2>&1 [cite: 572]
goto :EOF

:APPLY_POLICIES
:: Lista de aplicaciones prioritarias extraidas de 2.bat
call :CREATE_QOS_POLICY_REG "Chrome_QoS" "C:\Program Files\Google\Chrome\Application\chrome.exe" [cite: 384]
call :CREATE_QOS_POLICY_REG "Edge_QoS" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" [cite: 384]
call :CREATE_QOS_POLICY_REG "Firefox_QoS" "C:\Program Files\Mozilla Firefox\firefox.exe" [cite: 384]
call :CREATE_QOS_POLICY_REG "Discord_QoS" "%USERPROFILE%\AppData\Local\Discord\update.exe" [cite: 385]
call :CREATE_QOS_POLICY_REG "Steam_QoS" "C:\Program Files (x86)\Steam\steam.exe" [cite: 385]
call :CREATE_QOS_POLICY_REG "Teams_QoS" "%USERPROFILE%\AppData\Local\Microsoft\Teams\Update.exe" [cite: 385]
call :CREATE_QOS_POLICY_REG "Spotify_QoS" "%USERPROFILE%\AppData\Roaming\Spotify\Spotify.exe" [cite: 385]

:: ----------------------------------------------------------------
:: 8. SERVICIOS DE RED INNECESARIOS
:: ----------------------------------------------------------------
echo [*] Deshabilitando servicios de red no esenciales...

sc config "lmhosts" start= disabled >nul 2>&1 [cite: 340]
sc stop "lmhosts" >nul 2>&1
sc config "NetTcpPortSharing" start= disabled >nul 2>&1 [cite: 450]
sc stop "NetTcpPortSharing" >nul 2>&1
sc config "RemoteRegistry" start= disabled >nul 2>&1 [cite: 340]
sc stop "RemoteRegistry" >nul 2>&1
sc config "RasMan" start= disabled >nul 2>&1 [cite: 340]
sc stop "RasMan" >nul 2>&1
sc config "SharedAccess" start= disabled >nul 2>&1 [cite: 340]
sc stop "SharedAccess" >nul 2>&1
sc config "NcdAutoSetup" start= disabled >nul 2>&1 [cite: 450]

@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Optimizacion de Red - Extraccion 3.BAT
color 0E

echo [!] Iniciando optimizacion de red (Enfoque Latencia y Drivers)...
echo [!] Extraccion de ajustes tecnicos de 3.BAT...

:: ----------------------------------------------------------------
:: 1. OPTIMIZACION GLOBAL NETSH (Pila TCP/IP)
:: ----------------------------------------------------------------
echo [*] Configurando parametros globales TCP/IP...

:: Desactivar heuristica y ajustes de descarga (Offloading)
netsh int tcp set heuristics disabled >nul 2>&1
netsh int tcp set heuristics wsh=disabled >nul 2>&1
netsh int tcp set security mpp=disabled >nul 2>&1
netsh int tcp set security profiles=disabled >nul 2>&1

:: Configuraciones globales de TCP (Chimney, DCA, RSC, Timestamps)
netsh int tcp set global chimney=enabled dca=enabled netdma=disabled rsc=disabled maxsynretransmissions=2 timestamps=disabled ecncapability=disabled >nul 2>&1

:: Desactivar protocolos de tunelizado innecesarios (Reducen overhead)
netsh interface teredo set state disabled >nul 2>&1
netsh int isatap set state disable >nul 2>&1
netsh interface 6to4 set state disabled >nul 2>&1

:: Ajustes IP Globales (Cache de rutas y vecinos)
netsh int ip set global neighborcachelimit=4096 >nul 2>&1
netsh int ip set global routecachelimit=4096 >nul 2>&1
netsh int ip set global dhcpmediasense=disabled >nul 2>&1
netsh int ip set global mediasenseeventlog=disabled >nul 2>&1
netsh int ip set global mldlevel=none >nul 2>&1
netsh int ip set global icmpredirects=disabled >nul 2>&1
netsh int ip set global sourceroutingbehavior=drop >nul 2>&1

:: Forzar configuracion Winsock
netsh winsock set autotuning on >nul 2>&1

:: ----------------------------------------------------------------
:: 2. BUCLE DE REGISTRO PARA ADAPTADORES (Configuracion Profunda)
:: ----------------------------------------------------------------
echo [*] Aplicando ajustes profundos al registro de adaptadores (Hardware)...

:: Este bucle busca claves de adaptadores y aplica configuraciones masivas
:: Extraido de las lineas 52-70 del archivo original.

for /f "eol=E" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f "NetbiosOptions" ^| findstr /V "NetbiosOptions"') do (
    :: Desactivar NetBIOS
    reg add "%%a" /v "NetbiosOptions" /t REG_DWORD /d "2" /f >nul 2>&1
    
    :: Iteracion para aplicar ajustes avanzados a cada adaptador encontrado
    for /f %%i in ('reg query "%%a" /v "*MaxRssProcessors" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*MaxRssProcessors" /t REG_SZ /d "2" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*NumRssQueues" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*NumRssQueues" /t REG_SZ /d "2" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*ReceiveBuffers" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*ReceiveBuffers" /t REG_SZ /d "1024" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TransmitBuffers" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TransmitBuffers" /t REG_SZ /d "1024" /f >nul 2>&1
    )
    
    :: Desactivar ahorros de energia y control de flujo (FlowControl)
    for /f %%i in ('reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*FlowControl" /t REG_SZ /d "0" /f >nul 2>&1
        reg add "%%i" /v "*ModernStandbyWoLMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1
    )
    
    :: Desactivar EEE (Energy Efficient Ethernet) y Green Ethernet
    for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*EEE" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >nul 2>&1
    )
    
    :: Desactivar Offloading (LSO, Checksum) para reducir carga del NIC
    for /f %%i in ('reg query "%%a" /v "*LsoV2IPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*LsoV2IPv4" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TCPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*JumboPacket" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*JumboPacket" /t REG_SZ /d "1514" /f >nul 2>&1
    )
)

:: ----------------------------------------------------------------
:: 3. ALGORITMO DE NAGLE Y LATENCIA (Interfaces Activas)
:: ----------------------------------------------------------------
echo [*] Desactivando Algoritmo de Nagle (TcpAckFrequency/TCPNoDelay)...

:: Itera sobre los adaptadores activos usando WMIC para aplicar los cambios
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do (
    reg add "HKLM\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f >nul 2>&1
    reg add "HKLM\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\System\CurrentControlSet\services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1
)

:: ----------------------------------------------------------------
:: 4. PARAMETROS DE REGISTRO TCP/IP
:: ----------------------------------------------------------------
echo [*] Ajustando parametros de registro TCP/IP (HKLM)...

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f >nul 2>&1

:: Desactivar priorizacion de VLAN (Puede causar latencia si no se usa)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "*PriorityVLANTag" /t REG_SZ /d "0" /f >nul 2>&1

:: ----------------------------------------------------------------
:: 5. POWERSHELL - OPTIMIZACION AVANZADA
:: ----------------------------------------------------------------
echo [*] Ejecutando optimizaciones de PowerShell (NetAdapter)...

:: Desactivar gestion de energia en todos los adaptadores
powershell -Command "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}" >nul 2>&1

:: Desactivar LSO (Large Send Offload)
powershell -Command "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}" >nul 2>&1

:: Desactivar IPv6 en bindings (Opcional, pero presente en el script original)
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue" >nul 2>&1

:: ----------------------------------------------------------------
:: 6. SERVICIOS Y CACHE DNS
:: ----------------------------------------------------------------
echo [*] Configurando servicios de red y DNS...

:: Cache DNS optimizada para rendimiento
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "86400" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f >nul 2>&1

:: Servicios innecesarios para latencia baja
sc config "lmhosts" start= disabled >nul 2>&1
sc config "NetTcpPortSharing" start= disabled >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d "0" /f >nul 2>&1

:: QoS Packet Scheduler (Deslimitar ancho de banda)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >nul 2>&1

:: ----------------------------------------------------------------
:: 7. PRIORIZACION MULTIMEDIA Y JUEGOS (SystemProfile)
:: ----------------------------------------------------------------
echo [*] Configurando perfil de sistema multimedia...

:: Network Throttling Index (Desactivado = ffffffff)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f >nul 2>&1

:: Prioridad de Juegos
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul 2>&1

:: Separacion de Prioridades Win32 (Valor 38 Decimal = 26 Hex, prioriza foreground)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f >nul 2>&1

@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Optimizacion de Red (QoS y Gaming) - Extraccion 4.BAT
color 0C

echo [!] Iniciando optimizacion de red (Enfoque QoS y Prioridad de Juegos)...
echo [!] Extraccion tecnica de 4.BAT...

:: ----------------------------------------------------------------
:: 1. OPTIMIZACION DE INTERFACES ACTIVAS (Smart Loop)
:: ----------------------------------------------------------------
echo [*] Detectando interfaces activas y optimizando latencia...

:: Bucle que usa PowerShell para encontrar solo adaptadores con Status='Up'
:: Aplica AckFrequency y NoDelay para respuesta inmediata
for /f "tokens=*" %%i in ('powershell -command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty InterfaceGuid"') do (
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%%i}" /v TcpAckFrequency /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%%i}" /v TCPNoDelay /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%%i}" /v TcpDelAckTicks /t REG_DWORD /d 0 /f >nul 2>&1
    echo [OK] Optimizada interfaz: {%%i}
)

:: ----------------------------------------------------------------
:: 2. POLITICAS QoS (DSCP) PARA APLICACIONES ESPECIFICAS
:: ----------------------------------------------------------------
echo [*] Creando reglas de QoS (Prioridad de Trafico) para aplicaciones...

:: Definimos la funcion de creacion aqui para usarla en linea
goto :APPLY_QOS_RULES

:CREATE_QOS_POLICY
:: Parametros: %1 = NombrePolitica, %2 = Ruta Ejecutable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Version" /t REG_SZ /d "1.0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Application Name" /t REG_SZ /d %2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Protocol" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Local Port" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Local IP" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Remote Port" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Remote IP" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "DSCP Value" /t REG_SZ /d "46" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\%~1" /v "Throttle Rate" /t REG_SZ /d "-1" /f >nul 2>&1
goto :EOF

:APPLY_QOS_RULES
:: Servicios de Sistema
call :CREATE_QOS_POLICY "Svchost_QoS" "C:\Windows\System32\svchost.exe"
call :CREATE_QOS_POLICY "TrustedInstaller_QoS" "C:\Windows\servicing\TrustedInstaller.exe"
call :CREATE_QOS_POLICY "Explorer_QoS" "C:\Windows\explorer.exe"

:: Navegadores y Comunicacion
call :CREATE_QOS_POLICY "Chrome_QoS" "chrome.exe"
call :CREATE_QOS_POLICY "Edge_QoS" "msedge.exe"
call :CREATE_QOS_POLICY "Firefox_QoS" "firefox.exe"
call :CREATE_QOS_POLICY "Discord_QoS" "update.exe"
call :CREATE_QOS_POLICY "Teams_QoS" "Update.exe"

:: Plataformas de Juegos
call :CREATE_QOS_POLICY "Steam_QoS" "steam.exe"
call :CREATE_QOS_POLICY "EpicLauncher_QoS" "EpicGamesLauncher.exe"

:: ----------------------------------------------------------------
:: 3. PRIORIDAD DE PROCESOS DE JUEGO (CPU/RED)
:: ----------------------------------------------------------------
echo [*] Elevando prioridad de procesos de juegos competitivos...

:: Lista de juegos extraida del archivo 4.bat
set GAMES_LIST="EscapeFromTarkov.exe" "FortniteClient-Win64-Shipping.exe" "Valorant.exe" "cs2.exe" "RainbowSix.exe" "PUBG.exe" "ApexLegends.exe" "Overwatch.exe" "League of Legends.exe" "r5apex.exe"

for %%g in (%GAMES_LIST%) do (
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~g\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f >nul 2>&1
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~g\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >nul 2>&1
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%~g\PerfOptions" /v "PagePriority" /t REG_DWORD /d "1" /f >nul 2>&1
)

:: ----------------------------------------------------------------
:: 4. OPTIMIZACION AVANZADA TCP/IP (Buffers y Memoria)
:: ----------------------------------------------------------------
echo [*] Ajustando buffers de memoria TCP y descarga...

:: Optimizacion de buffers libres (Aumenta el rendimiento en conexiones rapidas)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxSendFree" /t REG_DWORD /d 10240 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxReceiveFree" /t REG_DWORD /d 10240 /f >nul 2>&1

:: Ajustes estandar de rendimiento
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d 65535 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d 65535 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d 65534 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d 30 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d 3 /f >nul 2>&1

:: Desactivar Task Offload (Manejo por CPU)
netsh int ipv4 set global taskoffload=disabled >nul 2>&1
netsh int ipv6 set global taskoffload=disabled >nul 2>&1

:: ----------------------------------------------------------------
:: 5. LANMAN Y ORDEN DE PROVEEDORES
:: ----------------------------------------------------------------
echo [*] Configurando LanmanWorkstation y Provider Order...

:: Priorizar RDPNP y Lanman para resolucion rapida
reg add "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder" /v "ProviderOrder" /t REG_SZ /d "RDPNP,LanmanWorkstation,webclient" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" /v "ProviderOrder" /t REG_SZ /d "RDPNP,LanmanWorkstation,webclient" /f >nul 2>&1

:: Aumentar creditos y desactivar limites estrictos en SMB
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "Smb2CreditsMin" /t REG_DWORD /d "512" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "Smb2CreditsMax" /t REG_DWORD /d "8192" /f >nul 2>&1

:: ----------------------------------------------------------------
:: 6. AJUSTES MULTIMEDIA Y SYSTEM PROFILE
:: ----------------------------------------------------------------
echo [*] Desactivando Network Throttling...

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f >nul 2>&1

:: ----------------------------------------------------------------
:: 7. OPTIMIZACION HARDWARE RED (PowerShell)
:: ----------------------------------------------------------------
echo [*] Desactivando ahorro de energia avanzado en adaptadores...

powershell -NoProfile -Command "Get-NetAdapter | Disable-NetAdapterPowerManagement -WakeOnMagicPacket:$false -WakeOnPattern:$false -DeviceSleepOnDisconnect:$false -SelectiveSuspend:$false -ArpOffload:$false -NSOffload:$false -D0PacketCoalescing:$false -RsnRekeyOffload:$false -NoRestart -ErrorAction SilentlyContinue" >nul 2>&1

echo.
echo [!] Optimizacion (Archivo 4) completada.
echo [!] Reinicia tu sistema para aplicar las politicas de QoS y prioridades.
pause