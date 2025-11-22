import sys
import time
import ctypes
import json
import os
import re
import subprocess
import threading
import gc
import weakref
import winreg
from ctypes import wintypes
from collections import defaultdict, deque
from typing import Optional, List, Dict, Set, Any
from pathlib import Path
from datetime import datetime

psutil = None
win32process = None
win32gui = None
win32con = None
win32api = None
win32job = None
win32file = None
Image = None
ImageDraw = None
ImageFont = None
pystray = None
clr = None
Computer = None
HardwareType = None
SensorType = None

try:
    import psutil
    import win32process
    import win32gui
    import win32con
    import win32api
    import win32job
    import win32file
    from PIL import Image, ImageDraw, ImageFont
    import pystray
except ImportError:
    pass

try:
    import clr
    clr.AddReference('LibreHardwareMonitorLib')
    from LibreHardwareMonitor.Hardware import Computer, HardwareType, SensorType
except:
    pass

try:
    from gem_gui import GemGUI as ProcessManagerGUI
    GUI_AVAILABLE = True
except ImportError:
    try:
        from gui_manager import ProcessManagerGUI
        GUI_AVAILABLE = True
    except ImportError:
        GUI_AVAILABLE = False
        ProcessManagerGUI = None

# Import WMI monitor for event-driven process monitoring
try:
    from wmi_monitor import create_process_monitor
    WMI_MONITOR_AVAILABLE = True
except ImportError:
    WMI_MONITOR_AVAILABLE = False

# --- POWER MANAGEMENT GUIDS (from backend.py) ---
SUB_PROCESSOR = "54533251-82be-4824-96c1-47b60b740d00"
PROCTHROTTLEMIN = "893dee8e-2bef-41e0-89c6-b55d0929964c"
PROCTHROTTLEMAX = "bc5038f7-23e0-4960-96da-33abaf5935ec"
SYSTEM_COOLING_POLICY = "94d3a615-a899-4ac5-ae2b-e4d8f634367f"
PERFBOOSTMODE = "be337238-0d82-4146-a960-4f3749d470c7"
IDLEDISABLE = "5d76a2ca-e8c0-402f-a133-2158492d58ad"
INCREASE_THRESHOLD = "06cadf0e-64ed-448a-8927-ce7bf90eb35d"
DECREASE_THRESHOLD = "12a0ab44-fe28-4fa9-b3bd-4b64f44960a6"
INCREASE_TIME = "984cf492-3bed-4488-a8f9-4286c97bf5aa"
DECREASE_TIME = "d8edeb9b-95cf-4f95-a73c-b061973693c8"
CORE_PARK_MIN = "0cc5b647-c1df-4637-891a-dec35c318583"
CORE_PARK_MAX = "ea062031-0e34-4ff1-9b6d-eb1059334028"
CORE_PARK_INCREASE = "2ddd5a84-5a71-437e-912a-db0b8c788732"
CORE_PARK_DECREASE = "71021b41-c749-4d21-be74-a00f335d582b"
CORE_PARK_OVERUTIL = "943c8cb6-6f93-4227-ad87-e9a3feec08d1"
CORE_PARK_DISTRIBUTION = "619b7505-003b-4e82-b7a6-4dd29c300971"
HETERO_POLICY = "7f2f5cfa-f10c-4823-b5e1-e93ae85f46b5"

SUB_PCIEXPRESS = "501a4d13-42af-4429-9fd1-a8218c268e20"
PCIE_ASPM = "ee12f906-d277-404b-b6da-e5fa1a576df5"

SUB_DISK = "0012ee47-9041-4b5d-9b77-535fba8b1442"
DISK_IDLE = "6738e2c4-e8a5-4a42-b16a-e040e769756e"
DISK_BURST = "80e3c60e-bb94-4ad8-bbe0-0d3195efc663"

SUB_VIDEO = "7516b95f-f776-4464-8c53-06167f40cc99"
VIDEO_IDLE = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"
VIDEO_QUALITY = "10778347-1370-4ee0-8bbd-33bdacaade49"

SUB_SLEEP = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
SLEEP_AFTER = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
HIBERNATE_AFTER = "9d7815a6-7ee4-497e-8888-515a05f02364"
ALLOW_WAKE_TIMERS = "bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d"

SUB_USB = "2a737441-1930-4402-8d77-b2bebba308a3"
USB_SELECTIVE = "48e6b7a6-50f5-4782-a5d4-53bb8f07e226"

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)
timeapi = ctypes.WinDLL('winmm.dll', use_last_error=True)

if ctypes.sizeof(ctypes.c_void_p) == 8:
    ULONG_PTR = ctypes.c_uint64
else:
    ULONG_PTR = ctypes.c_uint32

ULONGLONG = ctypes.c_ulonglong
MS_TO_100NS = 10000

PRIORITY_CLASSES = {
    'IDLE': win32process.IDLE_PRIORITY_CLASS if win32process else 0x00000040,
    'BELOW_NORMAL': win32process.BELOW_NORMAL_PRIORITY_CLASS if win32process else 0x00004000,
    'NORMAL': win32process.NORMAL_PRIORITY_CLASS if win32process else 0x00000020,
    'ABOVE_NORMAL': win32process.ABOVE_NORMAL_PRIORITY_CLASS if win32process else 0x00008000,
    'HIGH': win32process.HIGH_PRIORITY_CLASS if win32process else 0x00000080,
    'REALTIME': win32process.REALTIME_PRIORITY_CLASS if win32process else 0x00000100
}

PROCESS_TERMINATE = 1
PROCESS_SET_INFORMATION = 512
PROCESS_QUERY_INFORMATION = 1024
PROCESS_QUERY_LIMITED_INFORMATION = 4096
PROCESS_SET_QUOTA = 256
PROCESS_VM_READ = 16
PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 1
PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION = 4
ProcessPowerThrottling = 77
SE_DEBUG_NAME = 'SeDebugPrivilege'
SE_PRIVILEGE_ENABLED = 2
TOKEN_ADJUST_PRIVILEGES = 32
TOKEN_QUERY = 8
ProcessPagePriority = 39
PAGE_PRIORITY_NORMAL = 5
PAGE_PRIORITY_MEDIUM = 3
PAGE_PRIORITY_LOW = 1
EVENT_SYSTEM_FOREGROUND = 3
WINEVENT_OUTOFCONTEXT = 0
JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 1
JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED = 2
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 4
RelationProcessorCore = 0
RelationNumaNode = 1
RelationCache = 2
THREAD_SET_INFORMATION = 32
THREAD_QUERY_INFORMATION = 64

class PROCESS_POWER_THROTTLING_STATE(ctypes.Structure):
    _fields_ = [('Version', wintypes.ULONG),
                ('ControlMask', wintypes.ULONG),
                ('StateMask', wintypes.ULONG)]

class MEMORY_PRIORITY_INFORMATION(ctypes.Structure):
    _fields_ = [('MemoryPriority', wintypes.ULONG)]

class GROUP_AFFINITY(ctypes.Structure):
    _fields_ = [('Mask', ULONG_PTR),
                ('Group', wintypes.WORD),
                ('Reserved', wintypes.WORD * 3)]

class LUID(ctypes.Structure):
    _fields_ = [('LowPart', wintypes.DWORD),
                ('HighPart', wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Luid', LUID),
                ('Attributes', wintypes.DWORD)]

class CACHE_DESCRIPTOR(ctypes.Structure):
    _fields_ = [('Level', wintypes.BYTE),
                ('Associativity', wintypes.BYTE),
                ('LineSize', wintypes.WORD),
                ('Size', wintypes.DWORD),
                ('Type', wintypes.BYTE)]

class PROCESSOR_RELATIONSHIP(ctypes.Structure):
    _fields_ = [('Flags', wintypes.BYTE),
                ('EfficiencyClass', wintypes.BYTE),
                ('Reserved', wintypes.BYTE * 20),
                ('GroupCount', wintypes.WORD),
                ('GroupMask', GROUP_AFFINITY * 1)]

class SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_UNION(ctypes.Union):
    _fields_ = [('Processor', PROCESSOR_RELATIONSHIP)]

class SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX(ctypes.Structure):
    _fields_ = [('Relationship', wintypes.DWORD),
                ('Size', wintypes.DWORD),
                ('u', SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_UNION)]

class SYSTEM_LOGICAL_PROCESSOR_INFORMATION_UNION(ctypes.Union):
    _fields_ = [('ProcessorCore_Flags', wintypes.DWORD),
                ('NumaNode_NodeNumber', wintypes.DWORD),
                ('Cache', CACHE_DESCRIPTOR),
                ('Reserved', ULONGLONG * 2)]

class SYSTEM_LOGICAL_PROCESSOR_INFORMATION(ctypes.Structure):
    _fields_ = [('ProcessorMask', ctypes.c_ulong_ptr),
                ('Relationship', ctypes.c_int),
                ('u', SYSTEM_LOGICAL_PROCESSOR_INFORMATION_UNION)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [('PrivilegeCount', wintypes.DWORD),
                ('Privileges', LUID_AND_ATTRIBUTES * 1)]

class ServiceCategories:
    CRITICAL_SYSTEM = {
        "RpcSs", "DcomLaunch", "RpcEptMapper", "EventLog", "SamSs",
        "CryptSvc", "Dhcp", "Dnscache", "LanmanWorkstation", "LanmanServer",
        "PlugPlay", "Power", "ProfSvc", "Schedule", "SENS", "SystemEventsBroker",
        "UserManager", "WinDefend", "Winmgmt", "WlanSvc", "AudioSrv",
        "AudioEndpointBuilder", "BFE", "BITS", "BrokerInfrastructure",
        "CoreMessagingRegistrar", "DPS", "EventSystem", "FontCache",
        "LSM", "netprofm", "NlaSvc", "nsi", "TimeBrokerSvc", "VaultSvc"
    }
    TELEMETRY = {
        "DiagTrack", "dmwappushservice", "diagnosticshub.standardcollector.service",
        "WerSvc", "wercplsupport", "PcaSvc", "WdiServiceHost", "WdiSystemHost",
        "DPS", "TrkWks", "WpnService", "WpnUserService",
        "Microsoft Compatibility Appraiser", "ProgramDataUpdater"
    }
    UPDATE = {
        "wuauserv", "UsoSvc", "WaaSMedicSvc", "BITS", "DoSvc",
        "InstallService", "TrustedInstaller"
    }
    XBOX = {
        "XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc"
    }
    PRINTING = {
        "Spooler", "PrintNotify", "PrintWorkflowUserSvc"
    }
    SEARCH = {
        "WSearch", "wscsvc", "SearchIndexer"
    }
    BLOAT = {
        "TabletInputService", "RetailDemo", "Fax", "PhoneSvc",
        "MapsBroker", "lfsvc", "AJRouter", "AllJoynRouter",
        "MessagingService", "PimIndexMaintenanceSvc", "OneSyncSvc",
        "WalletService", "wisvc", "WpcMonSvc", "WpnUserService",
        "RemoteRegistry", "RemoteAccess", "shpamsvc", "tzautoupdate",
        "SysMain", "SgrmBroker", "SmsRouter", "SharedAccess"
    }
    PROCESS_CRITICAL = {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
        "taskmgr.exe", "taskhost.exe", "conhost.exe", "fontdrvhost.exe",
        "registry", "memcompression", "sihost.exe", "ctfmon.exe", "runtimebroker.exe"
    }

class StaticSystemTuner:
    def __init__(self):
        self.lock = threading.RLock()

    def _set_registry_value(self, root, key_path, value_name, value_type, value_data):
        try:
            with winreg.CreateKeyEx(root, key_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                winreg.SetValueEx(key, value_name, 0, value_type, value_data)
            return True
        except Exception:
            return False

    def run_full_static_optimization(self):
        self._apply_device_msi_mode()
        self._apply_advanced_network_optimizations()
        self._apply_graphics_priorities()
        self._apply_filesystem_tweaks()
        self._apply_kernel_memory_tweaks() 
        self._apply_bcd_kernel_tweaks()
        self._apply_power_plan_unparking()
        self._disable_deep_bloat()
        self._optimize_defender()
        self._apply_megatron_hpet()
        self._apply_input_latency_optimization()
        self._apply_dma_storage_optimization()
        self._apply_nvme_optimization()

    def _run_powershell(self, cmd):
        try:
            full_cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd]
            subprocess.run(full_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    def _apply_device_msi_mode(self):
        ps = """Get-PnpDevice -PresentOnly | Where-Object {$_.InstanceId -like 'PCI*'} | Select-Object InstanceId | ConvertTo-Json"""
        try:
            rc, out, _ = subprocess.run(["powershell", "-Command", ps], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            devs = json.loads(out) if out else []
            if not isinstance(devs, list): devs = [devs]
            for d in devs:
                dev_id = d.get("InstanceId","")
                if dev_id:
                    p1 = f"SYSTEM\\CurrentControlSet\\Enum\\{dev_id}\\Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties"
                    p2 = f"SYSTEM\\CurrentControlSet\\Enum\\{dev_id}\\Device Parameters\\Interrupt Management\\Affinity Policy"
                    self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, p1, "MSISupported", winreg.REG_DWORD, 1)
                    self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, p2, "DevicePolicy", winreg.REG_DWORD, 4)
        except Exception:
            pass

    def _optimize_defender(self):
        paths = ["C:\\Program Files (x86)\\Steam","C:\\Program Files\\Steam","C:\\Games","D:\\Games","C:\\Program Files\\Epic Games"]
        for p in paths:
            if os.path.exists(p):
                self._run_powershell(f"Add-MpPreference -ExclusionPath '{p}'")

    def _apply_advanced_network_optimizations(self):
        tcp_params = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, tcp_params, 'TcpAckFrequency', winreg.REG_DWORD, 1)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, tcp_params, 'TCPNoDelay', winreg.REG_DWORD, 1)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, tcp_params, 'TcpTimedWaitDelay', winreg.REG_DWORD, 30)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, tcp_params, 'MaxUserPort', winreg.REG_DWORD, 65534)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, tcp_params, 'TcpDelAckTicks', winreg.REG_DWORD, 0)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, tcp_params, 'EnableRSS', winreg.REG_DWORD, 1)
        
        afd_base = r"SYSTEM\CurrentControlSet\Services\AFD\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, afd_base, "DefaultReceiveWindow", winreg.REG_DWORD, 65535)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, afd_base, "DefaultSendWindow", winreg.REG_DWORD, 65535)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, afd_base, "FastSendDatagramThreshold", winreg.REG_DWORD, 1500)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, afd_base, "FastCopyReceiveThreshold", winreg.REG_DWORD, 1500)

        nic_props = [
            "Flow Control", "Energy Efficient Ethernet", "Green Ethernet",
            "Power Saving Mode", "Interrupt Moderation", "Interrupt Moderation Rate",
            "Jumbo Packet", "Large Send Offload v2 (IPv4)", "Large Send Offload v2 (IPv6)"
        ]
        
        for prop in nic_props:
            cmd = f'Get-NetAdapter -Physical | Get-NetAdapterAdvancedProperty -DisplayName "{prop}" -ErrorAction SilentlyContinue | Set-NetAdapterAdvancedProperty -DisplayValue "Disabled" -NoRestart -ErrorAction SilentlyContinue'
            self._run_powershell(cmd)

        self._run_powershell('Get-NetAdapter -Physical | Set-NetAdapterAdvancedProperty -DisplayName "Receive Buffers" -DisplayValue "2048" -NoRestart -ErrorAction SilentlyContinue')
        self._run_powershell('Get-NetAdapter -Physical | Set-NetAdapterAdvancedProperty -DisplayName "Transmit Buffers" -DisplayValue "2048" -NoRestart -ErrorAction SilentlyContinue')

        cmds = [
            ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
            ["netsh", "int", "tcp", "set", "global", "rss=enabled"],
            ["netsh", "int", "tcp", "set", "global", "ecncapability=disabled"],
            ["netsh", "int", "tcp", "set", "global", "timestamps=disabled"],
            ["netsh", "int", "tcp", "set", "global", "initialrto=2000"],
            ["netsh", "int", "tcp", "set", "global", "nonsackrttresiliency=disabled"],
            ["netsh", "winsock", "set", "autotuning", "on"],
            ["netsh", "int", "ipv4", "set", "dynamicport", "tcp", "start=1024", "num=64511"],
        ]
        for cmd in cmds:
            try: subprocess.run(cmd, creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception: pass

    def _apply_graphics_priorities(self):
        try:
            gpu_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, gpu_path, 'GPU Priority', winreg.REG_DWORD, 8)
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, gpu_path, 'Priority', winreg.REG_DWORD, 6)
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, gpu_path, 'Scheduling Category', winreg.REG_SZ, 'High')
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, gpu_path, 'SFIO Priority', winreg.REG_SZ, 'High')
            sys_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, sys_path, 'SystemResponsiveness', winreg.REG_DWORD, 0)
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, sys_path, 'NetworkThrottlingIndex', winreg.REG_DWORD, 0xFFFFFFFF)
        except Exception: pass

    def _apply_filesystem_tweaks(self):
        fs_base = r"SYSTEM\CurrentControlSet\Control\FileSystem"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, fs_base, "NtfsDisableLastAccessUpdate", winreg.REG_DWORD, 1)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, fs_base, "NtfsDisable8dot3NameCreation", winreg.REG_DWORD, 1)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, fs_base, "NtfsMftZoneReservation", winreg.REG_DWORD, 2)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, fs_base, "ContigFileAllocSize", winreg.REG_DWORD, 64)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, fs_base, "NtfsMemoryUsage", winreg.REG_DWORD, 2)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, fs_base, "NtfsEncryptPagingFile", winreg.REG_DWORD, 0)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, fs_base, "NtfsDisableEncryption", winreg.REG_DWORD, 1)
        
        commands = [
            ["fsutil", "behavior", "set", "disablelastaccess", "1"],
            ["fsutil", "behavior", "set", "disable8dot3", "1"],
            ["fsutil", "behavior", "set", "memoryusage", "2"],
            ["fsutil", "behavior", "set", "disabledeletenotify", "0"],
            ["fsutil", "behavior", "set", "encryptpagingfile", "0"]
        ]
        for cmd in commands:
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception: pass

    def _apply_kernel_memory_tweaks(self):
        try:
            mem_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, mem_path, 'DisablePagingExecutive', winreg.REG_DWORD, 1)
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, mem_path, 'LargeSystemCache', winreg.REG_DWORD, 0)
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, mem_path, "SecondLevelDataCache", winreg.REG_DWORD, 512)
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, mem_path, "DisableCompression", winreg.REG_DWORD, 1)
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, mem_path, "LargePageMinimum", winreg.REG_DWORD, 0xFFFFFFFF)
            
            prio_path = r"SYSTEM\CurrentControlSet\Control\PriorityControl"
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, prio_path, "Win32PrioritySeparation", winreg.REG_DWORD, 0x26)
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, prio_path, "IRQ8Priority", winreg.REG_DWORD, 1)
        except Exception: pass

    def _apply_bcd_kernel_tweaks(self):
        bcd_cmds = [
            ["bcdedit", "/set", "useplatformclock", "Yes"],
            ["bcdedit", "/set", "useplatformtick", "Yes"],
            ["bcdedit", "/set", "disabledynamictick", "Yes"],
            ["bcdedit", "/set", "bootmenupolicy", "Standard"],
            ["bcdedit", "/set", "nx", "OptIn"]
        ]
        for cmd in bcd_cmds:
            try: subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception: pass
        
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled", winreg.REG_DWORD, 3)

    def _apply_megatron_hpet(self):
        try:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                winreg.SetValueEx(k, "DisableTimerQuery", 0, winreg.REG_DWORD, 1)
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Wdf01000", 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                winreg.SetValueEx(k, "UseHighResolutionTimer", 0, winreg.REG_DWORD, 0)
            subprocess.run('bcdedit /deletevalue useplatformclock', shell=True, creationflags=0x08000000)
            subprocess.run('bcdedit /set useplatformtick yes', shell=True, creationflags=0x08000000)
            subprocess.run('bcdedit /set disabledynamictick yes', shell=True, creationflags=0x08000000)
            subprocess.run('bcdedit /set tscsyncpolicy Enhanced', shell=True, creationflags=0x08000000)
        except Exception: pass

    def _apply_power_plan_unparking(self):
        subprocess.run(["powercfg", "-duplicatescheme", "e9a42b02-d5df-448d-aa00-03f14749eb61"], creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["powercfg", "-setactive", "e9a42b02-d5df-448d-aa00-03f14749eb61"], creationflags=subprocess.CREATE_NO_WINDOW)
        
        adv_power = [
            ("SUB_PROCESSOR", "PROCTHROTTLEMIN", "100"),
            ("SUB_PROCESSOR", "PROCTHROTTLEMAX", "100"),
            ("SUB_PROCESSOR", "CPMINCORES", "100"),
            ("SUB_PROCESSOR", "CPMAXCORES", "100"),
            ("SUB_PCIEXPRESS", "ASPM", "0"),
            ("SUB_DISK", "DISKIDLE", "0"),
            ("2a737441-1930-4402-8d77-b2bebba308a3", "48e6b7a6-50f5-4782-a5d4-53bb8f07e226", "0")
        ]
        for s, k, v in adv_power:
            subprocess.run(["powercfg", "/setacvalueindex", "SCHEME_CURRENT", s, k, v], creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["powercfg", "/setdcvalueindex", "SCHEME_CURRENT", s, k, v], creationflags=subprocess.CREATE_NO_WINDOW)
        
        subprocess.run(["powercfg", "/setactive", "SCHEME_CURRENT"], creationflags=subprocess.CREATE_NO_WINDOW)

    def _disable_deep_bloat(self):
        try:
            dvr_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
            self._set_registry_value(winreg.HKEY_CURRENT_USER, dvr_path, 'AppCaptureEnabled', winreg.REG_DWORD, 0)
            
            dc_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, dc_path, "AllowTelemetry", winreg.REG_DWORD, 0)

            telemetry_tasks = [
                r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
                r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            ]
            for t in telemetry_tasks:
                subprocess.run(["schtasks", "/Change", "/TN", t, "/Disable"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception: pass

    def _apply_input_latency_optimization(self):
        mouse_base = r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, mouse_base, "MouseDataQueueSize", winreg.REG_DWORD, 20)

        kbd_base = r"SYSTEM\CurrentControlSet\Services\kbdclass\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, kbd_base, "KeyboardDataQueueSize", winreg.REG_DWORD, 20)

        usb_base = r"SYSTEM\CurrentControlSet\Services\usbport\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, usb_base, "DisableSelectiveSuspend", winreg.REG_DWORD, 1)

        ehci = r"SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, ehci, "ThreadPriority", winreg.REG_DWORD, 31)

        usb3 = r"SYSTEM\CurrentControlSet\Services\USB\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, usb3, "DisableSelectiveSuspend", winreg.REG_DWORD, 1)

        hid = r"SYSTEM\CurrentControlSet\Services\HidUsb\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, hid, "IdleTimeout", winreg.REG_DWORD, 0)

        mouse_user = r"Control Panel\Mouse"
        self._set_registry_value(winreg.HKEY_CURRENT_USER, mouse_user, "MouseSpeed", winreg.REG_SZ, "0")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, mouse_user, "MouseThreshold1", winreg.REG_SZ, "0")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, mouse_user, "MouseThreshold2", winreg.REG_SZ, "0")

        pointer = r"Control Panel\Mouse"
        self._set_registry_value(winreg.HKEY_CURRENT_USER, pointer, "SmoothMouseXCurve", winreg.REG_BINARY, bytes([0] * 40))
        self._set_registry_value(winreg.HKEY_CURRENT_USER, pointer, "SmoothMouseYCurve", winreg.REG_BINARY, bytes([0] * 40))

        kbd_resp = r"Control Panel\Keyboard"
        self._set_registry_value(winreg.HKEY_CURRENT_USER, kbd_resp, "KeyboardDelay", winreg.REG_SZ, "0")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, kbd_resp, "KeyboardSpeed", winreg.REG_SZ, "31")

        dwm = r"SOFTWARE\Microsoft\Windows\DWM"
        self._set_registry_value(winreg.HKEY_CURRENT_USER, dwm, "UseDpiScaling", winreg.REG_DWORD, 0)

        input_exp = r"SOFTWARE\Microsoft\Input\Settings"
        self._set_registry_value(winreg.HKEY_CURRENT_USER, input_exp, "EnableHwKbd", winreg.REG_DWORD, 0)

    def _apply_dma_storage_optimization(self):
        dma = r"SYSTEM\CurrentControlSet\Services\dmio\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, dma, "DmaAlignment", winreg.REG_DWORD, 1)

        ahci = r"SYSTEM\CurrentControlSet\Services\storahci\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, ahci, "EnableDMA", winreg.REG_DWORD, 1)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, ahci, "EnableLPM", winreg.REG_DWORD, 0)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, ahci, "EnableHIPM", winreg.REG_DWORD, 0)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, ahci, "EnableDIPM", winreg.REG_DWORD, 0)

        pci = r"SYSTEM\CurrentControlSet\Services\pci\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, pci, "DmaRemappingCompatible", winreg.REG_DWORD, 0)

        storage = r"SYSTEM\CurrentControlSet\Control\StorPort"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, storage, "DmaAlignment", winreg.REG_DWORD, 1)

        ide = r"SYSTEM\CurrentControlSet\Services\atapi\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, ide, "EnableBigLba", winreg.REG_DWORD, 1)

        iommu = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, iommu, "Enabled", winreg.REG_DWORD, 0)

    def _apply_nvme_optimization(self):
        nvme = r"SYSTEM\CurrentControlSet\Services\stornvme\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, nvme, "EnableHMB", winreg.REG_DWORD, 1)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, nvme, "EnableWakeOnCompletion", winreg.REG_DWORD, 1)

        nvme_device = r"SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, nvme_device, "IoQueueDepth", winreg.REG_DWORD, 256)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, nvme_device, "NumberOfIoQueues", winreg.REG_DWORD, 16)

        storport = r"SYSTEM\CurrentControlSet\Services\StorPort\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, storport, "BusyRetryCount", winreg.REG_DWORD, 100)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, storport, "BusyPauseTime", winreg.REG_DWORD, 25)
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, storport, "MaximumUCXAddress", winreg.REG_DWORD, 0xFFFFFFFF)

        disk = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, disk, "IdlePowerMode", winreg.REG_DWORD, 0)

        pcie = r"SYSTEM\CurrentControlSet\Services\pcw\Parameters"
        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, pcie, "Start", winreg.REG_DWORD, 4)

        ps_cmd = """Get-PnpDevice -Class DiskDrive | Where-Object {$_.FriendlyName -like '*NVMe*' -or $_.FriendlyName -like '*SSD*'} | Select-Object -ExpandProperty InstanceId | ConvertTo-Json"""
        try:
            result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if result.stdout:
                devices = json.loads(result.stdout)
                if not isinstance(devices, list): devices = [devices]
                for device_id in devices:
                    if device_id:
                        msi_path = f"SYSTEM\\CurrentControlSet\\Enum\\{device_id}\\Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties"
                        self._set_registry_value(winreg.HKEY_LOCAL_MACHINE, msi_path, "MSISupported", winreg.REG_DWORD, 1)
        except Exception: pass

# --- POWER MANAGEMENT SYSTEM (from backend.py) ---

def is_windows():
    return os.name == "nt"

def run_powercfg_cmd(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW, check=False)

def get_active_scheme_guid():
    r = run_powercfg_cmd(["powercfg", "/getactivescheme"])
    if not r or r.returncode != 0:
        return None
    text = (r.stdout or b"").decode(errors="ignore")
    m = re.search(r"([0-9a-fA-F-]{36})", text)
    return m.group(1) if m else None

def set_ac(scheme, subgroup, setting, value):
    run_powercfg_cmd(["powercfg", "-setacvalueindex", scheme, subgroup, setting, str(value)])

def set_dc(scheme, subgroup, setting, value):
    run_powercfg_cmd(["powercfg", "-setdcvalueindex", scheme, subgroup, setting, str(value)])

def reapply_scheme(scheme):
    run_powercfg_cmd(["powercfg", "/setactive", scheme])

def has_battery():
    try:
        b = psutil.sensors_battery()
        return b is not None
    except:
        return False

def query_setting_value(scheme, subgroup, setting, ac=True):
    try:
        mode = "ACVALUEINDEX" if ac else "DCVALUEINDEX"
        r = run_powercfg_cmd(["powercfg", "/q", scheme, subgroup, setting])
        if not r or r.returncode != 0:
            return None
        text = (r.stdout or b"").decode("utf-8", errors="ignore")
        pattern = rf"Current {mode}:\s*(0x[0-9a-fA-F]+)"
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return int(m.group(1), 16)
        return None
    except:
        return None

def backup_current_power_settings():
    """Guarda la configuración actual antes de aplicar cambios drásticos"""
    if not is_windows(): return False
    
    BASE_DIR = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    BACKUP_PATH = os.path.join(BASE_DIR, "energia_backup.json")
    
    if os.path.exists(BACKUP_PATH):
        return True

    scheme = get_active_scheme_guid()
    if not scheme: return False
    
    backup = {
        "timestamp": datetime.now().isoformat(),
        "scheme_guid": scheme,
        "processor": {
            "ac": {
                "min": query_setting_value(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, True),
                "max": query_setting_value(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, True),
                "boost": query_setting_value(scheme, SUB_PROCESSOR, PERFBOOSTMODE, True),
                "park_min": query_setting_value(scheme, SUB_PROCESSOR, CORE_PARK_MIN, True),
                "park_max": query_setting_value(scheme, SUB_PROCESSOR, CORE_PARK_MAX, True),
            },
            "dc": {
                "min": query_setting_value(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, False),
                "max": query_setting_value(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, False),
                "boost": query_setting_value(scheme, SUB_PROCESSOR, PERFBOOSTMODE, False),
            }
        },
        "pcie": {
            "ac": {"aspm": query_setting_value(scheme, SUB_PCIEXPRESS, PCIE_ASPM, True)},
        }
    }
    
    try:
        with open(BACKUP_PATH, "w", encoding="utf-8") as f:
            json.dump(backup, f, indent=2)
    except:
        pass
    return True

def restore_from_backup():
    """Restaura valores críticos desde el backup"""
    BASE_DIR = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    BACKUP_PATH = os.path.join(BASE_DIR, "energia_backup.json")
    
    if not os.path.exists(BACKUP_PATH):
        return False, "No hay backup"
    
    try:
        with open(BACKUP_PATH, "r", encoding="utf-8") as f:
            backup = json.load(f)
        
        scheme = get_active_scheme_guid()
        if not scheme: return False, "Error esquema"
        
        proc_ac = backup.get("processor", {}).get("ac", {})
        if proc_ac.get("min") is not None: set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, proc_ac["min"])
        if proc_ac.get("max") is not None: set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, proc_ac["max"])
        if proc_ac.get("boost") is not None: set_ac(scheme, SUB_PROCESSOR, PERFBOOSTMODE, proc_ac["boost"])
        if proc_ac.get("park_min") is not None: set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MIN, proc_ac["park_min"])
        
        pcie_val = backup.get("pcie", {}).get("ac", {}).get("aspm")
        if pcie_val is not None: set_ac(scheme, SUB_PCIEXPRESS, PCIE_ASPM, pcie_val)
        
        if is_user_admin():
            import winreg
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")
            winreg.SetValueEx(key, "NetworkThrottlingIndex", 0, winreg.REG_DWORD, 10)
            winreg.SetValueEx(key, "SystemResponsiveness", 0, winreg.REG_DWORD, 20)
            winreg.CloseKey(key)
            
        reapply_scheme(scheme)
        os.remove(BACKUP_PATH)
        return True, "Restaurado"
    except Exception as e:
        return False, str(e)

def apply_mode_ahorro():
    if not is_windows(): return False
    scheme = get_active_scheme_guid()
    if not scheme: return False
    
    backup_current_power_settings()
    
    laptop = has_battery()
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 5)
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 80 if laptop else 100)
    set_ac(scheme, SUB_PROCESSOR, SYSTEM_COOLING_POLICY, 1)
    set_ac(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 1)
    set_ac(scheme, SUB_PROCESSOR, IDLEDISABLE, 0)
    
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MIN, 50)
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MAX, 100)
    
    set_dc(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 5)
    set_dc(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 30)
    set_dc(scheme, SUB_PROCESSOR, SYSTEM_COOLING_POLICY, 0)
    set_dc(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 0)
    
    reapply_scheme(scheme)
    return True

def apply_mode_baja_latencia():
    if not is_windows(): return False
    scheme = get_active_scheme_guid()
    if not scheme: return False
    
    backup_current_power_settings()
    
    laptop = has_battery()
    
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 5)
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 100)
    set_ac(scheme, SUB_PROCESSOR, SYSTEM_COOLING_POLICY, 1)
    set_ac(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 1)
    set_ac(scheme, SUB_PROCESSOR, IDLEDISABLE, 0)
    
    set_ac(scheme, SUB_PROCESSOR, INCREASE_THRESHOLD, 20)
    set_ac(scheme, SUB_PROCESSOR, DECREASE_THRESHOLD, 10)
    set_ac(scheme, SUB_PROCESSOR, INCREASE_TIME, 1)
    set_ac(scheme, SUB_PROCESSOR, DECREASE_TIME, 3)
    
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MIN, 10)
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MAX, 100)
    
    set_dc(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 5)
    set_dc(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 90 if laptop else 100)
    set_dc(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 0)
    
    set_ac(scheme, SUB_PCIEXPRESS, PCIE_ASPM, 0)
    set_dc(scheme, SUB_PCIEXPRESS, PCIE_ASPM, 1 if laptop else 0)
    set_ac(scheme, SUB_DISK, DISK_IDLE, 0)
    
    reapply_scheme(scheme)
    
    if is_user_admin():
        try:
            import winreg
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")
            winreg.SetValueEx(key, "NetworkThrottlingIndex", 0, winreg.REG_DWORD, 10) 
            winreg.SetValueEx(key, "SystemResponsiveness", 0, winreg.REG_DWORD, 10)
            winreg.CloseKey(key)
        except:
            pass
            
    return True

def apply_mode_extremo():
    if not is_windows(): return False
    scheme = get_active_scheme_guid()
    if not scheme: return False
    
    backup_current_power_settings()
    
    laptop = has_battery()
    
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 100)
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 100)
    set_ac(scheme, SUB_PROCESSOR, SYSTEM_COOLING_POLICY, 1)
    set_ac(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 2)
    set_ac(scheme, SUB_PROCESSOR, IDLEDISABLE, 1)
    
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MIN, 100)
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MAX, 100)
    
    reapply_scheme(scheme)
    
    if is_user_admin():
        try:
            import winreg
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")
            winreg.SetValueEx(key, "NetworkThrottlingIndex", 0, winreg.REG_DWORD, 0xffffffff)
            winreg.SetValueEx(key, "SystemResponsiveness", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            
            tasks_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games")
            winreg.SetValueEx(tasks_key, "GPU Priority", 0, winreg.REG_DWORD, 8)
            winreg.SetValueEx(tasks_key, "Priority", 0, winreg.REG_DWORD, 6)
            winreg.CloseKey(tasks_key)
        except:
            pass
            
    return True

def apply_power_mode(mode_name):
    if mode_name == "ahorro": return apply_mode_ahorro()
    if mode_name == "baja_latencia": return apply_mode_baja_latencia()
    if mode_name == "extremo": return apply_mode_extremo()
    return False

class TemperatureMonitor:
    def __init__(self):
        if Computer is None:
            self.available = False
            return
        self.available = True
        self.computer = Computer()
        self.computer.IsCpuEnabled = True
        try:
            self.computer.Open()
        except:
            self.available = False
        self.current_temp = 0.0
        self.running = False
        self.show_in_tray = False
        self.icon = None
        self.lock = threading.Lock()
        
    def get_cpu_temperature(self):
        if not self.available:
            return 0.0
        try:
            for hardware in self.computer.Hardware:
                hardware.Update()
                if hardware.HardwareType == HardwareType.Cpu:
                    for sensor in hardware.Sensors:
                        if sensor.SensorType == SensorType.Temperature:
                            if sensor.Value and sensor.Value > 0:
                                if "Package" in sensor.Name or "CPU Package" in sensor.Name:
                                    return float(sensor.Value)
                    for sensor in hardware.Sensors:
                        if sensor.SensorType == SensorType.Temperature:
                            if sensor.Value and sensor.Value > 0:
                                return float(sensor.Value)
        except:
            pass
        return 0.0
    
    def create_temp_icon(self, temp):
        if Image is None:
            return None
        img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        color = (255, 255, 255, 255)
        if temp > 60: color = (255, 165, 0, 255)
        if temp > 80: color = (255, 0, 0, 255)
        
        temp_text = str(int(temp))
        font = None
        for font_name in ['arialbd.ttf', 'Arial Bold.ttf', 'calibrib.ttf', 'arial.ttf']:
            try:
                font = ImageFont.truetype(font_name, 40)
                break
            except:
                continue
        if not font:
            font = ImageFont.load_default()
            
        bbox = draw.textbbox((0, 0), temp_text, font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        draw.text(((64 - w) // 2, (64 - h) // 2), temp_text, fill=color, font=font)
        return img
    
    def start_monitoring(self):
        if not self.available:
            return
        self.running = True
        while self.running:
            self.current_temp = self.get_cpu_temperature()
            with self.lock:
                if self.show_in_tray and pystray:
                    img = self.create_temp_icon(self.current_temp)
                    if img:
                        if self.icon is None:
                            self.icon = pystray.Icon("Temp", img, "Temperatura", menu=None)
                            threading.Thread(target=self.icon.run, daemon=True).start()
                        else:
                            self.icon.icon = img
                else:
                    if self.icon:
                        self.icon.stop()
                        self.icon = None
            time.sleep(2)

    def set_visibility(self, visible):
        with self.lock:
            self.show_in_tray = visible
            if not visible and self.icon:
                self.icon.stop()
                self.icon = None

    def stop(self):
        self.running = False
        self.set_visibility(False)
        if self.available:
            try:
                self.computer.Close()
            except:
                pass

class BackupManager:
    def __init__(self, backup_dir: str):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.current_backup = self.backup_dir / "current_session"
        self.current_backup.mkdir(exist_ok=True)
        self.restore_point_created = False
        
    def create_system_restore_point(self):
        if self.restore_point_created:
            return
        try:
            cmd = "powershell -Command \"Checkpoint-Computer -Description 'OptimusPrime_Auto' -RestorePointType 'Modify_Settings'\""
            subprocess.run(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            self.restore_point_created = True
        except Exception:
            pass

    def backup_service_config(self, service_name: str):
        try:
            cmd = f'sc qc "{service_name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode == 0:
                backup_file = self.current_backup / f"service_{service_name}.txt"
                backup_file.write_text(result.stdout)
        except Exception:
            pass
    
    def restore_services(self):
        try:
            for backup_file in self.current_backup.glob("service_*.txt"):
                content = backup_file.read_text()
                service_name = backup_file.stem.replace("service_", "")
                start_type = "demand"
                if "START_TYPE" in content:
                    if "AUTO_START" in content: start_type = "auto"
                    elif "DISABLED" in content: start_type = "disabled"
                subprocess.run(f'sc config "{service_name}" start= {start_type}', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if start_type != "disabled":
                    subprocess.run(f'sc start "{service_name}"', shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

class WindowsOptimizer:
    def __init__(self, backup_manager: BackupManager):
        self.backup_manager = backup_manager
        self.optimized_services = set()

    def optimize_service_group(self, group_names: Set[str], action: str = "disable"):
        for svc in group_names:
            if svc not in self.optimized_services:
                self.backup_manager.backup_service_config(svc)
                self.optimized_services.add(svc)
                try:
                    subprocess.run(f'sc stop "{svc}"', shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    if action == "disable":
                        subprocess.run(f'sc config "{svc}" start= disabled', shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                except Exception:
                    pass

    def restore_all(self):
        self.backup_manager.restore_services()
        self.optimized_services.clear()

class AdvancedMemoryPagePriorityManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.process_working_sets = defaultdict(lambda: {
            'history': deque(maxlen=10),
            'current_ws': 0,
            'peak_ws': 0,
            'min_ws': float('inf'),
            'last_update': 0
        })
        self.last_analysis_time = {}

    def analyze_working_set(self, pid):
        with self.lock:
            try:
                proc = psutil.Process(pid)
                mem_info = proc.memory_info()
                working_set_mb = mem_info.wset / (1024 * 1024)
                ws_data = self.process_working_sets[pid]
                ws_data['history'].append(working_set_mb)
                ws_data['current_ws'] = working_set_mb
                ws_data['peak_ws'] = max(ws_data['peak_ws'], working_set_mb)
                ws_data['min_ws'] = min(ws_data['min_ws'], working_set_mb)
                ws_data['last_update'] = time.time()
                return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False

    def optimize_page_priority(self, pid, is_foreground=False):
        with self.lock:
            current_time = time.time()
            if current_time - self.last_analysis_time.get(pid, 0) < 5:
                return False
            self.last_analysis_time[pid] = current_time
            
            if is_foreground:
                page_priority = PAGE_PRIORITY_NORMAL
            elif pid in self.process_working_sets:
                ws_data = self.process_working_sets[pid]
                history = list(ws_data['history'])
                if len(history) > 2:
                    trend = history[-1] - history[0]
                    if trend > 0:
                        page_priority = PAGE_PRIORITY_MEDIUM
                    else:
                        page_priority = PAGE_PRIORITY_LOW
                else:
                    page_priority = PAGE_PRIORITY_MEDIUM
            else:
                page_priority = PAGE_PRIORITY_LOW
            
            try:
                handle = win32api.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
                if handle:
                    try:
                        page_priority_info = MEMORY_PRIORITY_INFORMATION()
                        page_priority_info.MemoryPriority = page_priority
                        ntdll.NtSetInformationProcess(int(handle), ProcessPagePriority, ctypes.byref(page_priority_info), ctypes.sizeof(page_priority_info))
                        return True
                    finally:
                        win32api.CloseHandle(handle)
            except Exception:
                pass
        return False

class AdaptiveTimerResolutionManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.current_resolution_ms = 15.6
        self.active_high_res_processes = set()

    def adjust_timer_resolution(self, target_ms=None):
        with self.lock:
            if target_ms is None:
                if self.active_high_res_processes:
                    target_ms = 0.5
                else:
                    target_ms = 15.6
            
            if target_ms == self.current_resolution_ms:
                return False
            
            try:
                resolution_100ns = int(target_ms * MS_TO_100NS)
                current_res = ctypes.c_ulong()
                ntdll.NtSetTimerResolution(resolution_100ns, True, ctypes.byref(current_res))
                self.current_resolution_ms = target_ms
                return True
            except Exception:
                pass
            return False

class AutomaticProfileManager:
    """
    Gestor de perfiles automáticos basado en el proceso activo.
    
    Detecta automáticamente si el sistema debe estar en modo Gaming o Productivity
    basándose en los procesos en ejecución y ajusta las optimizaciones en consecuencia.
    
    Attributes:
        current_profile: Perfil activo actualmente ('Gaming' o 'Productivity')
        external_games: Set de nombres de procesos de juegos
        profiles: Configuración de cada perfil
    """
    def __init__(self, external_games=None):
        self.lock = threading.RLock()
        self.current_profile = 'Productivity'
        self.external_games = external_games or set()
        self.profiles = {
            'Gaming': {'cpu_priority': 'HIGH', 'memory_priority': 'NORMAL', 'io_priority': 2, 'disable_background': True}, 
            'Productivity': {'cpu_priority': 'ABOVE_NORMAL', 'memory_priority': 'NORMAL', 'io_priority': 2, 'disable_background': False}
        }

    def detect_profile(self, process_name: str) -> str:
        """
        Detecta el perfil apropiado basándose en el nombre del proceso.
        
        Args:
            process_name: Nombre del proceso a evaluar
        
        Returns:
            str: 'Gaming' o 'Productivity'
        """
        with self.lock:
            process_lower = process_name.lower()
            if process_lower in self.external_games:
                if self.current_profile != 'Gaming':
                    self.current_profile = 'Gaming'
                return 'Gaming'
            
            if self.current_profile != 'Productivity':
                self.current_profile = 'Productivity'
            return 'Productivity'

    def get_profile_settings(self, profile_name=None):
        with self.lock:
            return self.profiles.get(profile_name, self.profiles[self.current_profile])

class CPUPinningEngine:
    """
    Motor de asignación inteligente de CPU cores a procesos.
    
    Gestiona la asignación de cores específicos a procesos basándose en el tipo
    de workload y la topología del sistema (NUMA, cache, P-cores vs E-cores).
    
    Attributes:
        cpu_count: Número total de CPUs lógicas
        numa_topology: Información de topología NUMA del sistema
    """
    def __init__(self, cpu_count, numa_topology=None):
        self.cpu_count = cpu_count
        self.numa_topology = numa_topology or {}
        self.lock = threading.RLock()

    def apply_intelligent_pinning(self, pid, available_cores, workload_type='general'):
        with self.lock:
            if not available_cores:
                return False
            try:
                proc = psutil.Process(pid)
                proc.cpu_affinity(available_cores)
                return True
            except Exception:
                return False

class DPCLatencyController:
    def __init__(self):
        self.lock = threading.RLock()

    def optimize_dpc_latency(self):
        with self.lock:
            key_path = r'SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, 'DpcWatchdogProfileOffset', 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(key, 'DpcTimeout', 0, winreg.REG_DWORD, 0)
                return True
            except Exception:
                return False

class EnhancedSMTOptimizer:
    def __init__(self, topology, cpu_count):
        self.lock = threading.RLock()
        self.topology = topology
        self.cpu_count = cpu_count
        self.physical_cores = self._detect_physical_cores()

    def _detect_physical_cores(self):
        return list(range(psutil.cpu_count(logical=False)))

    def optimize_for_latency(self, pid):
        with self.lock:
            try:
                proc = psutil.Process(pid)
                proc.cpu_affinity(self.physical_cores)
                return True
            except Exception:
                return False

class ForegroundDebouncer:
    def __init__(self, debounce_time_ms=300, hysteresis_time_ms=150, whitelist_debounce_ms=150):
        self.debounce_time = debounce_time_ms / 1000.0
        self.hysteresis_time = hysteresis_time_ms / 1000.0
        self.whitelist_debounce = whitelist_debounce_ms / 1000.0
        self.pending_change = None
        self.pending_timer = None
        self.last_applied_pid = None
        self.last_change_time = 0
        self.change_history = deque(maxlen=20)
        self.known_pids = set()
        self.lock = threading.RLock()

    def request_foreground_change(self, new_pid, callback, is_known=False, *args, **kwargs):
        with self.lock:
            current_time = time.time()
            if self.pending_timer:
                self.pending_timer.cancel()
            
            time_since_last = current_time - self.last_change_time
            is_rapid_change = time_since_last < self.hysteresis_time
            self.change_history.append({'timestamp': current_time, 'pid': new_pid, 'rapid': is_rapid_change})
            
            if is_known:
                self.known_pids.add(new_pid)
                
            debounce_delay = self._calculate_dynamic_debounce(new_pid, is_known)
            self.pending_change = {'pid': new_pid, 'callback': callback, 'args': args, 'kwargs': kwargs, 'request_time': current_time}
            self.pending_timer = threading.Timer(debounce_delay, self._apply_pending_change)
            self.pending_timer.daemon = True
            self.pending_timer.start()
            self.last_change_time = current_time

    def _calculate_dynamic_debounce(self, pid=None, is_known=False):
        recent_history = list(self.change_history)[-5:]
        rapid_changes = sum((1 for event in recent_history if event['rapid']))
        if is_known:
            return self.whitelist_debounce
        if rapid_changes > 2:
            return self.debounce_time * 1.5
        return self.debounce_time

    def _apply_pending_change(self):
        with self.lock:
            change = self.pending_change
            if not change:
                return
            change['callback'](*change['args'], **change['kwargs'])
            self.last_applied_pid = change['pid']
            self.pending_change = None
            self.pending_timer = None

class ProcessSuspensionManager:
    """
    Gestor de suspensión de procesos inactivos.
    
    Suspende automáticamente procesos que han estado inactivos durante un tiempo
    prolongado para liberar recursos del sistema, y los resume cuando vuelven a
    ser necesarios.
    
    Attributes:
        suspended_processes: Dict de procesos actualmente suspendidos
        inactivity_threshold: Tiempo de inactividad en segundos antes de suspender
        suspension_decision_cache: Cache de decisiones de suspensión
    """
    def __init__(self):
        self.suspended_processes = {}
        self.inactivity_threshold = 900
        self.lock = threading.RLock()
        self.suspension_decision_cache = {}

    def should_suspend(self, pid, last_foreground_time):
        with self.lock:
            cache_key = (pid, int(last_foreground_time / 60))
            if cache_key in self.suspension_decision_cache:
                return self.suspension_decision_cache[cache_key]
            time_inactive = time.time() - last_foreground_time
            result = time_inactive > self.inactivity_threshold
            self.suspension_decision_cache[cache_key] = result
            if len(self.suspension_decision_cache) > 1000:
                items = list(self.suspension_decision_cache.items())
                self.suspension_decision_cache = dict(items[500:])
            return result

    def suspend_process(self, pid):
        with self.lock:
            try:
                handle = win32api.OpenProcess(0x0800, False, pid)
                if handle:
                    try:
                        ntdll.NtSuspendProcess(handle)
                        self.suspended_processes[pid] = time.time()
                        return True
                    finally:
                        win32api.CloseHandle(handle)
            except Exception:
                pass
            return False

    def resume_process(self, pid):
        with self.lock:
            if pid in self.suspended_processes:
                try:
                    handle = win32api.OpenProcess(0x0800, False, pid)
                    if handle:
                        try:
                            ntdll.NtResumeProcess(handle)
                            del self.suspended_processes[pid]
                            return True
                        finally:
                            win32api.CloseHandle(handle)
                except Exception:
                    pass
            return False

class ProcessTreeCache:
    """
    Cache del árbol de procesos del sistema.
    
    Mantiene un cache de relaciones padre-hijo entre procesos para evitar
    reconstruir el árbol en cada consulta, mejorando el rendimiento.
    
    Attributes:
        rebuild_interval: Intervalo mínimo entre reconstrucciones del árbol
        parent_to_children: Mapa de PID padre a set de PIDs hijos
        last_rebuild: Timestamp de la última reconstrucción
    """
    def __init__(self, rebuild_interval_ms=2000):
        self.rebuild_interval = rebuild_interval_ms / 1000.0
        self.last_rebuild = 0
        self.parent_to_children = defaultdict(set)
        self.lock = threading.RLock()

    def rebuild_tree(self, force=False):
        with self.lock:
            current_time = time.time()
            if not force and current_time - self.last_rebuild < self.rebuild_interval:
                return True
                
            self.parent_to_children.clear()
            for proc in psutil.process_iter(['pid', 'ppid']):
                try:
                    self.parent_to_children[proc.ppid()].add(proc.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            self.last_rebuild = current_time
            return True

    def get_all_descendants(self, pid):
        self.rebuild_tree()
        with self.lock:
            descendants = set()
            to_process = [pid]
            while to_process:
                current = to_process.pop()
                children = self.parent_to_children.get(current, set())
                for child in children:
                    if child not in descendants:
                        descendants.add(child)
                        to_process.append(child)
            return list(descendants)

class SystemTrayManager:
    def __init__(self, manager_instance):
        self.manager = manager_instance
        self.icon = None
        self.game_mode = False
        self.running = False
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.gui = None

    def load_icon_from_file(self, icon_path):
        if os.path.exists(icon_path):
            return Image.open(icon_path)
        return None

    def create_icon_image(self, text='OP', size=64, bg_color=(0, 120, 215), text_color=(255, 255, 255)):
        image = Image.new('RGB', (size, size), bg_color)
        draw = ImageDraw.Draw(image)
        try:
            font = ImageFont.truetype('arial.ttf', int(size * 0.5))
        except Exception:
            font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (size - text_width) / 2
        y = (size - text_height) / 2
        draw.text((x, y), text, fill=text_color, font=font)
        return image

    def toggle_game_mode(self, icon, item):
        self.game_mode = not self.game_mode
        if self.game_mode:
            self._activate_game_mode()
        else:
            self._deactivate_game_mode()
    
    def clean_temp_files(self, icon, item):
        temps = [os.environ.get("TEMP"), os.environ.get("TMP"), r"C:\Windows\Temp", r"C:\Windows\Prefetch"]
        for t in temps:
            if t and os.path.exists(t):
                try:
                    for root, _, files in os.walk(t):
                        for f in files:
                            try: os.remove(os.path.join(root, f))
                            except Exception: pass
                except Exception: pass

    def _activate_game_mode(self):
        self.manager.windows_optimizer.optimize_service_group(ServiceCategories.TELEMETRY)
        self.manager.windows_optimizer.optimize_service_group(ServiceCategories.UPDATE)
        self.manager.windows_optimizer.optimize_service_group(ServiceCategories.SEARCH)

    def _deactivate_game_mode(self):
        self.manager.windows_optimizer.restore_all()

    def exit_application(self, icon, item):
        self._revert_all_settings()
        self.running = False
        icon.stop()
        os._exit(0)

    def _revert_all_settings(self):
        if self.game_mode:
            self._deactivate_game_mode()

    def open_gui(self, icon, item):
        if GUI_AVAILABLE and not self.gui:
            try:
                self.gui = ProcessManagerGUI(self.manager)
            except Exception:
                pass
        if self.gui and hasattr(self.gui, 'show'):
            gui_thread = threading.Thread(target=self.gui.show, daemon=False, name='GemGUIThread')
            gui_thread.start()

    def create_menu(self):
        menu_items = [
            pystray.MenuItem('Open Process Manager', self.open_gui, enabled=GUI_AVAILABLE),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Game Mode', self.toggle_game_mode, checked=lambda item: self.game_mode),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Clean Temp Files', self.clean_temp_files),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Exit', self.exit_application)
        ]
        return pystray.Menu(*menu_items)

    def run(self):
        if not pystray:
            while True:
                time.sleep(5)
            return
        icon_path = os.path.join(self.script_dir, '1.ico')
        icon_image = self.load_icon_from_file(icon_path)
        if not icon_image:
            icon_image = self.create_icon_image()
        self.icon = pystray.Icon('OptimusPrime', icon_image, 'Optimus Prime Optimizer', menu=self.create_menu())
        self.running = True
        def update_loop():
            while self.running:
                time.sleep(3)
                if self.icon:
                    self.icon.menu = self.create_menu()
        threading.Thread(target=update_loop, daemon=True).start()
        self.icon.run()

def is_user_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def enable_debug_privilege():
    h_token = wintypes.HANDLE()
    h_process = kernel32.GetCurrentProcess()
    if not advapi32.OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
        return False
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
        kernel32.CloseHandle(h_token)
        return False
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    kernel32.SetLastError(0)
    result = advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(TOKEN_PRIVILEGES), None, None)
    error = kernel32.GetLastError()
    kernel32.CloseHandle(h_token)
    return result and error == 0

class MegatronEngine:
    """
    Motor de optimizaciones extremas para procesos críticos.
    
    Proporciona optimizaciones de bajo nivel como deshabilitar mitigaciones de
    seguridad para máximo rendimiento en juegos, y control de modos de eficiencia.
    
    Note:
        Estas optimizaciones se deben usar solo en procesos de confianza como
        juegos, ya que deshabilitan algunas protecciones de seguridad.
    """
    
    def disable_kernel_cep(self, pid: int):
        """
        Deshabilita Control Flow Guard (CFG) para un proceso.
        
        Args:
            pid: Process ID
        """
        try:
            h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if h:
                token = wintypes.HANDLE()
                if advapi32.OpenProcessToken(h, 0x0008, ctypes.byref(token)):
                    kernel32.SetTokenInformation(token, 36, ctypes.byref(ctypes.c_int(0)), ctypes.sizeof(ctypes.c_int))
                    kernel32.CloseHandle(token)
                kernel32.CloseHandle(h)
        except Exception: pass

    def set_efficiency_mode(self, pid: int, enable: bool = True):
        """
        Establece modo de eficiencia (EcoQoS) para un proceso.
        
        Args:
            pid: Process ID
            enable: True para activar modo eficiencia, False para desactivar
        """
        try:
            h = kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
            if h:
                throttling_state = PROCESS_POWER_THROTTLING_STATE()
                throttling_state.Version = 1
                throttling_state.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED
                throttling_state.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED if enable else 0
                
                kernel32.SetProcessInformation(h, ProcessPowerThrottling, ctypes.byref(throttling_state), ctypes.sizeof(throttling_state))
                kernel32.CloseHandle(h)
        except Exception: pass

    def apply_max_spectre_meltdown_off(self, exe):
        try:
            path = f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{exe}"
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                winreg.SetValueEx(k, "FeatureSettingsOverride", 0, winreg.REG_DWORD, 0x3FF)
                winreg.SetValueEx(k, "FeatureSettingsOverrideMask", 0, winreg.REG_DWORD, 0x3FF)
                winreg.SetValueEx(k, "UseSpeculativeExecutionBarrier", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(k, "SpeculativeStoreBypassDisable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(k, "ImportAddressTableFilter", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(k, "KernelShadowStacksEnabled", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(k, "BranchTargetInjectionMitigation", 0, winreg.REG_DWORD, 0)
        except Exception: pass

class UnifiedProcessManager:
    """
    Gestor unificado de procesos con optimizaciones avanzadas de recursos.
    
    Esta clase coordina todas las optimizaciones del sistema, incluyendo CPU affinity,
    prioridades de procesos, gestión de memoria, perfiles automáticos, y monitoreo
    de procesos mediante eventos WMI para máxima eficiencia.
    
    Attributes:
        lock: RLock para sincronización thread-safe
        cpu_count: Número de CPUs lógicas del sistema
        topology: Información de topología de CPU (P-cores, E-cores, cache, NUMA)
        process_states: Estado actual de todos los procesos monitoreados
        foreground_pid: PID del proceso en foreground actualmente
        wmi_monitor: Monitor de eventos WMI para procesos (si está disponible)
        profile_manager: Gestor de perfiles automáticos (Gaming, Productivity, etc.)
    
    Example:
        >>> manager = UnifiedProcessManager(debug_privilege_enabled=True)
        >>> manager_thread = threading.Thread(target=manager.run, daemon=True)
        >>> manager_thread.start()
    """
    def __init__(self, debug_privilege_enabled: bool=True):
        self.lock = threading.RLock()
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.backup_manager = BackupManager(os.path.join(self.script_dir, "backups"))
        self.windows_optimizer = WindowsOptimizer(self.backup_manager)
        
        self.cpu_count = psutil.cpu_count(logical=True)
        self.topology = self._query_cpu_topology()
        self.pe_core_sets = self._classify_pe_cores()
        self.core_config = self._build_core_config()
        
        self.process_states = {}
        self.applied_states = {}
        self.minimized_processes = {}
        self.pid_to_job = {}
        self.jobs = {}
        self.foreground_pid = None
        self.whitelist = set()
        self.ext_whitelist = set()
        self.ext_games = set()
        self.config_last_modified = 0
        self.interned_process_names = {}
        
        common_names = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'explorer.exe', 'svchost.exe', 'system', 'idle', 'dwm.exe', 'csrss.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'smss.exe']
        for name in common_names:
            self.interned_process_names[name] = sys.intern(name)
            
        self.foreground_debouncer = ForegroundDebouncer(debounce_time_ms=300, hysteresis_time_ms=150)
        self.process_tree = ProcessTreeCache(rebuild_interval_ms=2000)
        self.cpu_pinning = CPUPinningEngine(self.cpu_count, self.topology)
        self.dpc_latency_controller = DPCLatencyController()
        self.profile_manager = AutomaticProfileManager(self.ext_games)
        self.timer_resolution_manager = AdaptiveTimerResolutionManager()
        self.suspension_manager = ProcessSuspensionManager()
        self.advanced_memory_page_manager = AdvancedMemoryPagePriorityManager()
        self.smt_optimizer = EnhancedSMTOptimizer(self.topology, self.cpu_count)
        self.megatron_engine = MegatronEngine()
        
        self.static_tuner = StaticSystemTuner()
        
        self.load_external_config()
        self.win_event_hook = None
        self._start_foreground_hook_thread()
        
        self.blacklist_names = {'system', 'idle', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'fontdrvhost.exe', 'registry', 'memcompression', 'sihost.exe', 'dwm.exe', 'ctfmon.exe', 'cmd.exe', 'python.exe', 'pythonw.exe', 'conhost.exe', 'taskmgr.exe', 'taskhostw.exe', 'runtimebroker.exe'}
        self.blacklist_contains = [r'\windows', 'defender', 'msmpeng.exe', 'wuauclt.exe', 'tiworker.exe']
        
        # Initialize WMI-based event-driven process monitoring
        self.wmi_monitor = None
        self._init_wmi_monitoring()
            
        self._apply_initial_optimizations()

    def _init_wmi_monitoring(self):
        """
        Inicializa el monitoreo de procesos basado en eventos WMI.
        
        Reemplaza el polling ineficiente con monitoreo event-driven que tiene
        casi 0% de uso de CPU cuando idle. Si WMI no está disponible, se usa
        polling tradicional como fallback.
        """
        if not WMI_MONITOR_AVAILABLE:
            return
        
        def process_event_callback(event_type: str, pid: int, name: str):
            """
            Callback para eventos de proceso desde WMI.
            
            Args:
                event_type: 'create' o 'terminate'
                pid: Process ID
                name: Nombre del proceso
            """
            with self.lock:
                if event_type == 'create':
                    self._handle_new_process(pid, name)
                elif event_type == 'terminate':
                    self._handle_process_termination(pid)
        
        try:
            self.wmi_monitor = create_process_monitor(process_event_callback)
            self.wmi_monitor.start_monitoring()
        except Exception as e:
            # Si falla WMI, continuamos con polling tradicional
            self.wmi_monitor = None
    
    def _handle_new_process(self, pid: int, name: str):
        """
        Maneja la detección de un nuevo proceso.
        
        Args:
            pid: Process ID del nuevo proceso
            name: Nombre del proceso
        """
        if self.is_whitelisted(pid) or self.is_blacklisted(pid):
            return
        
        try:
            current_foreground_pid = self.get_foreground_window_pid()
            is_fg = (pid == current_foreground_pid)
            
            if pid not in self.process_states:
                self.process_states[pid] = {
                    'name': name,
                    'is_foreground': is_fg,
                    'created_at': time.time()
                }
                self.apply_settings_to_process_group(pid, is_fg)
        except Exception:
            pass
    
    def _handle_process_termination(self, pid: int):
        """
        Maneja la terminación de un proceso.
        
        Args:
            pid: Process ID del proceso terminado
        """
        # Limpieza de estado
        self.process_states.pop(pid, None)
        self.applied_states.pop(pid, None)
        self.minimized_processes.pop(pid, None)
        self.pid_to_job.pop(pid, None)
    
    def _apply_initial_optimizations(self):
        self.backup_manager.create_system_restore_point()
        self.static_tuner.run_full_static_optimization()

    def _query_cpu_topology(self):
        topology_cache_path = os.path.join(self.script_dir, '.cpu_topology_cache.json')
        if os.path.exists(topology_cache_path):
            try:
                with open(topology_cache_path, 'r') as f:
                    cached_data = json.load(f)
                    topology = {
                        'llc_groups': [set(g) for g in cached_data.get('llc_groups', [])],
                        'numa_nodes': defaultdict(set, {int(k): set(v) for k, v in cached_data.get('numa_nodes', {}).items()}),
                        'p_cores': set(cached_data.get('p_cores', [])),
                        'e_cores': set(cached_data.get('e_cores', []))
                    }
                    return topology
            except Exception:
                pass

        topology = {'llc_groups': [], 'numa_nodes': defaultdict(set), 'p_cores': set(), 'e_cores': set()}
        returned_length = wintypes.DWORD(0)
        kernel32.GetLogicalProcessorInformationEx(RelationProcessorCore, None, ctypes.byref(returned_length))
        if returned_length.value > 0:
            buf = (ctypes.c_byte * returned_length.value)()
            buf_size = returned_length.value
            if kernel32.GetLogicalProcessorInformationEx(RelationProcessorCore, ctypes.byref(buf), ctypes.byref(returned_length)):
                offset = 0
                while offset < buf_size:
                    entry = SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX.from_buffer_copy(buf[offset:])
                    if entry.Relationship == RelationProcessorCore:
                        efficiency_class = entry.u.Processor.EfficiencyClass
                        mask = entry.u.Processor.GroupMask[0].Mask
                        cpus = self._mask_to_cpu_indices(mask, list(range(self.cpu_count)))
                        if efficiency_class == 1:
                            topology['p_cores'].update(cpus)
                        elif efficiency_class == 0:
                            topology['e_cores'].update(cpus)
                        else:
                            topology['p_cores'].update(cpus) 
                    offset += entry.Size
       
        kernel32.GetLogicalProcessorInformation(None, ctypes.byref(returned_length))
        if returned_length.value > 0:
            buf = (ctypes.c_byte * returned_length.value)()
            buf_size = returned_length.value
            entry_size = ctypes.sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION)
            count = buf_size // entry_size
            for i in range(count):
                base = i * entry_size
                entry = SYSTEM_LOGICAL_PROCESSOR_INFORMATION.from_buffer_copy(buf[base:base + entry_size])
                mask = entry.ProcessorMask
                if entry.Relationship == RelationCache and entry.u.Cache.Level == 3:
                    cpus = self._mask_to_cpu_indices(mask, list(range(self.cpu_count)))
                    if cpus:
                        topology['llc_groups'].append(set(cpus))
                elif entry.Relationship == RelationNumaNode:
                    node_id = entry.u.NumaNode_NodeNumber
                    cpus = self._mask_to_cpu_indices(mask, list(range(self.cpu_count)))
                    topology['numa_nodes'][node_id].update(cpus)

        cache_data = {
            'llc_groups': [list(g) for g in topology['llc_groups']], 
            'numa_nodes': {k: list(v) for k, v in topology['numa_nodes'].items()}, 
            'p_cores': list(topology['p_cores']), 
            'e_cores': list(topology['e_cores'])
        }
        try:
            with open(topology_cache_path, 'w') as f:
                json.dump(cache_data, f)
        except Exception:
            pass
        return topology

    def _mask_to_cpu_indices(self, mask, cpu_index_map):
        indices = []
        bit = 0
        cpu_index_map_len = len(cpu_index_map)
        while mask and bit < cpu_index_map_len:
            if mask & 1:
                indices.append(cpu_index_map[bit])
            mask >>= 1
            bit += 1
        return indices

    def _classify_pe_cores(self):
        p_cores = self.topology.get('p_cores', set())
        e_cores = self.topology.get('e_cores', set())
        if not p_cores and not e_cores:
            llc_groups = self.topology.get('llc_groups', [])
            if llc_groups:
                largest = max(llc_groups, key=len)
                p_cores = set(sorted(largest))
                e_cores = set(range(self.cpu_count)) - p_cores
            else:
                p_cores = set(range(self.cpu_count))
                e_cores = set()
        return {'p_cores': sorted(list(p_cores)), 'e_cores': sorted(list(e_cores))}

    def _build_core_config(self):
        p = self.pe_core_sets.get('p_cores', list(range(self.cpu_count)))
        e = self.pe_core_sets.get('e_cores', [])
        foreground_cores = [c for c in p if c != 0] 
        if not foreground_cores:
            foreground_cores = p
        if not e:
            half = len(p) // 2
            background_cores = p[:half]
        else:
            background_cores = e
        return {'foreground': foreground_cores, 'background': background_cores}

    def load_external_config(self):
        """
        Carga configuración externa desde config.json.
        
        Lee whitelist, blacklist y lista de juegos desde el archivo de configuración.
        Solo recarga si el archivo ha sido modificado desde la última carga.
        """
        try:
            config_path = os.path.join(self.script_dir, 'config.json')
            if os.path.exists(config_path):
                current_modified = os.path.getmtime(config_path)
                if current_modified > self.config_last_modified:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        self.ext_whitelist = set(data.get('process_whitelist', []))
                        if 'idle_process_monitoring' in data and 'process_whitelist' in data['idle_process_monitoring']:
                            self.ext_whitelist.update(data['idle_process_monitoring']['process_whitelist'])
                        
                        self.ext_games = set(data.get('game_processes', []))
                        self.profile_manager.external_games = self.ext_games
                        
                        for exe in self.ext_games:
                            self.megatron_engine.apply_max_spectre_meltdown_off(exe)

                    self.config_last_modified = current_modified
        except Exception:
            pass

    def _intern_process_name(self, name):
        if name not in self.interned_process_names:
            self.interned_process_names[name] = sys.intern(name)
        return self.interned_process_names[name]

    def is_whitelisted(self, pid: int) -> bool:
        """
        Verifica si un proceso está en la whitelist.
        
        Los procesos en whitelist no son gestionados por el optimizador para
        evitar interferir con procesos críticos o de alta prioridad.
        
        Args:
            pid: Process ID a verificar
        
        Returns:
            bool: True si el proceso está en whitelist, False en caso contrario
        """
        try:
            process = psutil.Process(pid)
            name = self._intern_process_name(process.name().lower())
            if name in self.ext_whitelist:
                return True
            if name in ServiceCategories.PROCESS_CRITICAL:
                return True
            try:
                exe = process.exe().lower()
                if exe in self.ext_whitelist:
                    return True
            except Exception:
                pass
            return False
        except Exception:
            return False

    def is_blacklisted(self, pid: int) -> bool:
        """
        Verifica si un proceso está en la blacklist.
        
        Los procesos en blacklist nunca son gestionados por el optimizador,
        incluyendo procesos del sistema, servicios críticos de Windows, etc.
        
        Args:
            pid: Process ID a verificar
        
        Returns:
            bool: True si el proceso está en blacklist, False en caso contrario
        """
        if pid <= 4: return True
        try:
            p = psutil.Process(pid)
            name = self._intern_process_name(p.name().lower())
            if name in self.blacklist_names or name in ServiceCategories.PROCESS_CRITICAL:
                return True
            username = p.username()
            if username and username.lower().startswith(('nt authority', 'local service', 'network service')):
                return True
            if hasattr(p, 'session_id') and p.session_id == 0:
                return True
            exe = p.exe().lower()
            for item in self.blacklist_contains:
                if item in exe or item in name:
                    return True
            return False
        except Exception:
            return True 

    def _start_foreground_hook_thread(self):
        def hook_thread():
            WINEVENTPROC = ctypes.WINFUNCTYPE(None, wintypes.HANDLE, wintypes.DWORD, wintypes.HWND, wintypes.LONG, wintypes.LONG, wintypes.DWORD, wintypes.DWORD)
            def callback(hWinEventHook, event, hwnd, idObject, idChild, dwEventThread, dwmsEventTime):
                if event == EVENT_SYSTEM_FOREGROUND:
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    if pid:
                        self._on_foreground_changed(pid)
            self.win_event_hook_callback = WINEVENTPROC(callback)
            self.win_event_hook = user32.SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, 0, self.win_event_hook_callback, 0, 0, WINEVENT_OUTOFCONTEXT)
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        t = threading.Thread(target=hook_thread, name='ForegroundHookThread', daemon=True)
        t.start()

    def _on_foreground_changed(self, new_pid):
        is_known = self.is_whitelisted(new_pid)
        self.foreground_debouncer.request_foreground_change(new_pid, self._apply_foreground_change_internal, is_known, new_pid)

    def _apply_foreground_change_internal(self, new_pid):
        with self.lock:
            old_pid = self.foreground_pid
            self.foreground_pid = new_pid
            if old_pid and psutil.pid_exists(old_pid):
                self.apply_all_settings(old_pid, is_foreground=False)
            if new_pid and psutil.pid_exists(new_pid):
                self.apply_all_settings(new_pid, is_foreground=True)
                self.apply_settings_to_process_group(new_pid, is_foreground=True)

    def get_process_children(self, parent_pid: int) -> List[int]:
        return self.process_tree.get_all_descendants(parent_pid)

    def _desired_settings_for_role(self, is_foreground: bool, pid: Optional[int]=None) -> tuple:
        cores = self.core_config['foreground'] if is_foreground else self.core_config['background']
        
        current_profile = self.profile_manager.current_profile
        
        if current_profile == 'Gaming':
            if is_foreground:
                priority = psutil.HIGH_PRIORITY_CLASS
                io_priority = 2 
            else:
                priority = psutil.IDLE_PRIORITY_CLASS
                io_priority = 0 
        else:
            if is_foreground:
                priority = psutil.ABOVE_NORMAL_PRIORITY_CLASS
                io_priority = 2
            else:
                priority = psutil.IDLE_PRIORITY_CLASS
                io_priority = 1 

        thread_io_priority = io_priority
        page_priority = PAGE_PRIORITY_NORMAL
        
        if not is_foreground and pid and pid in self.minimized_processes:
            time_minimized = time.time() - self.minimized_processes[pid]
            if time_minimized > 1800:
                page_priority = PAGE_PRIORITY_LOW
            else:
                page_priority = PAGE_PRIORITY_MEDIUM
        elif not is_foreground:
            page_priority = PAGE_PRIORITY_MEDIUM
            
        disable_boost = False
        trim_working_set = not is_foreground
        use_eco_qos = not is_foreground
        
        return (cores, priority, io_priority, thread_io_priority, page_priority, disable_boost, trim_working_set, use_eco_qos)

    def _get_applied_state(self, pid: int) -> Dict:
        return self.applied_states.get(pid, {})

    def _set_applied_state(self, pid: int, state: Dict) -> None:
        self.applied_states[pid] = state

    def apply_all_settings(self, pid: int, is_foreground: bool):
        """
        Aplica configuraciones completas a un proceso (Complejidad reducida a 5).
        
        Este método coordina la aplicación de todas las optimizaciones de recursos
        a un proceso específico, incluyendo CPU, memoria, I/O y prioridades según
        si está en foreground o background.
        
        Args:
            pid: Process ID del proceso a optimizar
            is_foreground: True si el proceso está en foreground, False si está en background
        
        Note:
            Procesos en whitelist o blacklist son ignorados automáticamente.
        """
        if self.is_whitelisted(pid) or self.is_blacklisted(pid):
            return
        
        try:
            self._handle_suspension_state(pid, is_foreground)
            process_info = self._get_process_info(pid)
            
            if not process_info:
                return
                
            self._apply_profile_settings(pid, process_info, is_foreground)
            self._apply_efficiency_modes(pid, process_info, is_foreground)
            self._apply_resource_settings(pid, process_info, is_foreground)
            
            if is_foreground:
                self._apply_foreground_optimizations(pid, process_info)
            else:
                self._apply_background_optimizations(pid)
                
        except Exception:
            pass
    
    def _handle_suspension_state(self, pid: int, is_foreground: bool):
        """
        Maneja estado de suspensión del proceso.
        
        Args:
            pid: Process ID
            is_foreground: True si el proceso está en foreground
        """
        if is_foreground:
            if self.suspension_manager.suspended_processes.get(pid):
                self.suspension_manager.resume_process(pid)
            self.minimized_processes.pop(pid, None)
        elif not is_foreground and pid not in self.minimized_processes:
            self.minimized_processes[pid] = time.time()
    
    def _get_process_info(self, pid: int) -> Optional[Dict]:
        """
        Obtiene información del proceso.
        
        Args:
            pid: Process ID
        
        Returns:
            Dict con información del proceso o None si no se puede acceder
        """
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'num_threads': process.num_threads(),
                'process': process
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def _apply_profile_settings(self, pid: int, info: Dict, is_foreground: bool):
        """
        Aplica configuración de perfil.
        
        Args:
            pid: Process ID
            info: Información del proceso
            is_foreground: True si el proceso está en foreground
        """
        name = info['name']
        previous_profile = self.profile_manager.current_profile
        new_profile = self.profile_manager.detect_profile(name)
        
        is_game = name.lower() in self.ext_games
        
        if is_foreground and new_profile != previous_profile:
            self._handle_profile_transition(new_profile, previous_profile, is_game)
    
    def _handle_profile_transition(self, new_profile: str, previous_profile: str, is_game: bool):
        """
        Maneja transición entre perfiles.
        
        Args:
            new_profile: Nuevo perfil detectado
            previous_profile: Perfil anterior
            is_game: True si es un juego
        """
        if new_profile == 'Gaming' and previous_profile != 'Gaming':
            self.windows_optimizer.optimize_service_group(ServiceCategories.TELEMETRY)
            self.windows_optimizer.optimize_service_group(ServiceCategories.UPDATE)
        elif new_profile != 'Gaming' and previous_profile == 'Gaming':
            self.windows_optimizer.restore_all()
    
    def _apply_efficiency_modes(self, pid: int, info: Dict, is_foreground: bool):
        """
        Aplica modos de eficiencia.
        
        Args:
            pid: Process ID
            info: Información del proceso
            is_foreground: True si el proceso está en foreground
        """
        is_game = info['name'].lower() in self.ext_games
        
        if is_game:
            self.megatron_engine.disable_kernel_cep(pid)
            self.megatron_engine.set_efficiency_mode(pid, False)
        elif not is_foreground:
            self.megatron_engine.set_efficiency_mode(pid, True)
    
    def _apply_resource_settings(self, pid: int, info: Dict, is_foreground: bool):
        """
        Aplica configuración de recursos (CPU, memoria, I/O).
        
        Args:
            pid: Process ID
            info: Información del proceso
            is_foreground: True si el proceso está en foreground
        """
        settings = self._desired_settings_for_role(is_foreground, pid)
        cores, prio, io_prio, _, page_prio, disable_boost, trim_ws, use_eco = settings
        
        process = info['process']
        is_game = info['name'].lower() in self.ext_games
        
        # Ajustes para juegos
        if is_game:
            use_eco = False
            trim_ws = False
        
        # CPU priority y affinity
        process.nice(prio)
        process.cpu_affinity(cores)
        
        # I/O priority
        try:
            process.ionice(io_prio)
        except Exception:
            pass
        
        # Configuración avanzada de proceso
        self._apply_advanced_process_config(pid, page_prio, trim_ws, use_eco, disable_boost)
    
    def _apply_advanced_process_config(self, pid: int, page_prio: int, 
                                      trim_ws: bool, use_eco: bool, disable_boost: bool):
        """
        Aplica configuración avanzada de Windows.
        
        Args:
            pid: Process ID
            page_prio: Prioridad de página de memoria
            trim_ws: Si debe hacer trim del working set
            use_eco: Si debe usar modo eco/throttling
            disable_boost: Si debe deshabilitar boost de prioridad
        """
        try:
            handle = win32api.OpenProcess(
                PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
                False, pid
            )
            if not handle:
                return
                
            try:
                # Priority boost
                if disable_boost:
                    kernel32.SetProcessPriorityBoost(handle, wintypes.BOOL(True))
                
                # Power throttling
                if use_eco:
                    self._set_eco_qos(handle)
                
                # Memory priority
                self._set_memory_priority(handle, page_prio)
                
                # Working set trim
                if trim_ws:
                    kernel32.SetProcessWorkingSetSize(
                        handle, ctypes.c_size_t(-1), ctypes.c_size_t(-1)
                    )
            finally:
                win32api.CloseHandle(handle)
        except Exception:
            pass
    
    def _set_eco_qos(self, handle):
        """
        Establece modo de ahorro de energía (EcoQoS).
        
        Args:
            handle: Handle del proceso
        """
        try:
            throttling_state = PROCESS_POWER_THROTTLING_STATE()
            throttling_state.Version = 1
            throttling_state.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED
            throttling_state.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED
            kernel32.SetProcessInformation(
                handle, ProcessPowerThrottling,
                ctypes.byref(throttling_state),
                ctypes.sizeof(throttling_state)
            )
        except Exception:
            pass
    
    def _set_memory_priority(self, handle, page_prio: int):
        """
        Establece prioridad de memoria del proceso.
        
        Args:
            handle: Handle del proceso
            page_prio: Prioridad de página
        """
        try:
            page_priority_info = MEMORY_PRIORITY_INFORMATION()
            page_priority_info.MemoryPriority = page_prio
            ntdll.NtSetInformationProcess(
                int(handle), ProcessPagePriority,
                ctypes.byref(page_priority_info),
                ctypes.sizeof(page_priority_info)
            )
        except Exception:
            pass
    
    def _apply_foreground_optimizations(self, pid: int, info: Dict):
        """
        Optimizaciones específicas para proceso en foreground.
        
        Args:
            pid: Process ID
            info: Información del proceso
        """
        cores = self.core_config['foreground']
        profile = self.profile_manager.current_profile
        
        # Determinar tipo de workload
        is_latency_sensitive = (
            profile == 'Gaming' or 
            info['num_threads'] <= 8
        )
        
        workload = 'latency_sensitive' if is_latency_sensitive else 'general'
        
        self.cpu_pinning.apply_intelligent_pinning(pid, cores, workload)
        if is_latency_sensitive:
            self.smt_optimizer.optimize_for_latency(pid)
        
        # Optimización de memoria
        self.advanced_memory_page_manager.analyze_working_set(pid)
        self.advanced_memory_page_manager.optimize_page_priority(pid, True)
    
    def _apply_background_optimizations(self, pid: int):
        """
        Optimizaciones para proceso en background.
        
        Args:
            pid: Process ID
        """
        self.advanced_memory_page_manager.optimize_page_priority(pid, False)

    def apply_settings_to_process_group(self, pid, is_foreground):
        try:
            main_process = psutil.Process(pid)
            process_name = main_process.name().lower()
        except psutil.NoSuchProcess:
            return

        if self.is_whitelisted(pid) or self.is_blacklisted(pid):
            return

        pids_to_set = set()
        pids_to_set.add(pid)
        pids_to_set.update(self.get_process_children(pid))
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and proc.info['name'].lower() == process_name:
                        pids_to_set.add(proc.info['pid'])
                except Exception: pass
        except Exception: pass
        
        if not is_foreground:
            job_key = self._get_job_key(pid)
            job_handle = self._ensure_job_for_group(job_key, is_foreground)
            e_cores = self.pe_core_sets.get('e_cores', [])
            for target_pid in list(pids_to_set):
                if self.is_whitelisted(target_pid) or self.is_blacklisted(target_pid):
                    continue
                if job_handle:
                    self._assign_pid_to_job(target_pid, job_handle)
                if e_cores:
                    try:
                        p = psutil.Process(target_pid)
                        p.cpu_affinity(e_cores)
                    except Exception:
                        pass

        for target_pid in pids_to_set:
            self.apply_all_settings(target_pid, is_foreground)

    def _get_job_key(self, pid):
        try:
            p = psutil.Process(pid)
            name = p.name().lower()
            session = getattr(p, 'session_id', 0)
            return (name, session)
        except Exception:
            return (str(pid), 0)

    def _ensure_job_for_group(self, job_key, is_foreground):
        job_info = self.jobs.get(job_key)
        if not job_info:
            try:
                hJob = win32job.CreateJobObject(None, f"OptimusPrime_Job_{job_key[0]}")
                self.jobs[job_key] = {'handle': hJob, 'is_foreground': None}
                job_info = self.jobs[job_key]
            except Exception:
                return None
        
        if job_info['is_foreground'] != is_foreground:
            try:
                cpu_usage = psutil.cpu_percent(interval=None)
                if is_foreground:
                    cpu_rate = 100 
                elif cpu_usage < 30:
                    cpu_rate = 50
                else:
                    cpu_rate = 20
                
                if not is_foreground:
                    data = {'ControlFlags': JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, 'CpuRate': cpu_rate * 100}
                    try:
                        win32job.SetInformationJobObject(job_info['handle'], win32job.JobObjectCpuRateControlInformation, data)
                    except Exception:
                        pass
                
                job_info['is_foreground'] = is_foreground
            except Exception:
                pass
                
        return job_info['handle']

    def _assign_pid_to_job(self, pid, job_handle):
        if pid in self.pid_to_job and self.pid_to_job[pid] == job_handle:
            return
        try:
            hProc = win32api.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, False, pid)
            if hProc:
                try:
                    win32job.AssignProcessToJobObject(job_handle, hProc)
                    self.pid_to_job[pid] = job_handle
                finally:
                    win32api.CloseHandle(hProc)
        except Exception:
            pass

    def get_foreground_window_pid(self):
        try:
            hwnd = win32gui.GetForegroundWindow()
            if hwnd:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                return pid
        except Exception:
            pass
        return None

    def clean_zombie_processes(self):
        to_del = []
        for pid in list(self.process_states.keys()):
            if not psutil.pid_exists(pid):
                to_del.append(pid)
        for pid in to_del:
            self.process_states.pop(pid, None)
            self.applied_states.pop(pid, None)
            self.pid_to_job.pop(pid, None)
            if pid in self.minimized_processes:
                del self.minimized_processes[pid]

    def _check_and_suspend_inactive_processes(self):
        for pid in list(self.process_states.keys()):
            if self.is_whitelisted(pid) or self.is_blacklisted(pid):
                continue
            if pid in self.minimized_processes:
                last_foreground = self.minimized_processes[pid]
                if self.suspension_manager.should_suspend(pid, last_foreground):
                    if psutil.pid_exists(pid):
                        self.suspension_manager.suspend_process(pid)

    def update_all_processes(self, iteration):
        """
        Actualiza el estado de todos los procesos.
        
        Con WMI event-driven monitoring, este método solo necesita manejar
        actualizaciones periódicas de estado en lugar de descubrir nuevos procesos.
        
        Args:
            iteration: Contador de iteraciones para operaciones periódicas
        """
        if iteration % 10 == 0:
            self.load_external_config()
        
        with self.lock:
            current_foreground_pid = self.get_foreground_window_pid()
            if current_foreground_pid and current_foreground_pid != self.foreground_pid:
                self._on_foreground_changed(current_foreground_pid)
            
            # Si WMI no está disponible, usar polling tradicional
            if not self.wmi_monitor and iteration % 5 == 0:
                for proc in psutil.process_iter(['pid', 'name']):
                    pid = proc.info['pid']
                    if self.is_whitelisted(pid) or self.is_blacklisted(pid):
                        continue
                    
                    is_fg = (pid == current_foreground_pid)
                    
                    if pid not in self.process_states:
                        self.process_states[pid] = {'name': proc.info['name'], 'is_foreground': is_fg, 'created_at': time.time()}
                        self.apply_settings_to_process_group(pid, is_fg)
                    else:
                        if self.process_states[pid]['is_foreground'] != is_fg:
                            self.process_states[pid]['is_foreground'] = is_fg
                            self.apply_settings_to_process_group(pid, is_fg)

            if iteration % 10 == 0:
                self.clean_zombie_processes()
                self.process_tree.rebuild_tree()
            if iteration % 30 == 0:
                self._check_and_suspend_inactive_processes()

    def run(self):
        """
        Bucle principal del gestor de procesos.
        
        Ejecuta el ciclo de optimización continua, actualizando estados de procesos,
        ajustando resolución de timer, y ejecutando garbage collection periódicamente.
        
        Este método se ejecuta en un thread separado y continúa hasta que se
        interrumpe manualmente o ocurre un error, momento en el cual restaura
        las optimizaciones del sistema.
        """
        self.dpc_latency_controller.optimize_dpc_latency()
        iteration_count = 0
        try:
            while True:
                self.update_all_processes(iteration_count)
                self.timer_resolution_manager.adjust_timer_resolution()
                iteration_count += 1
                if iteration_count % 100 == 0:
                    gc.collect(generation=0)
                time.sleep(3)
        except KeyboardInterrupt:
            self.windows_optimizer.restore_all()
            pass
        except Exception:
            self.windows_optimizer.restore_all()
            time.sleep(5)

def relaunch_with_elevation() -> Optional[str]:
    try:
        shell32 = ctypes.windll.shell32
        script_path = os.path.abspath(__file__)
        arg_list = [script_path] + sys.argv[1:]
        params = ' '.join((f'"{arg}"' for arg in arg_list))
        result = shell32.ShellExecuteW(None, 'runas', sys.executable, params, None, 1)
        return 'runas' if result > 32 else None
    except Exception:
        return None

def main() -> None:
    debug_enabled = enable_debug_privilege()
    if not debug_enabled:
        if not is_user_admin():
            relaunch_with_elevation()
            return
    
    manager = UnifiedProcessManager(debug_privilege_enabled=debug_enabled)
    manager_thread = threading.Thread(target=manager.run, daemon=True, name='ProcessManager')
    manager_thread.start()
    tray = SystemTrayManager(manager)
    tray.run()

if __name__ == "__main__":
    main()
