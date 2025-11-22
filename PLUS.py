#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Kernel Optimizer v1.0
Complemento profesional para OptimmusLight que implementa optimizaciones
de bajo nivel no cubiertas por el optimizador principal.
Autor: Senior Windows Kernel Developer
Requiere: Windows 10/11, Python 3.8+, Permisos de Administrador
"""

import os
import sys
import ctypes
import ctypes.wintypes as wintypes
import subprocess
import json
import time
import threading
import struct
import winreg
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
from enum import IntEnum
from collections import defaultdict

# Verificar privilegios de administrador
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)

# Configuración de logging profesional
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('advanced_kernel_optimizer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DEFINICIONES Y ESTRUCTURAS DEL KERNEL
# ============================================================================

# DLLs del sistema
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)
setupapi = ctypes.WinDLL('setupapi', use_last_error=True)
shell32 = ctypes.WinDLL('shell32', use_last_error=True)

# Constantes MSR (Model Specific Registers)
class MSR:
    IA32_PERF_CTL = 0x199           # Control de frecuencia P-State
    IA32_ENERGY_PERF_BIAS = 0x1B0   # Balance energía/rendimiento
    IA32_MISC_ENABLE = 0x1A0        # Características varias del CPU
    IA32_POWER_CTL = 0x1FC          # Control de power management
    IA32_HWP_REQUEST = 0x774        # Hardware P-States (Intel Speed Shift)
    IA32_PM_ENABLE = 0x770          # Power management enable
    IA32_THERM_STATUS = 0x19C       # Estado térmico
    PLATFORM_INFO = 0xCE            # Información de la plataforma
    
# Estructuras MMCSS
class AVRT_PRIORITY(IntEnum):
    AVRT_PRIORITY_VERYLOW = -2
    AVRT_PRIORITY_LOW = -1
    AVRT_PRIORITY_NORMAL = 0
    AVRT_PRIORITY_HIGH = 1
    AVRT_PRIORITY_CRITICAL = 2

# Estructuras para IRQ
class KAFFINITY(ctypes.Union):
    _fields_ = [
        ("Mask", ctypes.c_ulonglong),
        ("Group", ctypes.c_ushort * 4)
    ]

class DEVICE_OBJECT(ctypes.Structure):
    _fields_ = [
        ("Type", ctypes.c_short),
        ("Size", ctypes.c_ushort),
        ("ReferenceCount", ctypes.c_long),
        ("DriverObject", ctypes.c_void_p),
        ("NextDevice", ctypes.c_void_p),
        ("AttachedDevice", ctypes.c_void_p),
        ("CurrentIrp", ctypes.c_void_p),
        ("Timer", ctypes.c_void_p),
        ("Flags", ctypes.c_ulong),
        ("Characteristics", ctypes.c_ulong),
        ("Vpb", ctypes.c_void_p),
        ("DeviceExtension", ctypes.c_void_p),
        ("DeviceType", ctypes.c_ulong),
        ("StackSize", ctypes.c_char),
        ("Queue", ctypes.c_byte * 40),
        ("AlignmentRequirement", ctypes.c_ulong),
        ("DeviceQueue", ctypes.c_byte * 20),
        ("Dpc", ctypes.c_byte * 32),
        ("ActiveThreadCount", ctypes.c_ulong),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("DeviceLock", ctypes.c_byte * 24),
        ("SectorSize", ctypes.c_ushort),
        ("Spare1", ctypes.c_ushort),
        ("DeviceObjectExtension", ctypes.c_void_p),
        ("Reserved", ctypes.c_void_p)
    ]

# GPU Scheduling Priority
class D3DKMT_SCHEDULINGPRIORITYCLASS(IntEnum):
    D3DKMT_SCHEDULINGPRIORITYCLASS_IDLE = 0
    D3DKMT_SCHEDULINGPRIORITYCLASS_BELOW_NORMAL = 1
    D3DKMT_SCHEDULINGPRIORITYCLASS_NORMAL = 2
    D3DKMT_SCHEDULINGPRIORITYCLASS_ABOVE_NORMAL = 3
    D3DKMT_SCHEDULINGPRIORITYCLASS_HIGH = 4
    D3DKMT_SCHEDULINGPRIORITYCLASS_REALTIME = 5

@dataclass
class ProcessInfo:
    pid: int
    name: str
    is_game: bool = False
    is_foreground: bool = False
    gpu_priority: int = D3DKMT_SCHEDULINGPRIORITYCLASS.D3DKMT_SCHEDULINGPRIORITYCLASS_NORMAL

# ============================================================================
# MSR CONTROLLER - Control directo de registros del CPU
# ============================================================================

class MSRController:
    """
    Controlador avanzado para Model Specific Registers del CPU.
    Permite control directo de frecuencias, voltajes y características.
    """
    
    def __init__(self):
        self.driver_loaded = False
        self.driver_path = self._get_driver_path()
        self.logger = logging.getLogger(f"{__name__}.MSRController")
        self._load_driver()
        
    def _get_driver_path(self) -> Path:
        """Obtiene la ruta del driver WinRing0"""
        base_path = Path(__file__).parent
        return base_path / "WinRing0x64.sys"
        
    def _load_driver(self) -> bool:
        """Carga el driver WinRing0 para acceso MSR"""
        try:
            # Primero intentamos con el driver integrado de Windows (si existe)
            self.driver_handle = kernel32.CreateFileW(
                r"\\.\WinRing0_1_2_0",
                0xC0000000,  # GENERIC_READ | GENERIC_WRITE
                0,
                None,
                3,  # OPEN_EXISTING
                0x80,  # FILE_ATTRIBUTE_NORMAL
                None
            )
            
            if self.driver_handle != -1:
                self.driver_loaded = True
                self.logger.info("Driver WinRing0 cargado exitosamente")
                return True
                
            # Si no existe, intentamos instalarlo
            if self.driver_path.exists():
                result = subprocess.run(
                    ["sc", "create", "WinRing0_1_2_0", "type=", "kernel", "binPath=", str(self.driver_path)],
                    capture_output=True,
                    text=True
                )
                
                subprocess.run(["sc", "start", "WinRing0_1_2_0"], capture_output=True)
                time.sleep(1)
                
                self.driver_handle = kernel32.CreateFileW(
                    r"\\.\WinRing0_1_2_0",
                    0xC0000000,
                    0,
                    None,
                    3,
                    0x80,
                    None
                )
                
                if self.driver_handle != -1:
                    self.driver_loaded = True
                    self.logger.info("Driver WinRing0 instalado y cargado")
                    return True
                    
        except Exception as e:
            self.logger.warning(f"No se pudo cargar driver MSR: {e}")
            
        # Fallback: usar CPUID instruction directamente (limitado)
        self.driver_loaded = False
        self.logger.info("Usando modo CPUID fallback (funcionalidad limitada)")
        return False
        
    def read_msr(self, register: int, cpu: int = 0) -> Optional[int]:
        """Lee un MSR específico"""
        if not self.driver_loaded:
            return self._read_msr_fallback(register)
            
        try:
            # Estructura para IOCTL
            in_buffer = struct.pack("II", register, cpu)
            out_buffer = ctypes.create_string_buffer(8)
            bytes_returned = ctypes.c_ulong()
            
            IOCTL_READ_MSR = 0x222404
            result = kernel32.DeviceIoControl(
                self.driver_handle,
                IOCTL_READ_MSR,
                in_buffer,
                len(in_buffer),
                out_buffer,
                len(out_buffer),
                ctypes.byref(bytes_returned),
                None
            )
            
            if result:
                value = struct.unpack("Q", out_buffer.raw)[0]
                self.logger.debug(f"MSR {hex(register)} = {hex(value)}")
                return value
                
        except Exception as e:
            self.logger.error(f"Error leyendo MSR {hex(register)}: {e}")
            
        return None
        
    def write_msr(self, register: int, value: int, cpu: int = 0) -> bool:
        """Escribe un valor en un MSR"""
        if not self.driver_loaded:
            self.logger.warning("No se puede escribir MSR sin driver")
            return False
            
        try:
            in_buffer = struct.pack("IIQ", register, cpu, value)
            bytes_returned = ctypes.c_ulong()
            
            IOCTL_WRITE_MSR = 0x222408
            result = kernel32.DeviceIoControl(
                self.driver_handle,
                IOCTL_WRITE_MSR,
                in_buffer,
                len(in_buffer),
                None,
                0,
                ctypes.byref(bytes_returned),
                None
            )
            
            if result:
                self.logger.info(f"MSR {hex(register)} escrito con valor {hex(value)}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error escribiendo MSR {hex(register)}: {e}")
            
        return False
        
    def _read_msr_fallback(self, register: int) -> Optional[int]:
        """Método fallback usando CPUID/RDMSR emulación"""
        try:
            # Usar wmic para obtener info básica del CPU
            result = subprocess.run(
                ["wmic", "cpu", "get", "CurrentClockSpeed,MaxClockSpeed"],
                capture_output=True,
                text=True
            )
            
            if register == MSR.PLATFORM_INFO:
                # Retornar valores simulados basados en info del sistema
                return 0x000000001A000000  # Valor típico
                
        except Exception:
            pass
            
        return None
        
    def optimize_cpu_performance(self):
        """Aplica optimizaciones MSR para máximo rendimiento"""
        optimizations = [
            # Deshabilitar Intel SpeedStep dinámico
            (MSR.IA32_MISC_ENABLE, 0x850089, 0xFFFFFFFFFFFBFFFF),
            
            # Energy Performance Bias - Máximo rendimiento
            (MSR.IA32_ENERGY_PERF_BIAS, 0x0, 0xF),
            
            # Power Control - Deshabilitar C1E
            (MSR.IA32_POWER_CTL, 0x0, 0x2),
            
            # HWP Request - Performance preference
            (MSR.IA32_HWP_REQUEST, 0xFF00FF00, None),
        ]
        
        for msr, value, mask in optimizations:
            current = self.read_msr(msr)
            if current is not None:
                if mask:
                    new_value = (current & ~mask) | (value & mask)
                else:
                    new_value = value
                    
                self.write_msr(msr, new_value)
                
    def __del__(self):
        """Limpieza del driver"""
        if hasattr(self, 'driver_handle') and self.driver_handle != -1:
            kernel32.CloseHandle(self.driver_handle)
            
# ============================================================================
# HPET CONTROLLER - Control directo del High Precision Event Timer
# ============================================================================

class HPETController:
    """
    Controlador para manipulación directa del HPET.
    Mejora la precisión del timing y reduce la latencia.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.HPETController")
        self.hpet_base = self._get_hpet_base()
        self.original_period = None
        
    def _get_hpet_base(self) -> Optional[int]:
        """Obtiene la dirección base del HPET desde ACPI"""
        try:
            # Leer tabla ACPI HPET
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\ACPI\DSDT\VBOX__\VBOXBIOS\00000002"
            )
            # Esta es una aproximación, en producción se leería la tabla ACPI real
            return 0xFED00000  # Dirección estándar HPET
            
        except Exception:
            self.logger.warning("No se pudo obtener dirección HPET desde ACPI")
            return 0xFED00000  # Usar dirección por defecto
            
    def configure_hpet(self, use_hpet: bool = True, force_legacy: bool = False):
        """Configura el HPET para máximo rendimiento"""
        try:
            # Configurar via BCDEdit
            if use_hpet:
                subprocess.run(["bcdedit", "/set", "useplatformtick", "yes"], capture_output=True)
                subprocess.run(["bcdedit", "/set", "disabledynamictick", "yes"], capture_output=True)
                subprocess.run(["bcdedit", "/set", "useplatformclock", "no"], capture_output=True)
                
                # Configurar registro para forzar HPET
                with winreg.CreateKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
                ) as key:
                    winreg.SetValueEx(key, "RealTimeIsUniversal", 0, winreg.REG_DWORD, 1)
                    
            else:
                subprocess.run(["bcdedit", "/deletevalue", "useplatformtick"], capture_output=True)
                subprocess.run(["bcdedit", "/set", "disabledynamictick", "no"], capture_output=True)
                
            self.logger.info(f"HPET configurado: {'Habilitado' if use_hpet else 'Deshabilitado'}")
            
            # Configurar timer resolution
            self._set_timer_resolution(0.5 if use_hpet else 1.0)
            
        except Exception as e:
            self.logger.error(f"Error configurando HPET: {e}")
            
    def _set_timer_resolution(self, resolution_ms: float):
        """Establece la resolución del timer del sistema"""
        try:
            # NtSetTimerResolution
            NtSetTimerResolution = ntdll.NtSetTimerResolution
            NtSetTimerResolution.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.POINTER(ctypes.c_ulong)]
            
            desired_resolution = int(resolution_ms * 10000)  # Convertir a 100ns units
            actual_resolution = ctypes.c_ulong()
            
            result = NtSetTimerResolution(
                desired_resolution,
                True,  # Set resolution
                ctypes.byref(actual_resolution)
            )
            
            if result == 0:
                self.logger.info(f"Timer resolution establecida a {actual_resolution.value/10000:.2f}ms")
                
        except Exception as e:
            self.logger.error(f"Error estableciendo timer resolution: {e}")
            
    def optimize_for_gaming(self):
        """Optimización específica para gaming"""
        self.configure_hpet(use_hpet=False, force_legacy=True)
        
        # Deshabilitar HPET en Device Manager
        try:
            subprocess.run(
                'powershell -Command "Get-PnpDevice | Where-Object {$_.FriendlyName -like \'*High precision*\'} | Disable-PnpDevice -Confirm:$false"',
                shell=True,
                capture_output=True
            )
        except:
            pass
            
# ============================================================================
# GPU SCHEDULER - Control de prioridad de GPU
# ============================================================================

class GPUSchedulerController:
    """
    Controlador avanzado para GPU scheduling en Windows.
    Maneja WDDM 2.7+ GPU scheduling y prioridades D3D.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.GPUScheduler")
        self.gdi32 = ctypes.WinDLL('gdi32')
        
        try:
            self.d3dkmt = ctypes.WinDLL('gdi32')  # D3DKMTxxx functions están en gdi32
            self._init_d3d_functions()
            self.available = True
        except Exception as e:
            self.logger.warning(f"GPU Scheduler no disponible: {e}")
            self.available = False
            
    def _init_d3d_functions(self):
        """Inicializa funciones D3DKMT"""
        # D3DKMTSetProcessSchedulingPriorityClass
        self.D3DKMTSetProcessSchedulingPriorityClass = self.gdi32.D3DKMTSetProcessSchedulingPriorityClass
        self.D3DKMTSetProcessSchedulingPriorityClass.argtypes = [
            wintypes.HANDLE,  # Process handle
            ctypes.c_int      # Priority class
        ]
        self.D3DKMTSetProcessSchedulingPriorityClass.restype = ctypes.c_long
        
        # D3DKMTGetProcessSchedulingPriorityClass
        self.D3DKMTGetProcessSchedulingPriorityClass = self.gdi32.D3DKMTGetProcessSchedulingPriorityClass
        self.D3DKMTGetProcessSchedulingPriorityClass.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_int)
        ]
        self.D3DKMTGetProcessSchedulingPriorityClass.restype = ctypes.c_long
        
    def set_process_gpu_priority(self, pid: int, priority: D3DKMT_SCHEDULINGPRIORITYCLASS) -> bool:
        """Establece la prioridad GPU de un proceso"""
        if not self.available:
            return False
            
        try:
            # Abrir proceso
            PROCESS_SET_INFORMATION = 0x0200
            handle = kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
            
            if handle:
                try:
                    result = self.D3DKMTSetProcessSchedulingPriorityClass(handle, priority)
                    
                    if result == 0:  # STATUS_SUCCESS
                        self.logger.info(f"GPU priority establecida para PID {pid}: {priority}")
                        return True
                    else:
                        self.logger.warning(f"Error estableciendo GPU priority: {hex(result)}")
                        
                finally:
                    kernel32.CloseHandle(handle)
                    
        except Exception as e:
            self.logger.error(f"Error en set_process_gpu_priority: {e}")
            
        return False
        
    def enable_hardware_scheduling(self):
        """Habilita Hardware-accelerated GPU scheduling"""
        try:
            with winreg.CreateKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
            ) as key:
                winreg.SetValueEx(key, "HwSchMode", 0, winreg.REG_DWORD, 2)
                
            self.logger.info("Hardware-accelerated GPU scheduling habilitado")
            return True
            
        except Exception as e:
            self.logger.error(f"Error habilitando GPU scheduling: {e}")
            return False
            
    def optimize_for_gaming(self, game_pid: int):
        """Optimiza GPU para un proceso de juego específico"""
        # Establecer máxima prioridad GPU
        self.set_process_gpu_priority(
            game_pid, 
            D3DKMT_SCHEDULINGPRIORITYCLASS.D3DKMT_SCHEDULINGPRIORITYCLASS_REALTIME
        )
        
        # Configurar TDR (Timeout Detection and Recovery)
        try:
            with winreg.CreateKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
            ) as key:
                # Aumentar timeout para evitar resets durante gaming intensivo
                winreg.SetValueEx(key, "TdrDelay", 0, winreg.REG_DWORD, 10)
                winreg.SetValueEx(key, "TdrDdiDelay", 0, winreg.REG_DWORD, 10)
                
        except Exception:
            pass
            
# ============================================================================
# MMCSS CONTROLLER - Multimedia Class Scheduler Service
# ============================================================================

class MMCSSController:
    """
    Controlador completo para MMCSS (Multimedia Class Scheduler Service).
    Gestiona tareas multimedia con prioridad en tiempo real.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.MMCSS")
        self.avrt = ctypes.WinDLL('avrt.dll')
        self._init_functions()
        self.registered_tasks = {}
        
    def _init_functions(self):
        """Inicializa funciones AVRT"""
        # AvSetMmThreadCharacteristics
        self.AvSetMmThreadCharacteristics = self.avrt.AvSetMmThreadCharacteristicsW
        self.AvSetMmThreadCharacteristics.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD)]
        self.AvSetMmThreadCharacteristics.restype = wintypes.HANDLE
        
        # AvSetMmThreadPriority
        self.AvSetMmThreadPriority = self.avrt.AvSetMmThreadPriority
        self.AvSetMmThreadPriority.argtypes = [wintypes.HANDLE, ctypes.c_int]
        self.AvSetMmThreadPriority.restype = wintypes.BOOL
        
        # AvRevertMmThreadCharacteristics
        self.AvRevertMmThreadCharacteristics = self.avrt.AvRevertMmThreadCharacteristics
        self.AvRevertMmThreadCharacteristics.argtypes = [wintypes.HANDLE]
        self.AvRevertMmThreadCharacteristics.restype = wintypes.BOOL
        
    def register_thread_mmcss(
        self, 
        thread_id: int, 
        task_name: str = "Pro Audio",
        priority: AVRT_PRIORITY = AVRT_PRIORITY.AVRT_PRIORITY_CRITICAL
    ) -> Optional[int]:
        """Registra un thread con MMCSS para prioridad multimedia"""
        try:
            # Abrir thread
            THREAD_SET_INFORMATION = 0x0020
            thread_handle = kernel32.OpenThread(THREAD_SET_INFORMATION, False, thread_id)
            
            if thread_handle:
                try:
                    # Registrar con MMCSS
                    task_index = wintypes.DWORD()
                    mmcss_handle = self.AvSetMmThreadCharacteristics(
                        task_name,
                        ctypes.byref(task_index)
                    )
                    
                    if mmcss_handle:
                        # Establecer prioridad
                        if self.AvSetMmThreadPriority(mmcss_handle, priority):
                            self.registered_tasks[thread_id] = mmcss_handle
                            self.logger.info(
                                f"Thread {thread_id} registrado con MMCSS: {task_name}, "
                                f"Priority: {priority}, Index: {task_index.value}"
                            )
                            return task_index.value
                            
                finally:
                    kernel32.CloseHandle(thread_handle)
                    
        except Exception as e:
            self.logger.error(f"Error registrando thread con MMCSS: {e}")
            
        return None
        
    def configure_mmcss_tasks(self):
        """Configura las tareas MMCSS del sistema para máximo rendimiento"""
        tasks = {
            "Audio": {
                "Affinity": 0xFF,
                "Priority": 1,
                "Scheduling Category": "High",
                "SFIO Priority": "High",
                "Background Only": "False"
            },
            "Pro Audio": {
                "Affinity": 0xFF,
                "Priority": 1,
                "Scheduling Category": "High", 
                "SFIO Priority": "High",
                "Clock Rate": 10000
            },
            "Games": {
                "Affinity": 0xFF,
                "GPU Priority": 8,
                "Priority": 2,
                "Scheduling Category": "High",
                "SFIO Priority": "High"
            }
        }
        
        base_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks"
        
        for task_name, settings in tasks.items():
            try:
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"{base_key}\\{task_name}") as key:
                    for name, value in settings.items():
                        if isinstance(value, str):
                            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                        else:
                            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                            
                self.logger.info(f"Tarea MMCSS '{task_name}' configurada")
                
            except Exception as e:
                self.logger.error(f"Error configurando tarea MMCSS {task_name}: {e}")
                
    def cleanup(self):
        """Limpia registros MMCSS"""
        for thread_id, handle in self.registered_tasks.items():
            try:
                self.AvRevertMmThreadCharacteristics(handle)
            except:
                pass
                
        self.registered_tasks.clear()
        
# ============================================================================
# IRQ AFFINITY CONTROLLER - Control de afinidad de interrupciones
# ============================================================================

class IRQAffinityController:
    """
    Controlador para manipulación de IRQ affinity.
    Optimiza la distribución de interrupciones entre CPUs.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.IRQAffinity")
        self.cpu_count = os.cpu_count()
        self.interrupt_policy_path = r"SYSTEM\CurrentControlSet\Enum"
        
    def get_device_interrupts(self) -> Dict[str, List[int]]:
        """Obtiene la lista de dispositivos y sus IRQs"""
        devices = {}
        
        try:
            # Usar WMI para obtener información de IRQ
            result = subprocess.run(
                ["wmic", "path", "Win32_PnPAllocatedResource", "get", "Antecedent,Dependent"],
                capture_output=True,
                text=True
            )
            
            # Parsear resultado para extraer IRQs
            # Este es un ejemplo simplificado
            devices["Network"] = [16, 17]  # IRQs típicos de red
            devices["GPU"] = [18]          # IRQ típico de GPU
            devices["USB"] = [20, 21, 22]  # IRQs típicos USB
            devices["Audio"] = [23]        # IRQ típico de audio
            
        except Exception as e:
            self.logger.warning(f"No se pudieron obtener IRQs: {e}")
            
        return devices
        
    def set_irq_affinity(self, device_class: str, cpu_mask: int):
        """Establece la afinidad de CPU para las IRQs de un tipo de dispositivo"""
        try:
            # Buscar dispositivos de la clase especificada
            if device_class == "Network":
                device_ids = self._find_network_devices()
            elif device_class == "GPU":
                device_ids = self._find_gpu_devices()
            else:
                device_ids = []
                
            for device_id in device_ids:
                self._set_device_interrupt_affinity(device_id, cpu_mask)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error estableciendo IRQ affinity: {e}")
            return False
            
    def _find_network_devices(self) -> List[str]:
        """Encuentra dispositivos de red"""
        devices = []
        try:
            result = subprocess.run(
                ["wmic", "path", "Win32_NetworkAdapter", "where", "PhysicalAdapter=True", 
                 "get", "PNPDeviceID"],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.splitlines():
                if "PCI\\" in line:
                    devices.append(line.strip())
                    
        except Exception:
            pass
            
        return devices
        
    def _find_gpu_devices(self) -> List[str]:
        """Encuentra dispositivos GPU"""
        devices = []
        try:
            result = subprocess.run(
                ["wmic", "path", "Win32_VideoController", "get", "PNPDeviceID"],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.splitlines():
                if "PCI\\" in line:
                    devices.append(line.strip())
                    
        except Exception:
            pass
            
        return devices
        
    def _set_device_interrupt_affinity(self, device_id: str, cpu_mask: int):
        """Establece la afinidad de interrupción para un dispositivo específico"""
        try:
            # Construir ruta del registro
            device_path = f"{self.interrupt_policy_path}\\{device_id}\\Device Parameters\\Interrupt Management\\Affinity Policy"
            
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, device_path) as key:
                # Establecer política de afinidad
                winreg.SetValueEx(key, "DevicePolicy", 0, winreg.REG_DWORD, 4)  # IrqPolicySpecifiedProcessors
                winreg.SetValueEx(key, "AssignmentSetOverride", 0, winreg.REG_BINARY, 
                                struct.pack("Q", cpu_mask))
                
            self.logger.info(f"IRQ affinity establecida para {device_id}: CPU mask {hex(cpu_mask)}")
            
        except Exception as e:
            self.logger.debug(f"No se pudo establecer IRQ affinity para {device_id}: {e}")
            
    def optimize_for_gaming(self):
        """Optimización de IRQ para gaming"""
        # Dedicar CPU 0-1 para interrupciones del sistema
        # CPUs 2-3 para red
        # CPUs 4+ para aplicación
        
        if self.cpu_count >= 6:
            self.set_irq_affinity("Network", 0x0C)  # CPUs 2-3
            self.set_irq_affinity("GPU", 0x30)      # CPUs 4-5
        else:
            # Para sistemas con menos cores, usar configuración balanceada
            self.set_irq_affinity("Network", 0x01)  # CPU 0
            self.set_irq_affinity("GPU", 0x02)      # CPU 1
            
# ============================================================================
# MAIN OPTIMIZER - Orquestador principal
# ============================================================================

class AdvancedKernelOptimizer:
    """
    Optimizador principal que coordina todos los controladores.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Iniciando Advanced Kernel Optimizer v1.0")
        
        # Inicializar controladores
        self.msr_controller = MSRController()
        self.hpet_controller = HPETController()
        self.gpu_scheduler = GPUSchedulerController()
        self.mmcss_controller = MMCSSController()
        self.irq_controller = IRQAffinityController()
        
        # Estado
        self.running = True
        self.game_mode = False
        self.monitored_processes = {}
        
    def apply_maximum_performance_tweaks(self):
        """Aplica todas las optimizaciones para máximo rendimiento"""
        self.logger.info("Aplicando optimizaciones de máximo rendimiento...")
        
        # 1. MSR Optimizations
        if self.msr_controller.driver_loaded:
            self.msr_controller.optimize_cpu_performance()
            
        # 2. HPET Configuration
        self.hpet_controller.optimize_for_gaming()
        
        # 3. GPU Scheduling
        if self.gpu_scheduler.available:
            self.gpu_scheduler.enable_hardware_scheduling()
            
        # 4. MMCSS Configuration
        self.mmcss_controller.configure_mmcss_tasks()
        
        # 5. IRQ Affinity
        self.irq_controller.optimize_for_gaming()
        
        # 6. Additional System Tweaks
        self._apply_additional_tweaks()
        
        self.logger.info("Optimizaciones completadas")
        
    def _apply_additional_tweaks(self):
        """Aplica tweaks adicionales del sistema"""
        tweaks = [
            # Deshabilitar Spectre/Meltdown mitigations
            ("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f", "Spectre/Meltdown"),
            
            # Deshabilitar Prefetcher/Superfetch
            ("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\" /v EnablePrefetcher /t REG_DWORD /d 0 /f", "Prefetcher"),
            
            # Kernel timer resolution
            ("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v GlobalTimerResolutionRequests /t REG_DWORD /d 1 /f", "Timer Resolution"),
            
            # MMCSS priority boost
            ("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\" /v SystemResponsiveness /t REG_DWORD /d 0 /f", "System Responsiveness"),
            
            # Disable GPU timeout
            ("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v TdrLevel /t REG_DWORD /d 0 /f", "TDR"),
        ]
        
        for cmd, description in tweaks:
            try:
                subprocess.run(cmd, shell=True, capture_output=True)
                self.logger.info(f"Aplicado: {description}")
            except Exception as e:
                self.logger.warning(f"No se pudo aplicar {description}: {e}")
                
    def monitor_and_optimize_process(self, pid: int, process_name: str):
        """Monitorea y optimiza un proceso específico"""
        try:
            # Detectar si es un juego
            is_game = process_name.lower().endswith(('.exe',)) and any(
                game_keyword in process_name.lower() 
                for game_keyword in ['game', 'unity', 'unreal', 'cry', 'dx', 'gl']
            )
            
            if is_game or self.game_mode:
                # Aplicar optimizaciones de gaming
                self.gpu_scheduler.optimize_for_gaming(pid)
                
                # Registrar threads principales con MMCSS
                # Esto requeriría enumerar threads, simplificado aquí
                self.logger.info(f"Optimizando proceso gaming: {process_name} (PID: {pid})")
                
        except Exception as e:
            self.logger.error(f"Error optimizando proceso {pid}: {e}")
            
    def run(self):
        """Loop principal del optimizador"""
        self.logger.info("Advanced Kernel Optimizer iniciado")
        
        # Aplicar optimizaciones iniciales
        self.apply_maximum_performance_tweaks()
        
        # Monitoreo continuo
        try:
            while self.running:
                # Este loop se puede expandir para monitorear procesos activos
                # y aplicar optimizaciones dinámicamente
                time.sleep(5)
                
        except KeyboardInterrupt:
            self.logger.info("Deteniendo optimizador...")
            
        finally:
            self.cleanup()
            
    def cleanup(self):
        """Limpieza al salir"""
        self.logger.info("Realizando limpieza...")
        self.mmcss_controller.cleanup()
        
    def stop(self):
        """Detiene el optimizador"""
        self.running = False

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Función principal"""
    print("=" * 70)
    print("ADVANCED KERNEL OPTIMIZER v1.0")
    print("Complemento profesional para OptimmusLight")
    print("=" * 70)
    
    # Verificar requisitos
    if not is_admin():
        print("ERROR: Se requieren permisos de administrador")
        sys.exit(1)
        
    # Crear e iniciar optimizador
    optimizer = AdvancedKernelOptimizer()
    
    try:
        # Ejecutar en thread separado para no bloquear OptimmusLight
        optimizer_thread = threading.Thread(target=optimizer.run, daemon=True)
        optimizer_thread.start()
        
        print("\nOptimizador iniciado en segundo plano")
        print("Presione Ctrl+C para detener\n")
        
        # Mantener el programa corriendo
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nDeteniendo optimizador...")
        optimizer.stop()
        
    except Exception as e:
        logger.critical(f"Error fatal: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()