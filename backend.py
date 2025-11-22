import os
import re
import subprocess
import sys
import ctypes
import json
import time
import threading
import psutil
import clr
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import pystray

try:
    clr.AddReference('LibreHardwareMonitorLib')
    from LibreHardwareMonitor.Hardware import Computer, HardwareType, SensorType
except:
    pass

# --- RUTAS Y ARCHIVOS ---
BASE_DIR = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
BACKUP_PATH = os.path.join(BASE_DIR, "energia_backup.json")

# --- GUIDS ---
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

def is_windows():
    return os.name == "nt"

def run_cmd(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW, check=False)

def get_active_scheme_guid():
    r = run_cmd(["powercfg", "/getactivescheme"])
    if not r or r.returncode != 0:
        return None
    text = (r.stdout or b"").decode(errors="ignore")
    m = re.search(r"([0-9a-fA-F-]{36})", text)
    return m.group(1) if m else None

def set_ac(scheme, subgroup, setting, value):
    run_cmd(["powercfg", "-setacvalueindex", scheme, subgroup, setting, str(value)])

def set_dc(scheme, subgroup, setting, value):
    run_cmd(["powercfg", "-setdcvalueindex", scheme, subgroup, setting, str(value)])

def reapply_scheme(scheme):
    run_cmd(["powercfg", "/setactive", scheme])

def has_battery():
    try:
        b = psutil.sensors_battery()
        return b is not None
    except:
        return False

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# --- SISTEMA DE BACKUP ---

def query_setting_value(scheme, subgroup, setting, ac=True):
    try:
        mode = "ACVALUEINDEX" if ac else "DCVALUEINDEX"
        r = run_cmd(["powercfg", "/q", scheme, subgroup, setting])
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
    
    # Si ya existe un backup, no lo sobrescribimos para preservar el estado ORIGINAL
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
    if not os.path.exists(BACKUP_PATH):
        return False, "No hay backup"
    
    try:
        with open(BACKUP_PATH, "r", encoding="utf-8") as f:
            backup = json.load(f)
        
        scheme = get_active_scheme_guid()
        if not scheme: return False, "Error esquema"
        
        # Restaurar CPU AC
        proc_ac = backup.get("processor", {}).get("ac", {})
        if proc_ac.get("min") is not None: set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, proc_ac["min"])
        if proc_ac.get("max") is not None: set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, proc_ac["max"])
        if proc_ac.get("boost") is not None: set_ac(scheme, SUB_PROCESSOR, PERFBOOSTMODE, proc_ac["boost"])
        if proc_ac.get("park_min") is not None: set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MIN, proc_ac["park_min"])
        
        # Restaurar PCIe
        pcie_val = backup.get("pcie", {}).get("ac", {}).get("aspm")
        if pcie_val is not None: set_ac(scheme, SUB_PCIEXPRESS, PCIE_ASPM, pcie_val)
        
        # Restaurar claves de red a valores seguros (Default de Windows aprox)
        if is_admin():
            import winreg
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")
            winreg.SetValueEx(key, "NetworkThrottlingIndex", 0, winreg.REG_DWORD, 10)
            winreg.SetValueEx(key, "SystemResponsiveness", 0, winreg.REG_DWORD, 20)
            winreg.CloseKey(key)
            
        reapply_scheme(scheme)
        
        # Borrar backup para permitir uno nuevo la próxima vez
        os.remove(BACKUP_PATH)
        return True, "Restaurado"
    except Exception as e:
        return False, str(e)

# --- MODOS DE ENERGÍA ---

def apply_mode_ahorro():
    if not is_windows(): return False
    scheme = get_active_scheme_guid()
    if not scheme: return False
    
    backup_current_power_settings() # Seguridad
    
    laptop = has_battery()
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 5)
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 80 if laptop else 100)
    set_ac(scheme, SUB_PROCESSOR, SYSTEM_COOLING_POLICY, 1)
    set_ac(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 1) # Eficiente
    set_ac(scheme, SUB_PROCESSOR, IDLEDISABLE, 0)
    
    # Parking agresivo para ahorrar
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MIN, 50)
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MAX, 100)
    
    # DC Config
    set_dc(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 5)
    set_dc(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 30)
    set_dc(scheme, SUB_PROCESSOR, SYSTEM_COOLING_POLICY, 0)
    set_dc(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 0)
    
    reapply_scheme(scheme)
    return True

def apply_mode_baja_latencia():
    """
    MODO HÍBRIDO INTELIGENTE:
    Latencia baja para juegos/trabajo, pero térmicamente seguro.
    """
    if not is_windows(): return False
    scheme = get_active_scheme_guid()
    if not scheme: return False
    
    # 1. Realizar Backup por seguridad antes de tocar nada
    backup_current_power_settings()
    
    laptop = has_battery()
    
    # AC: Rendimiento con eficiencia térmica
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 5)       # Permitir bajar vueltas en idle
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 100)
    set_ac(scheme, SUB_PROCESSOR, SYSTEM_COOLING_POLICY, 1) # Active cooling
    set_ac(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 1)         # Enabled/Efficient (Clave para menos calor)
    set_ac(scheme, SUB_PROCESSOR, IDLEDISABLE, 0)           # Permitir C-States (Clave para enfriar en idle)
    
    # Respuesta rápida pero no instantánea (estabilidad térmica)
    set_ac(scheme, SUB_PROCESSOR, INCREASE_THRESHOLD, 20)
    set_ac(scheme, SUB_PROCESSOR, DECREASE_THRESHOLD, 10)
    set_ac(scheme, SUB_PROCESSOR, INCREASE_TIME, 1)
    set_ac(scheme, SUB_PROCESSOR, DECREASE_TIME, 3)
    
    # Core Parking Dinámico
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MIN, 10)
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MAX, 100)
    
    # DC: Eficiencia
    set_dc(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 5)
    set_dc(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 90 if laptop else 100)
    set_dc(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 0)
    
    # Periféricos
    set_ac(scheme, SUB_PCIEXPRESS, PCIE_ASPM, 0) # Off
    set_dc(scheme, SUB_PCIEXPRESS, PCIE_ASPM, 1 if laptop else 0)
    set_ac(scheme, SUB_DISK, DISK_IDLE, 0)
    
    reapply_scheme(scheme)
    
    # Optimizaciones de Red (Registry) - Valores "Dulces" (10)
    if is_admin():
        try:
            import winreg
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")
            # 10 decimal es un buen balance. 0xFFFFFFFF es inestable para audio.
            winreg.SetValueEx(key, "NetworkThrottlingIndex", 0, winreg.REG_DWORD, 10) 
            winreg.SetValueEx(key, "SystemResponsiveness", 0, winreg.REG_DWORD, 10)
            winreg.CloseKey(key)
        except:
            pass
            
    return True

def apply_mode_extremo():
    """
    MODO COMPETITIVO PURO:
    Sacrifica temperatura por latencia mínima absoluta.
    """
    if not is_windows(): return False
    scheme = get_active_scheme_guid()
    if not scheme: return False
    
    backup_current_power_settings()
    
    laptop = has_battery()
    
    # Todo al máximo, sin estados de reposo
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMIN, 100)
    set_ac(scheme, SUB_PROCESSOR, PROCTHROTTLEMAX, 100)
    set_ac(scheme, SUB_PROCESSOR, SYSTEM_COOLING_POLICY, 1)
    set_ac(scheme, SUB_PROCESSOR, PERFBOOSTMODE, 2) # Aggressive
    set_ac(scheme, SUB_PROCESSOR, IDLEDISABLE, 1)   # NO IDLE (Calor alto)
    
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MIN, 100) # Sin parking
    set_ac(scheme, SUB_PROCESSOR, CORE_PARK_MAX, 100)
    
    reapply_scheme(scheme)
    
    if is_admin():
        try:
            import winreg
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")
            winreg.SetValueEx(key, "NetworkThrottlingIndex", 0, winreg.REG_DWORD, 0xffffffff)
            winreg.SetValueEx(key, "SystemResponsiveness", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            
            # Prioridad GPU
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
        self.computer = Computer()
        self.computer.IsCpuEnabled = True
        try:
            self.computer.Open()
        except:
            pass
        self.current_temp = 0.0
        self.running = False
        self.show_in_tray = False
        self.icon = None
        self.lock = threading.Lock()
        
    def get_cpu_temperature(self):
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
        img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Color dinámico basado en temperatura
        color = (255, 255, 255, 255) # Blanco
        if temp > 60: color = (255, 165, 0, 255) # Naranja
        if temp > 80: color = (255, 0, 0, 255) # Rojo
        
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
        self.running = True
        while self.running:
            self.current_temp = self.get_cpu_temperature()
            with self.lock:
                if self.show_in_tray:
                    img = self.create_temp_icon(self.current_temp)
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
        try:
            self.computer.Close()
        except:
            pass