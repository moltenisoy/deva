"""
Sistema de limpieza automática con monitoreo de recursos
Ejecuta limpiezas según condiciones de CPU/Disco y programa futuras limpiezas
"""

import os
import sys
import json
import time
import threading
import psutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import shutil
import tkinter as tk

# === CONFIGURACIÓN ===
CONFIG_FILE = "config.json"
TEMP_THRESHOLD = 50  # % máximo de CPU/Disco para limpieza temporal
FULL_THRESHOLD = 40  # % máximo de CPU/Disco para limpieza completa
RETRY_INTERVAL = 30 * 60  # 30 minutos en segundos
TEMP_SCHEDULE_DAYS = 2  # 48 horas
FULL_SCHEDULE_DAYS = 7  # 7 días

# === FUNCIONES DE NOTIFICACIÓN ===
def mostrar_notificacion(mensaje, color="#39FF14"):
    """Muestra notificación estilo Matrix con mensaje personalizado"""
    def _show():
        root = tk.Tk()
        root.withdraw()
        root.update()

        noti = tk.Toplevel(root)
        noti.overrideredirect(True)
        noti.attributes("-topmost", True)
        noti.attributes("-alpha", 0.0)
        noti.configure(bg="#001a00")

        # Ajustar tamaño según longitud del mensaje
        ancho = max(350, len(mensaje) * 8)
        alto = 150
        margen_derecho = 50
        margen_superior = 100

        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        x = screen_w - ancho - margen_derecho
        y = margen_superior

        noti.geometry(f"{ancho}x{alto}+{x}+{y}")

        # Borde verde fosforescente
        frame = tk.Frame(noti, bg=color, bd=1, relief="flat")
        frame.pack(fill="both", expand=True, padx=2, pady=2)

        inner = tk.Frame(frame, bg="#001a00")
        inner.pack(fill="both", expand=True, padx=3, pady=3)

        # Mensaje con saltos de línea
        label = tk.Label(inner, text=mensaje, bg="#001a00", fg=color,
                        font=("Segoe UI", 12, "bold"), justify="center")
        label.pack(expand=True)

        # Fade-in
        def fade_in(step=0):
            alpha = step / 20.0
            if alpha < 1.0:
                noti.attributes("-alpha", alpha)
                root.after(30, fade_in, step + 1)
            else:
                noti.attributes("-alpha", 1.0)
                root.after(5000, fade_out)

        # Fade-out
        def fade_out(step=0):
            alpha = 1.0 - (step / 30.0)
            if alpha > 0:
                noti.attributes("-alpha", alpha)
                root.after(50, fade_out, step + 1)
            else:
                noti.destroy()
                root.destroy()

        fade_in()
        root.mainloop()

    threading.Thread(target=_show, daemon=True).start()

# === FUNCIONES DE LIMPIEZA ===
def rm_path(p):
    """Borra archivo o carpeta de forma segura"""
    try:
        p = Path(p)
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p, ignore_errors=True)
            return True
        elif p.exists():
            p.unlink(missing_ok=True)
            return True
    except:
        pass
    return False

def clear_dir(path):
    """Limpia contenido de directorio"""
    count = 0
    size = 0
    path = Path(path)
    if not path.exists():
        return count, size
    
    for item in path.iterdir():
        try:
            item_size = get_size(item)
            if rm_path(item):
                count += 1
                size += item_size
        except:
            pass
    return count, size

def get_size(path):
    """Obtiene tamaño de archivo o carpeta"""
    path = Path(path)
    if path.is_file():
        return path.stat().st_size
    elif path.is_dir():
        total = 0
        for item in path.rglob('*'):
            if item.is_file():
                try:
                    total += item.stat().st_size
                except:
                    pass
        return total
    return 0

def limpieza_temporal():
    """Limpieza básica de archivos temporales"""
    print("Ejecutando limpieza de temporales...")
    files_deleted = 0
    space_freed = 0
    
    env = os.environ
    USER = Path(env.get("USERPROFILE", "C:\\Users\\Default"))
    LOCAL = Path(env.get("LOCALAPPDATA", USER / "AppData" / "Local"))
    WINDIR = Path(env.get("WINDIR", "C:\\Windows"))
    
    temp_dirs = [
        Path(env.get("TEMP", "")),
        Path(env.get("TMP", "")),
        LOCAL / "Temp",
        WINDIR / "Temp"
    ]
    
    for temp_dir in temp_dirs:
        if temp_dir and temp_dir.exists():
            count, size = clear_dir(temp_dir)
            files_deleted += count
            space_freed += size
    
    # Prefetch básico
    prefetch = WINDIR / "Prefetch"
    if prefetch.exists():
        for file in prefetch.glob("*.pf"):
            try:
                size = file.stat().st_size
                file.unlink()
                files_deleted += 1
                space_freed += size
            except:
                pass
    
    return files_deleted, space_freed

def limpieza_completa():
    """Limpieza profunda del sistema"""
    print("Ejecutando limpieza completa...")
    files_deleted = 0
    space_freed = 0
    
    # Primero hacer limpieza temporal
    temp_files, temp_space = limpieza_temporal()
    files_deleted += temp_files
    space_freed += temp_space
    
    env = os.environ
    USER = Path(env.get("USERPROFILE", "C:\\Users\\Default"))
    LOCAL = Path(env.get("LOCALAPPDATA", USER / "AppData" / "Local"))
    ROAMING = Path(env.get("APPDATA", USER / "AppData" / "Roaming"))
    WINDIR = Path(env.get("WINDIR", "C:\\Windows"))
    
    # Lista de rutas adicionales para limpieza completa
    additional_paths = [
        LOCAL / "Microsoft" / "Windows" / "Explorer",  # thumbcache
        ROAMING / "Microsoft" / "Windows" / "Recent",
        LOCAL / "Microsoft" / "Windows" / "INetCache",
        LOCAL / "Microsoft" / "Windows" / "WebCache",
        WINDIR / "SoftwareDistribution" / "Download",
        Path("C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive"),
        Path("C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue"),
    ]
    
    # Navegadores principales
    browser_caches = [
        LOCAL / "Google" / "Chrome" / "User Data" / "Default" / "Cache",
        LOCAL / "Google" / "Chrome" / "User Data" / "Default" / "Code Cache",
        LOCAL / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache",
        LOCAL / "Microsoft" / "Edge" / "User Data" / "Default" / "Code Cache",
        ROAMING / "Mozilla" / "Firefox" / "Profiles",
    ]
    
    # Apps comunes
    app_caches = [
        ROAMING / "discord" / "Cache",
        ROAMING / "discord" / "Code Cache",
        LOCAL / "Discord" / "Cache",
        ROAMING / "Spotify" / "Storage",
        LOCAL / "Steam" / "appcache",
        ROAMING / "Code" / "Cache",
        ROAMING / "Code" / "CachedData",
        LOCAL / "Microsoft" / "Teams" / "Cache",
    ]
    
    all_paths = additional_paths + browser_caches + app_caches
    
    for path in all_paths:
        if path.exists():
            if path.is_dir():
                count, size = clear_dir(path)
            else:
                size = get_size(path)
                if rm_path(path):
                    count = 1
                else:
                    count = 0
                    size = 0
            files_deleted += count
            space_freed += size
    
    # Limpiar DNS y caché de red
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=5)
    except:
        pass
    
    return files_deleted, space_freed

# === FUNCIONES DE MONITOREO ===
def check_system_resources():
    """Verifica uso de CPU y disco"""
    cpu_percent = psutil.cpu_percent(interval=2)
    disk_usage = psutil.disk_io_counters()
    time.sleep(1)
    disk_usage2 = psutil.disk_io_counters()
    
    # Calcular actividad de disco (MB/s)
    disk_read_speed = (disk_usage2.read_bytes - disk_usage.read_bytes) / (1024 * 1024)
    disk_write_speed = (disk_usage2.write_bytes - disk_usage.write_bytes) / (1024 * 1024)
    disk_activity = (disk_read_speed + disk_write_speed) / 2
    
    # Considerar disco ocupado si > 10 MB/s
    disk_percent = min(100, disk_activity * 10)
    
    return cpu_percent, disk_percent

def wait_for_idle(threshold, max_wait=None):
    """Espera hasta que el sistema esté por debajo del threshold"""
    start_time = time.time()
    while True:
        cpu, disk = check_system_resources()
        print(f"CPU: {cpu:.1f}%, Disco: {disk:.1f}%")
        
        if cpu < threshold and disk < threshold:
            return True
        
        if max_wait and (time.time() - start_time) > max_wait:
            return False
        
        time.sleep(10)  # Verificar cada 10 segundos

# === GESTIÓN DE CONFIGURACIÓN ===
def load_config():
    """Carga configuración desde archivo JSON"""
    if not Path(CONFIG_FILE).exists():
        return {
            "last_temp_clean": None,
            "last_full_clean": None,
            "next_temp_clean": None,
            "next_full_clean": None
        }
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {
            "last_temp_clean": None,
            "last_full_clean": None,
            "next_temp_clean": None,
            "next_full_clean": None
        }

def save_config(config):
    """Guarda configuración en archivo JSON"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def should_run_cleaning(config, cleaning_type):
    """Verifica si debe ejecutarse una limpieza según la programación"""
    now = datetime.now()
    
    if cleaning_type == "temp":
        if not config.get("next_temp_clean"):
            return True
        next_clean = datetime.fromisoformat(config["next_temp_clean"])
        return now >= next_clean
    
    elif cleaning_type == "full":
        if not config.get("next_full_clean"):
            return True
        next_clean = datetime.fromisoformat(config["next_full_clean"])
        return now >= next_clean
    
    return False

def format_size(bytes):
    """Formatea bytes a unidad legible"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} TB"

# === FUNCIÓN PRINCIPAL ===
def main():
    print("=== Sistema de Limpieza Automática ===")
    print(f"Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Cargar configuración
    config = load_config()
    
    # Verificar si hay limpiezas programadas para hoy
    temp_pending = should_run_cleaning(config, "temp")
    full_pending = should_run_cleaning(config, "full")
    
    if not temp_pending and not full_pending:
        print("No hay limpiezas programadas para hoy.")
        print(f"Próxima limpieza temporal: {config.get('next_temp_clean', 'No programada')}")
        print(f"Próxima limpieza completa: {config.get('next_full_clean', 'No programada')}")
        sys.exit(0)
    
    # Flag para saber si se ejecutó alguna limpieza
    cleaning_done = False
    
    # === LIMPIEZA TEMPORAL (al inicio) ===
    if temp_pending:
        print("Limpieza temporal pendiente...")
        print(f"Esperando que CPU y disco estén por debajo de {TEMP_THRESHOLD}%...")
        
        while True:
            cpu, disk = check_system_resources()
            if cpu < TEMP_THRESHOLD and disk < TEMP_THRESHOLD:
                files, space = limpieza_temporal()
                
                # Actualizar configuración
                config["last_temp_clean"] = datetime.now().isoformat()
                config["next_temp_clean"] = (datetime.now() + timedelta(days=TEMP_SCHEDULE_DAYS)).isoformat()
                save_config(config)
                
                # Mostrar notificación
                mensaje = f"🧹 LIMPIEZA TEMPORAL COMPLETADA\n\n" \
                         f"Archivos eliminados: {files:,}\n" \
                         f"Espacio liberado: {format_size(space)}"
                mostrar_notificacion(mensaje)
                
                print(f"✓ Limpieza temporal completada: {files} archivos, {format_size(space)} liberados")
                cleaning_done = True
                break
            else:
                print(f"Sistema ocupado (CPU: {cpu:.1f}%, Disco: {disk:.1f}%). Reintentando en 30 min...")
                time.sleep(RETRY_INTERVAL)
    
    # === LIMPIEZA COMPLETA (después de 3 minutos) ===
    if full_pending:
        print("\nEsperando 3 minutos antes de verificar limpieza completa...")
        time.sleep(180)  # 3 minutos
        
        print("Limpieza completa pendiente...")
        print(f"Esperando que CPU y disco estén por debajo de {FULL_THRESHOLD}%...")
        
        while True:
            cpu, disk = check_system_resources()
            if cpu < FULL_THRESHOLD and disk < FULL_THRESHOLD:
                files, space = limpieza_completa()
                
                # Actualizar configuración
                config["last_full_clean"] = datetime.now().isoformat()
                config["next_full_clean"] = (datetime.now() + timedelta(days=FULL_SCHEDULE_DAYS)).isoformat()
                save_config(config)
                
                # Mostrar notificación
                mensaje = f"🚀 LIMPIEZA COMPLETA EJECUTADA\n\n" \
                         f"Archivos eliminados: {files:,}\n" \
                         f"Espacio liberado: {format_size(space)}"
                mostrar_notificacion(mensaje, "#00FF00")
                
                print(f"✓ Limpieza completa ejecutada: {files} archivos, {format_size(space)} liberados")
                cleaning_done = True
                break
            else:
                print(f"Sistema ocupado (CPU: {cpu:.1f}%, Disco: {disk:.1f}%). Reintentando en 30 min...")
                time.sleep(RETRY_INTERVAL)
    
    if cleaning_done:
        print("\n=== Limpieza finalizada con éxito ===")
        print(f"Próxima limpieza temporal: {config.get('next_temp_clean', 'No programada')}")
        print(f"Próxima limpieza completa: {config.get('next_full_clean', 'No programada')}")
    
    # Mantener notificaciones visibles antes de cerrar
    time.sleep(10)

if __name__ == "__main__":
    try:
        # Verificar permisos de administrador (opcional pero recomendado)
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠ Ejecutando sin permisos de administrador. Algunas limpiezas podrían fallar.")
            print("  Para mejores resultados, ejecuta como administrador.\n")
        
        main()
    except KeyboardInterrupt:
        print("\n\nLimpieza cancelada por el usuario.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()