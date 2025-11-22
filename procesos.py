import json
import os
import sys
import time
import threading
import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta
from typing import Dict, Set

import psutil

try:
    from screeninfo import get_monitors
except ImportError:
    get_monitors = None


CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# ---------------------- Configuración ---------------------- #

DEFAULT_EXTRA_CONFIG = {
    "idle_process_monitoring": {
        # minutos sin ser ventana activa para considerar "inactivo"
        "idle_minutes_threshold": 60,
        # intervalo entre revisiones (segundos)
        "check_interval_seconds": 60,
        # porcentaje mínimo de CPU/DISCO para considerar actividad baja
        "low_activity_percent_threshold": 1.0,
        # porcentaje a partir del cual se considera actividad alta (no preguntar y no cerrar)
        "high_activity_percent_threshold": 5.0,
        # lista blanca de procesos por nombre de ejecutable (case-insensitive)
        "process_whitelist": [
            "explorer.exe",
            "System",
            "System Idle Process"
        ],
        # si True, se aplican también nombres de proceso listados en "whitelist_files"
        "inherit_file_whitelist_as_process_names": False
    }
}


def load_and_patch_config(path: str) -> Dict:
    """
    Carga config.json, añade las nuevas claves bajo 'idle_process_monitoring' si no existen,
    sin alterar las claves existentes, y guarda de nuevo el archivo si fue modificado.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No se encontró el archivo de configuración: {path}")

    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)

    original_config = json.dumps(config, sort_keys=True, ensure_ascii=False, indent=2)

    # Añadir sección 'idle_process_monitoring' y sus campos solo si faltan
    if "idle_process_monitoring" not in config or not isinstance(config["idle_process_monitoring"], dict):
        config["idle_process_monitoring"] = {}

    idle_conf = config["idle_process_monitoring"]
    for k, v in DEFAULT_EXTRA_CONFIG["idle_process_monitoring"].items():
        if k not in idle_conf:
            idle_conf[k] = v

    patched_config = json.dumps(config, sort_keys=True, ensure_ascii=False, indent=2)

    if patched_config != original_config:
        # Guardar respetando formato JSON estándar; el orden de claves puede cambiar,
        # pero el contenido original se mantiene.
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

    return config


# ---------------------- Utilidades Win32 ---------------------- #

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

GetForegroundWindow = user32.GetForegroundWindow
GetWindowThreadProcessId = user32.GetWindowThreadProcessId

EnumWindows = user32.EnumWindows
IsWindowVisible = user32.IsWindowVisible
GetWindowTextW = user32.GetWindowTextW
GetWindowTextLengthW = user32.GetWindowTextLengthW

SW_SHOWNOACTIVATE = 4
HWND_TOPMOST = -1
SWP_NOSIZE = 0x0001
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010

SetWindowPos = user32.SetWindowPos
MoveWindow = user32.MoveWindow
GetWindowRect = user32.GetWindowRect


def get_foreground_pid() -> int | None:
    hwnd = GetForegroundWindow()
    if not hwnd:
        return None
    pid = wintypes.DWORD()
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value or None


def list_top_level_windows():
    windows = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    def enum_proc(hwnd, lParam):
        if not IsWindowVisible(hwnd):
            return True
        length = GetWindowTextLengthW(hwnd)
        if length == 0:
            return True
        buff = ctypes.create_unicode_buffer(length + 1)
        GetWindowTextW(hwnd, buff, length + 1)
        title = buff.value.strip()
        if title:
            windows.append((hwnd, title))
        return True

    EnumWindows(enum_proc, 0)
    return windows


def get_monitor_size():
    # Usamos screeninfo si está disponible; si no, fallback a GetSystemMetrics
    if get_monitors:
        mons = get_monitors()
        if mons:
            m = mons[0]
            return m.width, m.height
    SM_CXSCREEN = 0
    SM_CYSCREEN = 1
    width = user32.GetSystemMetrics(SM_CXSCREEN)
    height = user32.GetSystemMetrics(SM_CYSCREEN)
    return width, height


# ---------------------- Notificación deslizante ---------------------- #

import tkinter as tk


class SlideNotification:
    def __init__(self, title: str, message: str, process_name: str):
        self.result = None  # "keep", "close", None
        self.root = tk.Tk()
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)
        self.root.title(title)

        # Construcción UI
        frame = tk.Frame(self.root, bg="#333333")
        frame.pack(fill="both", expand=True)

        lbl_title = tk.Label(frame, text=title, bg="#333333", fg="white", font=("Segoe UI", 11, "bold"))
        lbl_title.pack(padx=10, pady=(8, 2), anchor="w")

        lbl_msg = tk.Label(frame, text=message, bg="#333333", fg="white", font=("Segoe UI", 9), justify="left")
        lbl_msg.pack(padx=10, pady=(0, 8), anchor="w")

        btn_frame = tk.Frame(frame, bg="#333333")
        btn_frame.pack(padx=10, pady=(0, 8), anchor="e")

        btn_keep = tk.Button(btn_frame, text="Mantener", command=self._on_keep, bg="#4CAF50", fg="white")
        btn_keep.pack(side="left", padx=(0, 5))

        btn_close = tk.Button(btn_frame, text="Cerrar", command=self._on_close, bg="#F44336", fg="white")
        btn_close.pack(side="left")

        self.process_name = process_name

        # Posición inicial y final
        self.screen_width, self.screen_height = get_monitor_size()
        self.width = 400
        self.height = 110

        self.final_y = 50
        self.x = (self.screen_width - self.width) // 2
        self.y = -self.height  # Arriba de la pantalla

        self.root.geometry(f"{self.width}x{self.height}+{self.x}+{self.y}")

    def _on_keep(self):
        self.result = "keep"
        self.root.destroy()

    def _on_close(self):
        self.result = "close"
        self.root.destroy()

    def _animate(self):
        # Deslizamiento hacia abajo hasta final_y
        step = 10
        delay = 10  # ms
        while self.y < self.final_y:
            self.y += step
            if self.y > self.final_y:
                self.y = self.final_y
            self.root.geometry(f"{self.width}x{self.height}+{self.x}+{self.y}")
            self.root.update()
            time.sleep(delay / 1000)

    def show(self) -> str | None:
        # Ejecutar animación en un hilo
        self.root.after(10, self._animate)
        self.root.mainloop()
        return self.result


# ---------------------- Lógica de monitor de procesos ---------------------- #

class IdleProcessMonitor:
    def __init__(self, config: Dict):
        self.config = config
        idle_cfg = config.get("idle_process_monitoring", {})

        self.idle_minutes_threshold: int = int(idle_cfg.get("idle_minutes_threshold", 60))
        self.check_interval_seconds: int = int(idle_cfg.get("check_interval_seconds", 60))
        self.low_activity_threshold: float = float(idle_cfg.get("low_activity_percent_threshold", 1.0))
        self.high_activity_threshold: float = float(idle_cfg.get("high_activity_percent_threshold", 5.0))

        process_whitelist = idle_cfg.get("process_whitelist", [])
        self.process_whitelist: Set[str] = {p.lower() for p in process_whitelist}

        # Opcional: heredar nombres de la lista blanca de archivos
        if idle_cfg.get("inherit_file_whitelist_as_process_names", False):
            for fname in config.get("whitelist_files", []):
                self.process_whitelist.add(fname.lower())

        self.last_foreground_change: Dict[int, datetime] = {}
        self.process_last_seen: Dict[int, datetime] = {}
        self.excluded_for_session: Set[int] = set()  # pids ignorados esta sesión

        self.lock = threading.Lock()

        # Inicializamos CPU percent para todos los procesos (primer muestreo = referencia)
        for p in psutil.process_iter(attrs=["pid"]):
            try:
                p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _update_foreground_process(self):
        pid = get_foreground_pid()
        if pid is None:
            return
        now = datetime.now()
        with self.lock:
            self.last_foreground_change[pid] = now
            self.process_last_seen[pid] = now

    def _refresh_process_last_seen(self):
        now = datetime.now()
        with self.lock:
            for p in psutil.process_iter(attrs=["pid"]):
                pid = p.info["pid"]
                self.process_last_seen[pid] = now

    def _get_idle_processes(self):
        now = datetime.now()
        idle_processes = []
        min_delta = timedelta(minutes=self.idle_minutes_threshold)

        with self.lock:
            for p in psutil.process_iter(attrs=["pid", "name", "username"]):
                pid = p.info["pid"]

                if pid in self.excluded_for_session:
                    continue

                # Ignoramos procesos del sistema sin usuario
                username = p.info.get("username") or ""
                if not username:
                    continue

                name = (p.info.get("name") or "").lower()
                if name in self.process_whitelist:
                    continue

                last_fg = self.last_foreground_change.get(pid)
                if not last_fg:
                    # si nunca fue foreground, contamos desde que lo "vimos" por primera vez
                    last_seen = self.process_last_seen.get(pid)
                    if not last_seen:
                        continue
                    delta = now - last_seen
                else:
                    delta = now - last_fg

                if delta >= min_delta:
                    idle_processes.append(p)
        return idle_processes

    def _get_disk_activity_percent(self, process: psutil.Process, interval: float = 0.0) -> float:
        """
        Aproximación: se mira IO del proceso en dos instantes y se extrapola en %
        respecto al total de IO del sistema en ese tiempo. No es exacto, pero sirve como señal.
        """
        try:
            p1 = process.io_counters()
            sys1 = psutil.disk_io_counters()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.0

        if interval <= 0:
            interval = 1.0
        time.sleep(interval)

        try:
            p2 = process.io_counters()
            sys2 = psutil.disk_io_counters()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.0

        p_bytes = (p2.read_bytes - p1.read_bytes) + (p2.write_bytes - p1.write_bytes)
        sys_bytes = (sys2.read_bytes - sys1.read_bytes) + (sys2.write_bytes - sys1.write_bytes)
        if sys_bytes <= 0:
            return 0.0
        percent = (p_bytes / sys_bytes) * 100.0
        return percent

    def _show_notification_and_get_choice(self, proc: psutil.Process, cpu: float, disk: float) -> str | None:
        name = proc.info.get("name") or f"PID {proc.pid}"
        msg = (
            f"La aplicación \"{name}\" lleva mucho tiempo en segundo plano\n"
            f"CPU: {cpu:.1f}%  |  Disco: {disk:.1f}%\n\n"
            f"¿Qué deseas hacer con esta aplicación?"
        )

        result_container = {}

        def _run():
            notif = SlideNotification("Aplicación en segundo plano", msg, name)
            result_container["result"] = notif.show()

        t = threading.Thread(target=_run)
        t.start()
        t.join()
        return result_container.get("result")

    def _terminate_process(self, proc: psutil.Process):
        try:
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def monitor_loop(self):
        print("Iniciando monitor de procesos inactivos...")
        while True:
            try:
                self._update_foreground_process()
                self._refresh_process_last_seen()

                idle_list = self._get_idle_processes()

                for proc in idle_list:
                    try:
                        # Recalcular CPU y disco
                        cpu = proc.cpu_percent(interval=0.1)
                        disk = self._get_disk_activity_percent(proc, interval=0.2)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                    # Si supera el umbral alto en CPU o disco, lo sacamos del monitoreo sin avisar
                    if cpu >= self.high_activity_threshold or disk >= self.high_activity_threshold:
                        print(
                            f"[INFO] Proceso {proc.pid} ({proc.info.get('name')}) "
                            f"tiene alta actividad (CPU={cpu:.1f}%, Disco={disk:.1f}%), "
                            f"se mantiene y deja de monitorear en esta sesión."
                        )
                        self.excluded_for_session.add(proc.pid)
                        continue

                    # Si por debajo de 1% en ambos -> cerrar sin preguntar
                    if cpu < self.low_activity_threshold and disk < self.low_activity_threshold:
                        print(
                            f"[CERRAR] Proceso {proc.pid} ({proc.info.get('name')}) "
                            f"inactivo (CPU={cpu:.1f}%, Disco={disk:.1f}%). Cerrando..."
                        )
                        self._terminate_process(proc)
                        self.excluded_for_session.add(proc.pid)
                        continue

                    # Entre 1% y 5% en alguno -> mostrar notificación
                    print(
                        f"[NOTIFICAR] Proceso {proc.pid} ({proc.info.get('name')}) "
                        f"inactivo con actividad moderada (CPU={cpu:.1f}%, Disco={disk:.1f}%)."
                    )
                    choice = self._show_notification_and_get_choice(proc, cpu, disk)
                    if choice == "keep":
                        print(f"[MANTENER] Proceso {proc.pid} marcado para mantener en esta sesión.")
                        self.excluded_for_session.add(proc.pid)
                    elif choice == "close":
                        print(f"[CERRAR-USUARIO] Proceso {proc.pid} será cerrado por decisión del usuario.")
                        self._terminate_process(proc)
                        self.excluded_for_session.add(proc.pid)
                    else:
                        # Si la notificación se cierra sin decisión clara, volvemos a evaluar en la siguiente iteración
                        print(f"[SIN DECISIÓN] Proceso {proc.pid} se reevaluará más adelante.")

                time.sleep(self.check_interval_seconds)

            except KeyboardInterrupt:
                print("Monitor detenido por el usuario.")
                break
            except Exception as e:
                print(f"Error en monitor_loop: {e}")
                time.sleep(self.check_interval_seconds)


def main():
    try:
        config = load_and_patch_config(CONFIG_PATH)
    except Exception as e:
        print(f"Error cargando configuración: {e}")
        sys.exit(1)

    monitor = IdleProcessMonitor(config)
    monitor.monitor_loop()


if __name__ == "__main__":
    main()