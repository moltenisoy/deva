import winreg
import os
import time
import json
import tkinter as tk
from tkinter import ttk
from pathlib import Path
import sys
import subprocess
from datetime import datetime
import logging
import math

# --- LÓGICA DE FONDO (Sin cambios) ---

# Configuración de logging
logging.basicConfig(
    filename='autoinicio_monitor_halo.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Configuración
SCAN_INTERVAL = 60
KNOWN_ENTRIES_FILE = 'entradas_conocidas_halo.json'
CONFIG_FILE = 'config_halo.json'

# Claves de registro a escanear
REGISTRY_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

# Carpeta de inicio
STARTUP_FOLDER = os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\Start Menu\Programs\Startup")

# --- ESTÉTICA HALO 3 (igual a gui_Version2) ---

THEME = {
    "display": "Halo 3",
    "bg": "#0a0f14",
    "panel": "#0f1620",
    "text": "#d3e3ff",
    "accent1": "#3fa7d6",   # azul
    "accent2": "#8fd14f",   # verde
    "accentWarn": "#ff6b6b",# rojo
    "font_family": "Segoe UI",
}

def resource_path(filename: str) -> str:
    return str(Path(__file__).with_name(filename))

# Mapeo de colores locales hacia THEME (para mantener nombres usados)
COLOR_BG = THEME["bg"]
COLOR_CARD = THEME["panel"]
COLOR_PRIMARY = THEME["accent1"]     # encabezados y bordes
COLOR_SECONDARY = THEME["accent2"]   # acciones positivas
COLOR_DANGER = THEME["accentWarn"]   # acciones destructivas
COLOR_WARNING = THEME["accent1"]     # usamos acento azul para "posponer"
COLOR_TEXT = THEME["text"]
COLOR_TEXT_LIGHT = "#a9bbff"         # tono claro derivado
COLOR_SHADOW = "#071019"             # sombra sutil acorde al fondo

# Fuentes
FONT_PRIMARY = (THEME["font_family"], 10)
FONT_PRIMARY_BOLD = (THEME["font_family"], 11, "bold")
FONT_TITLE = (THEME["font_family"], 16, "bold")


class UNSCButton(tk.Canvas):
    def __init__(self, parent, text, command, bg_color, hover_color, width=160, height=45, **kwargs):
        super().__init__(parent, width=width, height=height, bg=COLOR_CARD, highlightthickness=0)
        self.text = text
        self.command = command
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.current_color = bg_color
        self.width = width
        self.height = height
        self.corner_radius = 10  # Para las esquinas cortadas

        self.draw_button()
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)

    def get_poly_coords(self, w, h, cr):
        # Coordenadas para un polígono con esquinas cortadas
        return [
            cr, 0, w - cr, 0,
            w, cr, w, h - cr,
            w - cr, h, cr, h,
            0, h - cr, 0, cr
        ]

    def draw_button(self):
        self.delete("all")

        w, h, cr = self.width, self.height, self.corner_radius

        # Sombra
        shadow_coords = self.get_poly_coords(w, h, cr)
        self.create_polygon(shadow_coords,
                            fill=COLOR_SHADOW, outline="", tags="shadow",
                            stipple="gray50")

        # Botón principal (ligeramente desplazado de la sombra)
        btn_coords = self.get_poly_coords(w-2, h-2, cr-1)
        # Centrar el botón sobre la sombra
        offset_x, offset_y = 1, 1
        btn_coords_shifted = [val + (offset_x if i % 2 == 0 else offset_y) for i, val in enumerate(btn_coords)]

        self.create_polygon(btn_coords_shifted,
                            fill=self.current_color, outline="", tags="button")

        # Texto
        self.create_text(w//2 + offset_x, h//2 + offset_y,
                         text=self.text.upper(), fill="#000000" if self.current_color in (COLOR_SECONDARY,) else "#000000",
                         font=FONT_PRIMARY_BOLD, tags="text")

    def animate_color(self, target_color):
        if not self.winfo_exists():
            return
        self.current_color = target_color
        self.draw_button()

    def on_enter(self, event):
        self.animate_color(self.hover_color)

    def on_leave(self, event):
        self.animate_color(self.bg_color)

    def on_click(self, event):
        if self.command:
            # Animación de click (desplazamiento)
            self.move("button", 1, 1)
            self.move("text", 1, 1)
            self.update()
            self.after(100, lambda: [
                self.move("button", -1, -1),
                self.move("text", -1, -1),
                self.command()
            ])

class HaloAlertWindow:
    def __init__(self, entrada):
        self.entrada = entrada
        self.respuesta = None
        self.window = tk.Toplevel()
        self.window.overrideredirect(True)
        self.window.configure(bg=COLOR_BG)

        # Icono (si existe)
        try:
            icon_path = resource_path("1.ico")
            if os.path.exists(icon_path):
                self.window.iconbitmap(default=icon_path)
        except Exception:
            pass

        # Tamaño y posición
        width, height = 700, 550
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f"{width}x{height}+{x}+{y}")

        self.window.attributes('-alpha', 0.0)
        self.window.attributes('-topmost', True)

        self.create_ui()
        self.fade_in()

        self.window.transient()
        self.window.grab_set()
        self.window.focus_force()

    def create_ui(self):
        # Frame principal con borde (estilo Halo: borde accent1)
        main_frame = tk.Frame(self.window, bg=COLOR_CARD,
                              highlightbackground=COLOR_PRIMARY, highlightthickness=2)
        main_frame.place(x=0, y=0, width=700, height=550)

        # Header
        header_frame = tk.Frame(main_frame, bg=COLOR_PRIMARY, height=80)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)

        # Icono animado (retícula HUD)
        self.icon_canvas = tk.Canvas(header_frame, width=70, height=70,
                                     bg=COLOR_PRIMARY, highlightthickness=0)
        self.icon_canvas.pack(side=tk.LEFT, padx=15, pady=5)
        self.reticle_size = 20
        self.reticle_growing = True
        self.animate_icon()

        # Título
        title_label = tk.Label(header_frame, text="ALERTA DE SISTEMA: NUEVA CONEXIÓN",
                               font=FONT_TITLE,
                               fg="#000000", bg=COLOR_PRIMARY)
        title_label.pack(side=tk.LEFT, pady=10)

        # Contenedor de contenido
        content_frame = tk.Frame(main_frame, bg=COLOR_CARD)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)

        # Subtítulo
        subtitle = tk.Label(content_frame,
                            text="EVALUACIÓN REQUERIDA: Entrada de autoinicio no autorizada detectada.",
                            font=(THEME["font_family"], 12), fg=COLOR_TEXT_LIGHT, bg=COLOR_CARD)
        subtitle.pack(pady=(0, 20), anchor="w")

        # Card de información
        info_card = tk.Frame(content_frame, bg=COLOR_BG, relief=tk.FLAT,
                             highlightbackground=COLOR_PRIMARY, highlightthickness=1)
        info_card.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        # Información detallada
        details = [
            ("TIPO DE CONTACTO", self.entrada['tipo']),
            ("IDENTIFICACIÓN", self.entrada['nombre']),
            ("VECTOR", self.entrada['ubicacion']),
        ]

        if self.entrada.get('valor'):
            details.append(("DATOS", self.entrada['valor']))

        for i, (label, value) in enumerate(details):
            detail_frame = tk.Frame(info_card, bg=COLOR_BG)
            detail_frame.pack(fill=tk.X, padx=15, pady=8)

            tk.Label(detail_frame, text=f"{label.upper()}:",
                     font=FONT_PRIMARY_BOLD,
                     fg=COLOR_PRIMARY, bg=COLOR_BG).pack(anchor="w")

            value_label = tk.Label(detail_frame, text=str(value),
                                   font=FONT_PRIMARY,
                                   fg=COLOR_TEXT, bg=COLOR_BG,
                                   wraplength=600, justify="left")
            value_label.pack(anchor="w", padx=(10, 0))

        # Botones
        button_frame = tk.Frame(content_frame, bg=COLOR_CARD)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        # Hover colors (ligeras variaciones)
        def lighten(hex_color, factor=0.12):
            try:
                c = hex_color.lstrip('#')
                r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
                r = min(255, int(r + (255 - r) * factor))
                g = min(255, int(g + (255 - g) * factor))
                b = min(255, int(b + (255 - b) * factor))
                return f"#{r:02x}{g:02x}{b:02x}"
            except Exception:
                return hex_color

        btn_keep = UNSCButton(button_frame, "Autorizar",
                              self.mantener, COLOR_SECONDARY, lighten(COLOR_SECONDARY))
        btn_keep.pack(side=tk.RIGHT, padx=5)

        btn_delete = UNSCButton(button_frame, "Eliminar",
                                self.eliminar, COLOR_DANGER, lighten(COLOR_DANGER))
        btn_delete.pack(side=tk.RIGHT, padx=5)

        btn_later = UNSCButton(button_frame, "Posponer",
                               self.preguntar_despues, COLOR_WARNING, lighten(COLOR_WARNING),
                               width=180)
        btn_later.pack(side=tk.LEFT, padx=5)

    def animate_icon(self):
        if not self.icon_canvas.winfo_exists():
            return

        self.icon_canvas.delete("all")
        x, y = 35, 35
        color = COLOR_BG

        # Retícula
        self.icon_canvas.create_oval(x - self.reticle_size, y - self.reticle_size,
                                     x + self.reticle_size, y + self.reticle_size,
                                     outline=color, width=2)

        # Crosshairs
        self.icon_canvas.create_line(x, y - self.reticle_size - 5, x, y - 5, fill=color, width=2)
        self.icon_canvas.create_line(x, y + 5, x, y + self.reticle_size + 5, fill=color, width=2)
        self.icon_canvas.create_line(x - self.reticle_size - 5, y, x - 5, y, fill=color, width=2)
        self.icon_canvas.create_line(x + 5, y, x + self.reticle_size + 5, y, fill=color, width=2)

        # Animar pulso
        if self.reticle_growing:
            self.reticle_size += 0.5
            if self.reticle_size >= 25:
                self.reticle_growing = False
        else:
            self.reticle_size -= 0.5
            if self.reticle_size <= 15:
                self.reticle_growing = True

        self.icon_canvas.after(50, self.animate_icon)

    def fade_in(self, alpha=0.0):
        if alpha < 0.95:  # Límite a 0.95 para un efecto "HUD"
            alpha += 0.1
            self.window.attributes('-alpha', alpha)
            self.window.after(30, lambda: self.fade_in(alpha))
        else:
            self.window.attributes('-alpha', 0.95)

    def fade_out(self, callback, alpha=0.95):
        if alpha > 0.0:
            alpha -= 0.1
            self.window.attributes('-alpha', alpha)
            self.window.after(30, lambda: self.fade_out(callback, alpha))
        else:
            callback()

    # --- Lógica de botones (Sin cambios) ---

    def mantener(self):
        self.respuesta = "MANTENER"
        self.guardar_decision()
        self.fade_out(self.window.destroy)

    def eliminar(self):
        self.respuesta = "ELIMINAR"
        eliminar_entrada(self.entrada['raw'])
        self.guardar_decision()
        self.fade_out(self.window.destroy)

    def preguntar_despues(self):
        self.respuesta = "PREGUNTAR_DESPUES"
        self.fade_out(self.window.destroy)

    def guardar_decision(self):
        if self.respuesta == "MANTENER":
            entradas_conocidas = cargar_entradas_conocidas()
            entradas_conocidas.append(self.entrada['raw'])
            guardar_entradas_conocidas(entradas_conocidas)

    def show(self):
        self.window.wait_window(self.window)
        return self.respuesta

# --- LÓGICA DE FONDO (Sin cambios) ---

def instalar_pyinstaller():
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
        logging.info("PyInstaller instalado correctamente.")
    except Exception as e:
        logging.error(f"Error instalando PyInstaller: {e}")

def cargar_entradas_conocidas():
    try:
        if not os.path.exists(KNOWN_ENTRIES_FILE):
            return []
        with open(KNOWN_ENTRIES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error cargando entradas conocidas: {e}")
        return []

def guardar_entradas_conocidas(entradas):
    try:
        with open(KNOWN_ENTRIES_FILE, 'w', encoding='utf-8') as f:
            json.dump(entradas, f, indent=2, ensure_ascii=False)
        logging.info(f"Entradas conocidas guardadas: {len(entradas)}")
    except Exception as e:
        logging.error(f"Error guardando entradas conocidas: {e}")

def obtener_autoinicios_actuales():
    entradas = []

    for root, path in REGISTRY_PATHS:
        try:
            with winreg.OpenKey(root, path) as key:
                for i in range(0, winreg.QueryInfoKey(key)[1]):
                    try:
                        nombre, valor, _ = winreg.EnumValue(key, i)
                        entradas.append({
                            'tipo': 'REGISTRO',
                            'ubicacion': path,
                            'nombre': nombre,
                            'valor': str(valor),
                            'raw': f"REG:{path} -> {nombre} => {valor}"
                        })
                    except Exception as e:
                        logging.warning(f"Error leyendo valor de registro: {e}")
        except FileNotFoundError:
            logging.warning(f"Ruta de registro no encontrada: {path}")
        except Exception as e:
            logging.error(f"Error accediendo a registro {path}: {e}")

    try:
        if os.path.exists(STARTUP_FOLDER):
            for file in os.listdir(STARTUP_FOLDER):
                if file.lower() not in ['desktop.ini', 'thumbs.db']:
                    file_path = os.path.join(STARTUP_FOLDER, file)
                    entradas.append({
                        'tipo': 'ARCHIVO',
                        'ubicacion': STARTUP_FOLDER,
                        'nombre': file,
                        'valor': file_path,
                        'raw': f"FILE:{STARTUP_FOLDER} -> {file}"
                    })
    except Exception as e:
        logging.error(f"Error escaneando carpeta de inicio: {e}")

    return entradas

def eliminar_entrada(entrada):
    try:
        if entrada.startswith("REG:"):
            _, resto = entrada.split(":", 1)
            path, datos = resto.split("->")
            path = path.strip()
            nombre = datos.split("=>")[0].strip()

            for root, reg_path in REGISTRY_PATHS:
                if reg_path == path:
                    try:
                        with winreg.OpenKey(root, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                            winreg.DeleteValue(key, nombre)
                        logging.info(f"Entrada de registro eliminada: {nombre}")
                        return True
                    except Exception as e:
                        logging.error(f"Error eliminando entrada de registro: {e}")

        elif entrada.startswith("FILE:"):
            _, resto = entrada.split(":", 1)
            folder, file = resto.split("->")
            archivo = os.path.join(folder.strip(), file.strip())

            if os.path.exists(archivo):
                os.remove(archivo)
                logging.info(f"Archivo eliminado: {archivo}")
                return True
    except Exception as e:
        logging.error(f"Error eliminando entrada: {e}")
        return False

if __name__ == '__main__':
    try:
        import PyInstaller
    except ImportError:
        instalar_pyinstaller()

    root = tk.Tk()
    root.withdraw()

    try:
        entradas_conocidas = cargar_entradas_conocidas()
        actuales = obtener_autoinicios_actuales()
        nuevas = [e for e in actuales if e['raw'] not in entradas_conocidas]

        if nuevas:
            logging.info(f"Nuevas entradas detectadas: {len(nuevas)}")
            for nueva in nuevas:
                alert = HaloAlertWindow(nueva)  # Ventana modal por cada nueva entrada
                respuesta = alert.show()
                logging.info(f"Respuesta para {nueva['nombre']}: {respuesta}")
        else:
            logging.info("No se detectaron nuevas entradas")
    except Exception as e:
        logging.error(f"Error durante la ejecución: {e}")
    finally:
        # Cierre garantizado de la app para que no quede en segundo plano
        try:
            if root.winfo_exists():
                root.destroy()
        except Exception as e:
            logging.error(f"Error al cerrar la aplicación: {e}")
        # Asegura que el proceso termine
        sys.exit(0)