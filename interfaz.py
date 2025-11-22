# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk
import psutil
import os
import json
import sys
from pathlib import Path
import pystray
from PIL import Image, ImageDraw
import threading
import ctypes
import multiprocessing
import procesos
import time
import biblioteca
import entradas
import optimuslight

BG_COLOR = '#1a3a52'
TXT_COLOR = '#FFFFFF'
FX_COLOR = '#0055A4'
BTN_HOVER_BG = '#003d7a'
BTN_HOVER_FG = '#FFFFFF'
LIST_BG = '#2c5268'
LIST_SELECT_BG = '#0055A4'
DIVIDER_COLOR = '#87CEEB'
TRANSPARENT_COLOR = '#000001'

CUSTOM_FONT_FAMILY = "Arial"

def get_script_dir():
    return Path(__file__).parent.resolve()

def load_custom_font():
    global CUSTOM_FONT_FAMILY
    font_path = get_script_dir() / "1.ttf"
    if font_path.exists():
        try:
            ctypes.windll.gdi32.AddFontResourceExW(str(font_path), 0x10, 0)
            CUSTOM_FONT_FAMILY = "CustomFont"
        except:
            pass

def load_config():
    config_path = get_script_dir() / "config.json"
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_config(config):
    config_path = get_script_dir() / "config.json"
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

def get_user_processes():
    procesos = set()
    current_user = psutil.Process().username()
    for p in psutil.process_iter(['name', 'username']):
        info = p.info
        if info.get('username') == current_user:
            name = info.get('name')
            if name:
                procesos.add(name)
    return sorted(list(procesos))

class ThreeStateSwitch(tk.Canvas):
    def __init__(self, parent, initial_mode="baja_latencia", command=None, **kwargs):
        super().__init__(parent, height=50, bg=BG_COLOR, highlightthickness=0, **kwargs)
        self.command = command
        self.mode_map = ["ahorro", "baja_latencia", "extremo"]
        self.current_idx = 1
        if initial_mode in self.mode_map:
            self.current_idx = self.mode_map.index(initial_mode)
        self.positions = []
        self.y_pos = 25
        self.radius = 10
        self.bind('<Button-1>', self.on_click)
        self.bind('<Configure>', self.on_resize)

    def on_resize(self, event):
        w = event.width
        self.positions = [w * 0.2, w * 0.5, w * 0.8]
        self.draw_switch()

    def draw_switch(self):
        self.delete("all")
        if not self.positions: return
        self.create_line(self.positions[0], self.y_pos, self.positions[2], self.y_pos, 
                         fill="#555555", width=4, capstyle=tk.ROUND)
        for i, x in enumerate(self.positions):
            if i == self.current_idx:
                self.create_oval(x - self.radius - 2, self.y_pos - self.radius - 2,
                                 x + self.radius + 2, self.y_pos + self.radius + 2,
                                 fill=DIVIDER_COLOR, outline=DIVIDER_COLOR)
            else:
                self.create_oval(x - self.radius, self.y_pos - self.radius,
                                 x + self.radius, self.y_pos + self.radius,
                                 fill="#333333", outline="#555555", width=2)
        self.create_text(self.positions[0], self.y_pos + 20, text="AHORRO", fill="#AAAAAA", font=(CUSTOM_FONT_FAMILY, 7))
        self.create_text(self.positions[1], self.y_pos + 20, text="LATENCIA", fill="#AAAAAA", font=(CUSTOM_FONT_FAMILY, 7))
        self.create_text(self.positions[2], self.y_pos + 20, text="EXTREMO", fill="#AAAAAA", font=(CUSTOM_FONT_FAMILY, 7))

    def on_click(self, event):
        closest_idx = -1
        min_dist = 1000
        for i, x in enumerate(self.positions):
            dist = abs(event.x - x)
            if dist < 40:
                if dist < min_dist:
                    min_dist = dist
                    closest_idx = i
        if closest_idx != -1 and closest_idx != self.current_idx:
            self.current_idx = closest_idx
            self.draw_switch()
            if self.command:
                self.command(self.mode_map[self.current_idx])

class ModernToggle(tk.Canvas):
    def __init__(self, parent, variable, **kwargs):
        super().__init__(parent, width=50, height=24, bg=BG_COLOR, highlightthickness=0, **kwargs)
        self.variable = variable
        self.variable.trace_add('write', self.update_toggle)
        self.bg_off = '#555555'
        self.bg_on = FX_COLOR
        self.toggle_color = '#FFFFFF'
        self.create_rectangle(2, 2, 48, 22, fill=self.bg_off, outline='', tags='background')
        self.create_rectangle(4, 4, 22, 20, fill=self.toggle_color, outline='', tags='toggle')
        self.create_rectangle(8, 8, 18, 16, fill=self.bg_off, outline='', tags='detail')
        self.bind('<Button-1>', self.on_click)
        self.update_toggle()

    def on_click(self, event):
        self.variable.set(not self.variable.get())

    def update_toggle(self, *args):
        if self.variable.get():
            self.coords('toggle', 30, 4, 48, 20)
            self.coords('detail', 34, 8, 44, 16)
            self.itemconfig('background', fill=self.bg_on)
            self.itemconfig('detail', fill=self.bg_on)
        else:
            self.coords('toggle', 4, 4, 22, 20)
            self.coords('detail', 8, 8, 18, 16)
            self.itemconfig('background', fill=self.bg_off)
            self.itemconfig('detail', fill=self.bg_off)

class App(tk.Tk):
    def __init__(self):
        load_custom_font()
        super().__init__()
        self.overrideredirect(True)
        self.geometry("820x620")
        try:
            self.wm_attributes('-transparentcolor', TRANSPARENT_COLOR)
        except:
            pass
        self.configure(bg=TRANSPARENT_COLOR)
        self.x_axis = None
        self.y_axis = None
        self.config = load_config()
        self.ensure_config_defaults()
        self.optimus_process = None
        self.backend_monitor = optimuslight.TemperatureMonitor()
        self.backend_monitor.show_in_tray = self.config["thermal_management"].get("show_temp_in_tray", True)
        threading.Thread(target=self.backend_monitor.start_monitoring, daemon=True).start()
        optimuslight.apply_power_mode(self.config["power_mode"])
        self.tray_icon = None
        self.setup_tray_icon()
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.configure_styles()
        self.bg_canvas = tk.Canvas(self, bg=TRANSPARENT_COLOR, highlightthickness=0)
        self.bg_canvas.pack(fill="both", expand=True)
        self.round_rect(self.bg_canvas, 0, 0, 820, 620, 20, fill=DIVIDER_COLOR, outline="")
        self.round_rect(self.bg_canvas, 4, 4, 816, 616, 16, fill=BG_COLOR, outline="")
        self.internal_container = tk.Frame(self.bg_canvas, bg=BG_COLOR)
        self.internal_container.place(x=10, y=10, width=800, height=600)
        self.title_bar = tk.Frame(self.internal_container, bg=BG_COLOR, height=30)
        self.title_bar.pack(fill="x", side="top")
        self.title_bar.bind("<ButtonPress-1>", self.start_move)
        self.title_bar.bind("<B1-Motion>", self.do_move)
        title_lbl = tk.Label(self.title_bar, text="PANEL DE CONTROL", bg=BG_COLOR, fg=DIVIDER_COLOR, 
                             font=(CUSTOM_FONT_FAMILY, 12, 'bold'))
        title_lbl.pack(side="left", padx=10)
        title_lbl.bind("<ButtonPress-1>", self.start_move)
        title_lbl.bind("<B1-Motion>", self.do_move)
        close_btn = tk.Button(self.title_bar, text="✕", bg=BG_COLOR, fg=TXT_COLOR, 
                              activebackground="red", activeforeground="white",
                              bd=0, font=("Arial", 12), command=self.hide_window)
        close_btn.pack(side="right", padx=10)
        right_frame = ttk.Frame(self.internal_container, style='TFrame')
        right_frame.pack(side="right", fill="y", padx=(10, 10), pady=10)
        divider = tk.Frame(self.internal_container, bg=DIVIDER_COLOR, width=2)
        divider.pack(side="right", fill="y", pady=10)
        self.main_frame = ttk.Frame(self.internal_container, style='TFrame')
        self.main_frame.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        self.panels = {}
        self.create_panel_procesos()
        self.create_panel_listas()
        self.create_panel_biblioteca()
        self.create_panel_monitoreo()
        self.create_panel_gestion_termica()
        self.nav_buttons = {}
        self.create_nav_button(right_frame, "PROCESOS", "procesos")
        self.create_nav_button(right_frame, "LISTAS", "listas")
        self.create_nav_button(right_frame, "BIBLIOTECA", "biblioteca")
        self.create_nav_button(right_frame, "MONITOREO", "monitoreo")
        self.create_nav_button(right_frame, "GESTIÓN TÉRMICA", "gestion_termica")
        self.show_panel("procesos")
        threading.Thread(target=self._temporizador_ejecutar_biblioteca, daemon=True).start()
        threading.Thread(target=self._temporizador_ejecutar_entradas, daemon=True).start()
        self.procesos_monitor_proc = None
        threading.Thread(target=self._control_procesos_monitor, daemon=True).start()
        if self.config.get("optimizer_enabled", False):
            self.start_optimus()

    def start_optimus(self):
        if self.optimus_process is None or not self.optimus_process.is_alive():
            self.optimus_process = multiprocessing.Process(target=optimuslight.main, daemon=True)
            self.optimus_process.start()

    def stop_optimus(self):
        if self.optimus_process and self.optimus_process.is_alive():
            self.optimus_process.terminate()
            self.optimus_process.join()

    def round_rect(self, canvas, x1, y1, x2, y2, radius=25, **kwargs):
        points = [x1+radius, y1, x1+radius, y1, x2-radius, y1, x2-radius, y1, x2, y1, x2, y1+radius, x2, y1+radius, x2, y2-radius, x2, y2-radius, x2, y2, x2-radius, y2, x2-radius, y2, x1+radius, y2, x1+radius, y2, x1, y2, x1, y2-radius, x1, y2-radius, x1, y1+radius, x1, y1+radius, x1, y1]
        return canvas.create_polygon(points, **kwargs, smooth=True)

    def start_move(self, event):
        self.x_axis = event.x
        self.y_axis = event.y

    def do_move(self, event):
        deltax = event.x - self.x_axis
        deltay = event.y - self.y_axis
        x = self.winfo_x() + deltax
        y = self.winfo_y() + deltay
        self.geometry(f"+{x}+{y}")

    def ensure_config_defaults(self):
        if "power_mode" not in self.config:
            self.config["power_mode"] = "baja_latencia"
        if "thermal_management" not in self.config:
            self.config["thermal_management"] = {"show_temp_in_tray": True}
        self.lista_blanca = self.config.get("process_whitelist", [])
        self.lista_juegos = self.config.get("game_processes", [])

    def _temporizador_ejecutar_entradas(self):
        time.sleep(10)
        entradas_conocidas = entradas.cargar_entradas_conocidas()
        actuales = entradas.obtener_autoinicios_actuales()
        nuevas = [e for e in actuales if e['raw'] not in entradas_conocidas]
        if nuevas:
            for nueva in nuevas:
                alert = entradas.HaloAlertWindow(nueva)
                alert.show()

    def _control_procesos_monitor(self):
        while True:
            game_running = False
            running_names = {p.info['name'] for p in psutil.process_iter(['name'])}
            for game in self.lista_juegos:
                if game in running_names:
                    game_running = True
                    break
            if game_running:
                if self.procesos_monitor_proc and self.procesos_monitor_proc.is_alive():
                    self.procesos_monitor_proc.terminate()
                    self.procesos_monitor_proc.join()
            else:
                if self.procesos_monitor_proc is None or not self.procesos_monitor_proc.is_alive():
                    self.procesos_monitor_proc = multiprocessing.Process(target=procesos.main, daemon=True)
                    self.procesos_monitor_proc.start()
            time.sleep(5)

    def _temporizador_ejecutar_biblioteca(self):
        minutos_espera = self.config.get("minutes_before_check", 5)
        minutos_espera = int(minutos_espera)
        segundos_espera = max(0, minutos_espera * 60)
        for _ in range(segundos_espera):
            if not self.winfo_exists():
                return
            time.sleep(1)
        bib = biblioteca.BibliotecaInteligente()
        bib.run_single_cycle()

    def setup_tray_icon(self):
        icon_path = get_script_dir() / "1.ico"
        if icon_path.exists():
            image = Image.open(icon_path)
        else:
            image = self.create_default_icon()
        def on_toggle_temp(icon, item):
            new_state = not item.checked
            self.config["thermal_management"]["show_temp_in_tray"] = new_state
            self.backend_monitor.set_visibility(new_state)
            save_config(self.config)
        menu = pystray.Menu(
            pystray.MenuItem("MOSTRAR TEMPERATURA", on_toggle_temp, checked=lambda item: self.config["thermal_management"].get("show_temp_in_tray", True)),
            pystray.MenuItem("AJUSTES", self.show_window),
            pystray.MenuItem("CERRAR SCRIPT", self.quit_app)
        )
        self.tray_icon = pystray.Icon("panel_control", image, "PANEL DE CONTROL", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def create_default_icon(self):
        width = 64
        height = 64
        image = Image.new('RGB', (width, height), color=(26, 58, 82))
        dc = ImageDraw.Draw(image)
        dc.rectangle([16, 16, 48, 48], fill=(0, 85, 164))
        return image

    def hide_window(self):
        self.withdraw()

    def show_window(self, icon=None, item=None):
        self.deiconify()
        self.lift()
        self.focus_force()

    def quit_app(self, icon=None, item=None):
        if self.optimus_process and self.optimus_process.is_alive():
            self.optimus_process.terminate()
        if self.procesos_monitor_proc and self.procesos_monitor_proc.is_alive():
            self.procesos_monitor_proc.terminate()
        self.backend_monitor.stop()
        self.save_all_config()
        if self.tray_icon:
            self.tray_icon.stop()
        self.quit()
        self.destroy()
        sys.exit(0)

    def configure_styles(self):
        self.style.configure('TFrame', background=BG_COLOR)
        self.style.configure('TLabel', background=BG_COLOR, foreground=TXT_COLOR, font=(CUSTOM_FONT_FAMILY, 10))
        self.style.configure('Title.TLabel', font=(CUSTOM_FONT_FAMILY, 14, 'bold'))
        self.style.configure('TButton', background=BG_COLOR, foreground=TXT_COLOR,
                             bordercolor=FX_COLOR, borderwidth=2, font=(CUSTOM_FONT_FAMILY, 10, 'bold'))
        self.style.map('TButton', background=[('active', BTN_HOVER_BG)], foreground=[('active', BTN_HOVER_FG)])
        self.style.configure('TEntry', fieldbackground=LIST_BG, foreground=TXT_COLOR,
                             bordercolor=FX_COLOR, borderwidth=2, font=(CUSTOM_FONT_FAMILY, 10))
        self.style.configure('TCheckbutton', background=BG_COLOR, foreground=TXT_COLOR, font=(CUSTOM_FONT_FAMILY, 10))

    def create_nav_button(self, parent, text, panel_name):
        button = ttk.Button(parent, text=text, command=lambda: self.show_panel(panel_name))
        button.pack(pady=5, ipadx=10, ipady=5, fill='x')
        self.nav_buttons[panel_name] = button

    def show_panel(self, panel_name):
        for name, panel in self.panels.items():
            if name == panel_name:
                panel.pack(fill="both", expand=True)
                self.nav_buttons[name].state(['disabled'])
            else:
                panel.pack_forget()
                self.nav_buttons[name].state(['!disabled'])

    def create_panel_procesos(self):
        panel = ttk.Frame(self.main_frame, style='TFrame')
        self.panels['procesos'] = panel
        ttk.Label(panel, text="PROCESOS DE USUARIO", style='Title.TLabel').pack(pady=(0, 10))
        optimizer_frame = ttk.Frame(panel, style='TFrame')
        optimizer_frame.pack(fill='x', padx=20, pady=(0, 15))
        toggle_container = ttk.Frame(optimizer_frame, style='TFrame')
        toggle_container.pack(anchor='w', pady=(0,10))
        ttk.Label(toggle_container, text="ACTIVAR OPTIMUSLIGHT", style='TLabel').pack(side='left', padx=(0, 10))
        self.optimizer_enabled_var = tk.BooleanVar(value=self.config.get("optimizer_enabled", True))
        optimizer_toggle = ModernToggle(toggle_container, self.optimizer_enabled_var)
        optimizer_toggle.pack(side='left')
        self.optimizer_enabled_var.trace_add('write', lambda *args: self.on_optimizer_toggle())
        mode_frame = ttk.Frame(optimizer_frame, style='TFrame')
        mode_frame.pack(anchor='center', pady=10, fill='x')
        ttk.Label(mode_frame, text="MODO DE RENDIMIENTO", style='TLabel', foreground=DIVIDER_COLOR).pack(anchor='center', pady=(0,5))
        current_mode = self.config.get("power_mode", "baja_latencia")
        self.mode_switch = ThreeStateSwitch(mode_frame, initial_mode=current_mode, command=self.set_power_mode_and_sync)
        self.mode_switch.pack(fill='x', padx=20)
        row3_frame = ttk.Frame(optimizer_frame, style='TFrame')
        row3_frame.pack(anchor='w', pady=15, fill='x')
        left_col3 = ttk.Frame(row3_frame, style='TFrame')
        left_col3.pack(side='left', fill='x', expand=True)
        ttk.Label(left_col3, text="FUNCIÓN EXTRA 2", style='TLabel').pack(side='left', padx=(0, 10))
        extra_var2 = tk.BooleanVar(value=self.config.get("extra_function_2", False))
        self.extra_function_2_var = extra_var2
        extra_toggle2 = ModernToggle(left_col3, extra_var2)
        extra_toggle2.pack(side='left')
        extra_var2.trace_add('write', lambda *args: self.on_extra_toggle(2))
        right_col3 = ttk.Frame(row3_frame, style='TFrame')
        right_col3.pack(side='left', fill='x', expand=True, padx=(20, 0))
        ttk.Label(right_col3, text="FUNCIÓN EXTRA 3", style='TLabel').pack(side='left', padx=(0, 10))
        extra_var3 = tk.BooleanVar(value=self.config.get("extra_function_3", False))
        self.extra_function_3_var = extra_var3
        extra_toggle3 = ModernToggle(right_col3, extra_var3)
        extra_toggle3.pack(side='left')
        extra_var3.trace_add('write', lambda *args: self.on_extra_toggle(3))
        content_frame = ttk.Frame(panel, style='TFrame')
        content_frame.pack(fill='both', expand=True)
        list_frame = ttk.Frame(content_frame, style='TFrame')
        list_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        header_frame = tk.Frame(list_frame, bg=LIST_BG, height=30)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        header_label = tk.Label(header_frame, text="PROCESOS EN EJECUCIÓN", bg=LIST_BG, fg=TXT_COLOR, font=(CUSTOM_FONT_FAMILY, 10, 'bold'))
        header_label.pack(side='left', padx=10, pady=5)
        refresh_btn = tk.Button(header_frame, text="⟳", bg=FX_COLOR, fg=TXT_COLOR, font=(CUSTOM_FONT_FAMILY, 12, 'bold'), 
                                borderwidth=0, padx=10, command=self.refresh_process_list, cursor='hand2')
        refresh_btn.pack(side='right', padx=5, pady=2)
        self.process_listbox = tk.Listbox(list_frame, bg=LIST_BG, fg=TXT_COLOR,
                                          selectbackground=LIST_SELECT_BG,
                                          selectforeground=TXT_COLOR,
                                          highlightthickness=0,
                                          borderwidth=0, relief='solid',
                                          selectmode='extended',
                                          font=(CUSTOM_FONT_FAMILY, 10))
        self.process_listbox.pack(fill='both', expand=True)
        self.refresh_process_list()
        bottom_buttons_frame = ttk.Frame(list_frame, style='TFrame')
        bottom_buttons_frame.pack(fill='x', pady=(5, 0))
        ttk.Button(bottom_buttons_frame, text="AÑADIR A LISTA BLANCA", command=self.add_to_whitelist).pack(side='left', fill='x', expand=True, padx=(0, 5))
        ttk.Button(bottom_buttons_frame, text="AÑADIR A JUEGOS", command=self.add_to_gamelist).pack(side='left', fill='x', expand=True, padx=(5, 0))

    def on_optimizer_toggle(self):
        enabled = self.optimizer_enabled_var.get()
        self.config["optimizer_enabled"] = enabled
        save_config(self.config)
        if enabled:
            self.start_optimus()
        else:
            self.stop_optimus()

    def set_power_mode_and_sync(self, mode_name):
        self.config["power_mode"] = mode_name
        save_config(self.config)
        optimuslight.apply_power_mode(mode_name)

    def on_extra_toggle(self, idx):
        var = getattr(self, f"extra_function_{idx}_var")
        self.config[f"extra_function_{idx}"] = var.get()
        save_config(self.config)

    def refresh_process_list(self):
        self.process_listbox.delete(0, tk.END)
        for proc in get_user_processes():
            self.process_listbox.insert(tk.END, proc)

    def add_to_whitelist(self):
        selected_indices = self.process_listbox.curselection()
        for i in selected_indices:
            proc_name = self.process_listbox.get(i)
            if proc_name not in self.lista_blanca:
                self.lista_blanca.append(proc_name)
        self.lista_blanca.sort()
        self.update_listas_display()
        self.save_all_config()

    def add_to_gamelist(self):
        selected_indices = self.process_listbox.curselection()
        for i in selected_indices:
            proc_name = self.process_listbox.get(i)
            if proc_name not in self.lista_juegos:
                self.lista_juegos.append(proc_name)
        self.lista_juegos.sort()
        self.update_listas_display()
        self.save_all_config()

    def create_panel_listas(self):
        panel = ttk.Frame(self.main_frame, style='TFrame')
        self.panels['listas'] = panel
        ttk.Label(panel, text="LISTAS CONFIGURADAS", style='Title.TLabel').pack(pady=(0, 10))
        content_frame = ttk.Frame(panel, style='TFrame')
        content_frame.pack(fill='both', expand=True)
        white_frame = ttk.Frame(content_frame, style='TFrame')
        white_frame.pack(side='left', fill='both', expand=True, padx=(0, 5))
        ttk.Label(white_frame, text="LISTA BLANCA").pack()
        self.whitelist_listbox = tk.Listbox(white_frame, bg=LIST_BG, fg=TXT_COLOR,
                                            selectbackground=LIST_SELECT_BG, selectforeground=TXT_COLOR,
                                            highlightthickness=0, borderwidth=2, relief='solid',
                                            font=(CUSTOM_FONT_FAMILY, 10))
        self.whitelist_listbox.pack(fill='both', expand=True, pady=(5,5))
        ttk.Button(white_frame, text="ELIMINAR", command=self.remove_from_whitelist).pack(fill='x')
        game_frame = ttk.Frame(content_frame, style='TFrame')
        game_frame.pack(side='right', fill='both', expand=True, padx=(5, 0))
        ttk.Label(game_frame, text="LISTA DE JUEGOS").pack()
        self.gamelist_listbox = tk.Listbox(game_frame, bg=LIST_BG, fg=TXT_COLOR,
                                           selectbackground=LIST_SELECT_BG, selectforeground=TXT_COLOR,
                                           highlightthickness=0, borderwidth=2, relief='solid',
                                           font=(CUSTOM_FONT_FAMILY, 10))
        self.gamelist_listbox.pack(fill='both', expand=True, pady=(5,5))
        ttk.Button(game_frame, text="ELIMINAR", command=self.remove_from_gamelist).pack(fill='x')
        self.update_listas_display()

    def update_listas_display(self):
        self.whitelist_listbox.delete(0, tk.END)
        for item in self.lista_blanca:
            self.whitelist_listbox.insert(tk.END, item)
        self.gamelist_listbox.delete(0, tk.END)
        for item in self.lista_juegos:
            self.gamelist_listbox.insert(tk.END, item)

    def remove_from_whitelist(self):
        selected_indices = self.whitelist_listbox.curselection()
        if not selected_indices: return
        proc_name = self.whitelist_listbox.get(selected_indices[0])
        if proc_name in self.lista_blanca:
            self.lista_blanca.remove(proc_name)
            self.update_listas_display()
            self.save_all_config()

    def remove_from_gamelist(self):
        selected_indices = self.gamelist_listbox.curselection()
        if not selected_indices: return
        proc_name = self.gamelist_listbox.get(selected_indices[0])
        if proc_name in self.lista_juegos:
            self.lista_juegos.remove(proc_name)
            self.update_listas_display()
            self.save_all_config()

    def create_panel_biblioteca(self):
        panel = ttk.Frame(self.main_frame, style='TFrame')
        self.panels['biblioteca'] = panel
        ttk.Label(panel, text="CONFIGURACIÓN BIBLIOTECA INTELIGENTE", style='Title.TLabel').pack(pady=(0, 10))
        canvas = tk.Canvas(panel, bg=BG_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(panel, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='TFrame')
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.bib_vars = {}
        self.create_config_entry(scrollable_frame, "MINUTOS ANTES DE REVISAR:", "minutes_before_check", 1)
        self.create_config_check(scrollable_frame, "REVISAR ESCRITORIO", "desktop_check_enabled", True)
        self.create_config_entry(scrollable_frame, "ARCHIVOS MÍNIMOS EN ESCRITORIO:", "desktop_min_files", 12)
        self.create_config_check(scrollable_frame, "REVISAR DESCARGAS", "downloads_check_enabled", True)
        self.create_config_entry(scrollable_frame, "ARCHIVOS MÍNIMOS EN DESCARGAS:", "downloads_min_files", 12)
        self.create_config_entry(scrollable_frame, "CARPETA DESTINO:", "destination_base_folder", "C:\\Biblioteca Inteligente")
        self.create_config_combo(scrollable_frame, "MANEJAR DUPLICADOS:", "handle_duplicates", ["rename", "overwrite", "ask"], "rename")
        self.create_config_check(scrollable_frame, "MOSTRAR NOTIFICACIONES", "notification_enabled", True)
        self.create_config_entry(scrollable_frame, "DURACIÓN NOTIFICACIÓN (SEGUNDOS):", "notification_duration_seconds", 5)
        self.create_config_check(scrollable_frame, "CREAR ACCESO DIRECTO EN ESCRITORIO", "create_desktop_shortcut", True)
        self.create_config_entry(scrollable_frame, "INTERVALO DE REVISIÓN (SEGUNDOS, 0=SOLO UNA VEZ):", "check_interval_seconds_after_first_run", 0)
        ttk.Button(scrollable_frame, text="GUARDAR CONFIGURACIÓN", command=self.save_all_config).pack(pady=20, fill='x', padx=20)

    def create_panel_monitoreo(self):
        panel = ttk.Frame(self.main_frame, style='TFrame')
        self.panels['monitoreo'] = panel
        ttk.Label(panel, text="CONFIGURACIÓN MONITOREO DE PROCESOS", style='Title.TLabel').pack(pady=(0, 10))
        canvas = tk.Canvas(panel, bg=BG_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(panel, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='TFrame')
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        if "idle_process_monitoring" not in self.config:
            self.config["idle_process_monitoring"] = {}
        self.mon_vars = {}
        self.create_mon_entry(scrollable_frame, "MINUTOS DE INACTIVIDAD PARA CONSIDERAR PROCESO INACTIVO:", "idle_minutes_threshold", 60)
        self.create_mon_entry(scrollable_frame, "INTERVALO DE REVISIÓN (SEGUNDOS):", "check_interval_seconds", 60)
        self.create_mon_entry(scrollable_frame, "UMBRAL DE BAJA ACTIVIDAD (%):", "low_activity_percent_threshold", 1.0)
        self.create_mon_entry(scrollable_frame, "UMBRAL DE ALTA ACTIVIDAD (%):", "high_activity_percent_threshold", 5.0)
        self.create_mon_check(scrollable_frame, "USAR WHITELIST_FILES COMO PROCESOS PROTEGIDOS", "inherit_file_whitelist_as_process_names", False)
        ttk.Button(scrollable_frame, text="GUARDAR CONFIGURACIÓN", command=self.save_all_config).pack(pady=20, fill='x', padx=20)

    def create_panel_gestion_termica(self):
        panel = ttk.Frame(self.main_frame, style='TFrame')
        self.panels['gestion_termica'] = panel
        ttk.Label(panel, text="GESTIÓN TÉRMICA DE CPU", style='Title.TLabel').pack(pady=(0, 20))
        if "thermal_management" not in self.config:
            self.config["thermal_management"] = {"soft_throttle_temp": 75, "aggressive_throttle_temp": 85, "emergency_shutdown_temp": 95, "show_temp_in_tray": False}
        self.thermal_vars = {}
        self.create_thermal_slider(panel, "THERMAL THROTTLING SUAVE (°C)", "soft_throttle_temp", 40, 90, 75)
        self.create_thermal_slider(panel, "THERMAL THROTTLING AGRESIVO (°C)", "aggressive_throttle_temp", 50, 100, 85)
        self.create_thermal_slider(panel, "APAGADO FORZADO POR SEGURIDAD (°C)", "emergency_shutdown_temp", 60, 110, 95)
        ttk.Button(panel, text="GUARDAR CONFIGURACIÓN TÉRMICA", command=self.save_thermal_config).pack(pady=20, fill='x', padx=20)

    def create_thermal_slider(self, parent, label_text, config_key, min_val, max_val, default_val):
        frame = ttk.Frame(parent, style='TFrame')
        frame.pack(fill='x', padx=20, pady=15)
        current_val = self.config.get("thermal_management", {}).get(config_key, default_val)
        label_frame = ttk.Frame(frame, style='TFrame')
        label_frame.pack(fill='x', pady=(0, 5))
        ttk.Label(label_frame, text=label_text, style='TLabel').pack(side='left')
        value_var = tk.StringVar(value=f"{current_val}°C")
        value_label = ttk.Label(label_frame, textvariable=value_var, style='TLabel', font=(CUSTOM_FONT_FAMILY, 10, 'bold'))
        value_label.pack(side='right')
        slider = tk.Scale(frame, from_=min_val, to=max_val, orient='horizontal', bg=LIST_BG, fg=TXT_COLOR, troughcolor=BG_COLOR, activebackground=FX_COLOR, highlightthickness=0, sliderrelief='flat', length=700, width=20, font=(CUSTOM_FONT_FAMILY, 8))
        slider.set(current_val)
        slider.pack(fill='x')
        def update_label(val):
            value_var.set(f"{int(float(val))}°C")
        slider.config(command=update_label)
        self.thermal_vars[config_key] = slider

    def save_thermal_config(self):
        if "thermal_management" not in self.config:
            self.config["thermal_management"] = {}
        for key, slider in self.thermal_vars.items():
            self.config["thermal_management"][key] = int(slider.get())
        save_config(self.config)

    def create_config_entry(self, parent, label_text, config_key, default_value):
        frame = ttk.Frame(parent, style='TFrame')
        frame.pack(fill='x', padx=20, pady=5)
        ttk.Label(frame, text=label_text).pack(side='left', padx=(0, 10))
        var = tk.StringVar(value=str(self.config.get(config_key, default_value)))
        entry = ttk.Entry(frame, textvariable=var, style='TEntry', width=40, font=(CUSTOM_FONT_FAMILY, 10))
        entry.pack(side='right', fill='x', expand=True)
        self.bib_vars[config_key] = var

    def create_config_check(self, parent, label_text, config_key, default_value):
        var = tk.BooleanVar(value=self.config.get(config_key, default_value))
        check = ttk.Checkbutton(parent, text=label_text, variable=var, style='TCheckbutton')
        check.pack(fill='x', padx=20, pady=5, anchor='w')
        self.bib_vars[config_key] = var

    def create_config_combo(self, parent, label_text, config_key, values, default_value):
        frame = ttk.Frame(parent, style='TFrame')
        frame.pack(fill='x', padx=20, pady=5)
        ttk.Label(frame, text=label_text).pack(side='left', padx=(0, 10))
        var = tk.StringVar(value=self.config.get(config_key, default_value))
        combo = ttk.Combobox(frame, textvariable=var, values=values, state='readonly', width=20, font=(CUSTOM_FONT_FAMILY, 10))
        combo.pack(side='right')
        self.bib_vars[config_key] = var

    def create_mon_entry(self, parent, label_text, config_key, default_value):
        frame = ttk.Frame(parent, style='TFrame')
        frame.pack(fill='x', padx=20, pady=5)
        ttk.Label(frame, text=label_text).pack(side='left', padx=(0, 10))
        current_val = self.config.get("idle_process_monitoring", {}).get(config_key, default_value)
        var = tk.StringVar(value=str(current_val))
        entry = ttk.Entry(frame, textvariable=var, style='TEntry', width=20, font=(CUSTOM_FONT_FAMILY, 10))
        entry.pack(side='right')
        self.mon_vars[config_key] = var

    def create_mon_check(self, parent, label_text, config_key, default_value):
        current_val = self.config.get("idle_process_monitoring", {}).get(config_key, default_value)
        var = tk.BooleanVar(value=current_val)
        check = ttk.Checkbutton(parent, text=label_text, variable=var, style='TCheckbutton')
        check.pack(fill='x', padx=20, pady=5, anchor='w')
        self.mon_vars[config_key] = var

    def save_all_config(self):
        self.config["process_whitelist"] = self.lista_blanca
        self.config["game_processes"] = self.lista_juegos
        self.config["optimizer_enabled"] = self.optimizer_enabled_var.get()
        for i in range(2, 4):
            var = getattr(self, f"extra_function_{i}_var")
            self.config[f"extra_function_{i}"] = var.get()
        for key, var in self.bib_vars.items():
            value = var.get()
            if key in ["minutes_before_check", "desktop_min_files", "downloads_min_files",
                        "notification_duration_seconds", "check_interval_seconds_after_first_run"]:
                if str(value).isdigit(): value = int(value)
            elif key in ["desktop_check_enabled", "downloads_check_enabled",
                        "notification_enabled", "create_desktop_shortcut"]:
                value = bool(value)
            self.config[key] = value
        if "idle_process_monitoring" not in self.config:
            self.config["idle_process_monitoring"] = {}
        for key, var in self.mon_vars.items():
            value = var.get()
            if key in ["idle_minutes_threshold", "check_interval_seconds"]:
                if str(value).isdigit(): value = int(value)
            elif key in ["low_activity_percent_threshold", "high_activity_percent_threshold"]:
                value = float(value)
            elif key == "inherit_file_whitelist_as_process_names":
                value = bool(value)
            self.config["idle_process_monitoring"][key] = value
        mon_whitelist = self.config["idle_process_monitoring"].get("process_whitelist", [])
        combined = set(mon_whitelist + self.lista_blanca + self.lista_juegos)
        self.config["idle_process_monitoring"]["process_whitelist"] = sorted(list(combined))
        save_config(self.config)

if __name__ == "__main__":
    app = App()
    app.mainloop()