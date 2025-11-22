#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import shutil
import ctypes
import ctypes.wintypes
import threading
from pathlib import Path

# Si necesitas que TODO el programa corra como administrador,
# es mejor lanzar el .exe como "Ejecutar como administrador" desde el sistema,
# en vez de relanzar aquí al importar este módulo.

# Importar win32com (opcional para accesos directos)
try:
    import win32com.client
    HAS_WIN32COM = True
except ImportError:
    HAS_WIN32COM = False
    print("AVISO: win32com no instalado. El acceso directo no tendrá icono personalizado.")


class BibliotecaInteligente:
    def __init__(self):
        self.script_dir = Path(sys.argv[0]).parent.resolve()
        self.config_file = self.script_dir / "config.json"
        self.config = self.load_config()
        if "extensions" not in self.config:
            self.config["extensions"] = {}
        self.base_folder = Path(self.config["destination_base_folder"])
        
    def load_config(self):
        """Carga la configuración desde config.json"""
        if not self.config_file.exists():
            print(f"ERROR: No se encuentra {self.config_file}")
            sys.exit(1)
        
        with open(self.config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def get_desktop_path(self):
        """Obtiene la ruta del escritorio del usuario"""
        CSIDL_DESKTOP = 0
        buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
        ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DESKTOP, None, 0, buf)
        return Path(buf.value)
    
    def get_downloads_path(self):
        """Obtiene la ruta de descargas del usuario"""
        return Path.home() / "Downloads"
    
    def is_file_valid(self, file_path):
        """Verifica si un archivo es válido para mover"""
        if not file_path.is_file():
            return False
        if file_path.suffix.lower() in ['.lnk', '.url']:
            return False
        if file_path.name in self.config.get("whitelist_files", []):
            return False
        return True
    
    def count_valid_files(self, folder):
        """Cuenta archivos válidos en una carpeta"""
        if not folder.exists():
            return 0
        return sum(1 for f in folder.iterdir() if self.is_file_valid(f))
    
    def get_category(self, file_path):
        """Determina la categoría de un archivo según su extensión"""
        ext = file_path.suffix.lower()
        for category, extensions in self.config["extensions"].items():
            if ext in [e.lower() for e in extensions]:
                return category
        return "varios"
    
    def create_folder_structure(self):
        """Crea la estructura de carpetas en el destino"""
        # Crear carpeta base
        self.base_folder.mkdir(parents=True, exist_ok=True)
        
        # Crear subcarpetas
        categories = list(self.config["extensions"].keys()) + ["varios"]
        for category in categories:
            folder = self.base_folder / category
            folder.mkdir(exist_ok=True)
            
            # Configurar icono si existe
            icon_name = self.config.get("icons", {}).get(category, "")
            if icon_name:
                self.set_folder_icon(folder, icon_name)
    
    def set_folder_icon(self, folder_path, icon_name):
        """Configura el icono de una carpeta"""
        icon_path = self.script_dir / icon_name
        
        # Solo configurar si el icono existe
        if not icon_path.exists():
            print(f"Icono no encontrado: {icon_path}")
            return
        
        # Crear desktop.ini
        desktop_ini = folder_path / "desktop.ini"
        
        # Si desktop.ini ya existe, eliminarlo primero
        if desktop_ini.exists():
            # Quitar atributos
            ctypes.windll.kernel32.SetFileAttributesW(str(desktop_ini), 0)
            desktop_ini.unlink()
        
        # Escribir nuevo desktop.ini
        content = f"""[.ShellClassInfo]
IconResource={str(icon_path)},0
IconFile={str(icon_path)}
IconIndex=0
"""
        desktop_ini.write_text(content, encoding='ansi')
        
        # Establecer atributos
        FILE_ATTRIBUTE_HIDDEN = 0x02
        FILE_ATTRIBUTE_SYSTEM = 0x04
        ctypes.windll.kernel32.SetFileAttributesW(str(desktop_ini), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
        ctypes.windll.kernel32.SetFileAttributesW(str(folder_path), FILE_ATTRIBUTE_SYSTEM)
    
    def handle_duplicate(self, src, dest):
        """Maneja archivos duplicados según configuración"""
        if not dest.exists():
            return dest
        
        mode = self.config["handle_duplicates"]
        
        if mode == "overwrite" or self.config.get("auto_overwrite_on_duplicates", False):
            return dest
        elif mode == "ask" or self.config.get("ask_on_duplicates", False):
            # Preguntar al usuario
            MB_YESNOCANCEL = 0x03
            MB_ICONQUESTION = 0x20
            result = ctypes.windll.user32.MessageBoxW(
                0,
                f"'{src.name}' ya existe.\n\nSí = Sobrescribir\nNo = Renombrar\nCancelar = Omitir",
                "Archivo duplicado",
                MB_YESNOCANCEL | MB_ICONQUESTION
            )
            
            if result == 6:  # Yes
                return dest
            elif result == 7:  # No
                return self.get_unique_name(dest)
            else:  # Cancel
                return None
        else:  # rename
            return self.get_unique_name(dest)
    
    def get_unique_name(self, file_path):
        """Genera un nombre único para un archivo"""
        counter = 1
        stem = file_path.stem
        suffix = file_path.suffix
        parent = file_path.parent
        
        while True:
            new_path = parent / f"{stem} ({counter}){suffix}"
            if not new_path.exists():
                return new_path
            counter += 1
    
    def move_file(self, src, category):
        """Mueve un archivo a su categoría"""
        dest_folder = self.base_folder / category
        dest_folder.mkdir(exist_ok=True)
        
        dest = dest_folder / src.name
        final_dest = self.handle_duplicate(src, dest)
        
        if final_dest:
            if final_dest.exists():
                final_dest.unlink()
            shutil.move(str(src), str(final_dest))
            return True
        return False
    
    def process_folder(self, folder_path, folder_name, min_files):
        """Procesa una carpeta y devuelve cuántos archivos movió"""
        if not folder_path.exists():
            return 0
        
        file_count = self.count_valid_files(folder_path)
        
        if file_count < min_files:
            print(f"{folder_name}: {file_count} archivos (mínimo: {min_files})")
            return 0
        
        print(f"Procesando {folder_name}: {file_count} archivos")
        
        # Crear estructura
        self.create_folder_structure()
        
        # Mover archivos
        moved_count = 0
        for file_path in list(folder_path.iterdir()):
            if self.is_file_valid(file_path):
                category = self.get_category(file_path)
                if self.move_file(file_path, category):
                    moved_count += 1
        
        print(f"Movidos {moved_count} archivos de {folder_name}")
        return moved_count

    # =========================
    #  NOTIFICACIÓN INTEGRADA
    #  (ESTILO notif2.py)
    # =========================
    def _mostrar_notificacion_estilo_notif(self, mensaje):
        """
        Notificación tipo notif2.py (fondo verde fosforescente, fade in/out).
        Se ejecuta en un hilo aparte para no bloquear.
        """
        import tkinter as tk

        def _worker():
            root = tk.Tk()
            root.withdraw()
            root.update()

            noti = tk.Toplevel(root)
            noti.overrideredirect(True)
            noti.attributes("-topmost", True)
            noti.attributes("-alpha", 0.0)      # Empezamos transparente
            noti.configure(bg="#001a00")

            ancho = 250
            alto = 150
            margen_derecho = 50
            margen_superior = 100

            screen_w = root.winfo_screenwidth()
            screen_h = root.winfo_screenheight()
            x = screen_w - ancho - margen_derecho
            y = margen_superior

            noti.geometry(f"{ancho}x{alto}+{x}+{y}")

            frame = tk.Frame(noti, bg="#39FF14", bd=1, relief="flat")
            frame.pack(fill="both", expand=True, padx=2, pady=2)

            inner = tk.Frame(frame, bg="#001a00")
            inner.pack(fill="both", expand=True, padx=3, pady=3)

            label = tk.Label(
                inner,
                text=mensaje,
                bg="#001a00",
                fg="#39FF14",
                font=("Segoe UI", 14, "bold"),
                justify="center",
                wraplength=220
            )
            label.pack(expand=True)

            # === FADE-IN ===
            def fade_in(step=0):
                alpha = step / 20.0
                if alpha < 1.0:
                    noti.attributes("-alpha", alpha)
                    root.after(30, fade_in, step + 1)
                else:
                    noti.attributes("-alpha", 1.0)
                    root.after(5000, fade_out)  # visible 5s

            # === FADE-OUT ===
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

        threading.Thread(target=_worker, daemon=True).start()

    # =========================
    #  MÉTODOS PÚBLICOS
    # =========================
    def run_single_cycle(self):
        """
        Ejecuta UNA sola revisión (sin esperar minutos iniciales ni bucles).
        Devuelve un diccionario con el resultado y lanza una notificación
        estilo notif2.py al terminar.
        """
        print("=" * 60)
        print("BIBLIOTECA INTELIGENTE - CICLO ÚNICO")
        print("=" * 60)

        total_moved = 0
        details = []

        # Escritorio
        if self.config.get("desktop_check_enabled", True):
            desktop = self.get_desktop_path()
            min_files = self.config.get("desktop_min_files", 12)
            moved = self.process_folder(desktop, "Escritorio", min_files)
            total_moved += moved
            details.append(f"Escritorio: {moved} archivo(s) movido(s)")

        # Descargas
        if self.config.get("downloads_check_enabled", False):
            downloads = self.get_downloads_path()
            min_files = self.config.get("downloads_min_files", 12)
            moved = self.process_folder(downloads, "Descargas", min_files)
            total_moved += moved
            details.append(f"Descargas: {moved} archivo(s) movido(s)")

        print("\n" + "=" * 60)
        if total_moved > 0:
            print(f"Reorganización completada. Total movidos: {total_moved}")
        else:
            print("No se requirió reorganización.")
        print("=" * 60)

        # Preparar mensaje de notificación
        if total_moved > 0:
            mensaje = f"Biblioteca Inteligente:\nSe reorganizaron {total_moved} archivo(s).\n"
            # Solo hasta 2 líneas de detalle para no recargar
            for linea in details[:2]:
                mensaje += f"\n{linea}"
        else:
            mensaje = "Biblioteca Inteligente:\nNo se requirió reorganización.\nTodo ya estaba ordenado."

        # Lanzar notificación estilo notif2.py
        if self.config.get("notification_enabled", True):
            self._mostrar_notificacion_estilo_notif(mensaje)

        return {
            "total_moved": total_moved,
            "details": details
        }

    def create_shortcut(self):
        """Crea un acceso directo en el escritorio"""
        from pathlib import Path
        desktop = self.get_desktop_path()
        shortcut_name = self.config.get("desktop_shortcut_name", "Biblioteca Inteligente.lnk")
        shortcut_path = desktop / shortcut_name
        
        if HAS_WIN32COM:
            try:
                shell = win32com.client.Dispatch("WScript.Shell")
                shortcut = shell.CreateShortcut(str(shortcut_path))
                shortcut.TargetPath = str(self.base_folder)
                shortcut.WorkingDirectory = str(self.base_folder)
                
                # Icono del acceso directo
                icon_name = self.config.get("icons", {}).get("shortcut", "")
                if icon_name:
                    icon_path = self.script_dir / icon_name
                    if icon_path.exists():
                        shortcut.IconLocation = f"{str(icon_path)},0"
                
                shortcut.Save()
                print(f"Acceso directo creado: {shortcut_path}")
            except Exception as e:
                print(f"Error creando acceso directo: {e}")
        else:
            # Crear acceso directo básico sin icono
            try:
                with open(shortcut_path, 'w') as f:
                    f.write(f"[InternetShortcut]\nURL=file:///{self.base_folder}")
                print(f"Acceso directo básico creado: {shortcut_path}")
            except Exception as e:
                print(f"Error creando acceso directo: {e}")

    def run(self):
        """
        Versión con espera inicial y bucles (tal como la tenías),
        pero al final también muestra la notificación estilo notif2.py.
        """
        print("=" * 60)
        print("BIBLIOTECA INTELIGENTE - INICIADA")
        print("=" * 60)
        
        # Esperar tiempo inicial
        wait_minutes = self.config.get("minutes_before_check", 5)
        print(f"Esperando {wait_minutes} minuto(s) antes de la primera revisión...")
        time.sleep(wait_minutes * 60)
        
        total_global = 0
        detalles_globales = []

        # Procesar
        while True:
            print("\n" + "=" * 60)
            print("INICIANDO REVISIÓN")
            print("=" * 60)
            
            processed = False
            
            # Procesar escritorio
            if self.config.get("desktop_check_enabled", True):
                desktop = self.get_desktop_path()
                min_files = self.config.get("desktop_min_files", 12)
                moved = self.process_folder(desktop, "Escritorio", min_files)
                if moved > 0:
                    processed = True
                total_global += moved
                detalles_globales.append(f"Escritorio: {moved} archivo(s) movido(s)")
            
            # Procesar descargas
            if self.config.get("downloads_check_enabled", False):
                downloads = self.get_downloads_path()
                min_files = self.config.get("downloads_min_files", 12)
                moved = self.process_folder(downloads, "Descargas", min_files)
                if moved > 0:
                    processed = True
                total_global += moved
                detalles_globales.append(f"Descargas: {moved} archivo(s) movido(s)")
            
            if processed:
                print("\nReorganización completada exitosamente")
            else:
                print("\nNo se requirió reorganización")
            
            # Verificar si continuar
            interval = self.config.get("check_interval_seconds_after_first_run", 0)
            if interval <= 0:
                break
            
            print(f"\nPróxima revisión en {interval} segundos...")
            time.sleep(interval)
        
        print("\n" + "=" * 60)
        print("BIBLIOTECA INTELIGENTE - FINALIZADA")
        print("=" * 60)
        time.sleep(3)

        # Notificación final para toda la sesión de run()
        if self.config.get("notification_enabled", True):
            if total_global > 0:
                msg = f"Biblioteca Inteligente:\nSe reorganizaron {total_global} archivo(s) en total."
                # Corregido posible error de caracteres invisibles en el loop
                for linea in detalles_globales[:2]:
                    msg += f"\n{linea}"
            else:
                msg = "Biblioteca Inteligente:\nNo se requirió reorganización.\nTodo ya estaba ordenado."
            self._mostrar_notificacion_estilo_notif(msg)


# Ejecutar como script independiente
if __name__ == "__main__":
    try:
        app = BibliotecaInteligente()
        app.run()
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario")
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        input("\nPresione Enter para salir...")