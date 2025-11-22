import tkinter as tk
from tkinter import ttk, messagebox
import winreg
import subprocess
import os
import datetime
import threading
import shutil
import ctypes
from ctypes import wintypes
import sys

# --- Admin Check ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

# --- Privilege Escalation Utilities ---
def enable_privileges():
    """
    Enables SeBackupPrivilege and SeRestorePrivilege for the current process.
    This is required to backup/restore protected system registry keys.
    """
    try:
        # Constants
        SE_BACKUP_NAME = "SeBackupPrivilege"
        SE_RESTORE_NAME = "SeRestorePrivilege"
        SE_PRIVILEGE_ENABLED = 0x00000002
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD),
                        ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID),
                        ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 2)]

        # Get process token
        h_token = wintypes.HANDLE()
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        
        # Open current process token
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 
                                       TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
                                       ctypes.byref(h_token)):
            return False

        # Get LUIDs for privileges
        luid_backup = LUID()
        luid_restore = LUID()
        
        if not advapi32.LookupPrivilegeValueW(None, SE_BACKUP_NAME, ctypes.byref(luid_backup)):
            return False
        if not advapi32.LookupPrivilegeValueW(None, SE_RESTORE_NAME, ctypes.byref(luid_restore)):
            return False

        # Prepare Privilege Structure
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 2
        tp.Privileges[0].Luid = luid_backup
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        tp.Privileges[1].Luid = luid_restore
        tp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED

        # Adjust Token
        if not advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 
                                            ctypes.sizeof(TOKEN_PRIVILEGES), None, None):
            return False
            
        # Check for ERROR_NOT_ALL_ASSIGNED (1300) although call returned True
        if kernel32.GetLastError() == 1300:
            return False

        return True
    except Exception as e:
        print(f"Privilege Error: {e}")
        return False

class OptimizationTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Registry Optimizer")
        self.root.geometry("450x300")
        self.center_window()
        self.root.resizable(False, False)

        # Styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Attempt to enable special privileges immediately
        if enable_privileges():
            self.privilege_status = "Admin + SeRestorePrivilege Active"
        else:
            self.privilege_status = "Admin (Standard)"

        # UI Elements
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.label = ttk.Label(self.main_frame, text="System Optimization Tool", font=("Helvetica", 12, "bold"))
        self.label.pack(pady=(0, 10))

        self.priv_label = ttk.Label(self.main_frame, text=f"Status: {self.privilege_status}", font=("Helvetica", 8))
        self.priv_label.pack(pady=(0, 15))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 20))
        
        self.status_label = ttk.Label(self.main_frame, text="Ready", font=("Helvetica", 9))
        self.status_label.pack(pady=(0, 10))

        # Buttons Frame
        self.btn_frame = ttk.Frame(self.main_frame)
        self.btn_frame.pack(fill=tk.X)

        self.btn_backup = ttk.Button(self.btn_frame, text="Backup", command=self.start_backup)
        self.btn_backup.pack(side=tk.LEFT, expand=True, padx=5)

        self.btn_restore = ttk.Button(self.btn_frame, text="Restore", command=self.start_restore)
        self.btn_restore.pack(side=tk.LEFT, expand=True, padx=5)

        self.btn_exit = ttk.Button(self.btn_frame, text="Exit", command=root.quit)
        self.btn_exit.pack(side=tk.LEFT, expand=True, padx=5)

                # Internal Data
        self.registry_keys = [
            # --- Network & System Optimizations ---
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            r"SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider",
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
            r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces",
            r"SOFTWARE\Microsoft\MSMQ\Parameters",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
            r"SOFTWARE\Policies\Microsoft\Windows\Psched",
            r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            r"SYSTEM\CurrentControlSet\Control\PriorityControl",
            r"SYSTEM\CurrentControlSet\Services\AFD\Parameters",
            r"SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator",
            r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet",
            r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            r"SOFTWARE\Policies\Microsoft\Windows\QoS",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
            # BLOQUEADO POR DRIVER DE RED ACTIVO:
            r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}",
            r"SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder",
            r"SYSTEM\CurrentControlSet\Control\NetworkProvider\Order",
            
            # --- Services, Telemetry & Privacy ---
            r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
            # A MENUDO PROTEGIDOS (TrustedInstaller):
            r"SYSTEM\CurrentControlSet\Services\DiagTrack",
            r"SYSTEM\CurrentControlSet\Services\dmwappushservice",
            r"SYSTEM\CurrentControlSet\Services\diagsvc",
            r"SYSTEM\CurrentControlSet\Services\DPS",
            r"SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service",
            r"SYSTEM\CurrentControlSet\Services\WdiServiceHost",
            r"SYSTEM\CurrentControlSet\Services\WdiSystemHost",
            r"SYSTEM\CurrentControlSet\Services\WerSvc",
            r"SYSTEM\CurrentControlSet\Services\PcaSvc",
            
            r"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe",
            r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications",
            r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            
            # SEGURIDAD / DEFENDER (CAUSAN ERROR SI TAMPER PROTECTION ESTÁ ACTIVO):
            r"SYSTEM\CurrentControlSet\Services\WinDefend",
            r"SYSTEM\CurrentControlSet\Services\SecurityHealthService",
            r"SYSTEM\CurrentControlSet\Services\WdNisSvc",
            r"SYSTEM\CurrentControlSet\Services\Sense",
            r"SYSTEM\CurrentControlSet\Services\wscsvc",
            r"SOFTWARE\Policies\Microsoft\Windows Defender",
            
            r"SYSTEM\CurrentControlSet\Services\WSearch",
            r"SYSTEM\CurrentControlSet\Services\WbioSrvc",
            r"SYSTEM\CurrentControlSet\Services\FontCache",
            r"SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0",
            r"SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc",
            r"SYSTEM\CurrentControlSet\Services\stisvc",
            r"SYSTEM\CurrentControlSet\Services\Wecsvc",
            r"SYSTEM\CurrentControlSet\Services\MapsBroker",
            r"SYSTEM\CurrentControlSet\Services\Spooler",
            r"SYSTEM\CurrentControlSet\Services\PrintNotify",
            r"SYSTEM\CurrentControlSet\Services\XblGameSave",
            r"SYSTEM\CurrentControlSet\Services\XboxNetApiSvc",
            r"SYSTEM\CurrentControlSet\Services\XboxGipSvc",
            r"SYSTEM\CurrentControlSet\Services\XblAuthManager",
            r"SYSTEM\CurrentControlSet\Services\wuauserv",
            r"SYSTEM\CurrentControlSet\Services\UsoSvc",
            r"SYSTEM\CurrentControlSet\Services\BITS",
            r"SYSTEM\CurrentControlSet\Services\DoSvc",
            r"SYSTEM\CurrentControlSet\Services\SysMain",
            r"SYSTEM\CurrentControlSet\Services\TabletInputService",
            r"SYSTEM\CurrentControlSet\Services\Fax",
            r"SYSTEM\CurrentControlSet\Services\PhoneSvc",
            r"SYSTEM\CurrentControlSet\Services\RetailDemo",
            r"SYSTEM\CurrentControlSet\Services\RemoteAccess",
            r"SYSTEM\CurrentControlSet\Services\RemoteRegistry",
            r"SYSTEM\CurrentControlSet\Services\SharedAccess",
            r"SYSTEM\CurrentControlSet\Services\TrkWks",
            r"SYSTEM\CurrentControlSet\Services\WpnService",
            r"SYSTEM\CurrentControlSet\Services\WpnUserService",
            r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors",
            r"SOFTWARE\Policies\Microsoft\Windows\Windows Search",
            r"SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry",
            r"SOFTWARE\Microsoft\Office\16.0\Common\Feedback",
            r"SOFTWARE\Policies\Microsoft\SQMClient\Windows",
            r"SOFTWARE\Policies\Microsoft\MRT",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy",
            r"SOFTWARE\Policies\Microsoft\Windows\AppCompat",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
            r"SOFTWARE\Microsoft\Personalization\Settings",
            r"SOFTWARE\Microsoft\InputPersonalization",
            r"SOFTWARE\Microsoft\Siuf\Rules",
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            r"SYSTEM\CurrentControlSet\Services\ShellHWDetection",
            r"SYSTEM\CurrentControlSet\Services\Themes",
            r"SYSTEM\CurrentControlSet\Services\lfsvc",
            r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
            r"SOFTWARE\Microsoft\Windows\ScheduledDiagnostics",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            r"SOFTWARE\Policies\Microsoft\EdgeUpdate",
            r"SOFTWARE\Policies\Microsoft\Edge",
            r"SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana",
            r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds",
            r"SYSTEM\Maps",
            r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
            r"System\GameConfigStore",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
            r"SOFTWARE\Policies\Microsoft\Windows\GameDVR",
            r"SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR",
            r"SOFTWARE\Microsoft\GameBar",
            r"SOFTWARE\Microsoft\Multimedia\Audio",
            r"SOFTWARE\Policies\Microsoft\Windows\StorageSense",

            # --- Graphics, GPU & DWM ---
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager",
            r"SOFTWARE\Microsoft\DirectX\UserGpuPreferences",
            r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler",
            r"SYSTEM\CurrentControlSet\Services\nvlddmkm",
            r"SYSTEM\CurrentControlSet\Services\amdkmdap\Parameters",
            r"SYSTEM\CurrentControlSet\Services\DXGKrnl",
            r"SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters",
            # BLOQUEADO POR DRIVER GRÁFICO ACTIVO:
            r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000",
            r"SOFTWARE\Microsoft\Avalon.Graphics",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            r"SOFTWARE\Microsoft\Windows\DWM",
            r"SOFTWARE\Microsoft\Windows\Dwm",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
            r"SYSTEM\CurrentControlSet\Services\GpuEnergyDrv",
            r"SOFTWARE\Microsoft\Direct3D",
            r"SOFTWARE\Microsoft\DirectDraw",

            # --- Kernel, Latency & Input ---
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions",
            r"SYSTEM\CurrentControlSet\Control\Power\PowerSettings",
            r"SYSTEM\CurrentControlSet\Control\Power",
            r"SOFTWARE\Microsoft\Ole",
            # A VECES BLOQUEADOS (Drivers de Input):
            # r"SYSTEM\CurrentControlSet\Services\mouclass\Parameters",
            # r"SYSTEM\CurrentControlSet\Services\kbdclass\Parameters",
            r"Control Panel\Desktop",
            r"Control Panel\Mouse",
            r"Control Panel\Accessibility\StickyKeys",
            r"Control Panel\Accessibility\ToggleKeys",
            r"Control Panel\Accessibility\Keyboard Response",

            # --- Storage, USB & Hardware ---
            r"SYSTEM\CurrentControlSet\Control\FileSystem",
            r"SYSTEM\CurrentControlSet\Services\storahci\Parameters",
            r"SYSTEM\CurrentControlSet\Services\stornvme\Parameters\Device",
            r"SYSTEM\CurrentControlSet\Services\usbuhci",
            r"SYSTEM\CurrentControlSet\Services\usbhub",
            r"SYSTEM\CurrentControlSet\Services\hidusb\Parameters",
            r"SOFTWARE\Microsoft\Shell\USB",
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy",
            r"SOFTWARE\Policies\Microsoft\Windows\FileHistory",
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
            r"SYSTEM\CurrentControlSet\Control\PnP",
            r"SYSTEM\CurrentControlSet\Control\PnP\Pci",
            r"SYSTEM\CurrentControlSet\Services\Disk",
            r"SYSTEM\CurrentControlSet\Services\i8042prt\Parameters",
            r"Control Panel\Cursors",
            r"SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters",
            r"SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters"
        ]
        
        self.backup_dir = os.path.join(os.getcwd(), "RegBackups")
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def update_status(self, text):
        self.status_label.config(text=text)
        self.root.update_idletasks()

    def get_backup_filename(self):
        base_name = "backup"
        ext = ".reg"
        counter = 1
        while True:
            if counter == 1:
                filename = f"{base_name}{ext}"
            else:
                filename = f"{base_name}{counter}{ext}"
            full_path = os.path.join(self.backup_dir, filename)
            if not os.path.exists(full_path):
                return full_path
            counter += 1

    def start_backup(self):
        threading.Thread(target=self.run_backup).start()

    def run_backup(self):
        self.disable_buttons()
        filename = self.get_backup_filename()
        self.update_status(f"Backing up to {os.path.basename(filename)}...")
        
        total = len(self.registry_keys)
        self.progress_var.set(0)

        try:
            # Initialize file with BOM + Header for UTF-16 LE
            with open(filename, 'w', encoding='utf-16-le') as f:
                f.write('\ufeff')
                f.write("Windows Registry Editor Version 5.00\n\n")

            for index, key in enumerate(self.registry_keys):
                hives = [("HKEY_LOCAL_MACHINE", "HKLM"), ("HKEY_CURRENT_USER", "HKCU")]
                
                for hive_full, hive_abbr in hives:
                    temp_file = "temp_export.reg"
                    full_key_path = f"{hive_abbr}\\{key}"
                    
                    cmd = f'reg export "{full_key_path}" "{temp_file}" /y'
                    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    if os.path.exists(temp_file):
                        try:
                            with open(temp_file, 'r', encoding='utf-16-le', errors='ignore') as tf:
                                content = tf.read()
                                content = content.replace('\ufeff', '')
                                clean_content = content.replace("Windows Registry Editor Version 5.00", "")
                                with open(filename, 'a', encoding='utf-16-le') as main_file:
                                    main_file.write(clean_content)
                        except:
                            pass # Skip bad reads
                        try:
                            os.remove(temp_file)
                        except:
                            pass

                progress = ((index + 1) / total) * 100
                self.progress_var.set(progress)
                self.root.update_idletasks()

            self.update_status("Backup Complete!")
            messagebox.showinfo("Success", f"Backup saved to:\n{filename}")
            
        except Exception as e:
            self.update_status("Error during backup")
            messagebox.showerror("Error", f"Backup failed: {str(e)}")
        finally:
            self.progress_var.set(0)
            self.enable_buttons()

    def start_restore(self):
        files = [os.path.join(self.backup_dir, f) for f in os.listdir(self.backup_dir) if f.endswith('.reg')]
        if not files:
            messagebox.showwarning("Warning", "No backup files found.")
            return

        latest_backup = max(files, key=os.path.getmtime)
        
        if messagebox.askyesno("Confirm Restore", f"Restore registry from:\n{os.path.basename(latest_backup)}?"):
            threading.Thread(target=self.run_restore, args=(latest_backup,)).start()

    def run_restore(self, filename):
        self.disable_buttons()
        self.update_status("Restoring registry...")
        self.progress_var.set(50)
        
        try:
            # Using subprocess with shell=True inherits the Python process token (with elevated privileges)
            cmd = f'reg import "{filename}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            self.progress_var.set(100)
            
            if result.returncode == 0:
                self.update_status("Restore Complete")
                messagebox.showinfo("Success", "Registry restored successfully.\nPlease restart your computer.")
            else:
                self.update_status("Restore Failed")
                # Provide a more helpful error message regarding Tamper Protection
                error_msg = result.stderr
                if "access" in error_msg.lower() or "acceso" in error_msg.lower():
                     messagebox.showerror("Restore Failed", 
                        f"Access Denied.\n\nERROR DETAILS:\n{error_msg}\n\nPOSSIBLE FIX:\n"
                        "1. Disable 'Tamper Protection' in Windows Security.\n"
                        "2. Disable 'Real-time protection' temporarily.\n"
                        "3. Try running again.")
                else:
                    messagebox.showerror("Error", f"Failed to restore: {error_msg}")
                
        except Exception as e:
            self.update_status("Error")
            messagebox.showerror("Error", str(e))
        finally:
            self.progress_var.set(0)
            self.enable_buttons()

    def disable_buttons(self):
        self.btn_backup.config(state=tk.DISABLED)
        self.btn_restore.config(state=tk.DISABLED)
        self.btn_exit.config(state=tk.DISABLED)

    def enable_buttons(self):
        self.btn_backup.config(state=tk.NORMAL)
        self.btn_restore.config(state=tk.NORMAL)
        self.btn_exit.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = OptimizationTool(root)
    root.mainloop()