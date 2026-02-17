#!/usr/bin/env python3
# Master Utilities v2.1 FIX
# Single-file, compatible with Python 3.9
# Admin password: "0305"

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext, filedialog
from datetime import datetime, date, time, timedelta
import platform, subprocess, shlex, shutil, os, json, threading, time as _time, socket, urllib.request

# -------- CONFIG --------
ADMIN_PASSWORD = "0305"
TASKS_FILE = "tasks.json"
NOTES_FILE = "notes.txt"
APP_VERSION = "2.1 FIX"

# -------- helpers --------
def modal_input(parent, title, prompt, show=None):
    dlg = tk.Toplevel(parent)
    dlg.transient(parent); dlg.grab_set()
    dlg.title(title)
    ttk.Label(dlg, text=prompt).pack(padx=12, pady=(12,4))
    v = tk.StringVar()
    ent = ttk.Entry(dlg, textvariable=v, width=40, show=show)
    ent.pack(padx=12, pady=(0,12))
    ent.focus_set()
    res = {'val': None}
    def ok():
        res['val'] = v.get().strip(); dlg.destroy()
    def cancel():
        dlg.destroy()
    btns = ttk.Frame(dlg); btns.pack(pady=(0,12))
    ttk.Button(btns, text="OK", command=ok).pack(side="left", padx=6)
    ttk.Button(btns, text="Cancelar", command=cancel).pack(side="left", padx=6)
    parent.wait_window(dlg)
    return res['val']

def perform_shutdown_now():
    try:
        plat = platform.system()
        if plat == "Windows":
            subprocess.Popen(shlex.split('shutdown /s /t 0'))
        elif plat == "Darwin":
            subprocess.Popen(['osascript','-e','tell app "System Events" to shut down'])
        elif plat == "Linux":
            try:
                subprocess.Popen(['systemctl','poweroff'])
            except Exception:
                subprocess.Popen(['shutdown','-h','now'])
        else:
            messagebox.showinfo("Info", "Apagado no soportado en este sistema.")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo apagar:\n{e}")

def run_in_thread(fn):
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    return t

# -------- App --------
class MasterUtilitiesApp:
    def __init__(self, root):
        self.root = root
        root.title(f"Master Utilities v{APP_VERSION}")
        root.geometry("800x520")
        root.minsize(700,450)
        self.platform = platform.system()

        # frames
        self.frame_login = ttk.Frame(root, padding=12)
        self.frame_menu = ttk.Frame(root, padding=12)
        self.frame_reloj = ttk.Frame(root, padding=12)
        self.frame_info = ttk.Frame(root, padding=12)
        self.frame_disk = ttk.Frame(root, padding=12)
        self.frame_ping = ttk.Frame(root, padding=12)
        self.frame_cleaner = ttk.Frame(root, padding=12)
        self.frame_ip = ttk.Frame(root, padding=12)

        self._build_login()
        self._build_menu()
        self._build_reloj()
        self._build_info()
        self._build_disk()
        self._build_ping()
        self._build_cleaner()
        self._build_ipinfo()

        self.show_frame(self.frame_login)

        # reloj internal
        self.reloj_target = None
        self.reloj_job = None
        self.warn_job = None
        self.warn_seconds = 60
        self.in_warn = False

    def show_frame(self, frame):
        for f in (self.frame_login, self.frame_menu, self.frame_reloj, self.frame_info,
                  self.frame_disk, self.frame_ping, self.frame_cleaner, self.frame_ip):
            f.pack_forget()
        frame.pack(fill="both", expand=True)

    # ---------- LOGIN ----------
    def _build_login(self):
        f = self.frame_login
        ttk.Label(f, text="Master Utilities", font=("Helvetica", 24, "bold")).pack(pady=(8,12))
        ttk.Label(f, text="Selecciona usuario:").pack(anchor="w")
        self.user_var = tk.StringVar(value="Master")
        user_combo = ttk.Combobox(f, textvariable=self.user_var, values=["Master","Invitado"], state="readonly", width=20)
        user_combo.pack(pady=6)
        ttk.Button(f, text="Entrar", command=self.handle_login).pack(pady=(6,4))
        ttk.Label(f, text="(Invitado cierra la app. Master usa contraseña.)", foreground="gray").pack(pady=(8,0))
        ttk.Button(f, text="Salir", command=self.root.destroy).pack(pady=6)

    def handle_login(self):
        sel = self.user_var.get()
        if sel == "Invitado":
            messagebox.showinfo("Invitado", "Has entrado como Invitado — cerrando la aplicación.")
            self.root.destroy()
            return
        pwd = modal_input(self.root, "Password Master", "Introduce la contraseña de Master:", show="*")
        if pwd is None:
            return
        if pwd == MASTER_PASSWORD:
            self.show_frame(self.frame_menu)
        else:
            messagebox.showerror("Acceso denegado", "Contraseña incorrecta.")

    # ---------- MENU ----------
    def _build_menu(self):
        f = self.frame_menu
        header = ttk.Frame(f); header.pack(fill="x")
        ttk.Label(header, text=f"Master Utilities — Menú (v{APP_VERSION})", font=("Helvetica", 16, "bold")).pack(side="left", pady=6)
        ttk.Button(header, text="Cerrar sesión", command=lambda: self.show_frame(self.frame_login)).pack(side="right")

        grid = ttk.Frame(f); grid.pack(pady=18)
        specs = [
            ("🕒 Reloj+", self.frame_reloj),
            ("ℹ️ System Info", self.frame_info),
            ("💽 Comprobar espacio", self.frame_disk),
            ("🌐 Test de red (ping)", self.frame_ping),
            ("🧹 Cleaner+", self.frame_cleaner),
            ("🌐 IP Info", self.frame_ip),
            ("📂 Abrir carpeta app", None)
        ]
        r = 0; c = 0
        for label, target in specs:
            if target:
                cmd = (lambda t=target: self.open_from_menu(t))
            else:
                cmd = self.open_app_folder
            b = ttk.Button(grid, text=label, width=26, command=cmd)
            b.grid(row=r, column=c, padx=10, pady=10)
            c += 1
            if c >= 2:
                c = 0; r += 1

    def open_from_menu(self, target):
        if target == self.frame_info: self.update_info()
        if target == self.frame_disk: self.update_disk()
        if target == self.frame_ping: pass
        if target == self.frame_cleaner: pass
        if target == self.frame_ip: pass
        self.show_frame(target)

    def open_app_folder(self):
        folder = os.path.abspath(os.getcwd())
        try:
            if self.platform == "Windows":
                os.startfile(folder)
            elif self.platform == "Darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir la carpeta:\n{e}")

    # ---------- RELOJ+ ----------
    def _build_reloj(self):
        f = self.frame_reloj
        head = ttk.Frame(f); head.pack(fill="x")
        ttk.Button(head, text="← Menú", command=lambda:self.show_frame(self.frame_menu)).pack(side="left")
        ttk.Label(head, text="🕒 Reloj+", font=("Helvetica", 16, "bold")).pack(pady=6)

        cfg = ttk.Frame(f); cfg.pack(padx=8, pady=8, fill="x")
        self.reloj_mode = tk.StringVar(value="hora")
        ttk.Radiobutton(cfg, text="Hora exacta (HH:MM)", variable=self.reloj_mode, value="hora").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(cfg, text="Apagar en X minutos", variable=self.reloj_mode, value="minutos").grid(row=1, column=0, sticky="w")

        ttk.Label(cfg, text="Fecha (YYYY-MM-DD) opcional:").grid(row=2, column=0, sticky="w", pady=(6,0))
        self.reloj_fecha = tk.StringVar()
        ttk.Entry(cfg, textvariable=self.reloj_fecha, width=22).grid(row=2, column=1, pady=(6,0))

        ttk.Label(cfg, text="Hora (HH:MM):").grid(row=3, column=0, sticky="w")
        self.reloj_hora = tk.StringVar()
        ttk.Entry(cfg, textvariable=self.reloj_hora, width=22).grid(row=3, column=1)

        ttk.Label(cfg, text="Minutos (si modo minutos):").grid(row=4, column=0, sticky="w")
        self.reloj_minutos = tk.StringVar(value="10")
        ttk.Entry(cfg, textvariable=self.reloj_minutos, width=22).grid(row=4, column=1)

        ttk.Button(cfg, text="Programar temporizador", command=self.start_reloj).grid(row=5, column=0, columnspan=2, pady=8, sticky="we")

        self.reloj_status = tk.StringVar(value="Esperando programación...")
        ttk.Label(f, textvariable=self.reloj_status, foreground="blue").pack(pady=(8,0))
        self.reloj_count = ttk.Label(f, text="", font=("Helvetica", 18))
        self.reloj_count.pack(pady=(6,0))

        # warning frame (hidden)
        self.warn_frame = ttk.Frame(f, padding=8, relief="ridge")
        self.warn_label = ttk.Label(self.warn_frame, text="", font=("Helvetica", 14), foreground="red")
        self.warn_label.pack()
        ttk.Button(self.warn_frame, text="Cancelar apagado (pwd)", command=self.cancel_reloj_with_pwd).pack(pady=6)
        ttk.Button(self.warn_frame, text="Apagar ahora", command=self.force_shutdown_reloj).pack()

    def start_reloj(self):
        now = datetime.now()
        mode = self.reloj_mode.get()
        if mode == "minutos":
            try:
                mins = int(self.reloj_minutos.get())
                if mins <= 0:
                    raise ValueError
            except Exception:
                messagebox.showerror("Error", "Introduce minutos válidos (entero >0).")
                return
            self.reloj_target = now + timedelta(minutes=mins)
        else:
            hora_text = self.reloj_hora.get().strip()
            if not hora_text:
                messagebox.showerror("Error", "Introduce hora HH:MM.")
                return
            try:
                hh, mm = map(int, hora_text.split(":"))
                if not (0 <= hh < 24 and 0 <= mm < 60):
                    raise ValueError
            except Exception:
                messagebox.showerror("Error", "Formato de hora inválido.")
                return
            fecha_text = self.reloj_fecha.get().strip()
            if fecha_text:
                try:
                    y,m,d = map(int, fecha_text.split("-"))
                    target_date = date(y,m,d)
                except Exception:
                    messagebox.showerror("Error", "Formato fecha inválido.")
                    return
            else:
                target_date = date.today()
            self.reloj_target = datetime.combine(target_date, time(hh,mm))

        if self.reloj_target <= now:
            messagebox.showerror("Error", "El tiempo objetivo ya pasó. Elige futuro.")
            return

        if not messagebox.askyesno("Confirmar", f"Programar apagado para {self.reloj_target.strftime('%Y-%m-%d %H:%M:%S')}?"):
            return

        self.reloj_status.set(f"Programado para {self.reloj_target.strftime('%Y-%m-%d %H:%M:%S')}")
        self._update_reloj_countdown()

    def _update_reloj_countdown(self):
        if not self.reloj_target:
            return
        now = datetime.now()
        delta = self.reloj_target - now
        total = int(delta.total_seconds())
        if total <= 0:
            self._start_reloj_warning()
            return
        h = (total // 3600) % 24
        m = (total % 3600) // 60
        s = total % 60
        txt = f"{h:02d}:{m:02d}:{s:02d}"
        self.reloj_count.config(text=f"Cuenta atrás: {txt}")
        self.reloj_job = self.root.after(1000, self._update_reloj_countdown)

    def _start_reloj_warning(self):
        if self.in_warn:
            return
        self.in_warn = True
        if self.reloj_job:
            self.root.after_cancel(self.reloj_job)
            self.reloj_job = None
        self.warn_seconds = 60
        self.warn_label.config(text=f"¡Hora de apagar! Tienes {self.warn_seconds} segundos para cerrar todo.")
        self.warn_frame.pack(pady=8)
        self._tick_reloj_warning()

    def _tick_reloj_warning(self):
        self.warn_label.config(text=f"¡Hora de apagar! Tienes {self.warn_seconds} segundos para cerrar todo.")
        if self.warn_seconds <= 0:
            self.warn_frame.pack_forget()
            self.in_warn = False
            self.reloj_status.set("Apagando ahora...")
            perform_shutdown_now()
            return
        self.warn_seconds -= 1
        self.warn_job = self.root.after(1000, self._tick_reloj_warning)

    def cancel_reloj_with_pwd(self):
        pwd = modal_input(self.root, "Confirmar cancelación", "Introduce password Master para cancelar:", show="*")
        if pwd is None:
            return
        if pwd != MASTER_PASSWORD:
            messagebox.showerror("Denegado", "Password incorrecta. No se cancela.")
            return
        # cancel
        if self.warn_job:
            self.root.after_cancel(self.warn_job)
            self.warn_job = None
        self.in_warn = False
        self.reloj_target = None
        self.warn_frame.pack_forget()
        self.reloj_status.set("Apagado cancelado.")
        self.reloj_count.config(text="")

    def force_shutdown_reloj(self):
        if self.warn_job:
            self.root.after_cancel(self.warn_job)
            self.warn_job = None
        self.warn_frame.pack_forget()
        self.in_warn = False
        self.reloj_status.set("Apagando ahora...")
        perform_shutdown_now()

    # ---------- System Info ----------
    def _build_info(self):
        f = self.frame_info
        head = ttk.Frame(f); head.pack(fill="x")
        ttk.Button(head, text="← Menú", command=lambda: self.show_frame(self.frame_menu)).pack(side="left")
        ttk.Label(head, text="Sistema Info", font=("Helvetica", 16, "bold")).pack(pady=6)

        self.info_text = scrolledtext.ScrolledText(f, height=16, wrap="word")
        self.info_text.pack(fill="both", expand=True, padx=6, pady=6)

    def update_info(self):
        self.info_text.delete("1.0", tk.END)
        lines = []
        lines.append(f"Platform: {platform.system()} {platform.release()}")
        lines.append(f"Node / Hostname: {platform.node()}")
        lines.append(f"Python: {platform.python_version()}")
        lines.append(f"Hora actual: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        # uptime best-effort
        uptime = "No disponible"
        try:
            import psutil
            boot = datetime.fromtimestamp(psutil.boot_time())
            delta = datetime.now() - boot
            uptime = str(delta).split(".")[0]
        except Exception:
            try:
                if platform.system() == "Linux":
                    with open("/proc/uptime", "r") as f:
                        sec = float(f.readline().split()[0])
                        uptime = str(timedelta(seconds=int(sec)))
                elif platform.system() == "Darwin":
                    out = subprocess.check_output(["sysctl", "-n", "kern.boottime"]).decode(errors='ignore')
                # Windows fallback omitted if psutil not present
            except Exception:
                uptime = "No disponible (instala psutil para mejor info)"
        lines.append(f"Uptime: {uptime}")
        # memory / cpu if psutil available
        try:
            import psutil
            mem = psutil.virtual_memory()
            lines.append(f"RAM: {mem.total//(1024**2)} MB total / {mem.available//(1024**2)} MB avail")
            lines.append(f"CPU cores (logical): {psutil.cpu_count(logical=True)}")
        except Exception:
            lines.append("RAM/CPU: (instala psutil para más detalles)")
        self.info_text.insert(tk.END, "\n".join(lines))

    # ---------- Disk usage ----------
    def _build_disk(self):
        f = self.frame_disk
        head = ttk.Frame(f); head.pack(fill="x")
        ttk.Button(head, text="← Menú", command=lambda: self.show_frame(self.frame_menu)).pack(side="left")
        ttk.Label(head, text="Comprobar espacio", font=("Helvetica", 16, "bold")).pack(pady=6)

        self.disk_text = scrolledtext.ScrolledText(f, height=14, wrap="word")
        self.disk_text.pack(fill="both", expand=True, padx=6, pady=6)
        ttk.Button(f, text="Actualizar", command=self.update_disk).pack(pady=(0,8))

    def update_disk(self):
        try:
            path = os.path.abspath(os.getcwd())
            total, used, free = shutil.disk_usage(path)
            pct = used / total * 100 if total else 0
            lines = [
                f"Path analizado: {path}",
                f"Total: {total // (1024**3)} GB",
                f"Usado: {used // (1024**3)} GB",
                f"Libre: {free // (1024**3)} GB",
                f"Porcentaje usado: {pct:.2f} %"
            ]
            self.disk_text.delete("1.0", tk.END)
            self.disk_text.insert(tk.END, "\n".join(lines))
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo obtener espacio en disco: {e}")

    # ---------- Ping ----------
    def _build_ping(self):
        f = self.frame_ping
        head = ttk.Frame(f); head.pack(fill="x")
        ttk.Button(head, text="← Menú", command=lambda: self.show_frame(self.frame_menu)).pack(side="left")
        ttk.Label(head, text="Test de red (ping)", font=("Helvetica", 16, "bold")).pack(pady=6)

        ttk.Label(f, text="Host (por defecto google.com):").pack(anchor="w", padx=6)
        self.ping_host = tk.StringVar(value="google.com")
        ttk.Entry(f, textvariable=self.ping_host, width=30).pack(padx=6, pady=4)
        ttk.Button(f, text="Hacer ping (4 paquetes)", command=self.start_ping_thread).pack(pady=4)
        self.ping_out = scrolledtext.ScrolledText(f, height=12)
        self.ping_out.pack(fill="both", expand=True, padx=6, pady=6)

    def start_ping_thread(self):
        run_in_thread(self.do_ping)

    def do_ping(self):
        host = self.ping_host.get().strip() or "google.com"
        self.ping_out.delete("1.0", tk.END)
        self.ping_out.insert(tk.END, f"Haciendo ping a {host}...\n\n")
        try:
            if self.platform == "Windows":
                cmd = ["ping", "-n", "4", host]
            else:
                cmd = ["ping", "-c", "4", host]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                self.ping_out.insert(tk.END, line)
                self.ping_out.see(tk.END)
            proc.wait()
            self.ping_out.insert(tk.END, f"\nPing finalizado (returncode {proc.returncode})")
        except Exception as e:
            self.ping_out.insert(tk.END, f"Error al ejecutar ping: {e}")

    # ---------- Cleaner+ ----------
    def _build_cleaner(self):
        f = self.frame_cleaner
        head = ttk.Frame(f); head.pack(fill="x")
        ttk.Button(head, text="← Menú", command=lambda: self.show_frame(self.frame_menu)).pack(side="left")
        ttk.Label(head, text="🧹 Cleaner+", font=("Helvetica", 16, "bold")).pack(pady=6)

        body = ttk.Frame(f); body.pack(padx=6, pady=6, fill="both", expand=True)
        ttk.Label(body, text="Acciones de limpieza disponibles:").pack(anchor="w", pady=(4,6))

        ttk.Button(body, text="Limpiar carpeta TEMP", command=self.clean_temp).pack(fill="x", pady=4)
        ttk.Button(body, text="Eliminar archivos temporales del usuario", command=self.clean_user_temp).pack(fill="x", pady=4)
        ttk.Button(body, text="Vaciar Papelera (Windows)", command=self.empty_recycle_bin).pack(fill="x", pady=4)
        ttk.Label(body, text="Nota: las operaciones pueden tardar y eliminar archivos irreversibles. Haz copia si dudas.", foreground="gray").pack(pady=(8,0))

        self.clean_log = scrolledtext.ScrolledText(body, height=8)
        self.clean_log.pack(fill="both", expand=True, pady=(6,0))

    def log_clean(self, text):
        self.clean_log.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')}  {text}\n")
        self.clean_log.see(tk.END)

    def clean_temp(self):
        if not messagebox.askyesno("Confirmar", "Eliminar archivos de la carpeta TEMP del sistema?"):
            return
        def job():
            temp = os.getenv('TEMP') or os.getenv('TMP') or '/tmp'
            self.log_clean(f"Iniciando limpieza TEMP: {temp}")
            removed = 0
            for root_dir, dirs, files in os.walk(temp):
                for name in files:
                    path = os.path.join(root_dir, name)
                    try:
                        os.remove(path); removed += 1
                    except Exception:
                        pass
                # optionally remove empty dirs
            self.log_clean(f"Archivos intentados de borrar: {removed}")
            messagebox.showinfo("Limpieza TEMP", "Intentada la limpieza de TEMP (revisa el log).")
        run_in_thread(job)

    def clean_user_temp(self):
        if not messagebox.askyesno("Confirmar", "Eliminar archivos temporales del usuario (AppData\\Local\\Temp)?"):
            return
        def job():
            user_temp = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp") if self.platform == "Windows" else (os.getenv('TMP') or '/tmp')
            self.log_clean(f"Iniciando limpieza usuario: {user_temp}")
            removed = 0
            for root_dir, dirs, files in os.walk(user_temp):
                for name in files:
                    path = os.path.join(root_dir, name)
                    try:
                        os.remove(path); removed += 1
                    except Exception:
                        pass
            self.log_clean(f"Archivos intentados de borrar: {removed}")
            messagebox.showinfo("Limpieza usuario", "Intentada la limpieza del temp de usuario (revisa el log).")
        run_in_thread(job)

    def empty_recycle_bin(self):
        if self.platform != "Windows":
            messagebox.showinfo("No soportado", "Vaciar papelera integrado solo en Windows (usa tu gestor).")
            return
        if not messagebox.askyesno("Confirmar", "Vaciar la Papelera de reciclaje (Windows)?"):
            return
        def job():
            try:
                # using PowerShell Clear-RecycleBin
                subprocess.check_call(["powershell", "-NoProfile", "-Command", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"])
                self.log_clean("Papelera vaciada (intento con PowerShell).")
                messagebox.showinfo("Papelera", "Papelera vaciada.")
            except Exception as e:
                self.log_clean(f"Error vaciar papelera: {e}")
                messagebox.showerror("Error", f"No se pudo vaciar la papelera: {e}")
        run_in_thread(job)

    # ---------- IP Info ----------
    def _build_ipinfo(self):
        f = self.frame_ip
        head = ttk.Frame(f); head.pack(fill="x")
        ttk.Button(head, text="← Menú", command=lambda: self.show_frame(self.frame_menu)).pack(side="left")
        ttk.Label(head, text="🌐 IP Info", font=("Helvetica", 16, "bold")).pack(pady=6)

        body = ttk.Frame(f); body.pack(fill="both", expand=True, padx=6, pady=6)
        ttk.Button(body, text="Mostrar IP local", command=self.show_local_ip).pack(fill="x", pady=4)
        ttk.Button(body, text="Mostrar IP pública", command=self.show_public_ip).pack(fill="x", pady=4)

        self.ip_text = scrolledtext.ScrolledText(body, height=10)
        self.ip_text.pack(fill="both", expand=True, pady=(8,0))

    def show_local_ip(self):
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            self.ip_text.insert(tk.END, f"Hostname: {hostname}\nLocal IP: {local_ip}\n\n")
            self.ip_text.see(tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo obtener IP local: {e}")

    def show_public_ip(self):
        def job():
            try:
                url = "https://api.ipify.org"
                with urllib.request.urlopen(url, timeout=8) as resp:
                    ip = resp.read().decode('utf-8').strip()
                self.ip_text.insert(tk.END, f"IP pública: {ip}\n\n")
                self.ip_text.see(tk.END)
            except Exception as e:
                self.ip_text.insert(tk.END, f"Error obteniendo IP pública: {e}\n\n")
                self.ip_text.see(tk.END)
        run_in_thread(job)

# ------ run -------
def main():
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use('clam')
    except Exception:
        pass
    app = MasterUtilitiesApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
