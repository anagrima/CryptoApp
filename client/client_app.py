import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
import random
from src.auth.auth_service import login
from src.auth.password_policy import valid_password
from src.auth.short_message_service import send_otp, verify_otp, set_otp_queue
from src.tickets import list_user_tickets, get_ticket_decrypted, add_ticket, transfer_ticket_with_authorization
from src.auth.auth_service import get_user_public_key
from src.sign.sign_service import sign_transfer_authorization
from src.crypto.asymmetric import deserialize_private_key
from src.tickets.models import Ticket
from src.config import SMS_2FA_ENABLED
from client.client_setup import client_register


# ======================
#  Clase principal (App)
# ======================
class App(tk.Tk):
    def __init__(self, otp_queue=None):
        super().__init__()
        self.title("CryptoApp – Tickets cifrados")
        self.geometry("640x480")
        self.resizable(False, False)
        self.username = None

        # Configuramos la cola para poder "enviar" SMS.
        if otp_queue:
            set_otp_queue(otp_queue)

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)

        self.frames = {}
        for F in (LoginFrame, OTPFrame, TicketsFrame, RegisterFrame):
            frame = F(container, self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show("LoginFrame")

    def show(self, name):
        self.frames[name].tkraise()
        # call optional on_show hook for frames that need it
        frame = self.frames.get(name)
        if frame and hasattr(frame, "on_show"):
            try:
                frame.on_show()
            except Exception:
                pass

    def logout(self):
        """Cerrar sesión: limpiar usuario y volver a LoginFrame."""
        self.username = None
        # if TicketsFrame exists, clear its view
        tf = self.frames.get("TicketsFrame")
        if tf:
            # remove items from treeview
            try:
                for i in tf.tree.get_children():
                    tf.tree.delete(i)
            except Exception:
                pass
        # clear password field on login frame if present
        lf = self.frames.get("LoginFrame")
        if lf:
            try:
                lf.e_pwd.delete(0, "end")
            except Exception:
                pass

        # clear otp field on otp frame if present
        of = self.frames.get("OTPFrame")
        if of:
            try:
                of.e_otp.delete(0, "end")
            except Exception:
                pass

        # clear register password fields if present
        rf = self.frames.get("RegisterFrame")
        if rf:
            try:
                rf.e_pwd.delete(0, "end")
                rf.e_pwd2.delete(0, "end")
            except Exception:
                pass

        self.show("LoginFrame")
        # limpiar cache de claves privadas cargadas por si existe
        try:
            from src.tickets.hybrid_encripted_store import clear_private_key_cache
            clear_private_key_cache(self.username)
        except Exception:
            # no crítico si falla limpiar cache
            pass


# ======================
#       Login
# ======================
class LoginFrame(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app

        ttk.Label(self, text="Usuario").pack(pady=(60, 4))
        self.e_user = ttk.Entry(self, width=30)
        self.e_user.pack()

        ttk.Label(self, text="Contraseña").pack(pady=(12, 4))
        self.e_pwd = ttk.Entry(self, width=30, show="*")
        self.e_pwd.pack()

        ttk.Button(self, text="Iniciar sesión", command=self.do_login).pack(pady=20)
        ttk.Button(self, text="Registrar nuevo usuario", command=lambda: self.app.show("RegisterFrame")).pack()

    def do_login(self):
        user = self.e_user.get().strip()
        pwd = self.e_pwd.get()
        if not user or not pwd:
            messagebox.showwarning("Campos requeridos", "Introduce usuario y contraseña.")
            return

        if login(user, pwd):
            self.app.username = user
            if SMS_2FA_ENABLED:
                send_otp(user)
                self.app.show("OTPFrame")
            else:
                self.app.show("TicketsFrame")
        else:
            messagebox.showerror("Error", "Credenciales inválidas.")


# ======================
#         OTP
# ======================
class OTPFrame(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app

        ttk.Label(self, text="Introduce el código OTP enviado por SMS").pack(pady=(60, 8))
        self.e_otp = ttk.Entry(self, width=12, justify="center")
        self.e_otp.pack()
        ttk.Button(self, text="Verificar", command=self.do_verify).pack(pady=12)
        ttk.Button(self, text="Reenviar código", command=self.resend).pack()

    def do_verify(self):
        code = self.e_otp.get().strip()
        if verify_otp(self.app.username, code):
            self.app.show("TicketsFrame")
        else:
            messagebox.showerror("Error", "Código OTP incorrecto.")

    def resend(self):
        send_otp(self.app.username)
        messagebox.showinfo("OTP", "Se ha reenviado el código.")

    def on_show(self):
        self.e_otp.delete(0, "end")


# ======================
#       Tickets
# ======================
class TicketsFrame(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app

        ttk.Label(self, text="Tus entradas").pack(pady=(16, 6))
        self.tree = ttk.Treeview(
            self,
            columns=("artist", "venue", "date", "seat"),
            show="headings",
            height=12,
        )
        for c, w in (("artist", 160), ("venue", 160), ("date", 140), ("seat", 120)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(padx=12, pady=8, fill="both", expand=True)

        btns = ttk.Frame(self)
        btns.pack(pady=8)
        ttk.Button(btns, text="Ver detalle", command=self.view_selected).grid(row=0, column=0, padx=6)
        self.add_demo_btn = ttk.Button(btns, text="Añadir demo", command=self.add_demo_ticket)
        self.add_demo_btn.grid(row=0, column=1, padx=6)
        self.transfer_btn = ttk.Button(btns, text="Transferir", command=self.transfer_selected)
        self.transfer_btn.grid(row=0, column=2, padx=6)
        ttk.Button(btns, text="Recargar", command=self.refresh).grid(row=0, column=3, padx=6)
        ttk.Button(btns, text="Cerrar sesión", command=lambda: self.app.logout()).grid(row=0, column=4, padx=6)
        # flag para evitar reentradas mientras se crea/gestiona un ticket
        self._busy = False

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        if not self.app.username:
            return
        ids = list_user_tickets(self.app.username)
        for tid in ids:
            t = get_ticket_decrypted(self.app.username, tid)
            # if decryption failed or ticket not found, skip it
            if t is None:
                # show a placeholder entry so user can see an unknown ticket (optional)
                # or simply skip to avoid crashing the UI
                continue
            try:
                self.tree.insert("", "end", iid=tid, values=(t.artist, t.venue, t.date_iso, t.seat))
            except Exception:
                # if any unexpected structure, skip this ticket
                continue

    def view_selected(self):
        sel = self.tree.focus()
        if not sel:
            messagebox.showwarning("Selecciona", "Selecciona un ticket.")
            return
        t = get_ticket_decrypted(self.app.username, sel)
        if t is None:
            messagebox.showerror("Error", "No se pudo recuperar/descifrar el ticket seleccionado.")
            return
        info = (
            f"Artista: {t.artist}\nLugar: {t.venue}\nFecha: {t.date_iso}\n"
            f"Asiento: {t.seat}\nQR: {t.qr_payload}"
        )
        messagebox.showinfo("Ticket", info)

    def _load_own_private_key(self, password: bytes | None = None):
        """Carga la clave privada del cliente desde `client/mock_client_keys/{username}_keys.json`.
        Devuelve el objeto clave privada deserializado o lanza FileNotFoundError/ValueError.
        """
        from pathlib import Path
        if not self.app.username:
            raise ValueError("Usuario no autenticado")
        key_file = Path("client/mock_client_keys") / f"{self.app.username}_keys.json"
        if not key_file.exists():
            raise FileNotFoundError("Archivo de claves local no encontrado para el usuario")
        import json
        data = json.loads(key_file.read_text(encoding="utf-8"))
        pem = data.get("private_key_pem")
        if not pem:
            raise ValueError("Clave privada PEM no encontrada en el archivo de claves local")
        # deserialize_private_key espera bytes or str PEM
        # si se proporciona password, intentar con ella
        if password is not None:
            try:
                return deserialize_private_key(pem, password=password)
            except Exception:
                # si falla, permitir que el flujo solicite una contraseña interactiva a continuación
                pass

        try:
            return deserialize_private_key(pem)
        except Exception:
            # si la clave está cifrada o la deserialización falla, pedir la contraseña al usuario de forma segura
            import tkinter.simpledialog as sd
            pwd = sd.askstring("Contraseña clave privada", "Introduce la contraseña de tu clave privada:", show="*")
            if pwd is None:
                # el usuario canceló
                raise ValueError("Contraseña no proporcionada por el usuario")
            # reintentar con la contraseña
            return deserialize_private_key(pem, password=pwd.encode("utf-8"))

    def transfer_selected(self):
        sel = self.tree.focus()
        if not sel:
            messagebox.showwarning("Selecciona", "Selecciona un ticket para transferir.")
            return
        if not self.app.username:
            messagebox.showerror("Error", "Usuario no autenticado.")
            return
        # pedir nombre de usuario destinatario
        # evitar reentradas
        if self._busy:
            return
        self._busy = True
        try:
            import tkinter.simpledialog as sd
            new_owner = sd.askstring("Transferir", "Nombre de usuario destinatario:")
            if not new_owner:
                self._busy = False
                return

            # obtener clave pública del nuevo owner desde el 'servidor' (user_store)
            new_owner_pub = get_user_public_key(new_owner)
            if not new_owner_pub:
                messagebox.showerror("Error", f"No se encontró el usuario '{new_owner}' o no tiene clave pública.")
                return

            # solicitar la contraseña de la clave privada ANTES de intentar cargarla
            import tkinter.simpledialog as sd
            key_pwd = sd.askstring("Contraseña de firma", "Introduce la contraseña de tu clave de firma:", show="*")
            if key_pwd is None:
                # usuario canceló
                return

            # cargar clave privada local del propietario para firmar la autorización
            try:
                priv = self._load_own_private_key(password=key_pwd.encode("utf-8"))
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo cargar la clave privada local: {e}")
                return

            # crear wrapper de autorización firmado
            # crear wrapper de autorización firmado
            try:
                wrapper = sign_transfer_authorization(priv, sel, new_owner_pub)
            except Exception as e:
                self._busy = False
                messagebox.showerror("Error", f"No se pudo crear la autorización de transferencia: {e}")
                return

            # En un despliegue real enviaríamos `wrapper` al servidor; aquí llamamos directamente al store
            try:
                transfer_ticket_with_authorization(self.app.username, new_owner, sel, wrapper)
                messagebox.showinfo("Transferencia", "Transferencia realizada con éxito.")
                self.refresh()
            except Exception as e:
                messagebox.showerror("Error", f"Transferencia fallida: {e}")
                self._busy = False
                return

        finally:
            self._busy = False

    def add_demo_ticket(self):
        u = self.app.username
        if not u:
            messagebox.showwarning("Usuario", "Debes iniciar sesión para crear tickets demo.")
            return
        now_dt = datetime.now()
        # unique ticket id using timestamp
        tid = f"DEMO-{now_dt.strftime('%Y%m%d%H%M%S%f')}"

        # choose random artist/venue/date/seat so tickets are distinguishable
        artists = ["The Cryptos", "Synth Lords", "BitBeats", "La Banda RSA"]
        venues = ["Sala GCM", "Auditorio UC3M", "Teatro Central", "Sala B"]
        artist = random.choice(artists)
        venue = random.choice(venues)
        # date in the next 1-30 days at an evening hour
        future_dt = now_dt + timedelta(days=random.randint(1, 30))
        hour = random.choice([18, 19, 20, 21])
        future_dt = future_dt.replace(hour=hour, minute=0, second=0, microsecond=0)
        date_iso = future_dt.strftime("%Y-%m-%dT%H:%M:%S")
        seat = f"Fila {random.randint(1,20)}, Asiento {random.randint(1,40)}"

        demo = Ticket(
            ticket_id=tid,
            username=u,
            artist=artist,
            venue=venue,
            date_iso=date_iso,
            seat=seat,
            qr_payload=f"qr:{u}:{tid}",
        )
        # evitar reentradas (doble-click) que provoquen añadir múltiples tickets
        if self._busy:
            return
        self._busy = True
        # deshabilitar el boton mientras se procesa
        try:
            self.add_demo_btn.config(state="disabled")
        except Exception:
            pass
        try:
            add_ticket(demo)
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            messagebox.showerror("Error al crear ticket demo", f"No se pudo crear el ticket demo: {e}\n\n{tb}")
            try:
                self.add_demo_btn.config(state="normal")
            except Exception:
                pass
            self._busy = False
            return

        try:
            self.refresh()
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            messagebox.showerror("Error al actualizar lista", f"Ticket creado pero no se pudo refrescar la lista: {e}\n\n{tb}")
            try:
                self.add_demo_btn.config(state="normal")
            except Exception:
                pass
            self._busy = False
            return

        # reactivar el boton
        try:
            self.add_demo_btn.config(state="normal")
        except Exception:
            pass
        self._busy = False


# ======================
#     Registro
# ======================
class RegisterFrame(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app

        ttk.Label(self, text="Registro de usuario").pack(pady=(40, 8))

        ttk.Label(self, text="Usuario").pack(pady=(8, 4))
        self.e_user = ttk.Entry(self, width=30)
        self.e_user.pack()

        ttk.Label(self, text="Teléfono (9 dígitos)").pack(pady=(8, 4))
        self.e_phone = ttk.Entry(self, width=30)
        self.e_phone.pack()

        ttk.Label(self, text="Contraseña").pack(pady=(8, 4))
        self.e_pwd = ttk.Entry(self, width=30, show="*")
        self.e_pwd.pack()

        ttk.Label(self, text="Repetir contraseña").pack(pady=(8, 4))
        self.e_pwd2 = ttk.Entry(self, width=30, show="*")
        self.e_pwd2.pack()

        # Nueva: contraseña para proteger la clave privada (firma)
        ttk.Label(self, text="Contraseña de firma (clave privada)").pack(pady=(8, 4))
        self.e_key_pwd = ttk.Entry(self, width=30, show="*")
        self.e_key_pwd.pack()

        ttk.Label(self, text="Repetir contraseña de firma").pack(pady=(8, 4))
        self.e_key_pwd2 = ttk.Entry(self, width=30, show="*")
        self.e_key_pwd2.pack()

        btns = ttk.Frame(self)
        btns.pack(pady=12)
        ttk.Button(btns, text="Crear cuenta", command=self.do_register).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Volver", command=lambda: app.show("LoginFrame")).grid(row=0, column=1, padx=6)

    def do_register(self):
        user = self.e_user.get().strip()
        pwd = self.e_pwd.get()
        pwd2 = self.e_pwd2.get()
        phone = self.e_phone.get().strip()

        if not all([user, pwd, pwd2, phone]):
            messagebox.showwarning("Campos requeridos", "Rellena todos los campos.")
            return
        if pwd != pwd2:
            messagebox.showwarning("Error", "Las contraseñas no coinciden.")
            return

        # valida y registra la contraseña de firma (debe cumplir política y ser distinta a la contraseña de acceso)
        key_pwd = self.e_key_pwd.get()
        key_pwd2 = self.e_key_pwd2.get()
        if key_pwd != key_pwd2:
            messagebox.showwarning("Error", "Las contraseñas de firma no coinciden.")
            return
        if not key_pwd:
            messagebox.showwarning("Error", "Debes proporcionar una contraseña de firma para proteger tu clave privada.")
            return
        # reutilizar la política de contraseñas del módulo auth
        if not valid_password(key_pwd):
            messagebox.showwarning("Error", f"La contraseña de firma no cumple la política mínima (longitud y complejidad).")
            return
        if key_pwd == pwd:
            messagebox.showwarning("Error", "La contraseña de firma debe ser distinta de la contraseña de inicio de sesión.")
            return

        key_pwd_bytes = key_pwd.encode("utf-8")

        # registra al cliente y guarda sus claves localmente (clave privada cifrada)
        ok = client_register(user, pwd, phone, key_password=key_pwd_bytes)

        if ok:
            messagebox.showinfo("Registro", "Usuario registrado. Ya puedes iniciar sesión.")
            self.app.show("LoginFrame")
        else:
            messagebox.showerror("Registro fallido", "No se pudo registrar. Revisa los requisitos de la contraseña o si el usuario ya existe.")

    def on_show(self):
        """Called when the RegisterFrame is shown: clear password fields so
        previous values (e.g. signing-key password) are not visible when
        opening the register form again.
        """
        try:
            self.e_pwd.delete(0, "end")
        except Exception:
            pass
        try:
            self.e_pwd2.delete(0, "end")
        except Exception:
            pass
        try:
            self.e_key_pwd.delete(0, "end")
        except Exception:
            pass
        try:
            self.e_key_pwd2.delete(0, "end")
        except Exception:
            pass


# ======================
#       Main
# ======================
def run(otp_queue=None):
    app = App(otp_queue)
    app.mainloop()

if __name__ == "__main__":
    run()
