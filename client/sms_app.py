import tkinter as tk
import queue
import threading

class SmsApp:
    def __init__(self, root, otp_queue):
        self.root = root
        self.otp_queue = otp_queue
        self.root.title("App SMS Ficticia")
        self.create_widgets()
        self.check_queue()

    def create_widgets(self):
        self.main_frame = tk.Frame(self.root, padx=20, pady=20)
        self.main_frame.pack()

        tk.Label(self.main_frame, text="Mensajes SMS Recibidos:", font=("Arial", 14, "bold")).pack(pady=10)

        self.sms_listbox = tk.Listbox(self.main_frame, height=10, width=50, font=("Arial", 12))
        self.sms_listbox.pack(pady=10)

    def check_queue(self):
        try:
            message = self.otp_queue.get(block=False)
            self.sms_listbox.insert(tk.END, message)
        except queue.Empty:
            pass
        self.root.after(100, self.check_queue)

def start_sms_app(otp_queue):
    root = tk.Tk()
    app = SmsApp(root, otp_queue)
    root.mainloop()