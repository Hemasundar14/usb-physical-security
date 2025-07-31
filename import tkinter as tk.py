import tkinter as tk
from tkinter import messagebox
import threading
import time

class USBPhysicalSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Physical Security For Systems")
        self.root.geometry("400x400")
        self.root.configure(bg="black")

        self.usb_enabled = True
        self.is_processing = False

        # 🔴 Project Info Button (Top)
        self.info_button = tk.Button(
            root, text="Project Info", bg="red", fg="white",
            font=("Helvetica", 12, "bold"), command=self.show_info
        )
        self.info_button.pack(pady=(10, 5))

        # ⚪ Title
        self.title_label = tk.Label(
            root, text="USB Physical Security!!!",
            font=("Helvetica", 16, "bold"), fg="white", bg="black"
        )
        self.title_label.pack(pady=10)

        # 🔘 Status Label
        self.status_label = tk.Label(
            root, text="USB Status: ENABLED", font=("Helvetica", 14),
            fg="lime", bg="black"
        )
        self.status_label.pack(pady=5)

        self.process_label = tk.Label(
            root, text="", font=("Helvetica", 11),
            fg="white", bg="black"
        )
        self.process_label.pack(pady=2)

        # 🔳 Buttons
        self.button_frame = tk.Frame(root, bg="black")
        self.button_frame.pack(pady=20)

        self.disable_button = tk.Button(
            self.button_frame, text="Disable USB", bg="red", fg="white",
            font=("Helvetica", 12), width=20, command=self.disable_usb
        )
        self.disable_button.pack(pady=10)

        self.enable_button = tk.Button(
            self.button_frame, text="Enable USB", bg="green", fg="white",
            font=("Helvetica", 12), width=20, command=self.enable_usb, state="disabled"
        )
        self.enable_button.pack(pady=10)

    def show_info(self):
        msg = (
            "🛡️ Project: USB Physical Security\n"
            "👨‍💻 Author: Hemasundar\n"
            "🏫 College: Guru Nanak Institutions\n"
            "📅 Year: 2025\n\n"
            "📌 Description:\n"
            "Blocks or enables USB ports with a simple GUI.\n"
            "Great for basic physical system security.\n\n"
            "🛠️ Tech Used: Python, Tkinter"
        )
        messagebox.showinfo("Project Info", msg)

    def update_ui(self):
        status = "ENABLED" if self.usb_enabled else "DISABLED"
        color = "lime" if self.usb_enabled else "red"
        self.status_label.config(text=f"USB Status: {status}", fg=color)

        if self.is_processing:
            self.process_label.config(text="Applying changes...")
            self.disable_button.config(state="disabled")
            self.enable_button.config(state="disabled")
        else:
            self.process_label.config(text="")
            self.disable_button.config(state="normal" if self.usb_enabled else "disabled")
            self.enable_button.config(state="normal" if not self.usb_enabled else "disabled")

    def simulate_action(self, enable: bool):
        self.is_processing = True
        self.update_ui()
        time.sleep(1.5)
        self.usb_enabled = enable
        self.is_processing = False
        self.update_ui()

    def disable_usb(self):
        threading.Thread(target=self.simulate_action, args=(False,), daemon=True).start()

    def enable_usb(self):
        threading.Thread(target=self.simulate_action, args=(True,), daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = USBPhysicalSecurityApp(root)
    root.mainloop()
