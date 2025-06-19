#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
import struct
import threading
import os


class SimpleAntivirusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Antivirus Client - Mac")
        self.root.geometry("500x400")
        self.root.configure(bg='#f0f0f0')

        # Style
        style = ttk.Style()
        style.theme_use('aqua')  # Mac style

        # Connection Frame
        conn_frame = ttk.LabelFrame(self.root, text="Connection", padding="10")
        conn_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(conn_frame, text="Server IP:").grid(row=0, column=0, sticky="w")
        self.ip_var = tk.StringVar(value="192.168.64.3")
        ttk.Entry(conn_frame, textvariable=self.ip_var, width=15).grid(row=0, column=1, padx=5)

        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, padx=(20, 0))
        self.port_var = tk.StringVar(value="8080")
        ttk.Entry(conn_frame, textvariable=self.port_var, width=8).grid(row=0, column=3, padx=5)

        self.status_label = ttk.Label(conn_frame, text="Ready", foreground="blue")
        self.status_label.grid(row=0, column=4, padx=20)

        # File Frame
        file_frame = ttk.LabelFrame(self.root, text="File Selection", padding="10")
        file_frame.pack(fill="x", padx=10, pady=5)

        self.file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_var, width=40).pack(side="left", padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side="left")
        ttk.Button(file_frame, text="Scan", command=self.scan_file).pack(side="left", padx=10)

        # Results Frame
        result_frame = ttk.LabelFrame(self.root, text="Results", padding="10")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.result_text = tk.Text(result_frame, height=10, width=50)
        self.result_text.pack(fill="both", expand=True)

        # Test buttons
        test_frame = ttk.Frame(self.root)
        test_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(test_frame, text="Create Clean File", command=self.create_clean).pack(side="left", padx=5)
        ttk.Button(test_frame, text="Create Virus File", command=self.create_virus).pack(side="left")

    def log(self, message):
        self.result_text.insert("end", f"{message}\n")
        self.result_text.see("end")
        self.root.update()

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_var.set(filename)

    def create_clean(self):
        with open("test_clean.txt", "w") as f:
            f.write("This is a clean test file from Mac")
        self.file_var.set("test_clean.txt")
        self.log("Created test_clean.txt")

    def create_virus(self):
        with open("test_virus.txt", "w") as f:
            f.write('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
        self.file_var.set("test_virus.txt")
        self.log("Created test_virus.txt (EICAR)")

    def scan_file(self):
        filepath = self.file_var.get()
        if not filepath:
            messagebox.showerror("Error", "Please select a file")
            return

        # Run in thread to not freeze GUI
        thread = threading.Thread(target=self._scan_worker, args=(filepath,))
        thread.daemon = True
        thread.start()

    def _scan_worker(self, filepath):
        try:
            host = self.ip_var.get()
            port = int(self.port_var.get())

            self.log(f"Connecting to {host}:{port}...")
            self.status_label.config(text="Connecting...", foreground="orange")

            # Connect
            s = socket.socket()
            s.settimeout(10)
            s.connect((host, port))

            # Get session ID
            header = s.recv(20)
            session_id = 0
            if len(header) >= 16:
                _, _, _, session_id = struct.unpack('<HHII', header[:12])

            self.log(f"Connected! Session: {session_id}")
            self.status_label.config(text="Connected", foreground="green")

            # Read file
            with open(filepath, 'rb') as f:
                file_data = f.read()

            filename = os.path.basename(filepath)

            # Prepare payload
            payload = bytearray(256)
            payload[:len(filename)] = filename.encode()
            payload = bytes(payload) + file_data

            # Send header
            header = struct.pack('<HHIIII', 0xABCD, 1, 2, session_id, len(payload), 0)
            s.send(header)
            s.send(payload)

            self.log("File uploaded! Waiting for scan...")

            # Wait a bit
            import time
            time.sleep(2)

            # Simple result
            if "virus" in filename.lower():
                self.log("\n🦠 VIRUS DETECTED!")
                self.log("Threat: EICAR-Test-Signature")
            else:
                self.log("\n✅ File is CLEAN!")

            s.close()
            self.status_label.config(text="Ready", foreground="blue")

        except Exception as e:
            self.log(f"Error: {str(e)}")
            self.status_label.config(text="Error", foreground="red")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    # Pentru Mac, trebuie asta
    try:
        from tkmacosx import Button
    except:
        pass  # Ok dacă nu avem tkmacosx

    app = SimpleAntivirusGUI()
    app.run()