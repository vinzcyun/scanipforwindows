# source của wyn
import ipaddress
import socket
import random
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time, strftime, localtime
import os
import requests
import threading
import psutil
import json
import csv
from io import BytesIO
from PIL import Image, ImageTk

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3389: "RDP", 5900: "VNC"
}

class PasswordDialog:
    def __init__(self, parent):
        self.parent = parent
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Enter Password")
        self.dialog.geometry("300x100")
        self.dialog.resizable(False, False)
        
        self.password_var = tk.StringVar()
        
        tk.Label(self.dialog, text="Enter password").pack(pady=10)
        self.password_entry = tk.Entry(self.dialog, show="*", textvariable=self.password_var)
        self.password_entry.pack()
        
        tk.Button(self.dialog, text="Submit", command=self.check_password).pack(pady=10)
        
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
    def check_password(self):
        entered_password = self.password_var.get()
        correct_password = self.get_password_from_url()
        
        if entered_password == correct_password:
            self.dialog.destroy()
        else:
            messagebox.showerror("Error", "Incorrect password. Please try again.")
            self.password_var.set("")
    
    def get_password_from_url(self):
        try:
            response = requests.get("https://is.gd/keyscanip")
            return response.text.strip()
        except:
            messagebox.showerror("Error", "Failed to fetch password. Please check your internet connection.")
            return ""
    
    def on_closing(self):
        self.parent.quit()

class IPScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Scanner v0.8")
        self.root.geometry("1000x700")

        self.set_custom_icon()

        self.setup_ui()
        self.check_ping()
        self.update_network_speed()
        self.load_config()
        self.show_information()

    def set_custom_icon(self):
        icon_url = "https://cdn3.iconfinder.com/data/icons/drone-soft/512/radar-512.png"
        icon_path = "radar_icon.png"

        if os.path.exists(icon_path):
            self.set_icon_from_file(icon_path)
        else:
            self.download_and_set_icon(icon_url, icon_path)

    def set_icon_from_file(self, icon_path):
        try:
            icon_image = Image.open(icon_path)
            icon_image = icon_image.resize((32, 32))
            icon_photo = ImageTk.PhotoImage(icon_image)
            self.root.iconphoto(True, icon_photo)
        except Exception as e:
            print(f"{e}")

    def download_and_set_icon(self, icon_url, icon_path):
        try:
            response = requests.get(icon_url)
            icon_data = BytesIO(response.content)
            icon_image = Image.open(icon_data)
            icon_image = icon_image.resize((32, 32))
            icon_image.save(icon_path)
            icon_photo = ImageTk.PhotoImage(icon_image)
            self.root.iconphoto(True, icon_photo)
        except Exception as e:
            print(f"{e}")

    def setup_ui(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        self.create_info_frame(left_frame)

        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.create_input_frame(right_frame)
        self.create_control_frame(right_frame)
        self.create_console_frame(right_frame)

        self.create_footer()

    def create_info_frame(self, parent):
        info_frame = ttk.LabelFrame(parent, text="Scan Information", padding=5)
        info_frame.pack(fill=tk.X, pady=(0, 10))

        labels = ["Total IPs:", "Scanned IPs:", "Open IPs:", "Scan Time:", "Scan Speed:", "Ping:", "Network Speed:"]
        self.info_labels = {}

        for i, text in enumerate(labels):
            ttk.Label(info_frame, text=text).grid(row=i, column=0, sticky="w")
            label = ttk.Label(info_frame, text="0", foreground="blue")
            label.grid(row=i, column=1, sticky="e")
            self.info_labels[text.lower().replace(" ", "_").replace(":", "")] = label

    def create_input_frame(self, parent):
        input_frame = ttk.Frame(parent)
        input_frame.pack(fill=tk.X, pady=5)

        ttk.Label(input_frame, text="IP Range(s) (CIDR):").pack(anchor="w")
        self.ip_range_entry = tk.Text(input_frame, width=50, height=8)
        self.ip_range_entry.pack(fill=tk.X, expand=True)

        file_frame = ttk.Frame(input_frame)
        file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(file_frame, text="Browse File", command=self.browse_file).pack(side=tk.LEFT)

        self.random_scan_var = tk.BooleanVar()
        ttk.Checkbutton(file_frame, text="Random Scan", variable=self.random_scan_var).pack(side=tk.LEFT, padx=(10, 0))

        port_frame = ttk.Frame(input_frame)
        port_frame.pack(fill=tk.X, pady=5)
        ttk.Label(port_frame, text="Enter Port").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(port_frame, width=10)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "3389")
        ttk.Button(port_frame, text="[^]", command=self.show_port_suggestions, width=3).pack(side=tk.LEFT)

        max_workers_frame = ttk.Frame(input_frame)
        max_workers_frame.pack(fill=tk.X, pady=5)
        ttk.Label(max_workers_frame, text="Max Workers").pack(side=tk.LEFT)
        self.max_workers_entry = ttk.Entry(max_workers_frame, width=10)
        self.max_workers_entry.pack(side=tk.LEFT, padx=5)
        self.max_workers_entry.insert(0, "100")

        config_frame = ttk.Frame(input_frame)
        config_frame.pack(fill=tk.X, pady=5)
        ttk.Button(config_frame, text="Save Config", command=self.save_config).pack(side=tk.LEFT)
        ttk.Button(config_frame, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=(10, 0))

    def create_control_frame(self, parent):
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, pady=10)

        ttk.Button(control_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="Stop Scan", command=self.stop_scan).pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(control_frame, length=300, mode='determinate')
        self.progress.pack(side=tk.LEFT, padx=(10, 5), fill=tk.X, expand=True)
        self.progress_label = ttk.Label(control_frame, text="0%")
        self.progress_label.pack(side=tk.LEFT)

    def create_console_frame(self, parent):
        console_frame = ttk.LabelFrame(parent, text="Console Output")
        console_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.console_textbox = tk.Text(console_frame, height=10)
        self.console_textbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        extra_frame = ttk.Frame(parent)
        extra_frame.pack(fill=tk.X, pady=10)
        ttk.Button(extra_frame, text="Open Download Folder", command=self.open_download_folder).pack(side=tk.LEFT, padx=(0, 10))

        self.dark_mode_var = tk.BooleanVar()
        ttk.Checkbutton(extra_frame, text="Dark Mode", variable=self.dark_mode_var, command=self.toggle_dark_mode).pack(side=tk.LEFT)

    def create_footer(self):
        footer_frame = ttk.Frame(self.root)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
        
        footer_text = "IP SCANNER v0.8\nTelegram: @oatdonemdume\nGitHub: vinzcyun"
        footer_label = ttk.Label(footer_frame, text=footer_text, font=("Arial", 7))
        footer_label.pack(side=tk.LEFT)

        help_button = ttk.Button(footer_frame, text="Help", command=self.show_help)
        help_button.pack(side=tk.RIGHT)

    def show_help(self):
        help_text = """
IP Scanner v0.8 - User Guide

1. Enter IP Range:
   - Input IP ranges in CIDR format (e.g., 192.168.1.0/24)
   - You can enter multiple ranges, one per line

2. Port Selection:
   - Enter a single port or multiple ports separated by commas
   - Click [^] for common port suggestions

3. Scan Options:
   - Random Scan: Randomize the order of IP scanning
   - Max Workers: Set the number of concurrent scanning threads

4. Controls:
   - Start Scan: Begin the scanning process
   - Stop Scan: Halt the ongoing scan
   - Save Config: Save current settings for future use
   - Export CSV: Export scan results to a CSV file

5. Additional Features:
   - Dark Mode: Toggle between light and dark themes
   - Open Download Folder: Quick access to the results folder

6. Scan Information:
   - View real-time statistics about the ongoing scan

For more information, visit our GitHub page or contact us on Telegram.
"""
        messagebox.showinfo("Help", help_text)

    def check_ping(self):
        try:
            response = requests.get("https://www.google.com/", timeout=5)
            ping = response.elapsed.total_seconds() * 1000
            self.info_labels['ping'].config(text=f"{ping:.2f} ms")
        except:
            self.info_labels['ping'].config(text="Error")
        self.root.after(5000, self.check_ping)

    def update_network_speed(self):
        net_io = psutil.net_io_counters()
        bytes_sent, bytes_recv = net_io.bytes_sent, net_io.bytes_recv
        
        self.root.after(1000, self._update_network_speed, bytes_sent, bytes_recv)

    def _update_network_speed(self, prev_bytes_sent, prev_bytes_recv):
        net_io = psutil.net_io_counters()
        bytes_sent, bytes_recv = net_io.bytes_sent, net_io.bytes_recv
        
        upload_speed = (bytes_sent - prev_bytes_sent) / 1024 / 1024  # Convert to MB/s
        download_speed = (bytes_recv - prev_bytes_recv) / 1024 / 1024  # Convert to MB/s
        
        self.info_labels['network_speed'].config(text=f"↑{upload_speed:.2f} MB/s ↓{download_speed:.2f} MB/s")
        self.root.after(1000, self.update_network_speed)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                self.ip_range_entry.delete("1.0", tk.END)
                self.ip_range_entry.insert(tk.END, file.read())

    def show_port_suggestions(self):
        port_suggestions = "\n".join([f"{port} - {service}" for port, service in COMMON_PORTS.items()])
        messagebox.showinfo("Port Suggestions", f"Common Ports and Services:\n\n{port_suggestions}")

    def toggle_dark_mode(self):
        if self.dark_mode_var.get():
            self.style.theme_use('clam')
            self.style.configure(".", background="#2E2E2E", foreground="white")
            self.style.configure("TButton", background="#4A4A4A", foreground="white")
            self.style.configure("TCheckbutton", background="#2E2E2E", foreground="white")
            self.style.configure("TLabel", background="#2E2E2E", foreground="white")
            self.style.configure("TLabelframe", background="#2E2E2E", foreground="white")
            self.style.configure("TLabelframe.Label", background="#2E2E2E", foreground="white")
            self.style.configure("TFrame", background="#2E2E2E")
            self.style.configure("TProgressbar", background="#4A4A4A")
            self.console_textbox.config(bg="#1E1E1E", fg="white")
            self.ip_range_entry.config(bg="#1E1E1E", fg="white")
        else:
            self.style.theme_use('clam')
            self.style.configure(".", background="white", foreground="black")
            self.style.configure("TButton", background="#E1E1E1", foreground="black")
            self.style.configure("TCheckbutton", background="white", foreground="black")
            self.style.configure("TLabel", background="white", foreground="black")
            self.style.configure("TLabelframe", background="white", foreground="black")
            self.style.configure("TLabelframe.Label", background="white", foreground="black")
            self.style.configure("TFrame", background="white")
            self.style.configure("TProgressbar", background="#E1E1E1")
            self.console_textbox.config(bg="white", fg="black")
            self.ip_range_entry.config(bg="white", fg="black")

    def open_download_folder(self):
        download_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        os.startfile(download_folder)

    def is_port_open(self, ip, port, timeout):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def check_and_save_ip(self, ip, port, timeout, output_file, results, existing_ips):
        if ip not in existing_ips and self.is_port_open(ip, port, timeout):
            with open(output_file, "a") as file:
                file.write(f"{ip}\n")
            results['open_ips'].append(ip)
            self.console_textbox.insert(tk.END, f"[FOUND] {ip}:{port}\n", "green")
            self.console_textbox.tag_configure("green", foreground="green")
        else:
            self.console_textbox.insert(tk.END, f"[NOT FOUND] {ip}:{port}\n", "red")
            self.console_textbox.tag_configure("red", foreground="red")
        results['scanned'] += 1
        self.console_textbox.see(tk.END)
        self.update_ui(results)

    def generate_random_ip(self):
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def scan_ips(self, ip_file, ports, max_workers, output_file, results):
        with open(ip_file, 'r') as file:
            all_ips = file.read().splitlines()

        if self.random_scan_var.get():
            results['total_ips'] = "∞"
        else:
            results['total_ips'] = len(all_ips)

        results['scanned'] = 0
        results['open_ips'] = []

        start_time = time()

        existing_ips = set()
        if os.path.exists(output_file):
            with open(output_file, "r") as file:
                existing_ips = set(file.read().splitlines())

        def update_progress():
            elapsed_time = time() - start_time
            results['scan_time'] = strftime("%H:%M:%S", localtime(elapsed_time))
            if elapsed_time > 0:
                scan_speed_ips = results['scanned'] / elapsed_time
                results['speed'] = f"{scan_speed_ips:.2f} IPs/s"
            else:
                results['speed'] = "0 IPs/s"
            self.update_ui(results)
            if not results['stop_scan']:
                self.root.after(100, update_progress)

        self.root.after(0, update_progress)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            while not results['stop_scan']:
                if self.random_scan_var.get():
                    current_ips = [self.generate_random_ip() for _ in range(1000)]
                else:
                    current_ips = all_ips

                futures = []
                for ip in current_ips:
                    if results['stop_scan']:
                        break
                    for port in ports:
                        futures.append(executor.submit(self.check_and_save_ip, ip, port, 5, output_file, results, existing_ips))

                for future in as_completed(futures):
                    if results['stop_scan']:
                        break
                    future.result()

                if not self.random_scan_var.get():
                    break

        end_time = time()
        elapsed_time = end_time - start_time
        results['scan_time'] = strftime("%H:%M:%S", localtime(elapsed_time))

        if elapsed_time > 0:
            scan_speed_ips = results['scanned'] / elapsed_time
            results['speed'] = f"{scan_speed_ips:.2f} IPs/s"
        else:
            results['speed'] = "0 IPs/s"

        self.update_ui(results)

    def start_scan(self):
        ports = [int(p.strip()) for p in self.port_entry.get().split(',')]
        max_workers = int(self.max_workers_entry.get())

        output_file = os.path.join(os.path.expanduser("~"), "Downloads", "ips.txt")
        self.results = {'stop_scan': False, 'port': self.port_entry.get()}

        temp_file = os.path.join(os.path.expanduser("~"), "Downloads", "do_not_del.txt")

        if self.random_scan_var.get():
            with open(temp_file, 'w') as f:
                for _ in range(1000):
                    f.write(f"{self.generate_random_ip()}\n")
        else:
            ip_range_input = self.ip_range_entry.get("1.0", tk.END).strip()
            if not ip_range_input:
                messagebox.showerror("Error", "Please provide IP range(s) or select Random Scan.")
                return
            ip_ranges = ip_range_input.split("\n")
            self.export_ips_to_file(ip_ranges, temp_file)

        scan_thread = threading.Thread(target=self.scan_ips, args=(temp_file, ports, max_workers, output_file, self.results))
        scan_thread.start()

    def stop_scan(self):
        if hasattr(self, 'results'):
            self.results['stop_scan'] = True
            messagebox.showinfo("Scan Stopped", "IP scanning has been stopped!")
        else:
            messagebox.showinfo("No Scan Running", "There is no active scan to stop.")

    def update_ui(self, results):
        self.info_labels['total_ips'].config(text=str(results['total_ips']))
        self.info_labels['scanned_ips'].config(text=str(results['scanned']))
        self.info_labels['open_ips'].config(text=str(len(results['open_ips'])))
        self.info_labels['scan_time'].config(text=results.get('scan_time', '00:00:00'))
        self.info_labels['scan_speed'].config(text=results.get('speed', '0 IPs/s'))

        if results['total_ips'] != "∞":
            progress_value = (results['scanned'] / int(results['total_ips'])) * 100
            self.progress['value'] = progress_value
            self.progress_label.config(text=f"{progress_value:.2f}%")
        else:
            self.progress_label.config(text="N/A")

        self.root.update_idletasks()

    def save_config(self):
        config = {
            'ip_ranges': self.ip_range_entry.get("1.0", tk.END).strip(),
            'port': self.port_entry.get(),
            'max_workers': self.max_workers_entry.get(),
            'random_scan': self.random_scan_var.get()
        }
        with open('ip_scanner_config.json', 'w') as f:
            json.dump(config, f)
        messagebox.showinfo("Config Saved", "Your configuration has been saved.")

    def load_config(self):
        try:
            with open('ip_scanner_config.json', 'r') as f:
                config = json.load(f)
            self.ip_range_entry.delete("1.0", tk.END)
            self.ip_range_entry.insert(tk.END, config['ip_ranges'])
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, config['port'])
            self.max_workers_entry.delete(0, tk.END)
            self.max_workers_entry.insert(0, config['max_workers'])
            self.random_scan_var.set(config['random_scan'])
        except FileNotFoundError:
            pass  # No config file found, use default values

    def export_csv(self):
        if not hasattr(self, 'results') or not self.results.get('open_ips'):
            messagebox.showinfo("No Data", "No scan results available to export.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return

        with open(file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP', 'Open Ports'])
            for ip in self.results['open_ips']:
                writer.writerow([ip, self.results.get('port', 'N/A')])
        
        messagebox.showinfo("Export Successful", f"Results exported to {file_path}")

    def export_ips_to_file(self, ip_ranges, output_file):
        with open(output_file, 'w') as file:
            for ip_range in ip_ranges:
                try:
                    for ip in ipaddress.ip_network(ip_range, strict=False):
                        file.write(f"{ip}\n")
                except ValueError:
                    self.console_textbox.insert(tk.END, f"Invalid IP range: {ip_range}\n")

    def show_information(self):
        try:
            response = requests.get("https://raw.githubusercontent.com/vinzcyun/random_vnc/main/info.txt")
            info = response.text.strip()
            messagebox.showinfo("Information", info)
        except:
            messagebox.showerror("Error", "Failed to fetch information. Please check your internet connection.")

if __name__ == "__main__":
    root = tk.Tk()
    password_dialog = PasswordDialog(root)
    root.wait_window(password_dialog.dialog)
    app = IPScanner(root)
    root.mainloop()