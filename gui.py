import tkinter as tk
from tkinter import messagebox, ttk
from scanner import Scanner
from detector import Detector
from logger import Logger
import os
import threading
import time


class NetPortScanGuardGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("NetPortScanGuard")
        self.root.geometry("500x350")

        self.scanner = Scanner()
        self.detector = Detector()
        self.logger = None
        self.scanning = False

        self.main_menu()

    def main_menu(self):
        self.clear_widgets()
        self.create_label("=== NetPortScanGuard ===", 14)
        self.create_button("端口扫描", self.scan_hosts)
        self.create_button("扫描检测", self.start_detection)
        self.create_button("查看日志", self.view_logs)
        self.create_button("退出系统", self.root.quit)

    def create_label(self, text, font_size, pady=10, anchor='center'):
        tk.Label(self.root, text=text, font=("Arial", font_size)).pack(pady=pady, anchor=anchor)

    def create_button(self, text, command, width=30, pady=5):
        tk.Button(self.root, text=text, width=width, command=command).pack(pady=pady, padx=20, anchor='center')

    def scan_hosts(self):
        self.logger = Logger("scan")
        self.logger.write_info("启动端口扫描")

        self.clear_widgets()
        self.create_label("\n\n\n\n\n\n\n正在扫描当前网段存活主机...\n请稍后", 12)
        self.root.update()

        alive_hosts = self.scanner.survival_host()
        if not alive_hosts:
            self.create_label("未发现存活主机", 12)
            self.logger.write_info("未发现存活主机")
            self.create_button("返回主菜单", self.close_log_and_return)
            return

        self.clear_widgets()
        self.create_label("=== 存活主机列表 ===", 12)
        listbox = tk.Listbox(self.root, width=60, height=10)
        for idx, (ip, mac) in enumerate(alive_hosts, 1):
            listbox.insert(tk.END, f"{idx}. IP: {ip}    MAC: {mac}")
        listbox.pack(pady=10, anchor='center')

        def on_select():
            selection = listbox.curselection()
            if selection:
                target_ip = alive_hosts[selection[0]][0]
                self.logger.write_info(f"选择主机：{target_ip}")
                self.select_scan_mode(target_ip)

        self.create_button("选择主机进行扫描", on_select)
        self.create_button("返回主菜单", self.close_log_and_return)

    def select_scan_mode(self, target_ip):
        self.clear_widgets()
        self.create_label(f"目标IP:{target_ip}\n选择扫描方式", 12)

        mode = tk.StringVar(value="1")
        modes = {
            "1": "完全连接",
            "2": "SYN",
            "3": "SYN|ACK",
            "4": "FIN"
        }

        for val, name in modes.items():
            tk.Radiobutton(self.root, text=name, variable=mode, value=val).pack(anchor="w", padx=20)

        self.status_label = tk.Label(self.root, text="当前端口：-")
        self.status_label.pack(anchor='center')

        self.time_label = tk.Label(self.root, text="已用时间：00:00:00")
        self.time_label.pack(anchor='center')

        progress = tk.DoubleVar()
        progressbar = ttk.Progressbar(self.root, variable=progress, maximum=100)
        progressbar.pack(pady=10, fill="x", padx=20)

        def update_elapsed_time():
            if self.scanning:
                elapsed = int(time.time() - self.scan_start_time)
                self.time_label.config(text=f"已用时间：{time.strftime('%H:%M:%S', time.gmtime(elapsed))}")
                self.root.after(1000, update_elapsed_time)

        def run_scan():
            ports = list(range(20, 1024))
            scan_name = modes[mode.get()]
            self.logger.write_info(f"开始 {scan_name} 扫描 {target_ip}")
            open_ports = []
            total = len(ports)

            self.scanning = True
            self.scan_start_time = time.time()
            self.root.after(1000, update_elapsed_time)

            for i, port in enumerate(ports, 1):
                try:
                    self.status_label.config(text=f"当前端口：{port}")
                    result = False
                    if mode.get() == "1":
                        result = self.scanner.tcp_connect_scan(target_ip, port)
                    elif mode.get() == "2":
                        result = self.scanner.tcp_syn_scan(target_ip, port)
                    elif mode.get() == "3":
                        result = self.scanner.tcp_synack_scan(target_ip, port)
                    elif mode.get() == "4":
                        result = self.scanner.tcp_fin_scan(target_ip, port)

                    if result:
                        self.logger.write_open_port(target_ip, port)
                        open_ports.append(port)
                except Exception as e:
                    self.logger.write_info(f"端口 {port} 扫描异常: {e}")
                    continue

                progress.set(i * 100 / total)
                self.root.update_idletasks()

            self.scanning = False
            self.logger.write_info("端口扫描完成")
            self.logger.close()

            used_time = time.time() - self.scan_start_time
            msg = f"开放端口: {open_ports}" if open_ports else "未发现开放端口"
            msg += f"\n\n总用时：{time.strftime('%H:%M:%S', time.gmtime(used_time))}"

            def after_scan():
                if messagebox.askyesno("扫描完成", f"{msg}\n\n是否继续扫描该主机？"):
                    self.select_scan_mode(target_ip)
                else:
                    self.close_log_and_return()

            self.root.after(100, after_scan)

        def start_thread():
            threading.Thread(target=run_scan, daemon=True).start()

        self.create_button("开始扫描", start_thread)
        self.create_button("重新选择IP", self.scan_hosts)
        self.create_button("返回主菜单", self.close_log_and_return)

    def start_detection(self):
        self.logger = Logger("detect")
        self.logger.write_info("启动扫描检测功能")
        self.detector.detect_scan(self.logger)
        messagebox.showinfo("完成", "扫描检测已完成。详情见日志。")
        self.close_log_and_return()

    def view_logs(self):
        self.clear_widgets()
        log_dir = "log"
        files = sorted([f for f in os.listdir(log_dir) if f.endswith(".log")], reverse=True)[:50]
    
        self.create_label("日志文件列表", 12)
        listbox = tk.Listbox(self.root, width=60)
        for f in files:
            listbox.insert(tk.END, f)
        listbox.pack(pady=5, fill="both", anchor='center')

        def read_log():
            selection = listbox.curselection()
            if selection:
                filename = files[selection[0]]
                with open(os.path.join(log_dir, filename), "r", encoding="utf-8") as f:
                    content = f.read()
                messagebox.showinfo("日志内容", content)

        self.create_button("查看选中文件", read_log)
        self.create_button("返回主菜单", self.main_menu)

    def close_log_and_return(self):
        if self.logger:
            self.logger.close()
            self.logger = None
        self.main_menu()

    def clear_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()


def center_window(root, width, height):
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    root.geometry(f"{width}x{height}+{x}+{y}")
    root.minsize(width, height)  # 最小尺寸，防止按钮丢失


def start_gui():
    root = tk.Tk()
    center_window(root, 500, 400)
    app = NetPortScanGuardGUI(root)
    root.mainloop()
