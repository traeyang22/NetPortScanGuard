import sys
from scanner import Scanner
from detector import Detector
from logger import Logger
from tqdm import tqdm
import os

class NetPortScanGuard:
    def __init__(self):
        self.logger = Logger()
        self.scanner = Scanner()
        self.detector = Detector()

    def run(self):
        while True:
            print("\n=== NetPortScanGuard ===")
            print("1. 端口扫描")
            print("2. 扫描检测")
            print("3. 查看日志")
            print("0. 退出系统")
            choice_function = input("请输入选项：").strip()

            if choice_function == "1":
                self.logger.start_log("scan")
                self.logger.info("开始端口扫描")
                print("正在扫描当前网段存活主机...")
                alive_hosts = self.scanner.survival_host()
                if not alive_hosts:
                    print("未发现存活主机")
                    self.logger.info("未发现存活主机")
                    self.logger.end_log()
                    continue

                print("\n=== 存活主机列表 ===")
                for idx, (ip, mac) in enumerate(alive_hosts, 1):
                    print(f"{idx}. IP: {ip}    MAC: {mac}")

                while True:
                    try:
                        select_idx = int(input("\n请输入要扫描的主机序号（输入0返回主菜单）："))
                        if select_idx == 0:
                            self.logger.end_log()
                            break
                        else:
                            target_ip = alive_hosts[select_idx - 1][0]
                            print("你选择扫描的IP是：", target_ip)
                            self.logger.info(f"选择扫描主机：{target_ip}")
                        break
                    except (ValueError, IndexError):
                        print("无效输入，请重新输入。")

                ports = range(20, 1024)

                while True:
                    print("\n=== 选择扫描方式 ===")
                    print("1. 完全连接扫描")
                    print("2. SYN扫描")
                    print("3. SYN|ACK扫描")
                    print("4. FIN扫描")
                    print("0. 返回主菜单")
                    choice_scanning_method = input("请输入选项：").strip()

                    if choice_scanning_method == "0":
                        self.logger.end_log()
                        break

                    if choice_scanning_method not in ["1", "2", "3", "4"]:
                        print("无效的选项，请重新输入。")
                        continue

                    scan_name = {
                        "1": "完全连接",
                        "2": "SYN",
                        "3": "SYN|ACK",
                        "4": "FIN"
                    }[choice_scanning_method]

                    print(f"正在对 {target_ip} 进行 {scan_name} 扫描，请稍候...\n")
                    self.logger.info(f"开始 {scan_name} 扫描目标：{target_ip}")
                    open_ports = []

                    with tqdm(total=len(ports), desc=f"{scan_name} 扫描进度", unit="端口", dynamic_ncols=True, file=sys.stdout) as pbar:
                        for port in ports:
                            try:
                                result = False
                                if choice_scanning_method == "1":
                                    result = self.scanner.tcp_connect_scan(target_ip, port)
                                elif choice_scanning_method == "2":
                                    result = self.scanner.tcp_syn_scan(target_ip, port)
                                elif choice_scanning_method == "3":
                                    result = self.scanner.tcp_synack_scan(target_ip, port)
                                elif choice_scanning_method == "4":
                                    result = self.scanner.tcp_fin_scan(target_ip, port)

                                if result:
                                    open_ports.append(port)
                                    tqdm.write(f"[+] {target_ip}:{port} 端口开放")
                                    self.logger.info(f"[+] {target_ip}:{port} 端口开放")
                            except Exception as e:
                                self.logger.info(f"[-] 端口 {port} 扫描失败: {str(e)}")
                                continue
                            pbar.update(1)

                    if not open_ports:
                        print("未发现开放端口")
                        self.logger.info("未发现开放端口")
                    self.logger.end_log()

            elif choice_function == "2":
                self.logger.start_log("detect")
                self.logger.info("开始扫描检测")
                self.detector.detect_scan()
                self.logger.end_log()

            elif choice_function == "3":
                log_dir = "log"
                files = sorted(
                    [f for f in os.listdir(log_dir) if f.endswith(".log")],
                    reverse=True
                )[:50]

                if not files:
                    print("\n暂无日志记录")
                    continue

                print("\n=== 最近的日志文件 ===")
                for idx, f in enumerate(files, 1):
                    print(f"{idx}. {f}")

                try:
                    idx = int(input("请输入要查看的日志编号（0返回主菜单）："))
                    if idx == 0:
                        continue
                    filename = files[idx - 1]
                    with open(os.path.join(log_dir, filename), "r", encoding="utf-8") as f:
                        print(f"\n--- 日志内容：{filename} ---")
                        print(f.read())
                except (ValueError, IndexError):
                    print("输入有误，请重新选择。")

            elif choice_function == "0":
                self.logger.info("退出系统")
                break

            else:
                print("无效的选项，请重新输入。")

if __name__ == "__main__":
    app = NetPortScanGuard()
    app.run()
