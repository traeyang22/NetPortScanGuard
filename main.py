import sys
from scanner import Scanner
from detector import Detector
from logger import Logger
from tqdm import tqdm

class NetPortScanGuard:
    def __init__(self):
        self.logger = Logger()
        self.scanner = Scanner()
        self.detector = Detector()

    def run(self):
        while True:
            print("\n=== NetPortScanGuard ===")
            print("1. 扫描指定主机端口")
            print("2. 启动扫描检测")
            print("0. 退出系统")
            choice_function = input("请输入选项：").strip()

            if choice_function == "1":
                print("正在扫描当前网段存活主机...")
                alive_hosts = self.scanner.survival_host()
                if not alive_hosts:
                    print("未发现存活主机")
                    continue

                print("\n=== 存活主机列表 ===")
                for idx, (ip, mac) in enumerate(alive_hosts, 1):
                    print(f"{idx}. IP: {ip}    MAC: {mac}")

                # 选择一个主机进行扫描
                while True:
                    try:
                        select_idx = int(input("\n请输入要扫描的主机序号（输入0返回主菜单）："))
                        if select_idx == 0:
                            break
                        else:
                            target_ip = alive_hosts[select_idx - 1][0]
                            print("你选择扫描的IP是：", target_ip)
                        break
                    except (ValueError, IndexError):
                        print("无效输入，请重新输入。")

                ports = range(20, 1024)  # 默认扫描端口范围

                while True:
                    print("\n=== 选择扫描方式 ===")
                    print("1. 完全连接扫描")
                    print("2. SYN扫描")
                    print("3. SYN|ACK扫描")
                    print("4. FIN扫描")
                    print("0. 返回主菜单")
                    choice_scanning_method = input("请输入选项：").strip()

                    if choice_scanning_method == "0":
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
                    open_ports = []

                    # 使用 tqdm 生成一个进度条
                    with tqdm(total=len(ports), desc=f"{scan_name} 扫描进度", unit="端口", dynamic_ncols=True, file=sys.stdout) as pbar:
                        for port in ports:
                            try:
                                # 每次扫描到一个开放端口，立即显示
                                if choice_scanning_method == "1":
                                    if self.scanner.tcp_connect_scan(target_ip, port):
                                        open_ports.append(port)
                                        tqdm.write(f"[+] {target_ip}:{port} 端口开放")  # 使用 tqdm.write 来避免与进度条冲突
                                elif choice_scanning_method == "2":
                                    if self.scanner.tcp_syn_scan(target_ip, port):
                                        open_ports.append(port)
                                        tqdm.write(f"[+] {target_ip}:{port} 端口开放")
                                elif choice_scanning_method == "3":
                                    if self.scanner.tcp_synack_scan(target_ip, port):
                                        open_ports.append(port)
                                        tqdm.write(f"[+] {target_ip}:{port} 端口开放")
                                elif choice_scanning_method == "4":
                                    if self.scanner.tcp_fin_scan(target_ip, port):
                                        open_ports.append(port)
                                        tqdm.write(f"[+] {target_ip}:{port} 端口开放")
                            except Exception as e:
                                continue  # 忽略端口扫描中可能出现的错误
                            
                            # 更新进度条
                            pbar.update(1)

                    # 扫描结束后检查开放端口
                    if not open_ports:
                        print("未发现开放端口")

            elif choice_function == "2":
                self.detector.detect_scan()

            elif choice_function == "0":
                self.logger.info("退出系统")
                break

            else:
                print("无效的选项，请重新输入。")

if __name__ == "__main__":
    app = NetPortScanGuard()
    app.run()
