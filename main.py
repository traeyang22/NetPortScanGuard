from scanner import Scanner
from detector import Detector
from logger import Logger

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
                        target_ip = alive_hosts[select_idx - 1][0]
                        break
                    except (ValueError, IndexError):
                        print("无效输入，请重新输入。")

                ports = range(20, 1024)  # 默认扫描20-1023端口

                while True:
                    print("\n=== 选择扫描方式 ===")
                    print("1. 全连接扫描")
                    print("2. 半开SYN扫描")
                    print("3. FIN隐蔽扫描")
                    print("0. 返回主菜单")
                    choice_scanning_method = input("请输入选项：").strip()

                    if choice_scanning_method == "0":
                        break

                    if choice_scanning_method not in ["1", "2", "3"]:
                        print("无效的选项，请重新输入。")
                        continue

                    if choice_scanning_method == "1":
                        for port in ports:
                            if self.scanner.tcp_connect_scan(target_ip, port):
                                print(f"[+] {target_ip}:{port} 端口开放")
                    elif choice_scanning_method == "2":
                        for port in ports:
                            if self.scanner.tcp_syn_scan(target_ip, port):
                                print(f"[+] {target_ip}:{port} 端口开放")
                    elif choice_scanning_method == "3":
                        for port in ports:
                            if self.scanner.tcp_fin_scan(target_ip, port):
                                print(f"[+] {target_ip}:{port} 端口开放")

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
