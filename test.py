from scanner import Scanner
scanner = Scanner()
hosts = scanner.survival_host()

print("\n=== 存活主机列表 ===")
for idx, (ip, mac) in enumerate(hosts, 1):
                    print(f"{idx}. IP: {ip}    MAC: {mac}")
while True:
                    try:
                        target_ip_idx = int(input("\n请输入要扫描的主机IP（输入0返回主菜单）："))
                        if target_ip_idx == 0:
                            break
                        else:
                                target_ip = hosts[target_ip_idx - 1][0]
                                print(target_ip)
                                break
                    except (ValueError, IndexError):
                        print("无效输入，请重新输入。")

ports = range(20, 1024)

for port in ports:
    scanner.tcp_connect_scan(target_ip, port)
    print(f"[+] {target_ip}:{port} 端口开放")
