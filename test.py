from scapy.all import ARP, Ether, srp
import socket

# 获取本机IP地址
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)
print("本机IP地址为：", local_ip)

# 拼接子网地址
ip_parts = local_ip.split(".")
if len(ip_parts) == 4:
    target_ip = ".".join(ip_parts[:3]) + ".1/24"
else:
    target_ip = None

if not target_ip:
    print("无法确定本地子网IP段")
else:
    print(f"正在扫描子网 {target_ip} ...")

    # 构造ARP请求包
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # 发送请求并接收响应
    result = srp(packet, timeout=2, verbose=0)[0]

    hosts = []
    for sent, received in result:
        hosts.append((received.psrc, received.hwsrc))
    
    print("\n=== 存活主机列表 ===")
    for ip, mac in hosts:
        print(f"IP地址: {ip}    MAC地址: {mac}")
