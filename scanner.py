import socket
from scapy.all import ARP, Ether, srp, IP, TCP, sr1, get_if_list, get_if_addr, conf

class Scanner:
    def __init__(self):
        pass

    def get_local_ip(self):
        """获取本机的IP地址"""
        hostname = socket.gethostname()
        ip_add = socket.gethostbyname(hostname)
        return ip_add

    def set_interface_by_ip(self, local_ip):
        """根据本地IP自动设置Scapy使用的接口"""
        ip_prefix = ".".join(local_ip.split(".")[:3]) + "."
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip.startswith(ip_prefix):
                    conf.iface = iface
                    print(f"[+] 使用接口：{iface}，IP：{ip}")
                    return True
            except Exception:
                continue
        print("[-] 未找到匹配的接口，请检查网络。")
        return False

    def survival_host(self):
        """扫描当前子网存活主机，返回[(IP, MAC)]列表"""
        local_ip = self.get_local_ip()
        print("本机IP地址为：", local_ip)

        if not self.set_interface_by_ip(local_ip):
            return []

        ip_parts = local_ip.split(".")
        if len(ip_parts) != 4:
            print("[-] 无法确定本地子网IP段")
            return []

        target_ip = ".".join(ip_parts[:3]) + ".1/24"
        print(f"[+] 扫描子网 {target_ip} 中的主机...")

        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        try:
            result = srp(packet, timeout=2, verbose=0)[0]
        except Exception as e:
            print("[-] ARP扫描失败：", e)
            return []

        hosts = [(recv.psrc, recv.hwsrc) for _, recv in result]
        return hosts

    def tcp_connect_scan(self, ip, port):
        """完全连接扫描"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def tcp_syn_scan(self, ip, port):
        """SYN 半连接扫描（需 root 权限）"""
        try:
            syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=1, verbose=0)
            if response and response.haslayer(TCP):
                return response[TCP].flags == 0x12  # SYN-ACK
            return False
        except Exception:
            return False

    def tcp_synack_scan(self, ip, port):
        """SYN|ACK 探测（非标准，模拟服务回应）"""
        try:
            synack_packet = IP(dst=ip) / TCP(dport=port, flags="SA")
            response = sr1(synack_packet, timeout=1, verbose=0)
            if response is None:
                return False
            if response.haslayer(TCP):
                # 一般服务不会回应 SA 包，因此 RST 表示端口开放
                return response[TCP].flags == 0x14  # RST-ACK
            return False
        except Exception:
            return False

    def tcp_fin_scan(self, ip, port):
        """FIN 扫描（适用于部分系统）"""
        try:
            fin_packet = IP(dst=ip) / TCP(dport=port, flags="F")
            response = sr1(fin_packet, timeout=1, verbose=0)
            if response is None:
                return True  # 无响应 => 可能开放
            if response.haslayer(TCP):
                return not (response[TCP].flags == 0x14)  # RST-ACK => 关闭
            return True
        except Exception:
            return False
