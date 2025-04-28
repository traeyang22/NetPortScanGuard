import socket
from scapy.all import ARP, Ether, srp, IP, TCP, sr1

class Scanner:
    def __init__(self):
        pass

    def survival_host(self):
        """扫描当前子网存活主机，返回[(IP, MAC)]列表"""
        target_ip = self.get_local_subnet()  # 例如 "192.168.1.1/24"
        if not target_ip:
            print("无法确定本地子网IP段")
            return []

        print(f"正在扫描子网 {target_ip} ...")

        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=2, verbose=0)[0]

        hosts = []
        for sent, received in result:
            hosts.append((received.psrc, received.hwsrc))

        return hosts

    def get_local_subnet(self):
        """获取本机局域网子网，例如返回 192.168.1.1/24"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print("本机IP地址为：",local_ip)
            ip_parts = local_ip.split(".")
            if len(ip_parts) == 4:
                return ".".join(ip_parts[:3]) + ".1/24"
        except Exception:
            return None

    def tcp_connect_scan(self, ip, port):
        """全连接TCP扫描"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True  # 端口开放
            else:
                return False
        except Exception:
            return False

    def tcp_syn_scan(self, ip, port):
        """半开SYN扫描（需要root权限）"""
        try:
            syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=1, verbose=0)
            if response is None:
                return False
            if response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
                    sr1(rst_packet, timeout=1, verbose=0)
                    return True
            return False
        except Exception:
            return False

    def tcp_fin_scan(self, ip, port):
        """FIN隐蔽扫描"""
        try:
            fin_packet = IP(dst=ip)/TCP(dport=port, flags="F")
            response = sr1(fin_packet, timeout=1, verbose=0)
            if response is None:
                return True  # 没回应，认为端口开放（根据RFC标准）
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:  # RST-ACK
                    return False
            return True
        except Exception:
            return False
