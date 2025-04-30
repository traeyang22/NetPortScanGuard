import socket
from scapy.all import ARP, Ether, srp, IP, TCP, sr1, get_if_list, get_if_addr, conf

class Scanner:
    def __init__(self):
        pass

    def get_local_ip(self):
        """获取本机的IP地址"""
        hostname = socket.gethostname()  # 获取主机名
        ip_add = socket.gethostbyname(hostname)
        return ip_add  # 通过主机名获取IP

    def set_interface_by_ip(self, local_ip):
        """
        根据本地IP地址自动设置Scapy使用的网络接口
        """
        # 提取IP前三段作为前缀，如192.168.1.
        ip_prefix = ".".join(local_ip.split(".")[:3]) + "."
        for iface in get_if_list():  # 遍历所有网络接口
            try:
                ip = get_if_addr(iface)  # 获取该接口的IP地址
                if ip.startswith(ip_prefix):  # 如果IP地址前缀匹配
                    conf.iface = iface  # 设置为Scapy默认接口
                    print(f"使用接口：{iface}，IP地址为：{ip}")
                    return True
            except Exception:
                continue  # 忽略无效接口
        print("没有找到匹配的接口，请检查IP段或网络状态。")
        return False

    def survival_host(self):
        """
        扫描当前子网存活主机，返回存活主机的[(IP, MAC)]列表
        """
        local_ip = self.get_local_ip()
        print("本机IP地址为：", local_ip)

        # 根据IP地址设置对应的网络接口
        if not self.set_interface_by_ip(local_ip):
            return []

        # 生成目标子网IP段，如192.168.1.1/24
        ip_parts = local_ip.split(".")
        if len(ip_parts) != 4:
            print("无法确定本地子网IP段")
            return []

        target_ip = ".".join(ip_parts[:3]) + ".1/24"
        print(f"正在扫描子网 {target_ip} ...")

        # 构造ARP请求数据包
        arp = ARP(pdst=target_ip)  # 目标IP段
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # 以太网广播MAC地址
        packet = ether / arp  # 组装完整ARP包

        try:
            # 发送数据包并接收回应（srp适用于二层通信）
            result = srp(packet, timeout=2, verbose=0)[0]
        except Exception as e:
            print("发送ARP包失败：", e)
            return []

        # 解析回应，提取每个主机的IP和MAC
        hosts = [(recv.psrc, recv.hwsrc) for _, recv in result]
        return hosts


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

    # def tcp_syn_scan(self, ip, port):
    #     """半连接SYN扫描（需要root权限）"""
    #     try:
    #         syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
    #         response = sr1(syn_packet, timeout=1, verbose=0)
    #         if response is None:
    #             return False
    #         if response.haslayer(TCP):
    #             if response[TCP].flags == 0x12:  # SYN-ACK
    #                 rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
    #                 sr1(rst_packet, timeout=1, verbose=0)
    #                 return True
    #         return False
    #     except Exception:
    #         return False

    # def tcp_fin_scan(self, ip, port):
    #     """FIN隐蔽扫描"""
    #     try:
    #         fin_packet = IP(dst=ip)/TCP(dport=port, flags="F")
    #         response = sr1(fin_packet, timeout=1, verbose=0)
    #         if response is None:
    #             return True  # 没回应，认为端口开放（根据RFC标准）
    #         if response.haslayer(TCP):
    #             if response[TCP].flags == 0x14:  # RST-ACK
    #                 return False
    #         return True
    #     except Exception:
    #         return False
