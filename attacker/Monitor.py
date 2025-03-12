from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether


class Monitor:
    def __init__(self, ip, fernet):
        self.path = "v5"
        self.ip = ip
        self.encryption = fernet
        self.isActive = False

    def start(self):
        self.isActive = True
        self.__send_path()

    def __send_path(self):
        self.path = input("Enter the location: ")
        enc_path = self.encryption.encrypt(self.path.encode())
        pkt = Ether() / IP(dst=self.ip) / \
              TCP(sport=RandNum(7000, 7499), dport=RandNum(30000, 34999), flags='A') / Raw(load=enc_path)
        sendp(pkt, verbose=0)

    def stop(self):
        command = "Stop monitoring"
        enc_command = self.encryption.encrypt(command.encode())
        pkt = Ether() / IP(dst=self.ip) / \
              TCP(sport=RandNum(7500, 7999), dport=RandNum(35000, 39999), flags='E') / Raw(load=enc_command)
        sendp(pkt, verbose=0)

    def get_status(self):
        return self.isActive

    def write_log(self, data):
        with open(self.__join_path(self.ip, "monitor_log.txt"), "a") as file:
            message = self.encryption.decrypt(data).decode()
            file.write(message + "\n")

    def __join_path(self, *names):
        path = "Clients"
        for a in names:
            path = path + "/" + a
        return path
