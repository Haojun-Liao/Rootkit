from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether

class FileTransfer:
    def __init__(self, ip, fernet):
        self.ip = ip
        self.path = ""
        self.encryption = fernet
        self.filename = ""
        self.max_data_size = 100

    def send(self):
        for pkt in self.__forge_pkt():
            sendp(pkt, verbose=0)

    def setPath(self, path):
        self.path = path
        self.filename = path.split('/')[-1]

    def __forge_pkt(self):
        data = self.__get_data()
        if data is None:
            yield Ether() / IP(dst=self.ip) / TCP(sport=RandNum(20000, 29999), dport=RandNum(40000, 49999),
                                                  flags='A')
            return
        data = self.encryption.encrypt(data)
        filename = self.encryption.encrypt(self.filename.encode())
        size = len(data)
        count = 0

        yield Ether() / IP(dst=self.ip) / TCP(sport=RandNum(20000, 29999), dport=RandNum(40000, 49999), flags='A') / Raw(load=filename)

        while count < size:
            yield Ether() / IP(dst=self.ip) / TCP(sport=RandNum(30000, 39999), dport=RandNum(30000, 39999), flags='A') \
                  / Raw(load=data[count:count+self.max_data_size])
            count = count + self.max_data_size

        eof = self.encryption.encrypt("EOF".encode())
        yield Ether() / IP(dst=self.ip) / TCP(sport=RandNum(40000, 49999), dport=RandNum(20000, 29999), flags='A') / Raw(load=eof)

    def __get_data(self):
        try:
            with open(self.path, "rb") as file:
                return file.read()
        except FileNotFoundError:
            print(f"{self.path} has been deleted")
        except IsADirectoryError:
            return
