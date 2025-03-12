from scapy.all import *
from cryptography.fernet import Fernet
import socket

class Client:
    def __init__(self, ip, key):
        if not self.__verifyIP(ip):
            exit(-1)
        self.ip = ip
        self.key = key
        print(self.ip)

    def __verifyIP(self, ip):
        try:
            if ip is None:
                print("IP address is invalid.")
            else:
                socket.inet_aton(ip)
                return True
        except socket.error:
            print("IP address is invalid.")
            return False

    def getIP(self):
        return self.ip

    def encryption(self):
        return self.key

    def changeKey(self, key):
        self.key = key
