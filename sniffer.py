import socket
import sys
from platform import system
import threading
import  time
import struct
import binascii

class Sniffer:
    def __init__(self):

        self.threads = []
        try:
            if(system() == 'Windows'):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(0x0003))
            elif (system() == 'Linux'):
                self.sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            self.starttime = time.time()

        except socket.error as msg:
            print("Socket could not be created. Error :",msg)
            if(__name__ == '__main__'):
                sys.exit()

        try:
            while 1:
                packet = self.sock.recvfrom(2048)
                timer = time.time() - self.starttime
                t = threading.Thread(target=self.preprocessing,args=(packet[0],timer))
                t.start()
                self.threads.append(t)

        except KeyboardInterrupt:   #break the loop , close and dump all data into file
            print("\nKeyboard Interrupt! Closing socket")
            self.sock.close()

            for thread in self.threads:
                thread.join()

            if __name__ == '__main__':
                sys.exit()

    def preprocessing(self,packet,timer):  #parse header data
        ethernet_header= packet[0:14]
        ethernet_header = struct.unpack('!6s6sH',ethernet_header)
        ethernet_header = [binascii.hexlify(ethernet_header[0]).decode() , binascii.hexlify(ethernet_header[1]).decode() , socket.ntohs(ethernet_header[2])]
        #destination mac , source mac , protocol
        print(ethernet_header,timer)

        if ethernet_header[2] == 8:  #ip . 1544 for arp
            ip_header = packet[14:34]
            ip_header = struct.unpack('!BB3HBBH4s4s',ip_header)
            
            arr = [(ip_header[0] >> 4), (ip_header[0] & 15)]  #version and header length
            for i in range(1,8):
                arr.append(ip_header[i])
            
            arr.append(socket.inet_ntoa(ip_header[8]))  #source ip
            arr.append(socket.inet_ntoa(ip_header[9]))  #destination ip

            ip_header = arr
            print(ip_header)

if __name__ == '__main__':
    sniff = Sniffer()