import socket
import sys
from platform import system
import threading
import  time
import struct
import binascii


class Flow:
    pass

FLOWS = {}    #can map (ip1,port1,ip2,port2) to list of Flow objects
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

                if packet[1][0] != 'lo':
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

        protocol = socket.ntohs(ethernet_header[2])
        if protocol == 8:  #ip . 1544 for arp
            ip_header = packet[14:34]
            ip_header = struct.unpack('!BB3HBBH4s4s',ip_header)
            
            source_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])

            ip_header_length = (ip_header[0] & 15) * 4

            if ip_header[6] == 6:  #TCP

                tcp_header = packet[(ip_header_length + 14):(ip_header_length + 34)]
                tcp_header = struct.unpack('!HHLLBB3H', tcp_header)

                source_port , dest_port = tcp_header[0] , tcp_header[1]

                identity = ((source_ip, source_port) , (dest_ip, dest_port))
                identity = (min(identity[0] ,identity[1]) ,max(identity[0] ,identity[1])) #sort in order to club packets flowing in either direction

                tcp_header_length = (tcp_header[4] >> 4) * 4
                flags = tcp_header[5]

                data_length = len(packet[(14 + ip_header_length + tcp_header_length) :])

                print(identity , format(flags ,'b').zfill(8) , data_length , timer)


if __name__ == '__main__':
    sniff = Sniffer()