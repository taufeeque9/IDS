import socket
import sys
from platform import system
import threading
import  time
import struct
import binascii
import os
import numpy as np

MY_IP = [socket.gethostbyname(socket.gethostname()),]
#You can try socket.getfqdn() if the above method gives '127.0.0.1'

if system() == 'Linux':
    MY_IP = set()
    stream = os.popen('ifconfig')
    ifconfig = stream.read()

    ifconfig = (ifconfig.split('\n\n'))[:-1]
    for i in range(len(ifconfig)):
        ifconfig[i] = ifconfig[i].split('\n' + ' '*8)

        for j in range(len(ifconfig[i])):
            ifconfig[i][j] = ifconfig[i][j].split()

        if (ifconfig[i][0][0] != 'lo:') and (ifconfig[i][1][0] == 'inet'):
            MY_IP.add(ifconfig[i][1][1])        

print(MY_IP)

lock = threading.Lock()

class Flow:
    def __init__(self, flow_id, identity, src_ip, flags, timer, packet_length, segment_length):
        self.timestamp = time.ctime()
        self.flow_id = flow_id
        self.features = {}       #dictionary of features

        self.state = True  #connection open/active
        self.identity = identity
        self.destination_port = (identity[0][1] if (identity[0][0] in MY_IP) else identity[1][1])
        self.fwd = src_ip  #ip of initiator
        
        self.num_packets = 1
        self.num_packets_forward = 1
        self.num_packets_backward = 0
        
        self.start_time = timer
        
        self.flow_duration = 0
        self.total_segment_length = self.fwd_segment_length = segment_length
        self.bwd_segment_length = 0
        self.avg_bwd_segment_size = 0
        
        self.fwd_fin = bool(flags & 1)
        self.bwd_fin = False
        self.psh_flag_count = ((flags >> 3) & 1)
        self.urg_flag_count = ((flags >> 5) & 1)

        self.flow_IAT_Max, self.prev_timer = 0 , timer

        self.Fwd_IAT = [timer,]
        self.Fwd_IAT_Max = 0
        self.Fwd_IAT_total = 0
        self.Fwd_IAT_std = 0

        self.packet_length = [packet_length,]
        self.bwd_packet_length = []
        self.max_packet_length = 0
        self.packet_length_mean = 0
        self.packet_length_std = 0
        self.packet_length_var = 0
        self.bwd_packet_length_max = 0
        self.bwd_packet_length_mean = 0
        self.bwd_packet_length_std = 0


    def add_packet(self, identity, src_ip, flags, timer, packet_length, segment_length):
        if (self.fwd_fin and self.bwd_fin):
            self.state = False  #connection closed

        self.num_packets += 1
        self.total_segment_length += segment_length
        self.packet_length.append(packet_length)

        self.flow_duration = (timer - self.start_time)

        self.psh_flag_count += ((flags >> 3) & 1)
        self.urg_flag_count += ((flags >> 5) & 1)

        self.flow_IAT_Max = max(self.flow_IAT_Max, (timer - self.prev_timer))
        self.prev_timer = timer

        if src_ip == self.fwd:
            self.num_packets_forward += 1
            self.fwd_segment_length += segment_length
            self.fwd_fin = (self.fwd_fin or bool(flags & 1))
            self.Fwd_IAT.append((timer - self.Fwd_IAT[-1]))

        else:
            self.bwd_packet_length.append(packet_length)
            self.num_packets_backward += 1
            self.bwd_segment_length += segment_length
            self.avg_bwd_segment_size = (self.bwd_segment_length / self.num_packets_backward)
            self.bwd_fin = (self.bwd_fin or bool(flags & 1))

    def find_features(self):
        self.Fwd_IAT_Max = max(self.Fwd_IAT)
        self.Fwd_IAT_std = np.std(self.Fwd_IAT)
        self.Fwd_IAT_total = np.sum(self.Fwd_IAT)

        self.packet_length_mean = np.mean(self.packet_length)
        self.max_packet_length = max(self.packet_length)
        self.packet_length_std = np.std(self.packet_length)
        self.packet_length_var = self.packet_length_std * self.packet_length_std

        if self.bwd_packet_length:
            self.bwd_packet_length_max = max(self.bwd_packet_length)
            self.bwd_packet_length_mean = np.mean(self.bwd_packet_length)
            self.bwd_packet_length_std = np.std(self.bwd_packet_length)

        self.features = {'Destination Port' : self.destination_port, 'Flow Duration' : self.flow_duration}
        self.features.update({'Bwd Packet Length Max' : self.bwd_packet_length_max, 'Bwd Packet Length Mean' : self.bwd_packet_length_mean})
        self.features.update({'Bwd Packet Length Std' : self.bwd_packet_length_std, 'Flow IAT Max' : self.flow_IAT_Max})
        self.features.update({'Fwd IAT Total' : self.Fwd_IAT_total, 'Fwd IAT Std' : self.Fwd_IAT_std})
        self.features.update({'Fwd IAT Max' : self.Fwd_IAT_Max, 'Max Packet Length' : self.max_packet_length})
        self.features.update({'Packet Length Mean' : self.packet_length_mean, 'Packet Length Std' : self.packet_length_std})
        self.features.update({'Packet Length Variance' : self.packet_length_var, 'PSH Flag Count' : self.psh_flag_count})
        self.features.update({'URG Flag Count' : self.urg_flag_count, 'Avg Bwd Segment Size' : self.avg_bwd_segment_size})


FLOWS = {}    #can map (ip1,port1,ip2,port2) to list of Flow objects

class Sniffer:
    def __init__(self, queue = 0):

        self.threads = []
        self.n_flows = 0  #will help in assigning flow IDs
        
        try:
            if (system() == 'Windows'):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((MY_IP[0], 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            elif (system() == 'Linux'):
                self.sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            self.starttime = time.time()

        except socket.error as msg:
            print("Socket could not be created. Error :", msg)
            if(__name__ == '__main__'):
                sys.exit()

        try:
            while 1:
                packet = self.sock.recvfrom(2048)
                timer = time.time() - self.starttime

                if packet[1][0] != 'lo':   #Don't need to sniff local interface for malicious packets(??)
                    t = threading.Thread(target=self.preprocessing,args=(packet[0], timer, queue))
                    t.start()
                    self.threads.append(t)

        except KeyboardInterrupt:   #break the loop , close and dump all data into file
            print("\nKeyboard Interrupt! Closing socket")

            if system() == 'Windows':
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sock.close()
            
            print("Flows")

            for thread in self.threads:
                thread.join()

            for identity in FLOWS:
                for flow in FLOWS[identity]:
                    flow.find_features()
                    if queue != 0:
                        queue.put(flow)
                    
                    print(flow.flow_id, flow.identity, flow.fwd, flow.num_packets, flow.total_segment_length, ("Open\n" if flow.state else "Closed\n"), flow.features)

            if __name__ == '__main__':
                sys.exit()

    def preprocessing(self, packet, timer, queue):  #parse header data
        ethernet_header= packet[0:14]
        ethernet_header = struct.unpack('!6s6sH',ethernet_header)

        protocol = socket.ntohs(ethernet_header[2])
        if (((protocol == 8) and (system() == 'Linux')) or ((protocol == 43200) and (system() == 'Windows'))):  #ip . 1544 for arp
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
    

                tcp_header_length = (tcp_header[4] >> 4) * 4
                flags = tcp_header[5]

                data_length = len(packet[(14 + ip_header_length + tcp_header_length) :])
                segment_length = tcp_header_length + data_length
                packet_length = ip_header_length + segment_length

                print(identity , format(flags ,'b').zfill(8) , data_length , timer, ("Outgoing" if (source_ip in MY_IP) else "Incoming"))
                identity = (min(identity[0] ,identity[1]) ,max(identity[0] ,identity[1])) #sort in order to club packets flowing in either direction
                lock.acquire()

                if identity in FLOWS:
                    for flow in FLOWS[identity]:
                        if flow.state: #flow is active
                            flow.add_packet(identity, source_ip, flags, timer, packet_length, segment_length)

                            if queue != 0:   #queue exists
                                queue.put(flow)  #send the flow for analysis the moment a packet(not the first) arrives

                            break

                    else:
                        self.n_flows += 1
                        FLOWS[identity].append(Flow(self.n_flows, identity, source_ip, flags, timer, packet_length, segment_length))

                else:
                    self.n_flows += 1
                    FLOWS[identity] = [Flow(self.n_flows, identity, source_ip, flags, timer, packet_length, segment_length),]

                

                lock.release()

if __name__ == '__main__':
    #time.sleep(10)
    sniff = Sniffer()