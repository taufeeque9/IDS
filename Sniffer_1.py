import socket
import struct
import sys
import re

def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65536)
        return data[0]
    except socket.timeout:
        data = ''
        print("Timeout error")
    except:
        print("An error occured")
        sys.exc_info()
        return data[0]

# get the time of service - 8 bits
def getTOS(data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC?ECP", 6: "Internetwork control", 7: "Network control" }
    delay = {0: "Normal delay", 2: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

    D = data & 0x10
    D >>= 4
    T = data & 0x8
    T >>= 3
    R = data & 0x4
    R >>= 2
    M = data & 0x2
    M >>= 1

    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return TOS

def getFlags(data):
    flagR = {0: "Reserved bit"}
    flagDF = {0: "Fragment if necessary", 1: "Do not fragment"}
    flagMF = {0: "Last fragment", 1: "More fragments"}
    R = data & 0x8000
    R >>=15
    DF = data & 0x4000
    DF >>=14
    MF = data & 0x2000
    MF >>= 13
    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags

def getProtocol(protocolNr):
    protocolFile = open('Protocols', 'r')
    protocolData = protocolFile.read()
    protocol = re.findall(r'\n' + str(protocolNr) + '(?:.)+\n', protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '')
        protocol = protocol.replace(str(protocolNr), '')
        protocol = protocol.lstrip()
        return protocol
    else:
        return"No such protocols found"

# the public network interface
HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

data = receiveData(s)
unpackedData = struct.unpack("!BBHHHBBH4s4s", data[:20])
print(unpackedData)

ip_header = data[14:34]
ip_header = struct.unpack('!BB3HBBH4s4s', ip_header)
ip_header_length = (ip_header[0] & 15) * 4

version_IHL = unpackedData[0]
version = version_IHL >> 4
IHl = version_IHL & 0xF
TOS = unpackedData[1]
totalLength = unpackedData[2]
ID = unpackedData[3]
flags = unpackedData[4]
fragment_offset = unpackedData[4] & 0x1FFF
TTL = unpackedData[5]
protocolNr = unpackedData[6]
checksum = unpackedData[7]
sourceAddress = socket.inet_ntoa(unpackedData[8])
destinationAddress = socket.inet_ntoa(unpackedData[9])

print("An IP packet with the size %i was captured" % totalLength)
if protocolNr == 6:
    print("Raw data: " + str(data))
    print("\nParsed data")
    print("Version:\t\t" + str(version))
    print("Header Length:\t\t" + str(IHl * 4) + 'bytes')
    print("Type of service:\t" + getTOS(TOS))
    print("Length:\t\t\t" + str(totalLength))
    print("ID:\t\t\t" + str(hex(ID)) + str(ID))
    print("Flags:\t\t\t" + getFlags(flags))
    print("Fragment offset:\t" + str(TTL))
    print("TTL:\t\t\t" + str(TTL))
    print("Protocol:\t\t" + getProtocol(protocolNr))
    print("Checksum:\t\t" + str(checksum))
    print("Source:\t\t\t" + sourceAddress)
    print("Destination:\t\t" + destinationAddress)
    print("Payload:\n" + str(data[20:]))

    tcp_header = data[(ip_header_length + 14): (ip_header_length + 34)]
    tcp_header = struct.unpack('!HHLLBB3H', tcp_header)
    source_port, dest_port = tcp_header[0], tcp_header[1]

    identity = ((sourceAddress, source_port), (destinationAddress, dest_port))
    identity = (min(identity[0], identity[1]),
                max(identity[0], identity[1]))  # sort in order to club packets flowing in either direction

    tcp_header_length = (tcp_header[4] >> 4) * 4
    flags = tcp_header[5]

    data_length = len(data[(14 + ip_header_length + tcp_header_length):])
    segment_length = tcp_header_length + data_length
    packet_length = ip_header_length + segment_length
    print(identity, format(flags, 'b').zfill(8), data_length,
          ("Incoming" if (sourceAddress in HOST) else "Outgoing"))

else:
    print("TCP packet wasn't captured")

# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)