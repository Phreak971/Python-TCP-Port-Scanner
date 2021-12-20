import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import optparse
from scapy.all import *
import sys

TCPportList = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
                                  143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
                                  1025, 587, 8888, 199, 1720,
                                  113, 554, 256]
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-p', '--port', dest='portStart', help='Port to scan')
    parser.add_option('-r', '--portEnd', dest='portEnd', help='Port Range End')
    parser.add_option('-S', '--stealth', dest='stealthScan', help='Stealth Scan or Half Scan', action= 'store_true')
    parser.add_option('-X', '--xmas', dest='xmasScan', help='Xmas Scan', action= 'store_true')
    return parser.parse_args()[0]

def XmasScan(ip, port):
    src_port = 0
    closed = 0
    filtered = 0
    dst_ip = ip
    if not port:
        port = TCPportList
    elif len(port) == 2:
        port.extend(range(port[0], port[1]))
        port = port[2:]
    elif len(port) == 1:
        pass
    else:
        return
    for dst_port in port:
        xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=0.5, verbose=0)
        if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
            print "[*] %d open|filtered" % dst_port
        elif(xmas_scan_resp.haslayer(TCP)):
            if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
                print "Closed"
        elif(xmas_scan_resp.haslayer(ICMP)):
            if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                filtered = filtered + 1
    if closed:
        print "[*] %d scanned ports closed" % closed
    if filtered:
        print "[*] %d scanned ports filtered" % filtered
def StealthScan(ip, port):
    src_port = 0
    closed = 0
    filtered = 0
    dst_ip = ip
    if not port:
        port = TCPportList
    elif len(port) == 2:
        port.extend(range(port[0], port[1]))
        port = port[2:]
    elif len(port) == 1:
        pass
    else:
        return
    for dst_port in port:
            stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=0.5, verbose=0)
            if(str(type(stealth_scan_resp)) == "<type 'NoneType'>"):
                filtered = filtered + 1 
            elif(stealth_scan_resp.haslayer(TCP)):
                if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
                    send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=0.5, verbose=0)
                    print "[*] %d open" % dst_port
                elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
                    closed = closed + 1
                elif(stealth_scan_resp.haslayer(ICMP)):
                    if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        filtered = filtered + 1 
    if closed:
        print "[*] %d scanned ports closed" % closed
    if filtered:
        print "[*] %d scanned ports filtered" % filtered
def FullScan(ip, port):
    src_port = 0
    closed = 0
    dst_ip = ip
    if not port:
        port = TCPportList
    elif len(port) == 2:
        port.extend(range(port[0], port[1]))
        port = port[2:]
    elif len(port) == 1:
        pass
    else:
        return
    for dst_port in port:
        tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=2, verbose=0)
        if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
            closed = closed + 1
        elif(tcp_connect_scan_resp.haslayer(TCP)):
                if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
                    send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=2, verbose=0)
                    print "[*] %d open" % dst_port
                elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
                    closed = closed + 1
    if closed:
        print "[*] %d scanned ports closed" % closed

options = get_arguments()
if sys.argv[1]:
    if options.portStart and options.portEnd:
        if options.stealthScan:
            StealthScan(sys.argv[1], [int(options.portStart), int(options.portEnd)])
        elif options.xmasScan:
            XmasScan(sys.argv[1], [int(options.portStart), int(options.portEnd)])
        else:
            FullScan(sys.argv[1], [int(options.portStart), int(options.portEnd)])
    elif options.portStart:
        if options.stealthScan:
            StealthScan(sys.argv[1], [int(options.portStart)])
        elif options.xmasScan:
            XmasScan(sys.argv[1], [int(options.portStart)])
        else:
            FullScan(sys.argv[1], [int(options.portStart)])
    else:
        if options.stealthScan:
            StealthScan(sys.argv[1], None)
        elif options.xmasScan:
            XmasScan(sys.argv[1], None)
        else:
            FullScan(sys.argv[1], None)
else:
    print("[-] No ip specified")
