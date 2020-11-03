import sys as sys
import socket as socket
import numpy as np


class scanner:
    """
    This class contains all implenetation for port scanner
    """

    def __init__(self):
        # These are favourite tcp ports that Nmap scans automatically.
        self.portList = np.array([80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
                                  143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
                                  1025, 587, 8888, 199, 1720,
                                  113, 554, 256])

    def favouriteScan(self, ip):
        # Scans from port list
        print(f'Port Scanner Report for: {ip}')
        closed = 0
        for port in self.portList:
            try:
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                if tcp.connect_ex((ip, port)) == 0:
                    print(f'{port}/tcp open')
                    tcp.close()
                else:
                    closed += 1
                    tcp.close()

            except Exception:
                pass

        print(f'{closed} scanned ports closed')

    def rangeScan(self, ip, portStart, portEnd):
        # Scan from range of ports given by user
        print(f'Port Scanner Report for: {ip}')
        closed = 0
        for port in range(portStart, portEnd + 1):
            try:

                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                if tcp.connect_ex((ip, port)) == 0:
                    print(f'{port}/tcp open')
                    tcp.close()
                else:
                    closed += 1
                    tcp.close()

            except Exception:
                pass
        print(f'{closed} scanned ports closed')

    def portScan(self, ip, port):
        # Scan a specific port on the host
        print(f'Port Scanner Report for: {ip}')
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if tcp.connect_ex((ip, port)) == 0:
                print(f'{port}/tcp open')
                tcp.close()
            else:
                print(f'{port}/tcp closed')
                tcp.close()
        except Exception:
            pass


def help():
    print('Usage\nportScanner.py [ip]')
    print('portScanner.py [ip] [port Specific]')
    print('portScanner.py [ip] [port Range start] [port range end]')
    print('Example\nportScanner.py 192.168.100.8')
    print('portScanner.py 192.168.100.8 8080')
    print('portScanner.py 192.168.100.8 80 443')


def main():

    socket.setdefaulttimeout(0.1)
    scan = scanner()
    try:
        if(len(sys.argv) == 2):
            # scan fav ports
            scan.favouriteScan(sys.argv[1])
        elif(len(sys.argv) == 3):
            # scan specific port
            scan.portScan(sys.argv[1], int(sys.argv[2]))
        elif(len(sys.argv) == 4):
            # scan port range
            scan.rangeScan(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
        else:
            help()

    except Exception:
        help()


if __name__ == '__main__':
    main()
