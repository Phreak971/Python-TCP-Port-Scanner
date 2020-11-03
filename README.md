# Python-TCP-Port-Scanner
A basic port scanner implemented in python using TCP.

## Overview
In this task I created a simple port scanner that sends a TCP SYN request to the given IP address on specified ports. If ports are not specified it scans the list of ports that are mostly opened. I also compared my scanner’s results with NMAP as proof that the scanner is working correctly.

## Working
The application takes the IP address of the host to be scanned along with the port or port range to be scanned if the port is open or not. The left window is Nmap and the right window is the Port Scanner implemented by me.

### Scanning for all favorite ports
![Screenshot of output](https://github.com/Phreak971/Python-TCP-Port-Scanner/blob/main/Screenshots/1.png)

### Scanning for a specific port
![Screenshot of output](https://github.com/Phreak971/Python-TCP-Port-Scanner/blob/main/Screenshots/2.png)

### Scanning for a range of ports
![Screenshot of output](https://github.com/Phreak971/Python-TCP-Port-Scanner/blob/main/Screenshots/3.png)


## Response from the Receiver
The communication takes place in following steps:
### When Port is Open
1.	Me: [SYN], I sent a synchronize request to the host 8.8.8.8 (Google’s Primary DNS).
2.	Host: [SYN, ACK], The port is open so the host responds with an Acknowledgement that it is up and working and sends a synchronize request to Me to check if i am alive.
3.	Me: [ACK], In response to host’s SYN I send an acknowledgement. In this way Three-way handshake is done and connection is established.
4.	Me: [FIN, ACK], Now it's time to end the connection as my code closes the connection after establishing so in next step, I send a [FIN, ACK] where FIN means Finish.
5.	Host: [FIN, ACK], The host also Acknowledges to close the connection and asks for a final Acknowledgement from me.
6.	Me: [ACK], After this connection is closed.

![Wireshark Screenshot of Packets](https://github.com/Phreak971/Python-TCP-Port-Scanner/blob/main/Screenshots/4.png)

### When Port is Closed
When the port is closed not much happens. Only a SYN request goes to the host but nothing comes in return.
![Wireshark Screenshot of Packets](https://github.com/Phreak971/Python-TCP-Port-Scanner/blob/main/Screenshots/5.png)
 
## Summary
Furthermore, the code is pretty much self-explanatory and comments are added where needed. I always wanted to make my own Nmap. So, this is a good demo for how that journey would be.

