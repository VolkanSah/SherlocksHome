# SherlocksHome - Get all Bastards! (EDU)
###### RedTeam Script Examples (EDU) by Volkan Sah - simple codings for 'Offensive Security' (updated 5/2024)
![screenshot sherlocks home python script](sherlockshome_edu.png)

This Black Python script example is a powerful tool to monitor traffic between clients and malicious .onion sites. It is not a game, and it is intended for use by security professionals and developers who know how to handle it safely.

Be careful! For this example, we use Python's Scapy library to listen with sensors and identify connections accessing a malicious .onion site. With Scapy, we can capture, dissect, and forge network packets. 

> [!WARNING]
> This Black Python script example is intended for use by security professionals and developers only. It is not intended for malicious purposes, and I cannot be held responsible for any misuse of this code. If you use this tool for illegal or unethical purposes, you alone will be held responsible for any consequences that may arise, including legal and ethical issues.


## Note
Please note that there are pre-steps (e.g., SoCat) you must complete before using this script. However, I will not disclose them to prevent malicious individuals from using this tool. If you choose to use it anyway, you may harm yourself and potentially face legal consequences from law enforcement.

## Main Code
This sample code captures packets communicating with a specific .onion address, records their timestamps and source IP address (if available), and exports them to a CSV file.

```python

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #                                                 
#   ,---.  ,--.                   ,--.             ,--.           ,--.  ,--.     by Nemesis Mr.Chess  #   
#  '   .-' |  ,---.  ,---. ,--.--.|  | ,---.  ,---.|  |,-.  ,---. |  '--'  | ,---. ,--,--,--. ,---.   #
#  `.  `-. |  .-.  || .-. :|  .--'|  || .-. || .--'|     / (  .-' |  .--.  || .-. ||        || .-. :  #
#  .-'    ||  | |  |\   --.|  |   |  |' '-' '\ `--.|  \  \ .-'  `)|  |  |  |' '-' '|  |  |  |\   --.  #
#  `-----' `--' `--' `----'`--'   `--' `---'  `---'`--'`--'`----' `--'  `--' `---' `--`--`--' `----'  #
#   Will get all Bastards!                                                                            #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
                                               
from scapy.all import *
import csv
import time
import re

onion_address = "INSERT .ONION ADDRESS HERE" # .onion address you want to monitor
packet_list = []

def packet_capture(packet):
    if packet.haslayer(IP):
        if packet[IP].dst == onion_address or packet[IP].src == onion_address:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_list.append([timestamp, src_ip, dst_ip, protocol])

while True:
    sniff(prn=packet_capture, filter=f"host {onion_address}", count=10)

    # Write packet data to CSV file
    with open('onion_communication.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol'])
        for row in packet_list:
            writer.writerow(row)

    # Check destination
    for pkt in packet_list:
        ip_src = pkt[1]
        ip_dst = pkt[2]
        if re.match(r'127\.0\.0\.1:(8080|8081|8083)', ip_dst):
            print(f'Potential intruder detected: {ip_src} -> {ip_dst}')

    # Reset packet_list
    packet_list = []

    # Add a delay or other logic as needed
    time.sleep(60)  # Wait for 1 minute before capturing the next batch of packets
```


## Explanation
1.Importing Libraries: The script starts by importing necessary libraries from Scapy, as well as CSV, time, and regular expressions (re) modules.
2. Setting the Onion Address: Replace "INSERT .ONION ADDRESS HERE" with the .onion address you want to monitor.
3. Packet Capture Function:
-- The packet_capture function is defined to capture packets.
-- It checks if the packet has an IP layer.
-- If the packet’s source or destination matches the specified .onion address, it extracts the timestamp, source IP, destination IP, and protocol.
-- This information is appended to the packet_list.

4. Sniffing Packets:
-- The sniff function from Scapy is used to continuously capture packets.
-- The packets are filtered to match the specified .onion address and processed by the packet_capture function.

5. Writing to CSV:
-- Captured packet data is written to a CSV file named onion_communication.csv every time 10 packets are captured.
-- The CSV file includes columns for Timestamp, Source IP, Destination IP, and Protocol.

6. Checking for Intruders:
-- The script checks if any captured packets are communicating with specific local ports (127.0.0.1:8080, 127.0.0.1:8081, 127.0.0.1:8083).
-- If such communication is detected, it prints a message indicating a potential intruder.

7. Resetting and Delaying:
-- The packet_list is reset after each batch of 10 packets.
-- The script waits for 1 minute before capturing the next batch of packets.

## other usefull Example : 
### Monitoring Traffic to Bad Domains

If you want to track all incoming traffic to bad links in a domain list, you can modify the script as follows:

```python
from scapy.all import *
bad_domains = set(line.strip() for line in open('domainlist.txt'))

def is_bad_domain(ip):
    # Extract the domain from the IP address
    domain = str(ip).split('.')[-2] + '.' + str(ip).split('.')[-1]
    return domain in bad_domains

def handle_packet(packet):
    # Check if the packet is a SOCKS5 packet
    if packet.haslayer(Raw) and b'\x05\x01\x00' in packet[Raw].load:
        # Extract the destination IP address
        ip = packet[IP].dst
        # Check if the destination IP is a bad domain
        if is_bad_domain(ip):
            print("Bad domain found: {}".format(ip))
        # Fork the packet to local ports
        # (insert fork code here)

# Start capturing packets on the network interface
sniff(filter="tcp", prn=handle_packet)


```

This modification reads a file named **domainlist.txt** containing a list of bad domains, and creates a set of those domains. The is_bad_domain() function checks if a given IP address belongs to one of the bad domains by extracting the domain from the IP address and checking if it's in the set of bad domains.

- Inside the handle_packet() function, after identifying a SOCKS5 packet and extracting the destination IP, we call is_bad_domain() to check if the IP belongs to a bad domain. If it does, a message indicating the bad domain was found is printed.

**Note that this is a basic example, and in a real-world scenario, additional checks and measures might be necessary to handle different types of traffic and avoid false positives.**

## Disclaimer

This script example is for educational purposes only and should not be used for any illegal, unethical, or malicious activities. Always ensure that you have proper authorization before conducting any security testing or penetration testing on any website or system. The creator of this script is not responsible for any misuse or damages caused by using this script.
Issues

Issues with this script are not accepted as it is intended for educational purposes only and not for production use.
## links to scapy
- [Scapy Website](https://scapy.net/)
- [Scapy on Github]( https://github.com/secdev/scapy)
- [Scapy Docs](https://scapy.readthedocs.io/en/latest/)

### Thank you for your support!
- If you appreciate my work, please consider [becoming a 'Sponsor'](https://github.com/sponsors/volkansah), giving a :star: to my projects, or following me. 
### Copyright
- [VolkanSah on Github](https://github.com/volkansah)
- [Developer Site](https://volkansah.github.io)

### License
This project is licensed under the MIT - see the [LICENSE](LICENSE) file for details
