# SherlocksHome - Get all Bastards! (EDU)
###### RedTeam Script Examples (EDU) by Volkan Sah - simple codings for 'Offensive Security' (updated 3/2024)
![screenshot sherlocks home python script](sherlockshome_edu.png)

This Black Python script  example is a powerful tool to monitor traffic between clients and malicious .onion sites. It is not a game, and it is intended for use by security professionals and developers who know how to handle it safely.

Be careful! For this example, we use Python's Scapy library to listen with sensors and identify connections accessing a malicious .onion site. With Scapy, we can capture, dissect, and forge network packets. 

## WARNING: READ CAREFULLY!
This Black Python script example is intended for use by security professionals and developers only. It is not intended for malicious purposes, and I cannot be held responsible for any misuse of this code. If you use this tool for illegal or unethical purposes, you alone will be held responsible for any consequences that may arise, including legal and ethical issues.

## Note
Please note that there is a pre-steps (e.g SoCat) you must complete before using this script. However, I will not disclose it to prevent malicious individuals from using this tool. If you choose to use it anyway, you may harm yourself and potentially face legal consequences from law enforcement.

- This sample code captures packets communicating with a specific .onion address, records their timestamps and source IP address (if available), and exports them to a CSV file.
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
#import logging
#logging.getLogger("scapy").setLevel(logging.CRITICAL)

onion_address = "INSERT .ONION ADDRESS HERE" # .onion address you want to monitor
# Create a list to store packets
packet_list = []
# Function to capture packets and append them to packet_list
def packet_capture(packet):
    if packet.haslayer(IP):
        if packet[IP].dst == onion_address or packet[IP].src == onion_address:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_list.aappend([timestamp, src_ip, dst_ip, protocol])
            # more logic here if needed!
# Start packet captureing
# eg. sniff(prn=packet_capture, your needs)
while some_condition:
sniff(prn=packet_capture, filter=f"host {onion_address}", count=10)
# Sherlock did his job, till yet! 
# Rest of the code here, e.g., save to CSV file, sleep, update the condition, etc.
#########################################################################################
# Content with logic removed for security reasons - this code is for education use only #
# Here are some tips:                                                                   #
# Start by sniffing/scanning the destination - tools like NMAP-BP can help              #
# Use an extractor with a kiss of JADE to handle logic or mechanics for each destination#
# Sorry, this sensor is powerful enough that you don't need any additional tools for edu#
# If necessary, you can share the results with law enforcement                          #
#########################################################################################
# Write packet data to CSV file
with open('onion_communication.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol'])
    for row in packet_list:
        writer.writerow(row)
```


When you run this code, it will capture all packets that communicate with the specified address, and write them to a CSV file named "onion_communication.csv". The CSV file will include the timestamp, source IP, destination IP, and protocol of each captured packet.

## WTF ??? ARE THE AUTOR INSANE????
Only sometimes! Let me explain you:


### Example 1
This function will check for IP packets and then match the destination IP address to the ones in (127.0.0.1:8080, 127.0.0.1:8081, and 127.0.0.1:8083). If a match is found, it will print out the source and destination IP addresses.

```python
def check_destination(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if re.match('127\.0\.0\.1:(8080|8081|8083)', ip_dst):
            print(f'Potential intruder detected: {ip_src} -> {ip_dst}')
            
 or
 
 def check_destination(pkt):
    if IP in pkt and TCP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        dst_port = pkt[TCP].dport
        if ip_dst == '127.0.0.1' and dst_port in [8080, 8081, 8083]:
            print(f'Potential intruder detected: {ip_src} -> {ip_dst}:{dst_port}')

            
            
```
- Use Scapy's sniff function to capture network traffic and pass it to the check_destination function:
```python
sniff(prn=check_destination, filter='tcp')
```
This will start capturing TCP packets and pass them to the check_destination function for analysis.
- Run the script and monitor the output for potential intruders.

Note that this script only captures packets on the local machine (127.0.0.1). Use e.g SoCat to ReUseAdress
### Example 2
This examples uses Scapy to sniff network packets and filter for TCP traffic. It then checks whether the packet is using the SOCKS5 protocol by inspecting the destination port. If it is, it extracts the destination IP address from the packet header and forks the traffic to two local ports (9051 and 9052) that can be accessed via Tor. The script uses the sniff function from Scapy to capture packets and a lambda function to pass the packets to the fork_to_tor function if they are using the SOCKS5 protocol.

```python
from scapy.all import *
import socket

def is_tor(pkt):
    if pkt.haslayer(TCP):
        tcp = pkt.getlayer(TCP)
        if tcp.dport == 9050:
            return True
    return False

def get_dest_ip(pkt):
    ip = pkt.getlayer(IP)
    return ip.dst

def fork_to_tor(pkt, sport, dport):
    pkt[IP].dst = '127.0.0.1'
    pkt[TCP].sport = sport
    pkt[TCP].dport = dport
    send(pkt)

def main():
    sniff(filter="tcp", prn=lambda x: fork_to_tor(x, 9051, 9052) if is_tor(x) else None)

if __name__ == '__main__':
    main()
```
### Example 3
If you want to track all incoming traffic to bad links in a domain list, you can modify like below

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
This modification reads in a file named domainlist.txt containing a list of bad domains, and creates a set of those domains. The is_bad_domain() function checks if a given IP address belongs to one of the bad domains, by extracting the domain from the IP address and checking if it's in the set of bad domains.

- Inside the handle_packet() function, after identifying a SOCKS5 packet and extracting the destination IP, we call is_bad_domain() to check if the IP belongs to a bad domain. If it does, we print a message indicating the bad domain was found.

- Note that this is a very basic example, and in a real-world scenario you may need to implement additional checks and measures to handle different types of traffic and avoid false positives.

- Please note that capturing packets may raise legal and ethical concerns, and it is your responsibility to ensure that your actions comply with the law and ethical standards. It is recommended that you seek legal and ethical guidance before using this technics.

## Disclaimer
This scriptexamples is for educational purposes only and should not be used for any illegal, unethical, or malicious activities. Always ensure that you have proper authorization before conducting any security testing or penetration testing on any website or system. The creator of this script is not responsible for any misuse or damages caused by using this script.

## issues
Issues to this script are not accepted as it is intended for educational purposes only and not for production use.

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
