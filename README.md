# SherlocksHome - Get Bastards Version!
This Black Python Script is not a game! It is a powerfull tool to chapter traffic betwien clients and evil .onion sites
I use it for How to kill the Onion! Be carefull!
To listen with sensors and identify connections accessing an evil .onion site, we use for this example: Python's Scapy library. 
Scapy allows us to capture, dissect and forge network packets. :smile: 
Here's an example code that captures packets that communicate with a specified .onion address, 
records their timestamps and the source IP address (if can get it), and exports them to a CSV file:

```python
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #                                              # #                                                                                                     #
#   ,---.  ,--.                   ,--.             ,--.           ,--.  ,--.                          #   
#  '   .-' |  ,---.  ,---. ,--.--.|  | ,---.  ,---.|  |,-.  ,---. |  '--'  | ,---. ,--,--,--. ,---.   #
#  `.  `-. |  .-.  || .-. :|  .--'|  || .-. || .--'|     / (  .-' |  .--.  || .-. ||        || .-. :  #
#  .-'    ||  | |  |\   --.|  |   |  |' '-' '\ `--.|  \  \ .-'  `)|  |  |  |' '-' '|  |  |  |\   --.  #
#  `-----' `--' `--' `----'`--'   `--' `---'  `---'`--'`--'`----' `--'  `--' `---' `--`--`--' `----'  #
#   He/She will get all bastards!                                                                     #                            
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #                                                                                                                  

from scapy.all import *
import csv
import time

onion_address = "INSERT .ONION ADDRESS HERE" # Replace with the .onion address you want to monitor
# Create a list to store captured packets
packet_list = []

# Define a function to capture packets and append them to packet_list
def packet_capture(packet):
    if packet.haslayer(IP):
        if packet[IP].dst == onion_address or packet[IP].src == onion_address:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_list.aappend([timestamp, src_ip, dst_ip, protocol])

# Start packet capture
sniff(prn=packet_capture)

# Write packet data to CSV file we ned it
with open('onion_communication.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol'])
    for row in packet_list:
        writer.writerow(row)
# Removed!#
# execute each connection in random logic with hidden_tunnels 

# This Sensor is powerfull enought you didnt need Nemises Version!
# you can give the results to the next police station!
```

When you run this code, it will capture all packets that communicate with the specified .onion address, and write them to a CSV file named "onion_communication.csv". The CSV file will include the timestamp, source IP, destination IP and protocol of each captured packet.

Note that capturing packets may raise legal and ethical concerns, and it is your responsibility to ensure that your actions comply with the law and ethical standards.
