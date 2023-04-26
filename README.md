# SherlocksHome - Get all Bastards Version!
This Black Python Script is not a game! It is a powerfull tool to chapter traffic between clients and evil .onion sites
I use it for How to kill the Onion? Be carefull!
To listen with sensors and identify connections accessing an evil .onion site, we use for this example: Python's Scapy library. 
Scapy allows us to capture, dissect and forge network packets. :smile: 
This example code that captures packets that communicate with a specified .onion address, 
records their timestamps and the source IP address (if can get it), and exports them to a CSV file:

```python
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #                                              # #                                                                                                     #
#   ,---.  ,--.                   ,--.             ,--.           ,--.  ,--.                          #   
#  '   .-' |  ,---.  ,---. ,--.--.|  | ,---.  ,---.|  |,-.  ,---. |  '--'  | ,---. ,--,--,--. ,---.   #
#  `.  `-. |  .-.  || .-. :|  .--'|  || .-. || .--'|     / (  .-' |  .--.  || .-. ||        || .-. :  #
#  .-'    ||  | |  |\   --.|  |   |  |' '-' '\ `--.|  \  \ .-'  `)|  |  |  |' '-' '|  |  |  |\   --.  #
#  `-----' `--' `--' `----'`--'   `--' `---'  `---'`--'`--'`----' `--'  `--' `---' `--`--`--' `----'  #
#   Will get all bastards!                                                                     #                            
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #                                                                                                                  

from scapy.all import *
import csv
import time

onion_address = "INSERT .ONION ADDRESS HERE" # Replace with the .onion address you want to monitor
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
sniff(prn=packet_capture)

# Sherlock did his job, till yet!
###################################################################
# Removed! to avoid stupid people # but here some tipps!
# - start sniff /scan destination NMAP-BP can help ;)
# execute /handel logic or mechanics for each 
# destination an Extractor with a kiss of JADE can help 
# Pro-Tipp: I love to let an readme.txt on the Target Desktop!
# sorry! This Sensor is powerfull enought you didn`t need Nemises!
# you can give the results to the next police station!
###################################################################

# Write packet data to CSV file
with open('onion_communication.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol'])
    for row in packet_list:
        writer.writerow(row)
```

When you run this code, it will capture all packets that communicate with the specified address, and write them to a CSV file named "onion_communication.csv". The CSV file will include the timestamp, source IP, destination IP and protocol of each captured packet.

## REALY REALY BIG BIG BIG BIG BIG WARNING !
This Black.Python Script is not a toy! If you chapter criminals and dont know what you do, they will come and kill your family in front of you than you will die!

Note that capturing packets may raise legal and ethical concerns, and it is your responsibility to ensure that your actions comply with the law and ethical standards.
