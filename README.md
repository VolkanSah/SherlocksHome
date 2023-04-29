# SherlocksHome - Get all Bastards!
This Black Python script is not a game! It is a powerful tool to monitor the traffic between clients and malicious .onion sites. We use a code like this to capture bad actors. **Be careful!** For this example, we use Python's Scapy library to listen with sensors and identify connections accessing a malicious .onion site. With Scapy, we can capture, dissect, and forge network packets. 😄 This sample code captures packets communicating with a specific .onion address, records their timestamps and source IP address (if available), and exports them to a CSV file.

Note: You must complete a pre-step before using this script! We will not explain it to prevent script kiddies and other malicious individuals from using it. If you choose to use it anyway, you will harm yourself and potentially face legal consequences from law enforcement


```python
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #                                                 
#   ,---.  ,--.                   ,--.             ,--.           ,--.  ,--.     by Nemesis Mr.Chess  #   
#  '   .-' |  ,---.  ,---. ,--.--.|  | ,---.  ,---.|  |,-.  ,---. |  '--'  | ,---. ,--,--,--. ,---.   #
#  `.  `-. |  .-.  || .-. :|  .--'|  || .-. || .--'|     / (  .-' |  .--.  || .-. ||        || .-. :  #
#  .-'    ||  | |  |\   --.|  |   |  |' '-' '\ `--.|  \  \ .-'  `)|  |  |  |' '-' '|  |  |  |\   --.  #
#  `-----' `--' `--' `----'`--'   `--' `---'  `---'`--'`--'`----' `--'  `--' `---' `--`--`--' `----'  #
#   Will get all bastards!                                                              EDU Version   #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #                                                 
from scapy.all import *
import csv
import time
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
###################################################################################
# Content removed for security reasons - this code is for education use only
# Here are some tips:
# Start by sniffing/scanning the destination - tools like NMAP-BP can help
# Use an extractor with JADE to handle logic or mechanics for each destination
# Sorry, this sensor is powerful enough that you don't need any additional tools
# If necessary, you can share the results with law enforcement
####################################################################################
# Write packet data to CSV file
with open('onion_communication.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol'])
    for row in packet_list:
        writer.writerow(row)
```

When you run this code, it will capture all packets that communicate with the specified address, and write them to a CSV file named "onion_communication.csv". The CSV file will include the timestamp, source IP, destination IP, and protocol of each captured packet.

WARNING: READ CAREFULLY!
This Black Python script is a powerful security tool intended for use by security professionals and developers only. It is not intended for malicious purposes, and I cannot be held responsible for any misuse of this code. If you use this tool for illegal or unethical purposes, you alone will be held responsible for any consequences that may arise, including legal and ethical issues.

Please note that capturing packets may raise legal and ethical concerns, and it is your responsibility to ensure that your actions comply with the law and ethical standards. It is recommended that you seek legal and ethical guidance before using this technics.
