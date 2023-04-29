# SherlocksHome - Get all Bastards! (EDU)
###### RedTeam Script Examples by Volkan Sah - simple codings for 'Offensive Security' (updated 3/2023)
![screenshot sherlocks home python script](sherlockshome_edu.png)

This Black Python script is a powerful tool designed to monitor traffic between clients and malicious .onion sites. It is not a game, and it is intended for use by security professionals and developers who know how to handle it safely. We use a code like this to capture bad actors.

Be careful! For this example, we use Python's Scapy library to listen with sensors and identify connections accessing a malicious .onion site. With Scapy, we can capture, dissect, and forge network packets. This sample code captures packets communicating with a specific .onion address, records their timestamps and source IP address (if available), and exports them to a CSV file.

## WARNING: READ CAREFULLY!
This Black Python script example is intended for use by security professionals and developers only. It is not intended for malicious purposes, and I cannot be held responsible for any misuse of this code. If you use this tool for illegal or unethical purposes, you alone will be held responsible for any consequences that may arise, including legal and ethical issues.

## Note
Please note that there is a pre-steps you must complete before using this script. However, I will not disclose it to prevent malicious individuals from using this tool. If you choose to use it anyway, you may harm yourself and potentially face legal consequences from law enforcement.


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

Please note that capturing packets may raise legal and ethical concerns, and it is your responsibility to ensure that your actions comply with the law and ethical standards. It is recommended that you seek legal and ethical guidance before using this technics.

## Disclaimer
This script is for educational purposes only and should not be used for any illegal, unethical, or malicious activities. Always ensure that you have proper authorization before conducting any security testing or penetration testing on any website or system. The creator of this script is not responsible for any misuse or damages caused by using this script.

## issues
Issues to this script are not accepted as it is intended for educational purposes only and not for production use.

## Credits
- [VolkanSah on Github](https://github.com/volkansah)
- [Developer Site](https://volkansah.github.io)
- [Become a 'Sponsor'](https://github.com/sponsors/volkansah)

#### links to scapy
- [Scapy Website](https://scapy.net/)
- [Scapy on Github]( https://github.com/secdev/scapy)
- [Scapy Docs](https://scapy.readthedocs.io/en/latest/)
## License
This script is released by [VolkanSah](https://github.com/volkansah) under the MIT License 
