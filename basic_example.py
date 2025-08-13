
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

LOCAL_PORT = 12345  # Port, den du mit socat forwardst
packet_list = []

def packet_capture(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
        packet_list.append([timestamp, src_ip, src_port, dst_ip, dst_port])

while True:
    sniff(prn=packet_capture, filter=f"tcp port {LOCAL_PORT}", count=10)

    # Write packet data to CSV file
    with open('onion_communication.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Timestamp', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port'])
        for row in packet_list:
            writer.writerow(row)

    # Optional: einfache Überwachung
    for pkt in packet_list:
        if pkt[3] == '127.0.0.1':  # Ziel ist der lokale Forward
            print(f'Potential traffic: {pkt[1]}:{pkt[2]} -> {pkt[3]}:{pkt[4]}')

    packet_list = []
    time.sleep(60)

