from scapy.all import IP, TCP, UDP, ICMP

print("NETWORK PACKET ANALYSIS")
print("-" * 35)

print("IP Layer:", IP().name)
print("TCP Layer:", TCP().name)
print("UDP Layer:", UDP().name)
print("ICMP Layer:", ICMP().name)
