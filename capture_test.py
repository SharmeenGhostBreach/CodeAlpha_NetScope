from scapy.all import sniff

print("Starting packet capture on eth0...")
print("Capturing 10 packets. Please generate some network activity.")

packets = sniff(
    iface="eth0",
    count=10,
    store=True
)

print("\nCapture completed!")
print("Total packets captured:", len(packets))

packets.summary()

