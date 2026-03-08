from scapy.all import get_if_list, show_interfaces

# This shows the "friendly name" and the "Scapy name"
show_interfaces()

print("\n--- List of all Interface Names ---")
print(get_if_list())
#.\VBoxManage.exe modifyvm "wedgtjo" --nic2 hostonly --hostonlyadapter2 "VirtualBox Host-Only Ethernet Adapter"
#netsh advfirewall firewall add rule name="Allow VirtualBox Ping" protocol=icmpv4:8,any dir=in action=allow