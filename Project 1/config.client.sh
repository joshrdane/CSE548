# Install required packages
apt install nmap -y

# Set static IP address on client nat network
nmcli connection modify "Wired connection 1" ipv4.method manual
nmcli connection modify "Wired connection 1" ipv4.address 10.0.2.20/24
nmcli connection modify "Wired connection 1" ipv4.gateway 10.0.2.10

# Delete the default route
route del default

# Set the default route to the Gateway/Server VM
route add default gw 10.0.2.20 dev enp0s3