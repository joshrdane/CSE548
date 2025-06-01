# Update/upgrade packages
apt update && apt upgrade -y

# Install Apache
apt install apache2

# Set static IP address on client nat network
nmcli connection modify "Wired connection 1" ipv4.method manual
nmcli connection modify "Wired connection 1" ipv4.address 10.0.2.10/24

# Set static IP  address on internet nat network
nmcli connection modify "Wired connection 2" ipv4.method manual
nmcli connection modify "Wired connection 2" ipv4.address 10.0.1.10/24

# Configure ip forwarding
echo "1" > /proc/sys/net/ipv4/ip_forward

# Configure index page
echo "Welcome to the Packet Filter Firewall (iptables) Project demo and test page!" > /var/www/html/index.html

# Use rc.firewall script to configure iptables
./rc.firewall