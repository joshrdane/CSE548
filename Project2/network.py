from mininet.net import Containernet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel

setLogLevel('info')

net = Containernet(controller=RemoteController, link=TCLink)

info('*** Adding controller\n')
c1 = net.addController('c1', controller=RemoteController, port=6633)

info('*** Adding docker containers\n')
h1 = net.addHost('h1', ip='192.168.2.10', mac='00:00:00:00:00:10')
h2 = net.addHost('h2', ip='192.168.2.20', mac='00:00:00:00:00:20')
h3 = net.addHost('h3', ip='192.168.2.30', mac='00:00:00:00:00:30')
h4 = net.addHost('h4', ip='192.168.2.40', mac='00:00:00:00:00:40')

info('*** Adding switches\n')
s1 = net.addSwitch('s1')

info('*** Creating links\n')
net.addLink(s1, h1)
net.addLink(s1, h2)
net.addLink(s1, h3)
net.addLink(s1, h4)

info('*** Starting network\n')
net.start()

CLI(net)

info('*** Stopping network\n')
net.stop()
