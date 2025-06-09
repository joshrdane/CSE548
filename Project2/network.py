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
d1 = net.addDocker('d1', ip='192.168.2.10', mac='00:00:00:00:00:10', dimage='ubuntu:trusty')
d2 = net.addDocker('d2', ip='192.168.2.20', mac='00:00:00:00:00:20', dimage='ubuntu:trusty')
d3 = net.addDocker('d3', ip='192.168.2.30', mac='00:00:00:00:00:30', dimage='ubuntu:trusty')
d4 = net.addDocker('d4', ip='192.168.2.40', mac='00:00:00:00:00:40', dimage='ubuntu:trusty')

info('*** Adding switches\n')
s1 = net.addSwitch('s1')

info('*** Creating links\n')
net.addLink(s1, d1)
net.addLink(s1, d2)
net.addLink(s1, d3)
net.addLink(s1, d4)

info('*** Starting network\n')
net.start()

CLI(net)

info('*** Stopping network\n')
net.stop()
