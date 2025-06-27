from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
import pox.lib.packet as pkt

log = core.getLogger()

ALLOW_PRIORITY = 1000
BLOCK_PRIORITY = 65535

IDLE_TIMEOUT = 60

class Firewall(EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        # List of currently blocked MACs
        self.blocked_macs = list()
        # Mapping of MAC to IP address
        self.mac_ip_map = dict()
        log.info("Enabling L3 Firewall Module")

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        log.info("Connection Initialized")

    def _handle_PacketIn(self, event):
        # Parse the packet
        packet = event.parsed
        # Discard any packets from blocked MACs
        # This is useful in flood situation where many packets reach the controller before the OpenFlow rule reaches the switch
        if packet.src not in self.blocked_macs:
            # Only consider IP packets
            if packet.type == packet.IP_TYPE:
                # Check if this MAC has been registered
                if packet.src in self.mac_ip_map.keys():
                    # Check if the MAC has a new IP address, indicating DoS attack
                    if self.mac_ip_map[packet.src] != packet.payload.srcip:
                        log.info("Blocking MAC " + str(packet.src))
                        # Add MAC to block list
                        self.blocked_macs.append(packet.src)
                        # Create OpenFlow rule
                        msg = of.ofp_flow_mod()
                        # Set high priority block
                        msg.priority = BLOCK_PRIORITY
                        # Set the rule to expire after the switch doesn't recieve packets from this MAC for a given time
                        msg.idle_timeout = IDLE_TIMEOUT
                        # Match IP packets that have the corresponding source MAC in the Ethernet header
                        # Omitting an action is equivalent to dropping
                        msg.match = of.ofp_match(dl_type=pkt.ethernet.IP_TYPE, dl_src=packet.src)
                        # Notify the controller when the rule expires
                        # Used so the source MAC can be removed from the block list
                        msg.flags = of.OFPFF_SEND_FLOW_REM
                        # Send the rule to the switch
                        event.connection.send(msg)
                # The MAC hasn't been registered, create an OpenFlow rule for it
                else:
                    # Create OpenFlow rule
                    msg = of.ofp_flow_mod()
                    # Set low priority allow
                    msg.priority = ALLOW_PRIORITY
                    # Match packets based on this packet
                    msg.match = of.ofp_match.from_packet(packet, event.port)
                    # Set the rule to expire after the switch doesn't recieve packets from this MAC for a given time
                    msg.idle_timeout = IDLE_TIMEOUT
                    # Set the message data
                    msg.data = event.ofp
                    # Set the action to allow matching packets
                    msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
                    # Send the rule to the switch
                    event.connection.send(msg)
                    # Register the MAC
                    self.mac_ip_map[packet.src] = packet.payload.srcip
    
    def _handle_FlowRemoved(self, event):
        log.info("Unblocking MAC " + str(event.ofp.match.dl_src))
        # Remove the MAC from the block list to match the state of the OpenFlow rules in the switch
        self.blocked_macs.remove(event.ofp.match.dl_src)
        # Remove the MAC to IP mapping
        self.mac_ip_map.pop(event.ofp.match.dl_src)

def launch():
    # Register the Firewall module
    core.registerNew(Firewall)
