

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

class ActLikeSwitch(DynamicPolicy):
    def __init__(self):
        super(ActLikeSwitch, self).__init__()
        # Set up the initial forwarding behavior for your mac learning switch to flood 
        # all packets
        self.forward = flood()

        # Set up a query that will receive new incoming packets
        self.query = packets(limit=1,group_by=['srcmac','switch'])
        # Set the initial internal policy value (each dynamic policy has a member 'policy'
        # when this member is assigned, the dynamic policy updates itself)
        self.policy = self.forward + self.query
        
        self.query.register_callback(self.learn_from_a_packet)

    def learn_from_a_packet(self, pkt):
        # Set the forwarding policy
        self.forward = if_(match(dstmac=pkt['srcmac'],
                                 switch=pkt['switch']), fwd(pkt['inport']),
                           self.forward)  
        # Update the policy
        self.policy = self.forward + self.query 
        print self.policy 

    
def main():
    return ActLikeSwitch()
