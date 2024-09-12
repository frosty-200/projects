class packet:
    def __init__(self, src_ip, dest_ip, src_port, dest_port, protocol):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol

    def __str__(self): # 
        return(f"{self.protocol} from {self.src_ip}: {self.src_port} to {self.dest_ip}: {self.dest_port}")

class rules: # establish the parameters for the packet, what each packet needs to have to make a request
    def __init__(self, src_ip, dest_ip, src_port, dest_port, protocol, action):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.action = action

    def matches(self, packet):
        # Check if both src_ip and dest_ip match exactly
        return (self.src_ip == packet.src_ip) and \
               (self.dest_ip == packet.dest_ip) and \
               (self.src_port == packet.src_port or self.src_port == "any") and \
               (self.dest_port == packet.dest_port or self.dest_port == "any") and \
               (self.protocol == packet.protocol or self.protocol == "any")

               
        # if self.src_ip.startswith("10") or packet.dest_ip.startswith("10"):
        #     return False
        # elif self.src_ip.startswith("192") and packet.dest_ip.startswith("192"):
        #     return True
        # elif self.src_ip.startswith("70") or packet.dest_ip.startswith("70"):
        #     return False  
        # return (self.src_ip == packet.src_ip or self.src_ip == "any") and\
        # (self.dest_ip == packet.dest_ip or self.dest_ip == "any") and\
        # (self.src_port == packet.src_port or self.src_port == "any") and\
        # (self.dest_port == packet.dest_port or self.dest_port == "any") and\
        # (self.protocol == packet.protocol or self.protocol == "any")
    
class Firewall:
    def __init__(self): # create empty rules and log lists, ready to be populated later
        self.rules = []
        self.log = []

    def add_rule(self, rule):
        self.rules.append(rule)

    def log_traffic(self,packet, action):  # tracks the action and packet that is passed
        self.log.append(f"{action.upper()}: {packet}")

    def process_packets(self,packet): # checks to see if the packets match the rules that have been set for the block or allow
        for rule in self.rules:
            if rule.matches(packet):
                self.log_traffic(packet, rule.action)
                return rule.action == "allow"
        self.log_traffic(packet, "block")
        return False

    def show_log(self): # simply shows the logs
        for event in self.log:
            print(event)



firewall = Firewall()

# Define some rules with strict IP matching
rule1 = rules("192.168.1.10", "192.168.1.20", "any", 80, "TCP", "allow")  # Only allows traffic from 192.168.1.10 to 192.168.1.20
rule2 = rules("10.0.0.1", "10.0.0.2", "any", "any", "UDP", "block")  # Blocks traffic only between 10.0.0.1 and 10.0.0.2

firewall.add_rule(rule1)
firewall.add_rule(rule2)

# Create packets
packet1 = packet("192.168.1.10", "192.168.1.20", 12345, 80, "TCP")  # Should match rule1 and be allowed
packet2 = packet("10.0.0.1", "10.0.0.2", 54321, 22, "UDP")  # Should match rule2 and be blocked
packet3 = packet("10.0.0.3", "192.168.1.1", 12345, 80, "TCP")  # Won't match any rule and should be blocked

# Process the packets
firewall.process_packets(packet1)
firewall.process_packets(packet2)
firewall.process_packets(packet3)

# Show the log
firewall.show_log()
