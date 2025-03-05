class FirewallRule:
    def __init__(self, rule_type, source_ip=None, dest_ip=None, source_port=None, dest_port=None, protocol=None):
        self.rule_type = rule_type  # 'ALLOW' or 'BLOCK'
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.protocol = protocol

    def matches(self, packet):
        """Checks if the packet matches the rule."""
        if self.source_ip and self.source_ip != packet.source_ip:
            return False
        if self.dest_ip and self.dest_ip != packet.dest_ip:
            return False
        if self.source_port and self.source_port != packet.source_port:
            return False
        if self.dest_port and self.dest_port != packet.dest_port:
            return False
        if self.protocol and self.protocol != packet.protocol:
            return False
        return True


class Packet:
    def __init__(self, source_ip, dest_ip, source_port, dest_port, protocol):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.protocol = protocol


class Firewall:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule):
        """Adds a new rule to the firewall."""
        self.rules.append(rule)

    def process_packet(self, packet):
        """Process an incoming packet based on the rules."""
        for rule in self.rules:
            if rule.matches(packet):
                if rule.rule_type == 'BLOCK':
                    print(f"Packet from {packet.source_ip}:{packet.source_port} to {packet.dest_ip}:{packet.dest_port} blocked.")
                    return "Blocked"
                elif rule.rule_type == 'ALLOW':
                    print(f"Packet from {packet.source_ip}:{packet.source_port} to {packet.dest_ip}:{packet.dest_port} allowed.")
                    return "Allowed"
        # If no rule matches, block the packet by default
        print(f"Packet from {packet.source_ip}:{packet.source_port} to {packet.dest_ip}:{packet.dest_port} blocked (default).")
        return "Blocked"


# --- Example usage ---

# Initialize a firewall
firewall = Firewall()

# Define some rules for the firewall
firewall.add_rule(FirewallRule('ALLOW', source_ip='192.168.1.50', dest_port=80))  # Allow HTTP requests from 192.168.1.50
firewall.add_rule(FirewallRule('BLOCK', source_ip='192.168.1.100'))  # Block traffic from 192.168.1.100
firewall.add_rule(FirewallRule('ALLOW', dest_port=443))  # Allow HTTPS traffic on port 443
firewall.add_rule(FirewallRule('BLOCK', source_port=22))  # Block SSH traffic (port 22)

# Simulate some network packets
packets = [
    Packet('192.168.1.50', '192.168.1.100', 12345, 80, 'TCP'),  # HTTP request from 192.168.1.50
    Packet('192.168.1.100', '192.168.1.50', 54321, 80, 'TCP'),  # HTTP request from 192.168.1.100 (should be blocked)
    Packet('192.168.1.50', '192.168.1.100', 12345, 443, 'TCP'),  # HTTPS request from 192.168.1.50
    Packet('192.168.1.50', '192.168.1.100', 12345, 22, 'TCP'),   # SSH request (should be blocked)
    Packet('10.0.0.1', '10.0.0.2', 56789, 8080, 'TCP'),  # Random TCP request (default block)
    Packet('172.16.0.5', '172.16.0.10', 34567, 443, 'TCP'),  # HTTPS request (should be allowed)
    Packet('192.168.2.3', '192.168.2.4', 11111, 53, 'UDP'),  # DNS request (default block)
]

# Process the packets through the firewall
for packet in packets:
    firewall.process_packet(packet)
