# ==============================================================================
class Host:
    def __init__(self, mac, ipv4, timestamp, name="", known=False):
        self.mac        = mac
        self.ipv4       = ipv4
        self.timestamp  = timestamp
        self.name       = name
        self.known      = known

# ==============================================================================