from CovertChannelBase import CovertChannelBase
from scapy.all import IP, sniff, ARP, LLC, UDP
import random

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        self.binary_message = ""
        self.encoding1 = [100,300,500,700,900]
        self.encoding0 = [200,400,600,800]

    def send(self, log_file_name, parameter1, parameter2):
        """
        - Generates a random binary message to send using covert channel techniques.
        - Uses the send() function from CovertChannelBase to transmit packets.
        - Logs the generated message to a file specified by log_file_name.
        """

        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        for bit in binary_message:
            rand_99 = random.randint(1, 99)
            ip_id = random.choice(self.encoding0) if bit == "0" else random.choice(self.encoding1)
            ip_id += rand_99
            packet = IP(id=ip_id, dst=parameter1)
            
            super().send(packet)

        print("Sender is finished!")

    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - Captures packets and decodes the binary message from the IP.id field.
        - Logs the decoded message to a file specified by log_file_name.
        """
    
        notSniffing = False
        def process_packet(packet):
            if packet.haslayer(IP) and packet[IP].dst == parameter1:
                ip_id = packet[IP].id
                decoded_ip = ip_id - (ip_id % 100 )
                
                if decoded_ip in self.encoding0:
                    self.binary_message += "0"
                elif decoded_ip in self.encoding1:
                    self.binary_message += "1"

                if len(self.binary_message) % 8 == 0:
                    char = self.convert_eight_bits_to_character(self.binary_message[-8:])
                    if char == ".":
                        
                        decoded_message = "".join(
                            self.convert_eight_bits_to_character(self.binary_message[i:i+8])
                            for i in range(0, len(self.binary_message), 8)
                        )
                        
                        self.log_message(
                            decoded_message,
                            log_file_name
                            )
                        raise StopIteration

        try:
            sniff(filter=f"ip dst {parameter1}", prn=process_packet, store=False)
        except StopIteration:
            pass


