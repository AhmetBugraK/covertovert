from CovertChannelBase import CovertChannelBase
from scapy.all import IP, sniff
import random


class MyCovertChannel(CovertChannelBase):
    
    def __init__(self):
        super().__init__()
        self.binary_message = ""


    def send(self, destination, encoding0, encoding1, log_file_name):
        """
        - Generates a random binary message to send using covert channel techniques.
        - Uses the send() function from CovertChannelBase to transmit packets.
        - Logs the generated message to a file specified by log_file_name.
        """

        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        for bit in binary_message:
            rand_99 = random.randint(1, 99)
            ip_id = random.choice(encoding0) if bit == "0" else random.choice(encoding1)
            ip_id += rand_99
            packet = IP(id=ip_id, dst=destination)
            
            super().send(packet)



    def receive(self, destination, encoding0, encoding1, log_file_name):
        """
        - Captures packets and decodes the binary message from the IP.id field.
        - Logs the decoded message to a file specified by log_file_name.
        """
    
        def process_packet(packet):
            if packet.haslayer(IP) and packet[IP].dst == destination:
                ip_id = packet[IP].id
                decoded_ip = ip_id - (ip_id % 100 )
                
                if decoded_ip in encoding0:
                    self.binary_message += "0"
                elif decoded_ip in encoding1:
                    self.binary_message += "1"

                if len(self.binary_message) % 8 == 0:
                    char = self.convert_eight_bits_to_character(self.binary_message[-8:])
                    if char == ".":
                        
                        decoded_message = "".join(
                            self.convert_eight_bits_to_character(self.binary_message[i:i+8])
                            for i in range(0, len(self.binary_message), 8)
                        )
                        
                        self.log_message(decoded_message, log_file_name)
                        raise StopIteration

        try:
            sniff(filter=f"ip dst {destination}", prn=process_packet, store=False)
        except StopIteration:
            pass


