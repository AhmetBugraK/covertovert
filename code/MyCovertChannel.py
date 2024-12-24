from CovertChannelBase import CovertChannelBase
from scapy.all import IP, sniff
from scapy.all import ARP, LLC


class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()


    def send(self, log_file_name, parameter1, parameter2):
        """
        - Generates a random binary message to send using covert channel techniques.
        - Uses the send() function from CovertChannelBase to transmit packets.
        - Logs the generated message to a file specified by log_file_name.
        """
        # Generate random binary message and log it
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        # Send packets for each bit in the binary message
        for bit in binary_message:
            # Create a packet with IP.id set according to the bit
            ip_id = parameter2 if bit == "0" else parameter2 + 1
            packet = IP(id=ip_id, dst=parameter1)
            
            # # Paket üzerinde hangi katmanların olduğunu kontrol et ve yazdır
            # if packet.haslayer(ARP):
            #     print("Packet has ARP layer")

            # if packet.haslayer(IP):
            #     print("Packet has IP layer")

            # if packet.haslayer(LLC):
            #     print("Packet has LLC layer")
            
            
            super().send(packet)
            print(f"Sent packet with IP.id={ip_id} for bit={bit}")

        print("Sender is finished!")


    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - Captures packets and decodes the binary message from the IP.id field.
        - Logs the decoded message to a file specified by log_file_name.
        """

        binary_message = ""

        def process_packet(packet):
            nonlocal binary_message
            if IP in packet and packet[IP].dst == parameter1:
                ip_id = packet[IP].id
                if ip_id == parameter2:
                    binary_message += "0"
                elif ip_id == parameter2 + 1:
                    binary_message += "1"

                # Stop receiving when the stop character is decoded
                if len(binary_message) % 8 == 0:  # Check every 8 bits
                    char = self.convert_eight_bits_to_character(binary_message[-8:])
                    if char == ".":
                        raise StopIteration

        try:
            sniff(filter=f"ip dst {parameter1}", prn=process_packet, store=True)
        except StopIteration:
            pass

        # Convert the binary message to a readable string
        decoded_message = "".join(
            self.convert_eight_bits_to_character(binary_message[i:i+8])
            for i in range(0, len(binary_message), 8)
        )

        # Log the received message
        self.log_message(decoded_message, log_file_name)
        print("Receiver is finished!")


