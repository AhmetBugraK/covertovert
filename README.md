# Covert Communication Channel Project  

## Project Description  
This project demonstrates the implementation of a covert communication channel between two containers using the Python Scapy module. The communication is achieved by encoding and decoding data in the `ID` field of IP packets, enabling a unidirectional covert channel. This method leverages the IP identification field to ensure data confidentiality.  

## Algorithm Explanation  
The covert communication channel works as follows:  

1. **Encoding at the Sender**  
   - The sender converts the text message into binary values.  
   - Each bit is transmitted as part of the `ID` field of an IP packet:  
     - If the bit is `1`, the IP identification field is set to a random value starting with numbers like `100`, `300`, `500` (e.g., `110`, `740`).  
     - If the bit is `0`, a random value starting with numbers like `200`, `400`, `600` is used.  
   - The sender logs the binary message being sent into a `.log` file for verification.  

2. **Decoding at the Receiver**  
   - The receiver extracts the `ID` field from the incoming IP packets.  
   - Values starting with `100`, `300`, or `500` are decoded as `1`.  
   - Values starting with `200`, `400`, or `600` are decoded as `0`.  
   - These binary values are grouped into 8-bit segments and converted back into the original text message.  
   - The receiver logs the decoded message into a separate `.log` file.  

This encoding/decoding scheme enables the transmission of one bit per packet.  

## Covert Channel Capacity  
The covert channel capacity was calculated using the following steps:  
1. A binary message of length `128` bits (16 characters) was prepared.  
2. The timer was started just before sending the first packet and stopped immediately after sending the last packet.  
3. The elapsed time was measured in seconds.  
4. The covert channel capacity was computed as:   
   `Covert Channel Capacity = 128 bits / Elapsed Time (seconds)`
5. The calculated covert channel capacity is: **12.03 bits/second**.  

## Log Files  
- **Sender Log**: Contains the binary message sent by the sender for verification.  
- **Receiver Log**: Contains the decoded message received for comparison and validation.  

These log files ensure the accuracy and reliability of the data transmission process.  

## Conclusion  
This project successfully establishes a covert communication channel using the IP identification field. The encoding and decoding algorithms effectively transmit data while maintaining confidentiality. The achieved covert channel capacity of **12.03 bits/second** demonstrates the efficiency of the implementation.  

---
