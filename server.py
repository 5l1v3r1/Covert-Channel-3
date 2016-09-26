'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    server.py
--
--  PROGRAM:        listens for packets being sent with covert data in ttl field
--
--  FUNCTIONS:      readMessage(packet)
--
--  DATE: September 24, 2016
--
--  REVISIONS: September 25, 2016
--
--  DESIGNERS: Kyle Gilles
--
--  NOTES:
--  Filters for packets being sent with a specific window size.
--  Assembles a message in bits based on the ttl field of said packets. After receiving
--  the conclusive packet, converts the bits to a readable message.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
#!/usr/bin/env python
import sys
from scapy.all import *

#initialize global variables
bitMessage="";
message ="";

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       readMessage
--  Parameters:
--      packet
--          lets function know we are sniffing for ip and tcp packets
--  Return Values:
--      none
--  Description:
--      sniff for packets, filtering for windowsize. A match either appends a bit to
--      a message array or tells us the transmission is complete. At this time, it converts
--      the bits to a string message and prints it.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def readMessage(packet):
    sourceIp = packet[IP].src
    ttl = packet[IP].ttl
    window = packet['TCP'].window
    global bitMessage
    global message

    # window size of 14000 determines a message packet was received.
    # the ttl field determines the bit
    if window == 14000:
        if ttl == 64:
            bitMessage+="0"
        elif ttl ==128:
            bitMessage+="1"
    #window size of 10000 determines message has been transmitted
    elif window ==10000:

        #group bits into groups of 7, each group resembles an ascii character
        messageArray=[bitMessage[i:i+7] for i in range (0, len(bitMessage), 7)]
        for character in messageArray:

            #convert the bits into a string and print
            message += str(chr(int(character, 2)))
        print message

if __name__ == '__main__':
    sniff(filter="ip and tcp", prn=readMessage)
