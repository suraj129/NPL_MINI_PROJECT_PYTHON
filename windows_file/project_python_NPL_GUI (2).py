
# coding: utf-8

# In[1]:

import Tkinter 
import socket, sys
from struct import *


# In[10]:

def main():
    
    master = Tkinter.Tk()
    master.title("Packet Deatils")
    master.geometry("400x200")
    
    tcp = 0
    udp = 1
    icmp = 2
    other = 3
    
    MyButton1 = Tkinter.Button(master, text="TCP PACKETS", width=25,height=2,bg='yellow', command=find_packet(tcp))
    MyButton1.grid(row=0, column=0)

    info = Tkinter.Label(master, text='')
    info.grid(row=0, column=2)

    MyButton2 = Tkinter.Button(master, text="UDP PACKETS", width=25,height=2, bg='yellow', command=find_packet(udp))
    MyButton2.grid(row=0, column=3)

    info = Tkinter.Label(master, text='')
    info.grid(row=1, column=0)

    MyButton3 = Tkinter.Button(master, text="ICMP PACKETS", width=25,height=2,bg='yellow',  command=find_packet(icmp))
    MyButton3.grid(row=2, column=0)

    info = Tkinter.Label(master, text='')
    info.grid(row=2, column=1)

    MyButton3 = Tkinter.Button(master, text="OTHER PACKETS", width=25,height=2,bg='yellow',  command=find_packet(other))
    MyButton3.grid(row=2, column=3)


    close = Tkinter.Button(master, text='Quit',bg='yellow',  command=master.destroy)
    close.grid(row=4, column=3)

    master.mainloop()        
main()


# In[3]:

def find_packet(a):
    print a
    


# In[4]:

def expolitaion(ip_address):
    
    pass


# In[5]:

def check_socket():
    try:
        s = socket.socket( socket.AF_INET, socket.SOCK_RAW , socket.ntohs(0x0003))
       
    except socket.error , msg:
        check_socket = Tkinter.Tk()
        check_socket.title("Socket Error !!")
        check_socket.geometry("300x100")
        info = Tkinter.Label(check_socket, text='Socket is Not Created')
        info.grid(row=0, column=1)
        retry = Tkinter.Button(check_socket, text='Retry', command=check_socket.destroy)
        retry.grid(row=1, column=2)
        close = Tkinter.Button(check_socket, text='Quit',  command=check_socket.destroy)
        close.grid(row=1, column=4)
        check_socket.mainloop()
check_socket()   


# In[6]:

import nmap


# In[7]:

def port_check(ip_address):                                                                     #Nmap used directly from python-nmap to generate a dictionary for port 25
    import subprocess,os,nmap
    ip_str = str(ip_address)
    nm = nmap.PortScanner()
    real_check = nm.scan(ip_address,'22-443')
    if real_check['scan'][ip_str]['tcp'] == 25:                                                 # Check for port 25 existence on the IP given
        if real_check['scan'][ip_str]['tcp'][25]['name'] == 'smtp':                             #Check for the Port 25 to be smtp and proceed if true
            print('True')
        else:
            print('False')
        if real_check['scan'][ip_str]['tcp'][25]['state'] == 'open':                            #Check for the Port 25 to be open and proceed if true
            print('True')
        else:
            print('False')
    else:
        print("Not possible")


# In[8]:

ip_address = "8.8.4.4"


# In[9]:

def fetch_ip():
    while True:
        try:
            import socket
            str = input("Enter the web address :")
            ip_add = socket.gethostbyname(str)
            return ip_add
        except socket.gaierror:
            print("Invalid Web address. Please Enter again!")


# In[ ]:

def eth_addr (a) :
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b

    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    loop=0
    # receive a packet
    while loop!=1:
        packet = s.recvfrom(65565)

        #packet string from tuple
        packet = packet[0]

        #parse ethernet header
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

        #Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8 :
            #Parse IP header
            #take first 20 characters for the ip header
            ip_header = packet[eth_length:20+eth_length]

            #now unpack them :)
            iph = unpack('!BBHHHBBH4s4s' , ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

            #TCP protocol
            if protocol == 6 :
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]

                #now unpack them :)
                tcph = unpack('!HHLLBBHHH' , tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]

                print "TCP PROtocol"

            #ICMP Packets
            elif protocol == 1 :
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]

                #now unpack them :)
                icmph = unpack('!BBH' , icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]

                print "ICMP protocol"

            #UDP packets
            elif protocol == 17 :
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u+8]

                #now unpack them :)
                udph = unpack('!HHHH' , udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]

                print "UDP protocol"

            #some other IP packet like IGMP
        else :
            print 'Protocol other than TCP/UDP/ICMP'
            print
        loop=loop+1 

