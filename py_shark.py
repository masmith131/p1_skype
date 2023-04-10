import pyshark


cap = pyshark.FileCapture('capture_appel1_skype_29-3-2023.pcapng')
count = 0

for i,packet in enumerate(cap):
    try: 
        if packet.dns.qry_name:
            count += 1
            print(packet.dns.qry_name)
            
            # Check if packet is DNS response and authoritative
            
            if packet.dns.flags.response == '1' and packet.dns.flags.auth == '1':
                print("Authoritative Name Servers for", packet.dns.qry_name)
                for ns in packet.dns.auth_ns:
                    print(ns)
                    
            #find out type of DNS query recursive, iterative or non
            
            

    except:
        pass 

print(count)
cap.close()


"""

cap = pyshark.FileCapture('capture_appel3_skype_29-3-2023.pcapng')
countcp = 0
countudp = 0
for i, packet in enumerate(cap):
    try:
        #find tcp packets
        if packet.tcp: 
            countcp += 1  
    except:
        pass
    try:
        if packet.udp:
            countudp += 1
    except:
        pass
    
print(countcp)
print(countudp)
"""