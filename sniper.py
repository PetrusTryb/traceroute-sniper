import random
from scapy.all import *
import socket
import struct
import os
from multiprocessing import Process

OUTPUT_FILE = "sniper_output.csv"
DEEP_SCAN_THRESHOLD = 15
THRESHOLD = 20

def threaded():
	while (1):
		random_ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
		trace_results,_ = traceroute(random_ip, maxttl=25, verbose=0, timeout=2, l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname="www.google.com")))
		count = len(set([x[1].src for x in trace_results]))
		if(len(trace_results)==0):
			continue
		if(count>DEEP_SCAN_THRESHOLD):
			print(" (deep scan) ", end="")
			trace_results,_ = traceroute(random_ip, maxttl=255, verbose=0, timeout=5, retry=3, l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname="www.google.com")))
		if(count<DEEP_SCAN_THRESHOLD):
			continue
		print(random_ip, count, end="")
		if(trace_results[-1][-1].src == random_ip):
			print(" [OK]", end="")
		else:
			print(" ", end="")
		if count > THRESHOLD:
			print(trace_results)
			print(" - Found!", end="")
		print("")

if __name__ == "__main__":
	num_threads = 32
	threads = []
	for i in range(num_threads):
		t = Process(target=threaded)
		t.start()
		threads.append(t)
	for t in threads:
		t.join()
	threaded()