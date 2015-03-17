Python porting of winpcap - pcap exported functions using ctypes.

No automatic install. Copy winpcapy.py into your site-packages dir.

Some examples are in the examples directory.
Get documentation about functions from official winpcap site

## Python version of winpcap sendpack example: ##
```
from ctypes import *
from winpcapy import *

fp=pcap_t
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
packet=(c_ubyte * 100)()
## Check the validity of the command line
if len(sys.argv) != 2:
    print ("usage: %s interface" % sys.argv[0])
    sys.exit(1)
## Open the adapter
fp = pcap_open_live(sys.argv[1],65536,PCAP_OPENFLAG_PROMISCUOUS ,1000,errbuf)
if not bool(fp):
    print ("\nUnable to open the adapter. %s is not supported by WinPcap\n" % sys.argv[1])
    sys.exit(2)
## Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1
packet[0]=1
packet[1]=1
packet[2]=1
packet[3]=1
packet[4]=1
packet[5]=1
## set mac source to 2:2:2:2:2:2
packet[6]=2
packet[7]=2
packet[8]=2
packet[9]=2
packet[10]=2
packet[11]=2

## Fill the rest of the packet
for i in range(12,100):
    packet[i]=i
## Send down the packet
if (pcap_sendpacket(fp,packet,100) != 0):
    print ("\nError sending the packet: %s\n" % pcap_geterr(fp))
    sys.exit(3)
pcap_close(fp)
sys.exit(0)
```



## Python version of winpcap basic dump example: ##

```
from ctypes import *
from winpcapy import *
import time
import sys
import string
import platform

if platform.python_version()[0] == "3":
	raw_input=input
#/* prototype of the packet handler */
#void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
PHAND=CFUNCTYPE(None,POINTER(c_ubyte),POINTER(pcap_pkthdr),POINTER(c_ubyte))

## Callback function invoked by libpcap for every incoming packet
def _packet_handler(param,header,pkt_data):
	## convert the timestamp to readable format
	local_tv_sec = header.contents.ts.tv_sec
	ltime=time.localtime(local_tv_sec);
	timestr=time.strftime("%H:%M:%S", ltime)
	print
	print("%s,%.6d len:%d" % (timestr, header.contents.ts.tv_usec, header.contents.len))

packet_handler=PHAND(_packet_handler)
alldevs=POINTER(pcap_if_t)()
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
## Retrieve the device list
if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
	print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
	sys.exit(1)
## Print the list
i=0
try:
	d=alldevs.contents
except:
	print ("Error in pcap_findalldevs: %s" % errbuf.value)
	print ("Maybe you need admin privilege?\n")
	sys.exit(1)
while d:
	i=i+1
	print("%d. %s" % (i, d.name))
	if (d.description):
		print (" (%s)\n" % (d.description))
	else:
		print (" (No description available)\n")
	if d.next:
		d=d.next.contents
	else:
		d=False

if (i==0):
	print ("\nNo interfaces found! Make sure WinPcap is installed.\n")
	sys.exit(-1)
print ("Enter the interface number (1-%d):" % (i))
inum= raw_input('--> ')
if inum in string.digits:
	inum=int(inum)
else:
	inum=0
if ((inum < 1) | (inum > i)):
	print ("\nInterface number out of range.\n")
	## Free the device list
	pcap_freealldevs(alldevs)
	sys.exit(-1)
## Jump to the selected adapter
d=alldevs
for i in range(0,inum-1):
	d=d.contents.next
## Open the device 
## Open the adapter
d=d.contents
adhandle = pcap_open_live(d.name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,errbuf)
if (adhandle == None):
	print("\nUnable to open the adapter. %s is not supported by Pcap-WinPcap\n" % d.contents.name)
	## Free the device list
	pcap_freealldevs(alldevs)
	sys.exit(-1)
print("\nlistening on %s...\n" % (d.description))
## At this point, we don't need any more the device list. Free it
pcap_freealldevs(alldevs)
## start the capture (we take only 15 packets)
pcap_loop(adhandle, 15, packet_handler, None)
pcap_close(adhandle)
```