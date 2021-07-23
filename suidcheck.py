#!/usr/bin/env python3

#Save the output from searching for SUID binaries:
#find / -perm -u=s -type f 2>/dev/null
#find / -user root -perm -4000 -print 2>/dev/null

import requests	#needed to inquire GTFObins latest list
from bs4 import BeautifulSoup	#needed to parse GTFObins HTML response
import sys	#needed for ingesting commandline arguments
import os.path
from os import path

IBlack="\033[0;90m"       # Black
IRed="\033[0;91m"         # Red
IGreen="\033[0;92m"       # Green
IYellow="\033[0;93m"      # Yellow
IBlue="\033[0;94m"        # Blue
IPurple="\033[0;95m"      # Purple
ICyan="\033[0;96m"        # Cyan
IWhite="\033[0;97m"       # White


banner  = IBlue + "████████████████████████████████████████████████████\n"
banner += ICyan + "█─▄▄▄▄█▄─██─▄█▄─▄█▄─▄▄▀█─▄▄▄─█─█─█▄─▄▄─█─▄▄▄─█▄─█─▄█\n"
banner += ICyan + "█▄▄▄▄─██─██─███─███─██─█─███▀█─▄─██─▄█▀█─███▀██─▄▀██\n"
banner += IWhite + "▀▄▄▄▄▄▀▀▄▄▄▄▀▀▄▄▄▀▄▄▄▄▀▀▄▄▄▄▄▀▄▀▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀\n"

print(banner)

#Default binaries found on UNIX
#Pulled from suid3num
defaults = ["arping", "at", "bwrap", "chfn", "chrome-sandbox", "chsh", "dbus-daemon-launch-helper", "dmcrypt-get-device", "exim4", "fusermount", "gpasswd", "helper", "kismet_capture", "lxc-user-nic", "mount", "mount.cifs", "mount.ecryptfs_private", "mount.nfs", "newgidmap", "newgrp", "newuidmap", "ntfs-3g", "passwd", "ping", "ping6", "pkexec", "polkit-agent-helper-1", "pppd", "snap-confine", "ssh-keysign", "su", "sudo", "traceroute6.iputils", "ubuntu-core-launcher", "umount", "VBoxHeadless", "VBoxNetAdpCtl", "VBoxNetDHCP", "VBoxNetNAT", "VBoxSDL", "VBoxVolInfo", "VirtualBoxVM", "vmware-authd", "vmware-user-suid-wrapper", "vmware-vmx", "vmware-vmx-debug", "vmware-vmx-stats", "Xorg.wrap"]

def overhead():
	#Error messaging in case there isn't a proper number of arguments
	if len(sys.argv) != 2:
		print("Improper number of arguments")
		sys.exit(0)
	else:
		#check if the argument passed is a file
		existCheck = path.exists(sys.argv[1])
		if existCheck == False:
			print("[-] Specified file '" + str(sys.argv[1]) + "' does not exist")
			sys.exit(0)
		fileCheck = path.isfile(sys.argv[1])
		if fileCheck == False:
			print("[-] Specified file '" + str(sys.argv[1]) + "' is not a file")
			sys.exit(0)

arg = sys.argv[1]
overhead()
print("[+] Checking with gtfobins")
response = requests.get('https://gtfobins.github.io/#+suid')

if response.status_code == 200:
	print("[+] Parsing gtfobins results")
elif response.status_code == 404:
	sys.exit("[-] Unable to contact gtfobins")

soup = BeautifulSoup(response.text, 'html.parser')

gtfolist = {}

#find all of the html href tags that contain #suid
#ex: /gtfobins/cupsfilter/#suid
#Then filter out the path before/after the vulnerable binary
#ex: cupsfilter
for tag in soup.find_all('a', href=True):
	if tag['href'].endswith('#suid') and tag['href'][0] != '#':
		suid = tag['href']
		suid = suid[10:]
		entry = suid.split("/",1)
		gtfolist[str(entry[0])] = "suid"
		#print(entry[0])

#print(gtfolist)

#Ingesting the file
with open(str(arg)) as f:
	lines = f.read().splitlines()

#read all the lines from the file
#check it against the database
print()
print(IRed + "SUID binaries discovered!")
for line in lines:
	binary = os.path.basename(line)
	if binary in gtfolist:
		print(IWhite + binary)

print()
print(IGreen + "These binaries are installed on linux by default")
for line in lines:
	binary = os.path.basename(line)
	if binary in defaults:
		print(IWhite + binary)

