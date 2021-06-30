#!/usr/bin/env python3

#Save the output from searching for SUID binaries:
#find / -perm -u=s -type f 2>/dev/null
#find / -user root -perm -4000 -print 2>/dev/null

import requests	#needed to inquire GTFObins latest list
from bs4 import BeautifulSoup	#needed to parse GTFObins HTML response
import sys	#needed for ingesting commandline arguments
import os.path
from os import path

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
response = requests.get('https://gtfobins.github.io/#+suid')

if response.status_code == 200:
	print("[+] Checking with gtfobins")
elif response.status_code == 404:
	print("[-] Unable to contact gtfobins")

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

print(gtfolist)

#Ingesting the file
with open(str(arg)) as f:
	lines = f.read().splitlines()

#read all the lines from the file
#check it against the database
for line in lines:
	binary = os.path.basename(line)
	if binary in gtfolist:
		print(binary)

