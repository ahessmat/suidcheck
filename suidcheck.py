#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup

response = requests.get('https://gtfobins.github.io/#+suid')

if response.status_code == 200:
	print("[+] Checking with gtfobins")
elif response.status_code == 404:
	print("[-] Unable to contact gtfobins")

soup = BeautifulSoup(response.text, 'html.parser')

#find all of the html href tags that contain #suid or #limited-suid
#ex: /gtfobins/cupsfilter/#suid
#Then filter out the path before/after the vulnerable binary
#ex: cupsfilter
for tag in soup.find_all('a', href=True):
	if tag['href'].endswith('suid') and tag['href'][0] != '#':
		suid = tag['href']
		suid = suid[10:]
		entry = suid.split("/",1)
		print(entry[0])
