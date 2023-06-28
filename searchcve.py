# search and verify for common vulnerabily exposure to see what exploit his needed... for educational purposes only
# searchcve v4.5
import requests
import re 
from colorama import Fore
import os
import sys
import time

# app colors
error = Fore.RED
success = Fore.GREEN
white = Fore.WHITE
ready = Fore.YELLOW
blue = Fore.BLUE



if os.name == 'posix':
   os.system('clear')

print(ready+'\n[+] SearchCVE - Running...\n'+white)
print(success+'[+] Created By Gospel Chukwunonso\n'+white)

def usage():
    print(ready+'\n[*] Usage - python searchcve.py [cve name]\n'+white)

if len(sys.argv) == 2:
   pass
else:
   usage()
   exit(0)

cve_name = sys.argv[1]

cve_info = f'https://cveawg.mitre.org/api/cve/{cve_name}'

data = requests.get(cve_info).text

strdt = eval(data)

if 'error' in strdt:
   print(error+'[+] CVE Is Invalid...\n'+white)
   exit(0)

print(ready+f'[+] Searching {cve_name} Details...\n'+white)
time.sleep(3)

if "affected" in strdt:
   print(error+'[+] [CRITICAL] - CVE Is Likely To Be Affected'+white)

aff = strdt['containers']['cna']['affected']

for itm in aff:
    print(blue+f"[-] [ * PRODUCT * ]: {itm['product']}\n"+white)
    print(blue+f"[-] [ * VENDOR * ]: {itm['vendor']}\n"+white)
    for oth in itm['versions']:
        print(blue+f'[-] [ * STATUS * ]: {oth["status"]}\n'+white)
        print(blue+f'[-] [* VERSION * ]: {oth["version"]}\n'+white)
        for dta in strdt['containers']['cna']['descriptions']:
            print(ready+'[-CVE Description-]\n'+white)
            print(blue+f'[+] {dta["value"]} \n'+white)
