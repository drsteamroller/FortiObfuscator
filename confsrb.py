#!/usr/bin/env python3
# Author: Andrew McConnell
# Date: 03/15/2023

import re
import random
import sys

# Global Variables
contents = []
og_filename = 0
str_repl = dict()
ip_repl = dict()
modifiers = []

#REGEX ----> Use "group" function to select the part that matches https://docs.python.org/3/library/re.html#match-objects
ipaddr4 = r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
ipaddr6 = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

# Helper Functions
def isRFC1918(ip):
    a,b,c,d = ip.split('.')

    # Very explicitly checks if the addresses are RFC 1918 Class A/B/C addresses
    if (int(a) == 10):
        return(True)
    elif(int(a) == 172 and int(b) in range(16,32)):
        return(True)
    elif(int(a) == 192 and int(b) == 168):
        return(True)
    else:
        return(False)

# a more granular check
def isValidIP6(addr):
	if type(addr) == bytes:
		addr = str(addr)[2:-1]
	
	maxcol = 7
	mincol = 2
	countcol = 0
	maxnums = 4
	countnums = 0
	validchars = re.compile(r'[A-Fa-f0-9:]')

	for num in addr:
		ch = validchars.search(num)
		if not ch:
			return False
		
		if num in ':':
			countcol += 1
			if countnums > maxnums:
				return False
			countnums = 0
		else:
			countnums += 1

	if countcol < mincol or countcol > maxcol:
		return False

	return True

'''
How it works:
1) Split the IP into a list of 4 numbers (we assume IPv4)
  a) expect_0 is set to True when we view a shift in 1's to 0's                                V We set it to True so if there's a '1' after a '0', it's not a net_mask
                                                    ===> 255.255.240.0 = 11111111.11111111.11110000.00000000
  b) constant is a catch-all for when we detect it isn't (or is!!!) a net_mask, and we return it accordingly

2) We take each value in the ip_list and check if it's non zero
  a) If it's non zero, we subtract 2^i from that value where i is a list from 7 to 0 (decremented).
    i) If the value hits zero during this process and i is not zero, set expect_0 to True and break out of the process [val is zero so we don't need to subtract any more]
    ii) If the value hits zero during the process and i IS zero (255 case), we continue to the next value
    ###### IF AT ALL DURING THIS PROCESS THE VALUE GOES BELOW ZERO, WE SET constant = False AND BREAK AND 'return constant' ######
  b) If the value starts out as zero, we don't bother with the process and just set expect_0 to True (catches 255.0.255.0 and similar cases)
'''
def isNetMask(ip):
    _ = ip.split('.')
    ip_list = list()
    for item in _:
        ip_list.append(int(item))

    # Return false for quad 0 case (default routes)
    if (ip_list == [0,0,0,0]):
        return False

    # Netmasks ALWAYS start with 1's
    expect_0 = False
    # We start out assuming constancy
    constant = True

    for val in ip_list:
        if (val != 0):
            for i in range(7, -1, -1):
                val = val - pow(2, i)
                if (val > 0 and not expect_0):
                    continue
                elif (val == 0  and i != 0):
                    expect_0 = True
                    break
                elif (val == 0 and not expect_0 and i == 0):
                    break
                else:
                    constant = False
                    break
            if (not constant):
                break
        else:
            expect_0 = True
    return constant

# Replaces IP addresses
def replace_ip4(ip):
    if (isNetMask(ip)):
        return ip
    if (ip not in ip_repl.keys()):
        repl = ""
        if (isRFC1918(ip) and "-privateips" not in modifiers and "-allips" not in modifiers):
            octets = ip.split('.')
            repl = f"{octets[0]}.{octets[1]}.{random.randrange(0, 256)}.{random.randrange(1, 256)}"
        elif (not isRFC1918(ip) and "-allips" not in modifiers):
            repl = f"{random.randrange(1, 255)}.{random.randrange(0, 255)}.{random.randrange(0, 255)}.{random.randrange(1, 255)}"
        else:
            repl = ip
        ip_repl[ip] = repl
        return repl
    
    # If we've replaced it before, pick out that replacement and return it
    else:
        return ip_repl[ip]

def replace_ip6(ip):

    if not isValidIP6(ip):
         return ip

    if (ip not in ip_repl.keys() and "-allips" not in modifiers):
        repl = f'{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}'
        ip_repl[ip] = repl
        return repl
    elif ("-allips" not in modifiers):
        return ip_repl[ip]
    else:
        return ip

def replace_str(s):
    if s in str_repl.keys():
        return str_repl[s]

    repl = ""
    for ch in s:
        c = 0
        if (random.random() > .5):
            c = chr(random.randint(65,90))
        else:
            c = chr(random.randint(97, 122))

        repl += c

    str_repl[s] = repl

    return repl

# Program Functions
def listOptions():
    print("\nhelp = list this output\n\
          load <file_path> = input file to be obfuscated\n\
          map = Show mapped addresses, only after 'obf' is run\n\
          writemap = Write the output of the map command to a text file\n\
          importmap <filename> = Import mapfile that was output from FortiObfuscate.py or another FFI program\n\
          export = export file\n\
          show = view contents file contents\n\
          obf = begin obfuscation with enabled settings\n\
          mods = show modifiers\n")

def listModifiers():
    print("\nExclude from replacement:\n-privateips\n-allips\n-vpntunnels\n-snmpcommunities\t<-affects both snmpv2c & v3\n\n+clear\t<- Clear modifiers")

# Load a configuration file into a list and return the list
def load(filename):
    c = ""
    contents.clear()
    cl_repl = input("\nClear IP map? (Choose 'y' if this is a different site's FortiGate. If the new loaded config is from the same site (therefore, the same private ips), then choose 'n')\n (y, N)> ")
    if (cl_repl == 'y'):
        ip_repl.clear()
    try:
        fl = open(filename, 'r')
        c = fl.readlines()
        fl.close()
    except:
        print("\nSomething when wrong, try full file path\n")
    
    return c

# Troubleshooting command to show the contents of what was loaded
def show():
    print(contents)

# Exports file that was loaded (pre or post obfuscation)
def export():
    new_filename = ""
    if (not og_filename):
        new_filename = input("No filename detected, what do you want the filename to be? > ")
    else:
        b, ext = og_filename.split('.')
        new_filename = (b + "_obfuscated." + ext)
    with open(new_filename, 'w') as outfl:
        outfl.writelines(contents)
    print("\nSuccessfully written to: {}\n".format(new_filename))

def showMap(op):
    if (not ip_repl):
        print("\nYou haven't obfuscated a configuration file yet\n")
        return

    ipv4s = "\t===>>> IPv4 ADDRESSES <<<===\nOriginal -> Replacement\n"
    ipv6s = "\t===>>> IPv6 ADDRESSES <<<===\nOriginal -> Replacement\n"
    
    for k, v in ip_repl.items():
        if len(v) > 15:
            ipv6s += f"{k} -> {v}\n"
        else:
            ipv4s += f"{k} -> {v}\n"
    sep = '=' * 50

    if (op == "p"):
        print(f"{ipv4s}\n{sep}\n{ipv6s}")
        return
    elif (op == "w"):
        with open(f"config_mapping.txt", 'w') as vi:
            vi.write("+---------- MAPPED IP ADDRESSES ----------+\n")
            for og, rep in ip_repl.items():
                vi.write(f"Original IP: {og}\nMapped IP: {rep}\n\n")
            vi.write("+---------- MAPPED MAC ADDRESSES ---------+\n\n")

            vi.write("+---------- MAPPED STRING VALUES ---------+\n")
            for og, rep in str_repl.items():
                vi.write(f"Original String: {og}\nMapped String: {rep}\n\n")
        print(f"\nMap file written to {og_filename}_ipmapping.txt\n")
    else:
        print("\nUnknown option\n")

def importMap(filename):
	lines = []
	with open(filename, 'r') as o:
		lines = o.readlines()
	
	print(lines)

	imp_ip = False
	imp_mac = False
	imp_str = False

	OG = ""
	for l in lines:
		if '+---' in l:
			if 'IP' in l:
				imp_ip = True
				imp_mac = False
				imp_str = False
			elif 'MAC' in l:
				imp_ip = False
				imp_mac = True
				imp_str = False
			elif 'STRING' in l:
				imp_ip = False
				imp_mac = False
				imp_str = True
			else:
				print("Map file is improperly formatted, do not make changes to the map file unless you know what you are doing")
				sys.exit(1)
			continue

		if not len(l):
			continue

		if imp_ip:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1].strip()
			else:
				ip_repl[OG] = components[1].strip()
				OG = ""
		elif imp_mac:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1].strip()
			else:
				#mac_repl[OG] = components[1]
				OG = ""
		elif imp_str:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1].strip()
			else:
				str_repl[OG] = components[1].strip()
				OG = ""
		
		else:
			print("Something went wrong, mappings might not be fully imported\n")
			print(f"Interpreted mappings based on import\nIP Mapping: {ip_repl}\nMAC Mapping:\nString Mapping: {str_repl}\n")


# Obfuscation main fuction
def obfuscate():

    # If no file loaded, prompt to load a file
    if (not contents):
        return("\nYou need to load a file first\n")

    ## FOR LOOP EXT VARS ##
    # Compile the regex found at the top of this program
    is_ip4 = re.compile(ipaddr4)
    is_ip6 = re.compile(ipaddr6, re.MULTILINE)

    # Flags to look for "edit <name>" within snmp/vpn config
    SNMP = False
    SNMP_HOSTS = False
    IPSEC_P1 = False
    IPSEC_P2 = False

    # Handle naming of snmp and vpn replacement names

    # Debugging
    x = ""

    # Parse through the list containing the lines of the configuration file
    for i, content in enumerate(contents):

        # Record the number of leading spaces, so we aren't having awkward lines that aren't in-line
        leading = " " * re.search('\S', content).start()
        
        # If we see 'set hostname' or 'set alias', replace those with 'US Federal Customer'
        if ("set hostname" in content or "set alias" in content or "description" in content):
            l = content.strip().split(" ")
            name = replace_str(l[2])
            l[2] = f"US_Fed_Cx_{name}\n"
            content = leading + "{} {} {}".format(l[0], l[1], l[2])
        
        # If we see an IP address, check if it's public, and if so, replace it
        if (is_ip4.search(content)):
            g = content.strip().split(" ")
            if (len(g) == 3):
                if ('"' in g[2]):
                    g[2] = g[2][1:-1]
                g[2] = replace_ip4(g[2])
            elif (len(g) > 3):
                for b, ip in enumerate(g[2:]):
                    g[b + 2] = replace_ip4(ip)

            leading += " ".join(g)
            content = leading + "\n"

        elif (is_ip6.search(content)):
            g = content.strip().split(" ")
            if (len(g) == 3):
                if ('"' in g[2]):
                    g[2] = g[2][1:-1]
                if ('/' in g[2]):
                    g[2] = replace_ip6(g[2].split('/')[0]) + g[2].split('/')[1]
                else:
                    g[2] = replace_ip6(g[2])
            elif (len(g) > 3):
                for b, ip in enumerate(g):
                    g[b + 2] = replace_ip6(ip)

            leading += " ".join(g)
            content = leading + "\n"
        
        ### SNMP Communities ###
        if ("-snmpcommunities" in modifiers):
            if ("config system snmp community" in content or "config system snmp user" in content):
                SNMP = True
            
            if (not SNMP_HOSTS and SNMP and "edit" in content):
                s = content.strip().split(" ")
                if (len(g) > 1):
                    name = s[1]
                    s[1] = f'fed_snmp_comm_{replace_str(name)}'
                
                leading += " ".join(s)
                content = leading + "\n"

            if (SNMP and "config hosts" in content):
                SNMP_HOSTS = True

            if (SNMP_HOSTS and "edit" in content):
                s = content.strip().split(" ")
                if (len(g) > 1):
                    name = s[1]
                    s[1] = f'fed_snmp_comm_{replace_str(name)}'

                leading += " ".join(s)
                content = leading + "\n"

            if (SNMP and "name" in content):
                s = content.strip().split(" ")
                leading += f'{s[0]} {s[1]} FED_SNMP_Community\n'
                content = leading

            if (SNMP_HOSTS and "end" in content):
                SNMP_HOSTS = False
            
            if (not SNMP_HOSTS and SNMP and "end" in content):
                SNMP = False
        
        ### VPN Tunnel Names ###
        if ("-vpntunnels" not in modifiers):
            if ("config vpn ipsec phase1-interface" in content):
                IPSEC_P1 = True

            if ("config vpn ipsec phase2-interface" in content):
                IPSEC_P2 = True

            if (IPSEC_P1 and "set remotegw-ddns" in content):
                v = content.strip().split(" ")
                
                repl = f'{replace_str(v[2])}.net'
                
                leading += f'{v[0]} {v[1]} {repl}\n'
                content = leading

            if (IPSEC_P1 and "edit" in content):
                v = content.strip().split(" ")
                repl = f'vpn_p1_{replace_str(v[1])}'

                leading += f"{v[0]} {repl}\n"
                content = leading
                
            if (IPSEC_P2 and "edit" in content):
                v = content.strip().split(" ")
                repl = f'vpn_p2_{replace_str(v[1])}'

                leading += f"{v[0]} {repl}\n"
                content = leading
            
            if (IPSEC_P2 and "set phase1name" in content):
                v = content.strip().split(" ")
                repl = replace_str(v[2])
                
                leading += f"{v[0]} {v[1]} {repl}\n"
                content = leading

            if (IPSEC_P1 and "end" in content):
                IPSEC_P1 = False

            if (IPSEC_P2 and "end" in content):
                IPSEC_P2 = False

        contents[i] = content

    return("\nOperation was successful\n")

print("\n\n::::::::::  ::::::::  :::::::::  ::::::::::                           :::::::::: :::::::::: :::::::::  \n" +
        ":+:        :+:    :+: :+:    :+: :+:                                  :+:        :+:        :+:    :+: \n" +
        "+:+        +:+    +:+ +:+    +:+ +:+                                  +:+        +:+        +:+    +:+ \n" +
        ":#::+::#   +#+    +:+ +#++:++#+  :#::+::#         +#++:++#++:++       :#::+::#   +#++:++#   +#+    +:+ \n" +
        "+#+        +#+    +#+ +#+    +#+ +#+                                  +#+        +#+        +#+    +#+ \n" +
        "#+#        #+#    #+# #+#    #+# #+#                                  #+#        #+#        #+#    #+# \n" +
        "###         ########  #########  ###                                  ###        ########## #########  \n")

print("______________________________________________________________________________________________________")
print("\nFortiObfuscate - Mask hostname, IP addresses, Usernames, VPN tunnels, SNMP communities, etc.\n*Under Construction\n")

# user input
uin = input("--> ")

# While the user inputted option is not 'q', 'u', 'i', 't' or a combination of those letters
while (uin not in 'quit'):

    # Do the option chosen by the user
    if ("load" in uin):
        og_filename = uin.split(" ")[1]
        contents = load(og_filename)
    elif (uin in "show"):
        show()
    elif (uin in "map"):
        showMap("p")
    elif (uin in "export"):
        export()
    elif (uin in "obf"):
        print(obfuscate())
    elif (uin in "mods"):
        listModifiers()
    elif (uin in "writemap"):
        showMap("w")
        print(str_repl)
    elif (uin in "importmap"):
         importMap(uin.split(" ")[1])
    elif ("-" in uin or '+' in uin):
        if ("-allips" == uin):
            modifiers.append("-allips")
            print(uin)
        elif ("-privateips" == uin):
            modifiers.append("-privateips")
            print(uin)
        elif ("-vpntunnels" == uin):
            modifiers.append("-vpntunnels")
            print(uin)
        elif ("-snmpcommunities" == uin):
            modifiers.append("-snmpcommunities")
            print(uin)
        elif ("+clear" == uin):
            modifiers.clear()
            print("\nCleared modifiers\n")
        else:
            print("\nUnrecognized modifier\n")
    # Unrecognized option: list the options
    else:
        listOptions()

    # prompt line
    uin = input("--> ")