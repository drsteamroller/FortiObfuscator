#!/usr/bin/env python3
# Description - On the way
# Author: Andrew McConnell
# Date: 03/15/2023

import re
import random

# Global Variables
contents = []
og_filename = 0
vdom_names = dict()
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
    if (ip not in ip_repl.keys() and "-allips" not in modifiers):
        repl = f'{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}'
        ip_repl[ip] = repl
        return repl
    elif ("-allips" not in modifiers):
        return ip_repl[ip]
    else:
        return ip

# Program Functions
def listOptions():
    print("\nhelp = list this output\nload <file_path> = input file to be obfuscated\nmap = Show mapped addresses, only after 'obf' is run\nwritemap = Write the output of the map command to a text file\nexport = export file\nshow = view contents file contents\nobf = begin obfuscation with enabled settings\nmods = show modifiers\n")

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
        with open(f"{og_filename}_ipmapping.txt", 'w') as vi:
            vi.write(f"{ipv4s}\n{sep}\n{ipv6s}")
        print(f"\nMap file written to {og_filename}_ipmapping.txt\n")
    else:
        print("\nUnknown option\n")

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
    snmp_comm_num = 1
    snmp_host_num = 1
    vpn_p1_num = 1
    vpn_p2_num = 1
    vpn_ddns_num = 1
    vpn_tun_map = {}

    # Debugging
    x = ""

    # Parse through the list containing the lines of the configuration file
    for i, content in enumerate(contents):

        # Record the number of leading spaces, so we aren't having awkward lines that aren't in-line
        leading = " " * re.search('\S', content).start()
        
        # If we see 'set hostname' or 'set alias', replace those with 'US Federal Customer'
        if ("set hostname" in content or "set alias" in content):
            l = content.strip().split(" ")
            l[2] = "US FEDERAL CUSTOMER\n"
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
                    s[1] = f'snmp_comm_{snmp_comm_num}'
                
                leading += " ".join(s)
                content = leading + "\n"
                snmp_comm_num += 1

            if (SNMP and "config hosts" in content):
                SNMP_HOSTS = True

            if (SNMP_HOSTS and "edit" in content):
                s = content.strip().split(" ")
                if (len(g) > 1):
                    s[1] = f'snmp_host_{snmp_host_num}'

                leading += " ".join(s)
                content = leading + "\n"
                snmp_host_num += 1

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
                
                repl = f'{vpn_ddns_num}.net'
                
                leading += f'{v[0]} {v[1]} {repl}\n'
                content = leading

            if (IPSEC_P1 and "edit" in content):
                v = content.strip().split(" ")
                repl = f'vpn_p1_{vpn_p1_num}'
                
                if (v[1] not in vpn_tun_map.keys()):
                    vpn_tun_map[v[1]] = repl
                    vpn_p1_num += 1
                else:
                    repl = vpn_tun_map[v[1]]

                leading += f"{v[0]} {repl}\n"
                content = leading
                
            if (IPSEC_P2 and "edit" in content):
                v = content.strip().split(" ")
                repl = f'vpn_p2_{vpn_p2_num}'

                leading += f"{v[0]} {repl}\n"
                content = leading
                vpn_p2_num += 1
            
            if (IPSEC_P2 and "set phase1name" in content):
                v = content.strip().split(" ")
                try:
                    repl = vpn_tun_map[v[2]]
                except KeyError as e:
                    # Odd case where P2 shows up in the backup before P1
                    vpn_tun_map[v[2]] = f'vpn_p1_{vpn_p1_num}'
                    repl = vpn_tun_map[v[2]]
                
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