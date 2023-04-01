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
                print(val)
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

# Replaces IP addresses with [Letter].[Letter].[Letter].[Letter]
def replace_ip4(ip):
    if (ip not in ip_repl.keys()):
        repl = ""
        if (isRFC1918(ip)):
            octets = ip.split('.')
            repl = f"{octets[0]}.{octets[1]}.{random.randrange(0, 256)}.{random.randrange(1, 256)}"
        else:
            repl = f"{random.randrange(1, 255)}.{random.randrange(0, 256)}.{random.randrange(0, 256)}.{random.randrange(1, 256)}"
        ip_repl[ip] = repl
        return repl
    
    # If we've replaced it before, pick out that replacement and return it
    else:
        return ip_repl[ip]

def replace_ip6(ip):
    if (ip not in ip_repl.keys()):
        repl = f'{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}'
        ip_repl[ip] = repl
        return repl
    else:
        return ip_repl[ip]

# Program Functions
def listOptions():
    print("\nhelp = list this output\nload <file_path> = input file to be obfuscated\nmap = Show mapped addresses, only after 'obf' is run\nexport = export file\nshow = view contents file contents\nobf = begin obfuscation with enabled settings\n")

# Load a configuration file into a list and return the list
def load(filename):
    c = ""
    try:
        fl = open(filename, 'r')
        c = fl.readlines()
        fl.close()
    except:
        print("Something when wrong, try full file path\n")
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
    print("Successfully written to: {}".format(new_filename))

def showMap():

    if (not ip_repl):
        print("You haven't obfuscated a configuration file yet\n")
        return

    ipv4s = "\t===>>> IPv4 ADDRESSES <<<===\n\
            Original -> Replacement\n"
    ipv6s = "\t===>>> IPv6 ADDRESSES <<<===\n\
            Original -> Replacement\n"
    
    for k, v in ip_repl.items():
        if len(v) > 15:
            ipv6s += f"{k} -> {v}\n"
        else:
            ipv4s += f"{k} -> {v}\n"
    sep = '=' * 24
    print(f"{ipv4s}\n{sep}\n{ipv6s}")

# Obfuscation main fuction
def obfuscate():

    # If no file loaded, prompt to load a file
    if (not contents):
        return("\nYou need to load a file first\n")

    # Compile the regex found at the top of this program
    is_ip4 = re.compile(ipaddr4)
    is_ip6 = re.compile(ipaddr6, re.MULTILINE)

    # Parse through the list containing the lines of the configuration file
    for line in range(len(contents)):
        # Record the number of leading spaces, so we aren't having awkward lines that aren't in-line
        leading = " " * re.search('\S', contents[line]).start()
        
        # If we see 'set hostname' or 'set alias', replace those with 'US Federal Customer'
        if ("set hostname" in contents[line] or "set alias" in contents[line]):
            l = contents[line].strip().split(" ")
            l[2] = "US FEDERAL CUSTOMER\n"
            contents[line] = leading + "{} {} {}".format(l[0], l[1], l[2])
        
        # If we see an IP address, check if it's public, and if so, replace it
        if (is_ip4.search(contents[line])):
            g = contents[line].strip().split(" ")
            if (len(g) > 2):
                if ('"' in g[2]):
                    g[2] = g[2][1:-1]
                g[2] = replace_ip4(g[2])

                leading += " ".join(g)
                contents[line] = leading + "\n"

        elif (is_ip6.search(contents[line])):
            print(contents[line])
            g = contents[line].strip().split(" ")
            if (len(g) > 2):
                if ('"' in g[2]):
                    g[2] = g[2][1:-1]
                g[2] = replace_ip6(g[2].split('/')[0])

                leading += " ".join(g)
                contents[line] = leading + "\n"
    
    return("\nOperation was successful\n")

print("\n\n::::::::::  ::::::::  :::::::::  ::::::::::                           :::::::::: :::::::::: :::::::::  \n" +
      ":+:        :+:    :+: :+:    :+: :+:                                  :+:        :+:        :+:    :+: \n" +
      "+:+        +:+    +:+ +:+    +:+ +:+                                  +:+        +:+        +:+    +:+ \n" +
      ":#::+::#   +#+    +:+ +#++:++#+  :#::+::#         +#++:++#++:++       :#::+::#   +#++:++#   +#+    +:+ \n" +
      "+#+        +#+    +#+ +#+    +#+ +#+                                  +#+        +#+        +#+    +#+ \n" +
      "#+#        #+#    #+# #+#    #+# #+#                                  #+#        #+#        #+#    #+# \n" +
      "###         ########  #########  ###                                  ###        ########## #########  \n")

print("______________________________________________________________________________________________________")
print("\nFortiObfuscate - Mask hostname, External IP addresses, Usernames, VPN tunnels*, SNMP communities*, etc.\n*Under Construction\n")

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
        showMap()
    elif (uin in "export"):
        export()
    elif (uin in "obf"):
        print(obfuscate())
    
    # Unrecognized option: list the options
    else:
        listOptions()

    # prompt line
    uin = input("--> ")