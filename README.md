# FortiObfuscator.py -> anonymizes FortiGate configuration files

Takes in a FortiGate configuration file and obfuscates the following:

- hostnames/aliases
- VPN tunnel names
- Private & public IP addresses (+ IPv6 addresses)
- Usernames
- SNMP communities (v1/2c/3)

## Usage

```
python FortiObfuscator.py
```

This loads the CLI program, the options available:

- Options:
```
help = list this output
load <file_path> = input file to be obfuscated
map = Show mapped addresses, only after 'obf' is run
writemap = Write the output of the map command to a text file
export = export file
show = view contents file contents
obf = begin obfuscation with enabled settings
mods = show modifiers
```

- Modifiers:
```
Exclude from replacement:
-privateips             <- Excludes JUST private IPs from replacement
-allips                 <- Excludes public & private IPs from replacement
-vpntunnels             <- Tunnel Phase 1 & 2 names + DDNS
-snmpcommunities        <- affects both snmpv2c & v3
```

## Known Issues

I built this program with the idea that you could load and work with multiple config files. Currently it only works with one at a time.