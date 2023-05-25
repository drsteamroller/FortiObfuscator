# confsrb.py -> anonymizes FortiGate configuration files

Takes in a FortiGate configuration file and obfuscates the following:

- hostnames/aliases
- VPN tunnel names
- Private & public IP addresses (+ IPv6 addresses)
- Usernames
- SNMP communities (v1/2c/3)

## Usage

```
python confsrb.py <conf-file> [options] OR
python confsrb.py -g conf1.conf,conf2.conf,conf3.conf... [options] OR
python confsrb.py -d <path> [options]
```

This loads the CLI program, the options available:

- Options:
```
-h: Display this output
-g: Use this option if you are inputting a group of logs. Usage: py confsrb.py -g conf1.conf,conf2.conf,conf3.conf... <options>
-d: Same as -g, but specifying a whole directory. Usage: py confsrb.py -d [path] <options> (Assumes all files in the directory are configuration files)
-sPIP": Scrub private IPs. Assumes /16 subnet
-pi": preserve all ip addresses
-ps": preserve snmp community names
-pv": preserve vpn phase1/2 names names
-map=<mapfilename>: Import IP/MAC/String mappings from other FFI program output
```