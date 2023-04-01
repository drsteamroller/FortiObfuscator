FortiObfuscator.py -> anonymizes FortiGate configuration files

Takes in a FortiGate configuration file and obfuscates the following:

- hostnames/aliases
- VPN tunnel names *
- Private & public IP addresses (+ IPv6 addresses)
- Usernames
- SNMP tunnels *

* Under construction