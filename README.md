# ogniochron

very simple iptables configurator with two "tables" in csv files:
* PASS - which defines ports to be opened, all other are dropped on input filter
  * only exception is port on which sshd service is listening, it's added as safeguard
* NAT - very simple wrapper for port forwarding, useful for proxmox which does not support this in GUI
  * all NAT rules are also added as PASS rules (otherwise it doesn't make sense to have them)

## usage

```
usage: ogniochron.py [-h] -nat nat_file -pas pass_file -o public_iface
                     [-debug] [-clear]

Ogniochron - very simple iptables configurator

optional arguments:
  -h, --help       show this help message and exit
  -nat nat_file    csv file for NAT rules
  -pas pass_file   csv file for PASS rules
  -o public_iface  interface facing internet
  -debug
  -clear           stop after removing old rules
``` 

### example NAT file

```
#lines starting with # are comments
#name,src_ip,src_port,dest_ip,dest_port,src_net
ipsec,1.2.3.4,500,10.1.2.3,500,
ipsec,1.2.3.4,4500,10.1.2.3,4500,
```

### example PASS file

```
#name,external_port,proto(tcp/udp),src_net
proxmox,8006,tcp,127.0.0.1
```

### `src_net` field

- single CIDR
- empty means `0.0.0.0/0`


### example run

```
# ./ogniochron.py -nat /etc/ogniochron_nat.csv -pas /etc/ogniochron_pass.csv -debug -o ens30
Dropping old rule:       ogniochron_test
Dropping old rule:       ogniochron_workstation_ssh
Dropping old rule:       ogniochron_natpass_workstation_ssh
Dropping old rule:       ogniochron_natpass_glyptodon
Dropping old rule:       ogniochron_proxmox
Dropping old rule:       ogniochron_input_related_established
Dropping old rule:       ogniochron_drop
Inserting new PASS rule: ogniochron_sshd_safeguard [tcp/22]
Inserting new PASS rule: ogniochron_proxmox [tcp/8006]
Inserting new NAT  rule: ogniochron_glyptodon [ext: 1.2.3.4:8080 to: 10.201.0.3:8080]
Inserting new PASS rule: ogniochron_natpass_glyptodon [tcp/8080]
Inserting new NAT  rule: ogniochron_workstation_ssh [ext: 1.2.3.4:22001 to: 10.201.0.2:22]
Inserting new PASS rule: ogniochron_natpass_workstation_ssh [tcp/22001]
Inserting new DROP rule: ogniochron_drop [everything!]

Table FILTER
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -p tcp -m comment --comment ogniochron_natpass_workstation_ssh -m tcp --dport 22001 -m tcp --dport 22001 -m comment --comment ogniochron_natpass_workstation_ssh -j ACCEPT
-A INPUT -p tcp -m comment --comment ogniochron_natpass_glyptodon -m tcp --dport 8080 -m tcp --dport 8080 -m comment --comment ogniochron_natpass_glyptodon -j ACCEPT
-A INPUT -p tcp -m comment --comment ogniochron_proxmox -m tcp --dport 8006 -m tcp --dport 8006 -m comment --comment ogniochron_proxmox -j ACCEPT
-A INPUT -p tcp -m comment --comment ogniochron_input_related_established -m state --state RELATED,ESTABLISHED -m comment --comment ogniochron_input_related_established -j ACCEPT
-A INPUT -p tcp -m comment --comment ogniochron_drop -m comment --comment ogniochron_drop -j DROP

Table NAT
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-A PREROUTING -p tcp -m comment --comment ogniochron_workstation_ssh -m tcp --dport 22001 -m comment --comment ogniochron_workstation_ssh -j DNAT --to-destination 10.201.0.2:22
-A POSTROUTING -s 10.201.0.0/16 -o enp3s0 -j MASQUERADE
-A POSTROUTING -s 10.227.0.0/16 -o enp3s0 -j MASQUERADE
```
