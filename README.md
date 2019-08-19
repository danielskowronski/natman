# ogniochron

very simple iptables configurator with two "tables" in csv files:
* PASS - which defines ports to be opened, all other are dropped on input filter
  * only exception is port on which sshd service is listening, it's added as safeguard
* NAT - very simple wrapper for port forwarding, useful for proxmox which does not support this in GUI
  * all NAT rules are also added as PASS rules (otherwise it doesn't make sense to have them)

## usage

```
usage: ogniochron.py [-h] -nat nat_file -pass pass_file

Ogniochron - very simple iptables configurator

optional arguments:
  -h, --help       show this help message and exit
  -nat nat_file    csv file for NAT rules
  -pass pass_file  csv file for PASS rules
  -debug
```

### example NAT file

```
#lines starting with # are comments
#name,src_port,dest_ip,dest_port
glyptodon,8080,10.201.0.3,8080
```

### example PASS file

```
#name,external_port,proto(tcp/udp)
proxmox,8006,tcp
```


### example run

```
# ./ogniochron.py -nat /etc/ogniochron_nat.csv -pas /etc/ogniochron_pass.csv -debug
Dropping old rule:       ogniochron_sshd_safeguard
Dropping old rule:       ogniochron_drop
Dropping old rule:       ogniochron_natpass_workstation_ssh
Dropping old rule:       ogniochron_natpass_glyptodon
Dropping old rule:       ogniochron_test
Dropping old rule:       ogniochron_proxmox
Dropping old rule:       ogniochron_output
Inserting new PASS rule: ogniochron_sshd_safeguard [tcp/22]
Inserting new PASS rule: ogniochron_proxmox [tcp/8006]
Inserting new NAT  rule: ogniochron_glyptodon [ext port: 8080 to: 10.201.0.3:8080]
Inserting new PASS rule: ogniochron_natpass_glyptodon [tcp/8080]
Inserting new NAT  rule: ogniochron_workstation_ssh [ext port: 22001 to: 10.201.0.2:22]
Inserting new PASS rule: ogniochron_natpass_workstation_ssh [tcp/22001]
Inserting new DROP rule: ogniochron_drop [everything!]
Inserting new PASS rule: ogniochron_sshd_safeguard [tcp/22]

Table FILTER
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -p tcp -m comment --comment ogniochron_sshd_safeguard -m tcp --dport 22 -m tcp --dport 22 -m comment --comment ogniochron_sshd_safeguard -j ACCEPT
-A INPUT -p tcp -m comment --comment ogniochron_drop -m comment --comment ogniochron_drop -j DROP
-A INPUT -p tcp -m comment --comment ogniochron_natpass_workstation_ssh -m tcp --dport 22001 -m tcp --dport 22001 -m comment --comment ogniochron_natpass_workstation_ssh -j ACCEPT
-A INPUT -p tcp -m comment --comment ogniochron_natpass_glyptodon -m tcp --dport 8080 -m tcp --dport 8080 -m comment --comment ogniochron_natpass_glyptodon -j ACCEPT
-A INPUT -p tcp -m comment --comment ogniochron_proxmox -m tcp --dport 8006 -m tcp --dport 8006 -m comment --comment ogniochron_proxmox -j ACCEPT
-A OUTPUT -p tcp -m comment --comment ogniochron_output -m comment --comment ogniochron_output -j ACCEPT

Table NAT
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
-A PREROUTING -p tcp -m comment --comment ogniochron_workstation_ssh -m tcp --dport 22001 -m comment --comment ogniochron_workstation_ssh -j DNAT --to-destination 10.201.0.2:22
-A POSTROUTING -s 10.201.0.0/16 -o enp3s0 -j MASQUERADE
-A POSTROUTING -s 10.227.0.0/16 -o enp3s0 -j MASQUERADE
```
