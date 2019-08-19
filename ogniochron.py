#!/usr/bin/python3
import iptc,argparse,csv,re,os,time,sys

def add_pass_rule(port, proto='tcp', comment=''):
  print('Inserting new PASS rule: '+comment+' ['+proto+'/'+str(port)+']')
  rule                  = iptc.Rule()
  rule.protocol         = proto
  rule.target           = iptc.Target(rule, 'ACCEPT')
  match_comment         = rule.create_match('comment')
  match_comment.comment = comment
  match                 = rule.create_match(proto)
  match.dport           = port
  rule.add_match(match)
  rule.add_match(match_comment)
  chain_filter.insert_rule(rule)

## argparse
parser = argparse.ArgumentParser(description='Ogniochron - very simple iptables configurator')
parser.add_argument('-nat',  metavar='nat_file',   nargs=1, help='csv file for NAT rules',  required=True)
parser.add_argument('-pas',  metavar='pass_file',  nargs=1, help='csv file for PASS rules', required=True)
parser.add_argument('-debug', action='store_true')
parser.add_argument('-clear', action='store_true', help='stop after removing old rules')
args = parser.parse_args()

## globals
table_nat    = iptc.Table(iptc.Table.NAT)
chain_nat    = iptc.Chain(table_nat,    'PREROUTING')
table_filter = iptc.Table(iptc.Table.FILTER)
chain_filter = iptc.Chain(table_filter, 'INPUT')
chain_output = iptc.Chain(table_filter, 'OUTPUT')

## drop old rules
table_nat.autocommit    = False
table_filter.autocommit = False

regexp = re.compile(r'^ogniochron_.*$')
for chain in chain_nat,chain_filter,chain_output:
  for rule in chain.rules:
    for match in rule.matches:
      if hasattr(match,'comment') and regexp.search(str(match.comment)):
        print('Dropping old rule:       '+match.comment)
        chain.delete_rule(rule)
        break

table_nat.commit()
table_filter.commit()
table_nat.autocommit    = True
table_filter.autocommit = True

if args.clear:
  sys.exit(0)

## allow SSHD port - just to be sure
portfind_cmd="netstat -plnt | grep sshd | grep -v tcp6 | awk '{print $4}' | awk -F: '{print $2}'"
sshd_port=int(os.popen(portfind_cmd).read())
add_pass_rule(str(sshd_port), 'tcp', 'ogniochron_sshd_safeguard')

## allow INPUT for established connections
rule = iptc.Rule()
rule.protocol         = 'tcp'
rule.target           = iptc.Target(rule, 'ACCEPT')
match                 = iptc.Match(rule, 'state')
match.state           = 'RELATED,ESTABLISHED'
match_comment         = rule.create_match('comment')
match_comment.comment = 'ogniochron_input_related_established'
rule.add_match(match)
rule.add_match(match_comment)
chain_filter.insert_rule(rule)

## parse PASS rules
with open(args.pas[0], newline='') as config_file:
  config_reader = csv.reader(config_file, delimiter=',', quotechar='|')
  for line in config_reader:
    if len(line)==0 or line[0][0]=='#':
      continue
    add_pass_rule(line[1],line[2],'ogniochron_'+line[0])

## parse NAT rules
with open(args.nat[0], newline='') as config_file:
  config_reader = csv.reader(config_file, delimiter=',', quotechar='|')
  for line in config_reader:
    if len(line)==0 or line[0][0]=='#':
      continue
    print('Inserting new NAT  rule: ogniochron_'+line[0]+' [ext port: '+line[1]+' to: '+line[2]+':'+line[3]+']')

    rule                  = iptc.Rule()
    rule.protocol         = 'tcp'
    match_comment         = rule.create_match('comment')
    match_comment.comment = 'ogniochron_'+line[0]
    match                 = iptc.Match(rule,'tcp')
    match.dport           = line[1]
    target                = rule.create_target('DNAT')
    target.to_destination = line[2]+':'+line[3]
    rule.target = target
    rule.add_match(match)
    rule.add_match(match_comment)
    chain_nat.insert_rule(rule)

    add_pass_rule(line[1],'tcp','ogniochron_natpass_'+line[0])

## finally drop rest of traffic
print('Inserting new DROP rule: ogniochron_drop [everything!]')
rule                  = iptc.Rule()
rule.protocol         = 'tcp'
rule.target           = iptc.Target(rule, 'DROP')
match_comment         = rule.create_match('comment')
match_comment.comment = 'ogniochron_drop'
rule.add_match(match_comment)
chain_filter.append_rule(rule)

## Summary
if args.debug:
  print()
  print('Table FILTER')
  print(os.popen('iptables -t filter -S').read())
  print('Table NAT')
  print(os.popen('iptables -t nat -S').read())
