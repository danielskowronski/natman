#!/usr/bin/python3
import iptc,argparse,csv,re

parser = argparse.ArgumentParser(description='NAT port forwarding MANager')
parser.add_argument('conf',  metavar='conf',  nargs=1, help='csv config file')
args = parser.parse_args()
chain = iptc.Chain(iptc.Table(iptc.Table.NAT), 'PREROUTING')

regexp = re.compile(r'^natman_.*$')
for rule in chain.rules:
  for match in rule.matches:
    if hasattr(match,'comment') and regexp.search(match.comment):
      print('Dropping old rule:  '+match.comment)
      chain.delete_rule(rule)
      break

with open(args.conf[0], newline='') as config_file:
  config_reader = csv.reader(config_file, delimiter=',', quotechar='|')
  for line in config_reader:
    if len(line)==0 or line[0][0]=='#':
      continue
    print('Inserting new rule: natman_'+line[0]+' (ext port: '+line[1]+' to: '+line[2]+':'+line[3]+')')

    rule                  = iptc.Rule()
    rule.protocol         = 'tcp'
    match_comment         = rule.create_match('comment')
    match_comment.comment = 'natman_'+line[0]
    match                 = iptc.Match(rule,'tcp')
    match.dport           = line[1]
    target                = rule.create_target('DNAT')
    target.to_destination = line[2]+':'+line[3]
    rule.target = target
    rule.add_match(match)
    rule.add_match(match_comment)
    chain.insert_rule(rule)

