# how to run: python quantum.py --interface eth0 --regexp /^regex$/ --datafile someFIle expr
import argparse

parser = argparse.ArgumentParser(description='idk')
parser.add_argument("--interface", help="interface")
parser.add_argument("--regexp", help="regular expression")
parser.add_argument("--datafile", help="datafile input")
parser.add_argument("expression", help="straight up input")

args = parser.parse_args()
print args
print args.interface
print args.regexp
print args.datafile
print args.expression
