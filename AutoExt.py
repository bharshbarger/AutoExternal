#!/usr/bin/env python

#try:
	#builtins
import argparse, time, os, sys, ftplib, socket, subprocess, sqlite3, re
from urlparse import urlparse
from subprocess import Popen, PIPE, STDOUT 

#from local modules import class
from reportgen import Reportgen
import setupAutoExtDB
from modules.dbcommands import Database
from modules.check_internet import CheckInternet
from modules.domain_query import Domainlookup
from modules.nmap import AutoNmap
from modules.ftp_check import Ftpscan
#from modules.transport_scan import TransportScan


#third party
#sslyze dependency in sslyze.py

	
#except Exception as e:
	#print('\n[!] Failed imports: %s \n' % (str(e)))

class AutoExt:
	def __init__(self, args, parser):

		#defaults
		self.version ='beta1.033017'
		self.args = args
		self.parser = parser
		self.startTime=time.time()
		self.reportDir='./reports/'
		self.targetsFile = ''
		self.targetList = []
		self.targetSet=set()
		self.autoExtDB = 'AutoExt.db'
		self.domainResult=set()
		self.clientName = None
		self.nmapOptions = []

		#init modules
		self.runCheckInet = CheckInternet()

	def clear(self):
	    os.system('cls' if os.name == 'nt' else 'clear')


	def banner(self):
		if self.args.verbose is True:print( '''
    _         _        _____      _                        _ 
   / \  _   _| |_ ___ | ____|_  _| |_ ___ _ __ _ __   __ _| |
  / _ \| | | | __/ _ \|  _| \ \/ / __/ _ \ '__| '_ \ / _` | |
 / ___ \ |_| | || (_) | |___ >  <| ||  __/ |  | | | | (_| | |
/_/   \_\__,_|\__\___/|_____/_/\_/\__\___|_|  |_| |_|\__,_|_|\n''')

		if self.args.verbose is True:print ('AutoExternal.py %s, a way to automate common external testing tasks\n' % self.version)
		if self.args.verbose is True:print (self.args)


	
	def checkargs(self, parser):

		#make sure you are online!
		self.runCheckInet.get_external_address()

		#check local dirs
		if not os.path.exists(self.reportDir):
			os.makedirs(self.reportDir)

		#require at least one argument
		if not (self.args.file or self.args.ipaddress):
		    print('\n[!] No scope provided, add a file with IPs with -f or IP address(es) with -i\n')
		    parser.print_help()
		    sys.exit(1)

		#if a file is supplied and no ip is supplied, open it with readTargets
		if self.args.file is not None and self.args.ipaddress is None:
			print('[i] Opening targets file %s' % self.args.file)
			self.targetsFile=self.args.file
			self.readTargets()

		#check threads, default is 2
		if self.args.threads is None:
			self.args.threads = 2

		#if threads specified, use that value
		if self.args.threads is not None:
			self.args.threads=int(self.args.threads)

		#nmap arguments
		if self.args.nmap is not None:
			self.args.nmapOptions = self.args.nmap 
			print('nmap args %s' % self.args.nmapOptions)

		#check for a supplied client name and exit if none provided
		if self.args.client is None:
			print('\n[!] Client name required, please provide with -c\n')
			sys.exit(0)
		else:
			#strip out specials in client name
			self.clientName = re.sub('\W+',' ', self.args.client)

		#check for database, create if missing
		if not os.path.exists(self.autoExtDB):
			print('\n[!] Database missing, creating %s \n' % self.autoExtDB)
			setupAutoExtDB.main()

	def readTargets(self):
		#open targets file
		with open(self.targetsFile) as f:
			targets = f.readlines()
			
			#add to target list, strip stuff
			for x in targets:
				self.targetList.append(x.strip())
		
		#print list if verbose 
		if self.args.verbose is True:print('\n[v] TARGET LIST: %s\n' % self.targetList)

		#iterate through targetList
		for i,t in enumerate(self.targetList):
			
			#test to see if its a valid ip using socket
			try:
				#print(socket.inet_aton(str(t))) 
				socket.inet_aton(t)
				#add to set
				self.targetSet.add(t)

			#if the ip isnt valid
			except socket.error:
				#tell them
				print ('[!] Invalid IP address [ %s ] found on line %s... Fixing!' %  (t,i+1))
				
				#fix the entries. this function will add resolved IPs to the targetSet
				self.fix_targets(t)

			except Exception as e:
				print(e)

		#finally do a regex on targetList to clean it up(remove non-ip addresses)
		ipAddrRegex=re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
		
		#only allow IP addresses--if it isnt'
		if not ipAddrRegex.match(t):
			#remove from targetList
			if self.args.verbose is True:print('[v] Removing invalid IP %s'% t)
			self.targetList.remove(t)
		else:
			#otherwise add to target set
			self.targetSet.add(t)

		#need to expand cidr and filter rfc1918, etc	

		#show user target set of unique IPs
		if self.args.verbose is True:print('[i] Reconciled target list:\n')
		if self.args.verbose is True:print(', '.join(self.targetSet))

		print('\n[i] All target checks are successful')

	def fix_targets(self, t):
		
		#function to resolve hostnames in target file or hostnames stripped from URLs to ip addresses.
		#handle full urls:
		if re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', t):
			parsed_uri = urlparse(t)
			domain = '{uri.netloc}'.format(uri=parsed_uri)
			if self.args.verbose is True:print('[i] Looking up IP for %s' % domain)
			hostDomainCmd = subprocess.Popen(['dig', '+short', domain], stdout = PIPE)
			#print('[i] IP address for %s found: %s' % (t,hostDomainCmd.stdout.read().strip('\n')))
			#for each line in the host commands output, add to a fixed target list
			self.targetSet.add(hostDomainCmd.stdout.read().strip('\n')) 
		
		#filter hostnames
		else:
			if self.args.verbose is True:print('[i] Looking up IP for hostname %s' % t)
			#just resolve ip from hostname if no http:// or https:// in the entry
			hostNameCmd = subprocess.Popen(['dig', '+short', t], stdout = PIPE)
			self.targetSet.add(hostNameCmd.stdout.read().strip('\n'))

	#add the supplied client to the database
	def add_client_db(self):
		
		dbOps = Database(self.clientName)
		dbOps.add_client()		 

	#invoke domain results module
	def domainlookup(self):

		self.runDns = Domainlookup(self.targetSet, self.clientName)
		self.runDns.query()

	#invoke nmap scans module
	def nmap_scan(self):

		nmap = AutoNmap(self.targetSet, self.clientName, self.nmapOptions)
		nmap.scan_tcp()
		#nmap.scan_udp()

	def ftp_scan(self):


		#need logic to feed in open ports from nmap module

		ftp = Ftpscan(self.targetSet)
		ftp.anon_test()


	#invoke report module
	def report(self):
		
		reportGen = Reportgen()
		reportGen.run(self.args, self.reportDir, self.lookup, self.whoisResult, self.domainResult, self.googleResult, self.shodanResult, self.pasteScrapeResult, self.harvesterResult, self.scrapeResult, self.credResult, self.pyfocaResult)


def main():

	#https://docs.python.org/3/library/argparse.html
	parser = argparse.ArgumentParser()
	parser.add_argument('-a', '--all', help = 'run All queries', action = 'store_true')
	parser.add_argument('-c', '--client', help = 'client name')
	parser.add_argument('-f', '--file', metavar='targets.txt',help = 'input file')
	parser.add_argument('-i', '--ipaddress', metavar='127.0.0.1', nargs='*',help = 'IP address(es) to scan')
	parser.add_argument('-n', '--nmap', metavar='nmap options', nargs='*',help = 'run nmap with optional args in double quotes, e.g "-T4 -p-"')
	parser.add_argument('-t', '--threads', metavar='2', help='generally how parallel to run tests')
	parser.add_argument('-v', '--verbose', help = 'Verbose', action = 'store_true')	
	
	args = parser.parse_args()

	#run functions with arguments passed
	runAutoext = AutoExt(args, parser)
	runAutoext.clear()
	runAutoext.banner()
	runAutoext.checkargs(parser)
	runAutoext.add_client_db()
	runAutoext.domainlookup()
	runAutoext.nmap_scan()
	#runAutoext.ftp_scan()
	#runAutoext.transport_scan()

	#runAutoext.report(args)

if __name__ == '__main__':

	main()
