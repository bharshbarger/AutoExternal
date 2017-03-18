#!/usr/bin/env python

#flow:
#get scope, test IP for valid IP
#present user with whois to confirm correct target
#https://pypi.python.org/pypi/whois  pip3 install whois



#import and run autosint, linkscrape, smbshakedown
#do an nmap, save to db?
#https://pypi.python.org/pypi/python-libnmap/0.6.1
#pip install libnmap
#store nmap to a db


#ssl



#if udp500, ike-scan/ikeforce/iker
#https://labs.portcullis.co.uk/tools/iker/

#ftp anon login or spray with ftplib

#if 80/443 scrape for login
#repurpose docx reportgen for report
#create some sort of findings db with like flask or tornado?

try:
	#builtins
	import argparse, time, os, sys, ftplib, socket, subprocess, sqlite3, re

	#local imports
	from reportgen import Reportgen
	import setupAutoExtDB
	
	#dependencies
	from libnmap.process import NmapProcess
	from libnmap.parser import NmapParser
	
except Exception as e:
	print('\n[!] Failed imports: %s \n' % (str(e)))

class AutoExt:
	def __init__(self, args):
		self.version ='beta1.031817'
		
		#start timer
		self.startTime=time.time()

		#local dirs
		self.reportDir='./reports/'

		#check local dirs
		if not os.path.exists(self.reportDir):
			os.makedirs(self.reportDir)
		self.targetsFile = ''
		self.targets=[]

		self.autoExtDB = 'AutoExt.db'
		#check for database
		if not os.path.exists(self.autoExtDB):
			print('\n[!] Database missing, creating %s \n' % self.autoExtDB)
			setupAutoExtDB.main()

		try:
			self.dbconn = sqlite3.connect(self.autoExtDB)
		except sqlite3.Error as e:
			print("[-] Database Error: %s" % e.args[0])

		
		#unique domain list result
		self.domainResult=set()

		#assign client name and sub out special chars unless you like sqli
		self.clientName = re.sub('\W+',' ', args.client)
		#conn to db
		cur = self.dbconn.cursor()
		print('[i] Setting up database for %s:' % self.clientName)
		c=self.clientName
		#insert rows
		try:
			cur.execute("INSERT INTO client (name) VALUES ('%s') " % (c))
			self.dbconn.commit()
		except sqlite3.Error as e:
			print("[-] Database Error: %s" % e.args[0])


	def clear(self):

		#clean up screen
	    os.system('cls' if os.name == 'nt' else 'clear')


	def banner(self, args):
			
		#verbosity flag to print logo and args
		if args.verbose is True:print( '''
    _         _        _____      _                        _ 
   / \  _   _| |_ ___ | ____|_  _| |_ ___ _ __ _ __   __ _| |
  / _ \| | | | __/ _ \|  _| \ \/ / __/ _ \ '__| '_ \ / _` | |
 / ___ \ |_| | || (_) | |___ >  <| ||  __/ |  | | | | (_| | |
/_/   \_\__,_|\__\___/|_____/_/\_/\__\___|_|  |_| |_|\__,_|_|\n''')

		if args.verbose is True:print ('AutoExternal.py %s, a way to automate common external testing tasks\n' % self.version)
		if args.verbose is True:print (args)


	
	def checkargs(self, args, parser):

		#require at least one argument
		if not (args.file or args.ipaddress):
		    print('\n[!] No scope provided, add a file with IPs with -f or IP address(es) with -i\n')
		    parser.print_help()
		    sys.exit(1)

		if args.file is not None and args.ipaddress is None:
			print('[i] Opening targets file')

			self.targetsFile=args.file

			with open(self.targetsFile) as f:
				targets = f.readlines()
				targets = [x.strip() for x in targets]
				self.targets = targets

				#filter only valid IP addresses from targets. could catch sqli/odd chars too?
				for i,t in enumerate(self.targets):
					try:
						socket.inet_aton(str(t))
					except socket.error:
						print ('\n[!] Invalid IP address %s entered at line %s!\n' %  (t,i+1))
						sys.exit()



				print('[+] All target IP addresses are valid!')

		if args.threads is None:
			args.threads = 2

		if args.threads is not None:
			args.threads=int(args.threads)

		if args.client is None:
			print('\n[!] Client name required, please provide with -c\n')
			sys.exit()

	def report(self, args):
		
		reportGen = Reportgen()
		reportGen.run(args, self.reportDir, self.lookup, self.whoisResult, self.domainResult, self.googleResult, self.shodanResult, self.pasteScrapeResult, self.harvesterResult, self.scrapeResult, self.credResult, self.pyfocaResult)

	def dnslookup(self,args):
		
		print('[i] Querying unique domains from targets list')
		for t in self.targets:

			try:
				domain=(socket.gethostbyaddr(t)[0].split('.')[1:])
				self.domainResult.add('.'.join(domain))
				time.sleep(0.5)
			except socket.error as e:
				continue

		#conn to db
		cur = self.dbconn.cursor()
		
		print('[i] Unique domains encountered for %s: \n' % self.clientName)

		#loop results 
		c=self.clientName
		for d in self.domainResult:
			print(str(''.join(d)))
			#insert rows
			try:
				cur.execute("INSERT INTO domains (name, client_id) VALUES ('%s',(SELECT ID from client where name ='%s'))" % (d,c))
				self.dbconn.commit()
			except sqlite3.Error as e:
				print("[-] Database Error: %s" % e.args[0])

		print('\n[i] Written to database\n')

	#https://libnmap.readthedocs.io/en/latest/process.html
	def nmap_tcp(self, args):

		print ('[i] Running nmap scan against %s targets\n' % len(self.targets))

		nm = NmapProcess(targets=self.targets, options="-n -p80 -T4 --min-hostgroup=50")
		nm.run()

		nmap_report = NmapParser.parse(nm.stdout)
		
		for scanned_hosts in nmap_report.hosts:
		    print scanned_hosts

	#https://libnmap.readthedocs.io/en/latest/process.html
	def nmap_udp(self, args):

		print ('[i] Running nmap scan against %s targets' % len(self.targets))

		nmap_proc = NmapProcess(targets=self.targets, options="-n -sU -T4 --min-hostgroup=50")
		nmap_proc.run_background()
		while nmap_proc.is_running():
		    print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nmap_proc.etc,
		                                                          nmap_proc.progress))
		    time.sleep(10)

		print("rc: {0} output: {1}".format(nmap_proc.rc, nmap_proc.summary))

def main():

	#https://docs.python.org/3/library/argparse.html
	parser = argparse.ArgumentParser()
	parser.add_argument('-a', '--all', help = 'run All queries', action = 'store_true')
	parser.add_argument('-c', '--client', help = 'client name')
	parser.add_argument('-f', '--file', metavar='targets.txt',help = 'input file')
	parser.add_argument('-i', '--ipaddress', metavar='127.0.0.1', nargs='*',help = 'IP address(es) to scan')
	parser.add_argument('-n', '--nmap', metavar='nmap options',help = 'run nmap')
	parser.add_argument('-t', '--threads', metavar='2', help='generally how parallel to run tests')
	parser.add_argument('-v', '--verbose', help = 'Verbose', action = 'store_true')	
	
	args = parser.parse_args()

	#run functions with arguments passed
	runAutoext = AutoExt(args)
	runAutoext.clear()
	runAutoext.banner(args)
	runAutoext.checkargs(args, parser)
	runAutoext.dnslookup(args)
	#runAutoext.nmap_tcp(args)
	#runAutoext.nmap_udp(args)
	#runAutoext.ftp(args)

	#runAutoext.report(args)

if __name__ == '__main__':

	main()
