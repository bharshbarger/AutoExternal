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
	import argparse, time, os, sys, ftplib, socket, subprocess

	#local imports
	from reportgen import Reportgen

	#dependencies
	import libnmap, ipwhois

	from libnmap.process import NmapProcess
	
except Exception as e:
	print('\n [!] Failed imports: ' +str(e))


class AutoExt:
	def __init__(self, args):
		self.version ='beta1.031717'
		
		#start timer
		self.startTime=time.time()

		#local dirs
		self.reportDir='./reports/'

		#check local dirs
		if not os.path.exists(self.reportDir):
			os.makedirs(self.reportDir)
		self.targetsFile = ''
		self.targets=[]

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
				for i,t in enumerate(self.targets):
				
					try:
						socket.inet_aton(str(t))
					except socket.error:
						print ('[!] Invalid IP address %s entered at line %s!' %  (t,i+1))
						sys.exit()



				print('[+] All target IP addresses are valid!')

		if args.threads is None:
			args.threads = 2

		if args.threads is not None:
			args.threads=int(args.threads)

	#run the docx report. text files happen in the respective functions
	def report(self, args):
		
		reportGen = Reportgen()
		reportGen.run(args, self.reportDir, self.lookup, self.whoisResult, self.domainResult, self.googleResult, self.shodanResult, self.pasteScrapeResult, self.harvesterResult, self.scrapeResult, self.credResult, self.pyfocaResult)


	#https://ipwhois.readthedocs.io/en/latest/NIR.html
	def whois(self, args):
		whoisResult=set()


		for t in self.targets:
			try:
				subprocess.Popen(['whois',t], stdout = subprocess.PIPE).communicate()[0].split('\n')
			except:
				print '[-] Error running whois command'
				sys.exit()
			time.sleep(5)

	def dnslookup(self,args):
		domainResult=set()

		for t in self.targets:

			domain=(socket.gethostbyaddr(t)[0].split('.')[1:])
			domainResult.add('.'.join(domain))
			print socket.gethostbyaddr(t)[0]
			print domainResult

			#domainResult.add(socket.gethostbyaddr(t))
			time.sleep(1)

	#https://libnmap.readthedocs.io/en/latest/process.html
	def nmap(self, args):

		print ('[i] Running nmap scan against %s targets' % len(self.targets))

		nmap_proc = NmapProcess(targets=self.targets, options="-n -p- -T4 --min-hostgroup=50")
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
	parser.add_argument('-i', '--ipaddress', metavar='127.0.0.1',help = 'IP address(es) to scan')
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
	runAutoext.whois(args)
	runAutoext.nmap(args)
	#runAutoext.ftp(args)

	#runAutoext.report(args)

if __name__ == '__main__':

	main()
