#!/usr/bin/env python3

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
#https://github.com/nabla-c0d3/sslyze




#if udp500, ike-scan/ikeforce/iker
#https://labs.portcullis.co.uk/tools/iker/

#ftp anon login or spray with ftplib

#if 80/443 scrape for login
#repurpose docx reportgen for report
#create some sort of findings db with like flask or tornado?

try:
	import libnmap, sslyze, whois
	from libnmap.process import NmapProcess
	import os, ftplib, time

except Exception as e:
	print('\n [!] Imports failed! ' +str(e))
	sys.exit(1)


class AutoExt():
	def __init__(self):
		self.version ='A1.031717'


	def parsenmap(self):


	#https://pypi.python.org/pypi/whois
	def whois(self):
		domain = whois.query(host)
		print(domain.__dict__)
		print(domain.name)
		print(domain.expiration_date)

	#https://libnmap.readthedocs.io/en/latest/process.html
	def nmap(self):

		nm = NmapProcess("scanme.nmap.org", options="-sV")
		rc = nm.run()

		if nm.rc == 0:
			print nm.stdout
		else:
			print nm.stderr

	#https://docs.python.org/3.6/library/ftplib.html
	def ftpscan(self, host):
		try:
			ftpConn = ftplib.FTP(host)
			ftpConn.login('anonymous', 'me@your.com')
			print('\n[*] ' + str(host) + ' FTP Anonymous Login Found.')
			ftpConn.quit()
		except Exception as e:
			print('\n[*] ' + str(host) + ' FTP Anonymous Login Failed.')

def main():

	#https://docs.python.org/3/library/argparse.html
	parser = argparse.ArgumentParser()
	parser.add_argument('-a', '--all', help = 'run All queries', action = 'store_true')
	parser.add_argument('-b', '--hibp', help='Search haveibeenpwned.com for breaches related to a domain', action='store_true')
	parser.add_argument('-c', '--creds', help = 'Search local copies of credential dumps', action = 'store_true')
	parser.add_argument('-d', '--domain', metavar='foo.com', nargs = 1, help = 'the Domain you want to search.')
	parser.add_argument('-f', '--file', metavar='targets.txt',help = 'input file')
	parser.add_argument('-g', '--googledork', metavar='password id_rsa', nargs = '+',help = 'query Google for supplied args that are treated as a dork. i.e. -g password becomes a search for "password site:<domain>". Combine terms inside of quotes like "site:rapid7.com inurl:aspx" ')
	parser.add_argument('-i', '--ipaddress', nargs = 1, help = 'the IP address you want to search. Must be a valid IP. ')
	#parser.add_argument('-n', '--nslookup',help = 'Name query DNS for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
	#parser.add_argument('-p', '--pastebinsearch', metavar='password id_rsa' ,nargs = '+', help = 'Search google for <arg> site:pastebin.com. Requires a pro account if you dont want to get blacklisted.')
	parser.add_argument('-s', '--shodan', help = 'query Shodan, API keys stored in ./api_keys/', action='store_true')
	parser.add_argument('-S', '--scraper', help = 'Scrape pastebin, github, indeed, more to be added. API keys stored in ./api_keys/', action = 'store_true')
	#parser.add_argument('-t', '--theharvester', help = 'Invoke theHarvester', action = 'store_true')
	parser.add_argument('-v', '--verbose', help = 'Verbose', action = 'store_true')	
	#parser.add_argument('-w', '--whois', help = 'query Whois for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
		
	args = parser.parse_args()

	#run functions with arguments passed
	runAutosint = Autosint(args)
	runAutosint.clear()
	runAutosint.banner(args)
	runAutosint.checkargs(args)
	runAutosint.report(args)
	
if __name__ == '__main__':

	main()