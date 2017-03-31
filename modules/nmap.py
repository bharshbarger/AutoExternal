#!/usr/bin/env python


try:
	from libnmap.process import NmapProcess
	from libnmap.parser import NmapParser
except Exception as e:
	print('\n[!] Failed imports: %s \n' % (str(e)))


class AutoNmap:

	def __init__(self, targetSet):

		self.options = ''
		self.targetList=list(targetSet)

	#https://libnmap.readthedocs.io/en/latest/process.html
	def scan_tcp(self):

		print ('[i] Running nmap scan against %s targets\n' % len(self.targetList))

		nm = NmapProcess(targets=self.targetList, options="-n -p80 -T4 --min-hostgroup=50")
		nm.run()

		nmap_report = NmapParser.parse(nm.stdout)
		
		for scanned_hosts in nmap_report.hosts:
		    print scanned_hosts

	#https://libnmap.readthedocs.io/en/latest/process.html
	def scan_udp(self):

		print ('[i] Running nmap scan against %s targets' % len(self.targetList))

		nmap_proc = NmapProcess(targets=self.targetList, options="-n -sU -T4 --min-hostgroup=50")
		nmap_proc.run_background()
		while nmap_proc.is_running():
		    print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nmap_proc.etc,
		                                                          nmap_proc.progress))
		    time.sleep(10)

		print("rc: {0} output: {1}".format(nmap_proc.rc, nmap_proc.summary))

def main():

	runNmap=AutoNmap()


if __name__ == '__main__':
	main()