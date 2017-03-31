#!/usr/bin/env python


try:
	import time
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

		nm = NmapProcess(targets=self.targetList, options="-n -p21,80,443,8080 -T4 --min-hostgroup=50")
		rc=nm.run_background()

		#if successful return code, dump the stdout xml of the nmap
		if nm.rc == 0:
			print nm.stdout
		else:
			print nm.stderr


		while nm.is_running():
			print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,nm.progress))
			time.sleep(2)

		print("rc: {0} output: {1}".format(nm.rc, nm.summary))



		nmap_report = NmapParser.parse(nm.stdout)
		return nmap_report
		
		#for scanned_hosts in nmap_report.hosts:
			#print scanned_hosts
		#self.print_scan(nmap_report)


	def print_scan(self,nmap_report):
		print("Starting Nmap {0} ( http://nmap.org ) at {1}".format(
			nmap_report.version,
			nmap_report.started))
		for host in nmap_report.hosts:
			if len(host.hostnames):
				tmp_host = host.hostnames.pop()
			else:
				tmp_host = host.address
			print("Nmap scan report for {0} ({1})".format(
				tmp_host,
				host.address))


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