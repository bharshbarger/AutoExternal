#!/usr/bin/env python


class TransportScan:

	def __init__(self,targetSet):

		self.targetSet=targetSet
		self.timeout = 10


	def run(self):
		
		for t in self.targetSet:
			print('Checking for anonymous FTP on %s' % t)
			try:
			
				ftp=FTP(t, timeout=3)
			except:
				continue
			
			ftp.login()
			ftp.retrlines('LIST')
			ftp.quit()
			time.sleep(1)

def main():

	runTlsCheck=TransportScan()


if __name__ == '__main__':
	main()		