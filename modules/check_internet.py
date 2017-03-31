#!/usr/bin/env python

try:
	import urllib, sys, json
except ImportError as e:
	print(e)


class CheckInternet:
	def get_external_address(self):
		try:
			''' Obtains External IP Address '''
			data = json.loads(urllib.urlopen("http://ip.jsontest.com/").read())
			#return data["ip"]	
			print('[i] Internet connection is ok. Your IP is %s' % (str(data["ip"])))
		except IOError:
			print('\n[!] Check your Internet connection! Exiting... \n')
			sys.exit(0)

def main():
	run=CheckInternet()
	run.get_external_address()

if __name__ == '__main__':

	main()

