#!/usr/bin/env python3

#flow:
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



import libnmap, sslyze
import os, ftplib


def ftpscan(host):
  	try:
      ftpConn = ftplib.FTP(host)
      ftpConn.login('anonymous', 'me@your.com')
      print('\n[*] ' + str(host) + ' FTP Anonymous Login Found.')
      ftpConn.quit()

	  except Exception as e:
      print('\n[*] ' + str(host) + ' FTP Anonymous Login Failed.')



if __name__ == '__main__':
	main()
