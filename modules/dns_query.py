#!/usr/bin/env python

import socket, sqlite3, time

from modules.dbcommands import Database


class Dnslookup:

	def __init__(self):
		self.domainResult=set()
		self.domainResult=set()

	def query(self,args,targets,clientName):

		
		print('[i] Running dig on IP addresses')
		for t in targets:
			try:
				domain=(socket.gethostbyaddr(t)[0].split('.')[1:])
				print('[i] %s resolves to %s' % (t, '.'.join(domain)))
				if domain is not None:
					self.domainResult.add('.'.join(domain))
				time.sleep(0.5)
			except socket.error as e:
				print('[!] %s does not resolve to a name' % t)
				continue



		print('[i] Unique domains encountered for %s: \n' % clientName)

		dbOps=Database(clientName)
		dbconn=dbOps.connect()

		#conn to db
		cur = dbconn.cursor()

		#loop results 
		c=clientName
		for d in self.domainResult:
			print(str(''.join(d)))
			#insert rows
			try:
				cur.execute("INSERT INTO domains (name, client_id) VALUES ('%s',(SELECT ID from client where name ='%s'))" % (d,c))
				dbconn.commit()
				dbconn.close()
			except sqlite3.Error as e:
				print("[-] Database Error: %s" % e.args[0])

		print('\n[i] Written to database\n')



def main():

	runQuery=Dnslookup()
	runQuery.query()


if __name__ == '__main__':

	main()