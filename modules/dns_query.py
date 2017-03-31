#!/usr/bin/env python

import socket
import sqlite3


from modules.dbcommands import connect


class Dnslookup:



	def query(self,args,targets,clientName):


		self.domainResult=set()
		print('[i] Running dig on IP addresses')
		for t in targets:

			try:
				domain=(socket.gethostbyaddr(t)[0].split('.')[1:])
				self.domainResult.add('.'.join(domain))
				time.sleep(0.5)
			except socket.error as e:
				continue

		
		print('[i] Unique domains encountered for %s: \n' % clientName)

		dbOps=Database()



		#conn to db
		cur = self.dbconn.cursor()

		#loop results 
		c=clientName
		for d in self.domainResult:
			print(str(''.join(d)))
			#insert rows
			try:
				cur.execute("INSERT INTO domains (name, client_id) VALUES ('%s',(SELECT ID from client where name ='%s'))" % (d,c))
				self.dbconn.commit()
			except sqlite3.Error as e:
				print("[-] Database Error: %s" % e.args[0])

		print('\n[i] Written to database\n')



def main():

	runQuery=Dnslookup()
	runQuery.query()


if __name__ == '__main__':

	main()