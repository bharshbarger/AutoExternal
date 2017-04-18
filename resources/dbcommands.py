#!/usr/bin/env python


import sqlite3


class Database:

	def __init__(self, clientName):

		self.autoExtDB = 'AutoExt.db'
		self.clientName = clientName


	def connect(self):

		try:
			dbconn = sqlite3.connect(self.autoExtDB)
		except sqlite3.Error as e:
			print("[-] Database Error: %s" % e.args[0])
		return dbconn

	def add_client(self):
		results = None

		dbconn = self.connect()

		#conn to db
		cur = dbconn.cursor()
		
		c = self.clientName
		#insert rows
		
		#check to see if the client name exists, and if it does print it, and if it doesnt add it
		try:

			#look for existing name from supplied arg
			print('\n[i] Checking for client [ %s ] in database\n' % self.clientName)
			cur.execute("SELECT * FROM client WHERE (name = '%s') " % (c))
			results = cur.fetchall()
			#cur.close()
			
			#if there is a result, print in a table
			if results:
				#print it
				print('ID___ Name___________ Contact____________  Date_______________')
				
				for row in results:
					print ('%-5s %-15s %-20s %-s' % (row[0], row[1], row[2], row[3]))
			#if there isn't a result
			else:
				#add customer
				print ('[i] Client %s not in database, adding' % self.clientName)
				try:
					cur.execute("INSERT INTO client (name) VALUES ('%s') " % (c))
					dbconn.commit()
					#and display it
					cur.execute("SELECT * FROM client WHERE (name = '%s') " % (c))
					results = cur.fetchall()
					#cur.close()
					cur.execute("SELECT * FROM client WHERE (name = '%s') " % (c))
					results = cur.fetchall()
					print('ID___ Name___________ Contact____________  Date_______________')
				
					for row in results:
						print ('%-5s %-15s %-20s %-s' % (row[0], row[1], row[2], row[3]))

				except sqlite3.Error as e:
					print("[-] Database Error: %s" % e.args[0])

		except sqlite3.Error as e:
			print("[-] Database Error: %s" % e.args[0])

		print('\n')




	def add_domains(self):

		dbconn=self.connect()

		#conn to db
		cur = dbconn.cursor()
		print('[i] Adding client [ %s ] to database:' % self.clientName)
		c=self.clientName
		#insert rows
		print('ID___ Name___________ Contact____________  Date_______________')


		#check to see if the client name exists, and if it does print it, and if it doesnt add it
		try:
			#look for existing name from supplied arg
			cur.execute("SELECT * FROM client WHERE (name = '%s') " % (c))
			results = cur.fetchall()
			cur.close()

			#if there is a result
			if results is not None:
				#print it
				for row in results:
					print ('%-5s %-15s %-20s %-s' % (row[0], row[1], row[2], row[3]))
			#if there isn't a result
			else:
				#add customer
				try:
					cur.execute("INSERT INTO client (name) VALUES ('%s') " % (c))
					dbconn.commit()
					#and display it
					cur.execute("SELECT * FROM client WHERE (name = '%s') " % (c))
					results = cur.fetchall()
					cur.close()
				except sqlite3.Error as e:
					print("[-] Database Error: %s" % e.args[0])

		except sqlite3.Error as e:
			print("[-] Database Error: %s" % e.args[0])

		print('\n')



	def add_nmap(self):

		dbconn=self.connect()

		#conn to db
		cur = dbconn.cursor()
		print('[i] Adding host [ %s ] to database:' % self.clientName)
		c=self.clientName
		#insert rows
		print('ID___ Name___________ Contact____________  Date_______________')


		#check to see if the client name exists, and if it does print it, and if it doesnt add it
		try:
			#look for existing name from supplied arg
			cur.execute("SELECT * FROM client WHERE (name = '%s') " % (c))
			results = cur.fetchall()
			cur.close()

			#if there is a result
			if results is not None:
				#print it
				for row in results:
					print ('%-5s %-15s %-20s %-s' % (row[0], row[1], row[2], row[3]))
			#if there isn't a result
			else:
				#add customer
				try:
					cur.execute("INSERT INTO client (name) VALUES ('%s') " % (c))
					dbconn.commit()
					#and display it
					cur.execute("SELECT * FROM client WHERE (name = '%s') " % (c))
					results = cur.fetchall()
					cur.close()
				except sqlite3.Error as e:
					print("[-] Database Error: %s" % e.args[0])

		except sqlite3.Error as e:
			print("[-] Database Error: %s" % e.args[0])

		print('\n')

def main():

	dbOps=Database()
	#dbOps.connect()



if __name__ == '__main__':
	main()