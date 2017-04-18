#!/usr/bin/env python

try:
	import sqlite3
except ImportError as e:
	raise ImportError('Error importing %s' % e)

class Database():
	def __init__(self):
		
		#vars
		self.autoExtDB = 'AutoExt.db'

	def createdatabase(self):

		# Database Connection

		try:
			connection = sqlite3.connect(self.autoExtDB)
			c = connection.cursor()

			#Create table
			c.execute('''CREATE TABLE client(
				ID INTEGER PRIMARY KEY,
				name text, 
				contact text, 
				Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
				UNIQUE(name))''')
			
			c.execute('''CREATE TABLE scope(
				ID INTEGER PRIMARY KEY,
				ip text,
				client_id integer, 
				FOREIGN KEY(client_id) REFERENCES client(ID))''')
			
			c.execute('''CREATE TABLE findings(
				ID INTEGER PRIMARY KEY, 
				title text, 
				name text, 
				ip text, 
				dread_id integer,
				client_id integer,
				FOREIGN KEY(client_id) REFERENCES client(ID)) ''')
			
			c.execute('''CREATE TABLE nmap(
				ID INTEGER PRIMARY KEY, 
				ip text, 
				port text, 
				protcol text, 
				state text,
				client_id integer, 
				FOREIGN KEY(client_id) REFERENCES client(ID))''')
			
			c.execute('''CREATE TABLE dread(
				ID INTEGER PRIMARY KEY, 
				damage integer, 
				reproducibility integer, 
				exploitability integer, 
				affected_users integer, 
				discoverability integer,
				client_id integer, 
				FOREIGN KEY(client_id) REFERENCES client(ID))''')
			
			c.execute('''CREATE TABLE domains(
				ID INTEGER PRIMARY KEY, 
				name text, 
				client_id integer, 
				FOREIGN KEY(client_id) REFERENCES client(ID))''')



			# Commit and close connection to database
			connection.commit()
			connection.close()

		except sqlite3.Error as e:
			print(" [-] Database Error: %s" % e.args[0])

def main():
	createDb = Database()
	createDb.createdatabase()


if __name__ == '__main__':
	main()
