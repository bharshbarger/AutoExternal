#!/usr/bin/env python


import sqlite3


class Database:

	def __init__(self):

		self.autoExtDB = 'AutoExt.db'


	def connect(self):

		try:
			dbconn = sqlite3.connect(self.autoExtDB)
		except sqlite3.Error as e:
			print("[-] Database Error: %s" % e.args[0])
		return dbconn

	def add_client(self):


		#conn to db
		cur = self.dbconn.cursor()
		print('[i] Adding client %s to database:' % self.clientName)
		c=self.clientName
		#insert rows
		try:
			cur.execute("SELECT * FROM client WHERE (name = '%s') " % (c))
			self.dbconn.commit()
		except sqlite3.Error as e:
			print("[-] Database Error: %s" % e.args[0])

		#create new client if existing client doesnt exist
		try:
			cur.execute("INSERT INTO client (name) VALUES ('%s') " % (c))
			self.dbconn.commit()
		except sqlite3.Error as e:
			print("[-] Database Error: %s" % e.args[0])


def main():

	dbOps=Database()
	#dbOps.connect()



if __name__ == '__main__':
	main()