#!/usr/bin/env python


class ModuleScan:

	def __init__(self,targetSet):

		self.targetSet=targetSet
		self.timeout = 10


	def run(self):
		
		for t in self.targetSet:
			print t

def main():

	runModule=ModuleScan()


if __name__ == '__main__':
	main()		