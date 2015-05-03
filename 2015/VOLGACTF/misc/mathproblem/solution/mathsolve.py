#!/usr/bin/env python
#
###############################################################################################	
#   __         __        ___          ___  ___ ___     ___       ___  __       __           
#  /__`  |\/| /  \ |__/ |__     |    |__  |__   |     |__  \  / |__  |__) \ / |  \  /\  \ / 
#  .__/  |  | \__/ |  \ |___    |___ |___ |___  |     |___  \/  |___ |  \  |  |__/ /~~\  |  
#
###############################################################################################
###############################################################################################
#
# VolgaCTF 2015
# MATHPROBLEM (MATH/300) Calculator
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#
###############################################################################################
###############################################################################################	
#   __         __        ___          ___  ___ ___     ___       ___  __       __           
#  /__`  |\/| /  \ |__/ |__     |    |__  |__   |     |__  \  / |__  |__) \ / |  \  /\  \ / 
#  .__/  |  | \__/ |  \ |___    |___ |___ |___  |     |___  \/  |___ |  \  |  |__/ /~~\  |  
#
###############################################################################################

from pwn import *

"""
Greetings, neonate! Let us check if you can solve one particular problem!
You're given a set of integer numbers x0,x1,...,xn and y. Using parenthesis '(' and ')' and regular arithmetic operations '*','/','+','-' over integer numbers you need to find a mathematical expression that involves each and every xi and evaluates to y. Sending the correct expression advances you to the next round.
E.g. if the problem says '137 421 700 746 equals 1395' your solution may look like this '(700-421)*(746/137)'.
N.b. Division operation is done according to regular integer division rules, 
so 746/137 == 5 and (700-421)*(746/137) != (700-421)*746/137.
Round 0. Solve!

"""

import itertools

def getNextProblem(r):
	print r.recvuntil("Solve!\n") # problem description
	return r.recvline().strip()	

def evaluate(expr):
	try:
		return int(eval(expr))  # dat command injection vulnerability
	except:
		return 0

def solveProblem(problem):
	print "solving '%s'" % problem
	p = problem.split("equals")
	l_side = p[0].strip().split(" ")
	r_side = int(p[1])
	operators = ['+', '-', '/', '*']

	for i in itertools.permutations(l_side,4):
		for x in itertools.product(operators, repeat=3): # cartesian product
			test = "%s%s%s%s%s%s%s" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "(%s%s%s)%s%s%s%s" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "(%s%s%s%s%s)%s%s" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "((%s%s%s)%s%s)%s%s" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "(%s%s(%s%s%s))%s%s" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "%s%s%s%s(%s%s%s)" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "%s%s(%s%s%s%s%s)" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "%s%s(%s%s(%s%s%s))" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "%s%s((%s%s%s)%s%s)" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "(%s%s%s)%s(%s%s%s)" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test

			test = "%s%s(%s%s%s)%s%s" % (i[0], x[0], i[1], x[1], i[2], x[2], i[3])
			test_result = evaluate(test)
			#print " %s = %s " % (test, test_result)
			if test_result == r_side:
				print "FOUND! %s" % test
				return test
			
def sendSolution(r, solution):
	r.sendline(solution)

host = "mathproblem.2015.volgactf.ru"
port = 8888

r = remote(host, port)

while True:
	try:
		sendSolution(r, solveProblem(getNextProblem(r)))
	except:
		break;

print r.recvline()
print r.recvline()