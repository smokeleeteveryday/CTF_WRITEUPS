#!/usr/bin/python
#
# Plaid CTF 2015
# Clifford (REVERSING/100)
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from constraint import *
import string

def bfsize(order):
    return (3 * order * order + -3 * order + 1)

def solve(order, k_val):
    # Set of possible values for cells
    charset = range(0, bfsize(order)+1)
    # Magic number sum
    magic_number = 20 + k_val
    # Already chosen
    picked = [9, 11, k_val]
    # Not yet chosen
    free_charset = [x for x in charset if not(x in picked)]
    # All cell names
    all_variables = string.lowercase[:len(string.lowercase)-1]
    # Free variables
    free_variables = all_variables.replace('a','').replace('f', '').replace('k', '')
    # Variables for which the uniqueness constraint holds
    diff_variables = [x for x in all_variables if not(x in ['d','e','j','p','u','v'])]

    problem = Problem()
    # Pre-set variables
    problem.addVariable('a', charset)
    problem.addVariable('k', charset)
    problem.addVariable('f', charset)
    # Free variables
    problem.addVariables(free_variables, free_charset)

    # Base constraints
    problem.addConstraint(lambda field: field==9, ['a'])
    problem.addConstraint(lambda field: field==0, ['d'])
    problem.addConstraint(lambda field: field==0, ['e'])
    problem.addConstraint(lambda field: field==11, ['f']) # 11 = 20 - 9
    problem.addConstraint(lambda field: field==0, ['j'])
    problem.addConstraint(lambda field: field==k_val, ['k'])
    problem.addConstraint(lambda field: field==0, ['p'])
    problem.addConstraint(lambda field: field==0, ['u'])
    problem.addConstraint(lambda field: field==0, ['v'])

    # Uniqueness constraint
    problem.addConstraint(AllDifferentConstraint(), diff_variables)

    # Rows & Columns

    block_size = 5
    rows = [all_variables[i:i+block_size] for i in range(0, len(all_variables), block_size)]
    columns = []
    for i in xrange(block_size):
        column = ""
        for j in xrange(len(rows)):
            column += rows[j][i]
        columns.append(column)

    # Row, column & diagonal sum constraints

    for i in xrange(len(rows)):
        problem.addConstraint(ExactSumConstraint(magic_number), rows[i])

    for i in xrange(len(columns)):
        problem.addConstraint(ExactSumConstraint(magic_number), columns[i])

    problem.addConstraint(ExactSumConstraint(magic_number), 'agmsy')
    problem.addConstraint(ExactSumConstraint(magic_number), 'flrx')
    problem.addConstraint(ExactSumConstraint(magic_number), 'kqw')

    solution = problem.getSolution()
    if (solution):
        print "[+]Solution: "
        print solution
        return True
    else:
        return False

order = 3
for i in xrange(0, bfsize(order)+1):
    if(i == 9):
        continue

    print "[*]Trying k=%d" % i

    if(solve(order, i)):
        exit()

print "[-]Got nothing :("