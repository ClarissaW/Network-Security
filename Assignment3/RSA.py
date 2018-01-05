import math
print("Please enter M, which is an integer")
M = int(input())
print("Please enter e, which is an integer")
e = int(input())
print("Please enter n, which is an integer")
n = int(input())
c = int(math.pow(M,e)%n)
print("The cipher text is " + str(c))