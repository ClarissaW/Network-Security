from random import randint

p = int(input("Please enter p : "))
g = int(input("Please enter g : "))
SA = randint(1,1000) # from 1 to 1000 and 1000 is not included
SB = randint(1,1000)
print("The secret key SA is ",SA)
print("The secret key SB is ",SB)

TA = (g**SA)%p
TB = (g**SB)%p
key_A = (TB**SA)%p
key_B = (TA**SB)%p
if key_A == key_B:
    print(key_A," is the secret key.")