# M is message, K is the key, mode is the encryption or decryption
#get message, the plaintext
def getMessage():
    print("Please enter the message")
    M = input()
    return M
#get the key of caesar cipher
def get_CaesarKey():
    print("Please enter the key number (1-26) ")
    K = int(input())
    return K

#get the key of vigenere cipher
def get_VigenereKey():
    print("Please enter the key")
    K = input()
    return K

#get the key of matrix transposition cipher
def get_TranspositionKey():
    print("Please enter the key, and do not enter space")
    K = input()
    return K

#the process of encryption and decryption of caesar cipher
def Caesar(mode,M,K):
    output = ""
    if mode == 'd':
        K = -K
    for char in M:
        asc = ord(char)
        result = asc + K
        # Capital
        if asc >=65 and asc <= 90:
            if result>=65 and result <=90:
                output += chr(result)
            elif K>0:
                output += chr(result-26)
            else:
                output += chr(result+26)
        # Lowercase
        if asc>=97 and asc <=122:
            if result >= 97 and result <= 122:
                output += chr(result)
            elif K>0:
                output += chr(result-26)
            else:
                output += chr(result+26)
    print("The result is :", output)

#the process of encryption and decryption of vigenere cipher
def Vigenere(mode,M,K):
    output = ""
    M = M.upper()
    K = K.upper()
#make the length of key and message be the same
    while (len(K)<len(M)):
        K += K
    if len(K)>len(M):
        K = K[0:len(M)]
    for i in range(0,len(M)):
        pt = int(ord(M[i]))-65
        key = int(ord(K[i]))-65
        if mode == 'd':
            if (pt-key<0):
                number = pt-key+26+65
            else:
                number = pt-key+65
        else:
            number = pt+key+65
        if number > 90:
            number = number - 26
        output += chr(number)
    print("The result is :", output)

#the process of encryption and decryption of matrix transpositon cipher
def Transposition(mode,M,K):
    Key = []
    # M = M.lower()
    if " " in M:
        M = M.replace(" ","%")
    pt = ""
    ct = ""
    matrix = [''] * len(K)
    for item in M:
        pt += item
    for item in K:
        Key.append(item)
    if len(pt) % len(K) != 0:
        len_group = int(len(pt)/len(K) + 1)
    else:
        len_group = int(len(pt)/len(K))
    while len_group * len(K) > len(pt):
        pt += "%"
#encryption
    if mode == 'e':
        for i in range(len(K)):
            j = i
            while j < len(pt):
                matrix[i] += pt[j]
                j += len(K)
        for i in range(len(K)):
            ct += matrix[int(Key[i]) - 1]
        print("The result is :", ct)

#decryption
    if mode == 'd':
        for i in range(1, len(K) + 1):
            j = (i - 1) * len_group
            while j < len_group * i:
                matrix[i - 1] += pt[j]
                j += 1
        m = 0
        while m < len_group:
            for i in range(len(K)):
                for j in range(len(K)):
                    if int(Key[j]) == i + 1:
                        ct += matrix[j][m]
            m += 1
        if "%" in ct:
            ct = ct.replace("%", " ")
        print("The result is :", ct)

#provide the choices of each cipher
print("Caesar cipher, Press 1")
print("Vigenere cipher, Press 2")
print("Matrix transposition cipher, Press 3")
print("Please choose one cipher, 1 or 2 or 3")
choose = input()
#get the mode, encryption or decryption
print("Do you want to encrypt or decrypt the message? Enter 'e' or 'd' ")
mode = input().lower()
M = getMessage()
if choose == '1':
    K = get_CaesarKey()
    Caesar(mode,M,K)
if choose == '2':
    K = get_VigenereKey()
    Vigenere(mode,M,K)
if choose == '3':
    K = get_TranspositionKey()
    Transposition(mode,M,K)