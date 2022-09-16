###############################  parte I- Geração de chaves #####################
#escolher p, q (dois numeros primos)
#gerar um numero aleatorio
import random
#print (p,q)

#usar rabin miller para verificar se é primo
def miller_rabin(n, k):
    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
# mudar depois
def gera_primos():
    n= random.getrandbits(1024)
    if miller_rabin(n,40)== True :
        return n
    return gera_primos()
    
p=17 # gera_primos()
q=11 # gera_primos()


import math

# https://inventwithpython.com/cryptomath.py
# mudar depois
def findModInverse(a, m):
    # Returns the modular inverse of a % m, which is
    # the number x such that a*x % m = 1

    if math.gcd(a, m) != 1:
        return None # no mod inverse if a & m aren't relatively prime

    # Calculate using the Extended Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 # // is the integer division operator
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

print(p,q)

#calcular n=  p*q
n=p*q 

#calcular f(n) = (p-1)(q-1)
fn = (p-1)*(q-1)
print(fn)

#encontrar um e tal que gcd(f(n), e) = 1; 1 < e < f (n)
e = 7 # random.randrange(2, fn)

while (math.gcd(fn, e) != 1):
    e = random.randrange(2, fn)

print(e)
#encontrar d tal que ed mod mod f(n) = 1
d = findModInverse(e, fn)
print(d)

## chaves
chave_privada = (d, n)
chave_publica = (e, n)




#parte II
#parte III
#parte IV
