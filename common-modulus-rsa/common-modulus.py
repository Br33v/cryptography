#############################################
# Autor: @Br33v
# Date: 22 dec. 2022
#Source: https://infosecwriteups.com/rsa-attacks-common-modulus-7bdb34f331a5 && https://blog.0daylabs.com/2015/01/17/rsa-common-modulus-attack-extended-euclidean-algorithm/
#############################################

import math
from base64 import b64decode
from Crypto.Util.number import *
from binascii import unhexlify

e1 = 65537
e2 = 343223
#si gcd(e1, e2) = 1, alors on a des entiers x et y tels que : xe1 + ye2 = gcd(e1, e2) : Theorème de Bézout
# C1 = M^e1 et C2 = M^e2
#On peut déduire: C1^x*C2^y = (M^e1)^x*(M^e2)^y = M^(xe1 + ye2) = M^gcd(e1, e2) = M^1 = M

n = int("AD6DD400CDD68EEC61D7C54B1567E16671D7401EBBA0ABE6B391575F8271EEEAD78ADE10D0964D0174DCFD2E5413DC1A075E0E7F83D143BF76C1C1ABA5A501103E518C5171149D0009EBD29255A2F11DBE5699BD2FA97FEAC9229CF07B1EAADE706D79253AB9D97872771E6DE651E22996958F7F5F42EA0A0DDDB506AEB9E2C3",16)

C1 = bytes_to_long(b64decode("BzFd4riBUZdFuPCkB3LOh+5iyMImeQ/saFLVD+ca2L8VKSz0+wtTaL55RRpHBAQdl24Fb3XyVg2N9UDcx3slT+vZs7tr03W7oJZxVp3M0ihoCwer3xZNieem8WZQvQvyNP5s5gMT+K6pjB9hDFWWmHzsn7eOYxRJZTIDgxA4k2w="))
C2 = bytes_to_long(b64decode("jmVRiKyVPy1CHiYLl8fvpsDAhz8rDa/Ug87ZUXZ//rMBKfcJ5MqZnQbyTJZwSNASnQfgel3J/xJsjlnf8LoChzhgT28qSppjMfWtQvR6mar1GA0Ya1VRHkhggX1RUFA4uzL56X5voi0wZEpJITUXubbujDXHjlAfdLC7BvL/5+w="))

#Pour trouver x, nous partons du principe que gcd(e1, e2) = 1, nous pouvons donc dire que x est l'inverse modulaire de e1 et e2
x = inverse(e1, e2)

#(e1*x) + (e2*y) = gcd(e1, e2)
#Maintenant que nous connaissons x, nous n'avons plus qu'à trouver y (en changeant les valeurs de la formule ci-dessus)
y = int((math.gcd(e1,e2) - e1 * x) / e2)

#Dans de nombreux cas, la valeur de b devra être négatif. Nous allons utiliser "i" qui est l'inverse multiplicatif modulaire de C2.
i = inverse(C2, n)

#On calcul le message en utilisant la formule suivante: M = (C1^x * i^-y) % n
M = (pow(C1,x,n)*pow(i,-y,n)) % n  

PlainText = hex(M)[2:]
print(unhexlify(PlainText))
