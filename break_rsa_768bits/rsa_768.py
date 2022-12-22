#author : Br33v - Brenguier Evan
#Date : 20 dec. 2022

from base64 import b64decode
from Crypto.Util.number import *

#Valeurs calculées à partir du site factordb.com, pour une clé RSA de 768 bits donné.
p = 3980750864240649373971...75946388957261768583317
q = 4727721461074353025362...30520711256363590397527

n = p * q

e = 65537 #exposant, valeur donné à partir du résultat de la commande 'openssl rsa -in pubkey.pem -pubin -text -modulus'

phi = (p-1)*(q-1) #nommé "z" ou "phi" selon les docs

d=inverse(e,phi) #inverse modulaire (algo euclide étendu)

ciphertext = b64decode('e8oQDihsmkvjT3sZe+EE8lwNvBEsFegYF6+OOFOiR6gMtMZxxba/bIgLUD8pV3yEf0gOOfHuB5bC3vQmo7bE4PcIKfpFGZBA') #message chiffré

c = bytes_to_long(ciphertext) # bytes -> int

#Pour déchiffrer un message on utilise la formule c^d mod(n) où "c" est le message chiffré
m = pow(c,d,n) #pow(x, y, z) avec "x = base de la puissance" "y = indique la puissance" et "z = indique le modulo" 

print(long_to_bytes(m)) #commande inverse de bytes_to_long, on repasse de int vers bytes
