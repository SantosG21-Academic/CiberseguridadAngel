from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

# 1- Usar el número primo estándar de Diffie-Hellman (grupo 14 de RFC 3526, 2048 bits)
parameters = dh.DHParameterNumbers(
    p=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
    g=2
).parameters(default_backend())

# Generar claves privadas para Alice, Bob y Eve
def generate_private_key():
    return parameters.generate_private_key() #estas claves son punteros?

alice_private = generate_private_key()
bob_private = generate_private_key()
eve_private = generate_private_key()

#print(alice_private, bob_private, eve_private)
# Extraer las claves privadas como enteros
x_Asecreto = alice_private.private_numbers().x
x_Bsecreto = bob_private.private_numbers().x
x_Esecreto = eve_private.private_numbers().x
#print(x_Asecreto, x_Bsecreto, x_Esecreto)
p = parameters.parameter_numbers().p

#Extraer X publica

x_Apub = pow(2, x_Asecreto, p)
x_Bpub = pow(2, x_Bsecreto, p)
x_Epub = pow(2, x_Esecreto, p)

# 3 - Calcular las claves K secretas según las ecuaciones dadas
K_EtoB = pow(x_Epub, x_Bsecreto, p)
K_AtoE = pow(x_Apub, x_Esecreto, p)

# 3.5 Verificar si las claves son iguales
if K_AtoE == K_EtoB:
    print("Las claves secretas K de Bob y Eve, y la clave K de Alice y Eve son iguales.")
    # Aplicar función hash SHA-256
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(K_EtoB.to_bytes((K_EtoB.bit_length() + 7) // 8, byteorder='big'))
    hashed_key = hasher.finalize()
    print("Clave hash:", hashed_key.hex())
else:
    print(f"Las claves secretas no son iguales. \nK(Bob+Eve): {K_EtoB}, \nK(Alice+Eve): {K_AtoE}")

#---Lo que sigue no es parte de la actividad como tal
print("\nTEST")
K_BtoA = pow(x_Bpub, x_Asecreto, p)

if K_BtoA == K_EtoB or K_BtoA == K_AtoE or K_EtoB == K_AtoE: #BA, EB, AE
    print("Algunas de las claves secretas son iguales. PELIGRO")
else:
    print(f"Las claves secretas no son iguales. \nK(Eve+Bob): {K_AtoE}")