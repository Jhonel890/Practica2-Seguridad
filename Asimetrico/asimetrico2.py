#Problema: Genera pares de claves para al menos dos algoritmos asimétricos diferentes (ej. RSA y EdDSA o X25519). Compara la longitud de las claves y sus formatos.
#Conceptos a aplicar: Diversidad de algoritmos asimétricos, tamaños de clave.


from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization

def generar_clave_rsa(bits=2048):
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def generar_clave_ed25519():
    clave_privada = ed25519.Ed25519PrivateKey.generate()
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def mostrar_info_clave(nombre, clave_privada, clave_publica):
    priv_pem = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(f"\n {nombre}")
    print(f"Longitud de clave privada (bytes): {len(priv_pem)}")
    print(f"Longitud de clave pública (bytes): {len(pub_pem)}")
    print("Formato clave pública:")
    print(pub_pem.decode())

def comparar_claves():
    # Generar y mostrar información de clave RSA
    clave_privada_rsa, clave_publica_rsa = generar_clave_rsa(2048)
    mostrar_info_clave("RSA 2048", clave_privada_rsa, clave_publica_rsa)

    # Generar y mostrar información de clave Ed25519 (EdDSA)
    clave_privada_eddsa, clave_publica_eddsa = generar_clave_ed25519()
    mostrar_info_clave("Ed25519", clave_privada_eddsa, clave_publica_eddsa)

if __name__ == "__main__":
    comparar_claves()
