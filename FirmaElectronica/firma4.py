#Problema: Genera un par de claves ECDSA o EdDSA. Firma un mensaje con la clave privada y verifica la firma con la clave pública. Compara el tamaño de la firma con una firma RSA para una seguridad equivalente.
#Conceptos a aplicar: ECDSA/EdDSA, eficiencia en tamaño de firmas.

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64

def generar_claves_ecdsa():
    clave_privada = ec.generate_private_key(ec.SECP256R1())
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def generar_claves_rsa():
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def firmar_ecdsa(clave_privada, mensaje):
    firma = clave_privada.sign(
        mensaje,
        ec.ECDSA(hashes.SHA256())
    )
    return firma

def verificar_ecdsa(clave_publica, mensaje, firma):
    try:
        clave_publica.verify(
            firma,
            mensaje,
            ec.ECDSA(hashes.SHA256())
        )
        print(" Firma ECDSA verificada correctamente.")
        return True
    except InvalidSignature:
        print(" Firma ECDSA inválida.")
        return False

def firmar_rsa(clave_privada, mensaje):
    firma = clave_privada.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma

def verificar_rsa(clave_publica, mensaje, firma):
    try:
        clave_publica.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(" Firma RSA verificada correctamente.")
        return True
    except InvalidSignature:
        print(" Firma RSA inválida.")
        return False

def comparar_firmas():
    mensaje = b"Mensaje de prueba para firmar."

    print("\n Generando claves ECDSA...")
    priv_ecdsa, pub_ecdsa = generar_claves_ecdsa()
    firma_ecdsa = firmar_ecdsa(priv_ecdsa, mensaje)
    verificar_ecdsa(pub_ecdsa, mensaje, firma_ecdsa)

    print("\n Generando claves RSA...")
    priv_rsa, pub_rsa = generar_claves_rsa()
    firma_rsa = firmar_rsa(priv_rsa, mensaje)
    verificar_rsa(pub_rsa, mensaje, firma_rsa)

    print("\n Comparación de tamaños de firmas:")
    print(f"Tamaño firma ECDSA: {len(firma_ecdsa)} bytes")
    print(f"Tamaño firma RSA:   {len(firma_rsa)} bytes")

if __name__ == "__main__":
    comparar_firmas()
