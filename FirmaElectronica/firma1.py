# Problema: Un documento necesita ser firmado por dos partes diferentes. Alice firma el documento, y luego Bob también lo firma (esto puede ser una firma secuencial sobre el mismo documento o dos firmas separadas que se adjuntan). Verifica ambas firmas.
# Conceptos a aplicar: Múltiples firmantes, concatenación de firmas.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generar_clave_privada():
    """
    Genera una clave privada RSA.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def firmar_documento(clave_privada, documento):
    """
    Firma un documento utilizando la clave privada RSA.
    """
    firma = clave_privada.sign(
        documento,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma

def verificar_firma(clave_publica, documento, firma):
    """
    Verifica la firma de un documento utilizando la clave pública RSA.
    """
    try:
        clave_publica.verify(
            firma,
            documento,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Error al verificar la firma: {e}")
        return False

def simular_firma_documento():
    print("Simulando firma de documento por Alice y Bob...\n")

    # 1. Alice genera su clave privada y pública
    clave_privada_alice = generar_clave_privada()
    clave_publica_alice = clave_privada_alice.public_key()
    print("Clave pública de Alice generada:")
    print(clave_publica_alice.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())

    # 2. Bob genera su clave privada y pública
    clave_privada_bob = generar_clave_privada()
    clave_publica_bob = clave_privada_bob.public_key()
    print("Clave pública de Bob generada:")
    print(clave_publica_bob.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())

    # 3. Documento a firmar
    documento = b"Este es un documento importante."
    print(f"\nDocumento a firmar: {documento.decode()}")

    # 4. Alice firma el documento
    firma_alice = firmar_documento(clave_privada_alice, documento)
    print("\nFirma de Alice generada (hex):")
    print(firma_alice.hex())

    # 5. Bob firma el mismo documento
    firma_bob = firmar_documento(clave_privada_bob, documento)
    print("\nFirma de Bob generada (hex):")
    print(firma_bob.hex())

    # 6. Verificar firmas
    print("\nVerificando firma de Alice...")
    if verificar_firma(clave_publica_alice, documento, firma_alice):
        print(" Firma de Alice verificada correctamente.")
    else:
        print(" Firma de Alice no válida.")

    print("\nVerificando firma de Bob...")
    if verificar_firma(clave_publica_bob, documento, firma_bob):
        print(" Firma de Bob verificada correctamente.")
    else:
        print(" Firma de Bob no válida.")

if __name__ == "__main__":
    simular_firma_documento()