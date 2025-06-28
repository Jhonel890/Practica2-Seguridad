# Problema: Implementa un escenario donde se puede "revocar" una clave de firma (simulado). Si una clave de firma se compromete, ya no debería poder usarse para firmar documentos válidamente (aunque las firmas antiguas seguirían siendo válidas hasta su expiración o revocación formal).
# Conceptos a aplicar: Revocación de claves, listas de revocación de certificados (CRL) o OCSP (conceptual).

import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Lista simulada de claves públicas revocadas (CRL)
CLAVES_REVOCADAS = []

def generar_clave_firma():
    clave_privada = ed25519.Ed25519PrivateKey.generate()
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def exportar_clave_publica(clave_publica):
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def firmar_documento(clave_privada, mensaje):
    return clave_privada.sign(mensaje)

def verificar_firma(clave_publica, mensaje, firma):
    clave_id = exportar_clave_publica(clave_publica)

    if clave_id in CLAVES_REVOCADAS:
        print(" Esta clave ha sido revocada. No se puede usar para verificar firmas.")
        return False

    try:
        clave_publica.verify(firma, mensaje)
        print(" Firma verificada correctamente.")
        return True
    except InvalidSignature:
        print(" Firma inválida.")
        return False

def revocar_clave(clave_publica):
    clave_id = exportar_clave_publica(clave_publica)
    if clave_id not in CLAVES_REVOCADAS:
        CLAVES_REVOCADAS.append(clave_id)
        print(" Clave pública revocada correctamente.")
    else:
        print("⚠️ La clave pública ya está revocada.")

def simular_revocacion():
    mensaje = b"Este es un documento confidencial."

    print("\n Generando clave de firma de Alice...")
    clave_privada, clave_publica = generar_clave_firma()

    firma = firmar_documento(clave_privada, mensaje)

    verificar_firma(clave_publica, mensaje, firma)

    revocar_clave(clave_publica)

    print("\n Verificando firma (después de revocar)...")
    verificar_firma(clave_publica, mensaje, firma)

    print("\n Firma y la clave pública:")
    print(" Firma:", firma.hex())
    print(" Clave pública:", exportar_clave_publica(clave_publica).hex())

if __name__ == "__main__":
    simular_revocacion()