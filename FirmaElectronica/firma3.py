#Problema: Genera un par de claves RSA. Crea un "certificado" simple que contenga información sobre la clave pública y firme este certificado con la misma clave privada. Este es un certificado auto-firmado, útil para entender el concepto de la cadena de confianza.
#Conceptos a aplicar: Certificados digitales (estructura básica), auto-firma, PKI (conceptual).

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import datetime
import json
import base64

# Lista simulada de certificados revocados (CRL) por serial_number
CERTIFICADOS_REVOCADOS = set()

# Generador simple de número de serie (puedes mejorarlo si deseas)
SERIAL_NUMBER_GLOBAL = 1

def generar_clave_rsa():
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def exportar_clave_publica(clave_publica):
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def firmar_certificado(clave_privada, certificado):
    firma = clave_privada.sign(
        certificado.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(firma).decode('utf-8')

def obtener_serial(certificado_json):
    certificado = json.loads(certificado_json)
    return certificado["serial_number"]

def verificar_certificado(clave_publica, certificado_json, firma):
    serial = obtener_serial(certificado_json)
    if serial in CERTIFICADOS_REVOCADOS:
        print(" Este certificado ha sido revocado. No se puede usar para verificar.")
        return False

    try:
        clave_publica.verify(
            base64.b64decode(firma),
            certificado_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(" Certificado verificado correctamente.")
        return True
    except InvalidSignature:
        print(" Firma de certificado inválida.")
        return False

def revocar_certificado(certificado_json):
    serial = obtener_serial(certificado_json)
    if serial not in CERTIFICADOS_REVOCADOS:
        CERTIFICADOS_REVOCADOS.add(serial)
        print(" Certificado revocado correctamente.")
    else:
        print("⚠️ El certificado ya está revocado.")

def crear_certificado(clave_publica, informacion):
    global SERIAL_NUMBER_GLOBAL
    certificado = {
        "version": 1,
        "serial_number": SERIAL_NUMBER_GLOBAL,
        "issuer": "CA Auto-Firmada",
        "subject": informacion,
        "public_key": exportar_clave_publica(clave_publica).decode('utf-8'),
        "valid_from": datetime.datetime.utcnow().isoformat(),
        "valid_to": (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
    }
    SERIAL_NUMBER_GLOBAL += 1
    return json.dumps(certificado, indent=4)

def simular_certificado():
    informacion = {
        "common_name": "Alice",
        "organization": "Empresa XYZ",
        "country": "ES"
    }

    print("\n Generando clave RSA de Alice...")
    clave_privada, clave_publica = generar_clave_rsa()

    certificado = crear_certificado(clave_publica, informacion)
    firma = firmar_certificado(clave_privada, certificado)

    print("\n Verificando certificado...")
    verificar_certificado(clave_publica, certificado, firma)

    revocar_certificado(certificado)

    print("\n Verificando certificado (después de revocar)...")
    verificar_certificado(clave_publica, certificado, firma)

    print("\n Certificado y firma:")
    print(" Certificado:", certificado)
    print(" Firma:", firma)

if __name__ == "__main__":
    simular_certificado()
