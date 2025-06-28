#Problema: Aunque no es una derivación directa como en simétrica, investiga cómo se usan las semillas determinísticas para generar pares de claves en criptografía. (Este ejercicio es más conceptual, puede que no haya una implementación directa en bibliotecas comunes fuera de HD Wallets).
#Conceptos a aplicar: Semillas criptográficas, determinismo en generación de claves (blockchain/bitcoin si te interesa).


import os
import binascii
from cryptography.hazmat.primitives.asymmetric import ed25519

def generar_semilla(tamano=32):
    """
    Genera una semilla determinística (clave secreta raíz).
    """
    return os.urandom(tamano)

def clave_desde_semilla(semilla):
    """
    Genera una clave Ed25519 a partir de una semilla fija (determinística).
    """
    clave_privada = ed25519.Ed25519PrivateKey.from_private_bytes(semilla)
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def mostrar_claves(nombre, clave_privada, clave_publica):
    priv_bytes = clave_privada.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = clave_publica.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    print(f"\n{nombre}")
    print(f"Clave privada (hex): {binascii.hexlify(priv_bytes).decode()}")
    print(f"Clave pública (hex): {binascii.hexlify(pub_bytes).decode()}")

def comparar_claves_deterministicas():
    semilla = b'\x00' * 32  # Semilla fija para demostrar determinismo
    print(f" Semilla usada (hex): {binascii.hexlify(semilla).decode()}")

    clave_privada_1, clave_publica_1 = clave_desde_semilla(semilla)
    clave_privada_2, clave_publica_2 = clave_desde_semilla(semilla)

    mostrar_claves("Clave 1", clave_privada_1, clave_publica_1)
    mostrar_claves("Clave 2", clave_privada_2, clave_publica_2)

    assert clave_publica_1.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ) == clave_publica_2.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ), " Las claves no coinciden (no determinístico)"

    print("\n Las claves generadas a partir de la misma semilla son idénticas (determinismo confirmado).")


# Requiere esta importación para formato Raw
from cryptography.hazmat.primitives import serialization

if __name__ == "__main__":
    comparar_claves_deterministicas()
