#Problema: Implementa un mecanismo (simulado) para solicitar una contraseña al usuario al cargar la clave privada RSA de un archivo, garantizando que la clave privada esté protegida.
#Conceptos a aplicar: Protección de clave privada, cifrado de clave privada en reposo.

import os
import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
def cargar_clave_privada(ruta_archivo):
    """
    Carga una clave privada RSA desde un archivo, solicitando una contraseña al usuario.
    """
    contrasena = getpass.getpass("Introduce la contraseña para cargar la clave privada: ")
    
    try:
        with open(ruta_archivo, "rb") as archivo:
            clave_privada = serialization.load_pem_private_key(
                archivo.read(),
                password=contrasena.encode(),
                backend=default_backend()
            )
        print("Clave privada cargada correctamente.")
        print("Clave cifrada:", clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        return clave_privada
    except Exception as e:
        print(f"Error al cargar la clave privada: {e}")
        return None
def guardar_clave_privada(clave_privada, ruta_archivo, contrasena):
    """
    Guarda una clave privada RSA en un archivo, cifrada con una contraseña.
    """
    try:
        with open(ruta_archivo, "wb") as archivo:
            archivo.write(
                clave_privada.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(contrasena.encode())
                )
            )
        print("Clave privada guardada correctamente.")
    except Exception as e:
        print(f"Error al guardar la clave privada: {e}")
# Ejemplo de uso
if __name__ == "__main__":
    # Generar una clave privada RSA (esto es solo un ejemplo, normalmente se generaría una vez)
    from cryptography.hazmat.primitives.asymmetric import rsa
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Guardar la clave privada en un archivo
    ruta_archivo = "clave_privada.pem"
    contrasena = getpass.getpass("Introduce una contraseña para guardar la clave privada: ")
    guardar_clave_privada(clave_privada, ruta_archivo, contrasena)
    
    # Cargar la clave privada desde el archivo
    cargar_clave_privada(ruta_archivo)

