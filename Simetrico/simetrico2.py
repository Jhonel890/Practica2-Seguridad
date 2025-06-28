#Problema: Cifra una cadena de texto larga utilizando el algoritmo ChaCha20. ChaCha20 es un cifrador de flujo que no requiere padding. Demuestra el cifrado y descifrado.
#Conceptos a aplicar: Cifradores de flujo, nonce, cifrado/descifrado.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Función para cifrar un mensaje usando ChaCha20
def cifrar_mensaje_chacha20(mensaje, clave, nonce):
    cipher = Cipher(algorithms.ChaCha20(clave, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    mensaje_cifrado = encryptor.update(mensaje.encode())
    return mensaje_cifrado

# Función para descifrar un mensaje usando ChaCha20
def descifrar_mensaje_chacha20(mensaje_cifrado, clave, nonce):
    cipher = Cipher(algorithms.ChaCha20(clave, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    mensaje_descifrado = decryptor.update(mensaje_cifrado).decode()
    return mensaje_descifrado

# Simulación de la comunicación

def simular_comunicacion_chacha20():
    # Generación de una clave y un nonce
    clave = os.urandom(32)  # ChaCha20 requiere una clave de 32 bytes
    nonce = os.urandom(16)  # Nonce de 16 bytes para ChaCha20

    print(f"Clave generada: {clave.hex()}")
    print(f"Nonce generado: {nonce.hex()}")

    # Mensaje a cifrar
    mensaje = "Este es un mensaje largo que será cifrado usando el algoritmo ChaCha20."
    print(f"Mensaje original: {mensaje}")

    # Cifrado del mensaje
    mensaje_cifrado = cifrar_mensaje_chacha20(mensaje, clave, nonce)
    print(f"Mensaje cifrado: {mensaje_cifrado.hex()}")

    # Descifrado del mensaje
    mensaje_descifrado = descifrar_mensaje_chacha20(mensaje_cifrado, clave, nonce)
    print(f"Mensaje descifrado: {mensaje_descifrado}")

# Ejecutar la simulación
if __name__ == "__main__":
    simular_comunicacion_chacha20()
    

