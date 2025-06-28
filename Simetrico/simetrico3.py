#Problema: Cifra un archivo grande (ej. 10MB) tanto con AES en modo GCM como con ChaCha20. Mide el tiempo que tarda cada algoritmo en cifrar y descifrar.
#Conceptos a aplicar: Rendimiento de algoritmos, comparación de cifradores.

import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def cifrar_aes_gcm(data, clave):
    nonce = generar_nonce(12)  # Para AES GCM el nonce recomendado es de 12 bytes
    cipher = Cipher(algorithms.AES(clave), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    mensaje_cifrado = encryptor.update(data) + encryptor.finalize()
    return nonce, mensaje_cifrado, encryptor.tag

def descifrar_aes_gcm(mensaje_cifrado, clave, nonce, tag):
    cipher = Cipher(algorithms.AES(clave), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(mensaje_cifrado) + decryptor.finalize()

def cifrar_chacha20(data, clave, nonce):
    cipher = Cipher(algorithms.ChaCha20(clave, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def descifrar_chacha20(mensaje_cifrado, clave, nonce):
    cipher = Cipher(algorithms.ChaCha20(clave, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(mensaje_cifrado)

def medir_tiempo_algoritmo(nombre, cifrar_func, descifrar_func, *args):
    inicio = time.time()
    cifrado = cifrar_func(*args)
    tiempo_cifrado = time.time() - inicio
    print(f"Cifrado {nombre}: {tiempo_cifrado:.4f} segundos")

    if nombre == "AES GCM":
        nonce, mensaje_cifrado, tag = cifrado
        inicio = time.time()
        descifrado = descifrar_func(mensaje_cifrado, args[1], nonce, tag)
    else:
        mensaje_cifrado = cifrado
        inicio = time.time()
        descifrado = descifrar_func(mensaje_cifrado, *args[1:])
    
    tiempo_descifrado = time.time() - inicio
    print(f"Descifrado {nombre}: {tiempo_descifrado:.4f} segundos")

    return mensaje_cifrado, descifrado

def comparar_algoritmos_memoria():
    clave_aes = generar_clave(32)
    clave_chacha = generar_clave(32)
    nonce_chacha = generar_nonce(16)
    
    print("Creando archivo de prueba en memoria...")
    datos = os.urandom(10 * 1024 * 1024)  # 10MB

    print("\nComparando AES GCM")
    cifrado_aes, descifrado_aes = medir_tiempo_algoritmo("AES GCM", cifrar_aes_gcm, descifrar_aes_gcm, datos, clave_aes)
    
    print("\nComparando ChaCha20")
    cifrado_chacha, descifrado_chacha = medir_tiempo_algoritmo("ChaCha20", cifrar_chacha20, descifrar_chacha20, datos, clave_chacha, nonce_chacha)
    
    assert descifrado_aes == datos, "El descifrado AES GCM no coincide con el original"
    assert descifrado_chacha == datos, "El descifrado ChaCha20 no coincide con el original"
    print("\nLos mensajes descifrados coinciden con el original.")

def generar_clave(tamano):
    """Genera una clave aleatoria de un tamaño específico."""
    return os.urandom(tamano)
def generar_nonce(tamano):
    """Genera un nonce aleatorio de un tamaño específico."""
    return os.urandom(tamano)   


if __name__ == "__main__":
    comparar_algoritmos_memoria()
