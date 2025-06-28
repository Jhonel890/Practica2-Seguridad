#Problema: Crea una clase o un módulo que encapsule las operaciones de cifrado y descifrado simétrico (ej. con AES-GCM). La clase debe tener métodos para generar claves, cifrar mensajes y descifrar mensajes, manejando internamente el IV/Nonce.
#Conceptos a aplicar: Programación orientada a objetos, encapsulación, abstracción de operaciones criptográficas.

import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Simetrico:
    """
    Clase para realizar cifrado y descifrado simétrico con AES-GCM o ChaCha20.
    """

    def __init__(self, algoritmo='AES-GCM'):
        if algoritmo not in ['AES-GCM', 'ChaCha20']:
            raise ValueError("Algoritmo no soportado. Usa 'AES-GCM' o 'ChaCha20'.")
        self.algoritmo = algoritmo
        self.clave = None

    def generar_clave(self, tamano=32):
        """
        Genera y almacena una clave aleatoria.
        """
        self.clave = os.urandom(tamano)
        return self.clave

    def generar_nonce(self, tamano):
        """
        Genera un nonce aleatorio del tamaño especificado.
        """
        return os.urandom(tamano)

    def cifrar(self, mensaje):
        """
        Cifra el mensaje y devuelve el mensaje cifrado, nonce y tag (si aplica).
        """
        if self.clave is None:
            raise ValueError("Primero debes generar la clave con generar_clave()")

        if self.algoritmo == 'AES-GCM':
            nonce = self.generar_nonce(12)
            cipher = Cipher(algorithms.AES(self.clave), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            mensaje_cifrado = encryptor.update(mensaje.encode()) + encryptor.finalize()
            return mensaje_cifrado, nonce, encryptor.tag

        elif self.algoritmo == 'ChaCha20':
            nonce = self.generar_nonce(16)
            cipher = Cipher(algorithms.ChaCha20(self.clave, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            mensaje_cifrado = encryptor.update(mensaje.encode())
            return mensaje_cifrado, nonce, None

    def descifrar(self, mensaje_cifrado, nonce, tag=None):
        """
        Descifra el mensaje utilizando el nonce y el tag (si aplica).
        """
        if self.clave is None:
            raise ValueError("Primero debes generar la clave con generar_clave()")

        if self.algoritmo == 'AES-GCM':
            cipher = Cipher(algorithms.AES(self.clave), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return (decryptor.update(mensaje_cifrado) + decryptor.finalize()).decode()

        elif self.algoritmo == 'ChaCha20':
            cipher = Cipher(algorithms.ChaCha20(self.clave, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(mensaje_cifrado).decode()

    def medir_tiempo(self, mensaje):
        """
        Mide el tiempo de cifrado y descifrado.
        """
        inicio = time.time()
        mensaje_cifrado, nonce, tag = self.cifrar(mensaje)
        tiempo_cifrado = time.time() - inicio
        print(f"Cifrado {self.algoritmo}: {tiempo_cifrado:.4f} segundos")

        inicio = time.time()
        mensaje_descifrado = self.descifrar(mensaje_cifrado, nonce, tag)
        tiempo_descifrado = time.time() - inicio
        print(f"Descifrado {self.algoritmo}: {tiempo_descifrado:.4f} segundos")

        return mensaje_cifrado, mensaje_descifrado


def simular_comunicacion():
    simetrico_aes = Simetrico(algoritmo='AES-GCM')
    simetrico_chacha = Simetrico(algoritmo='ChaCha20')

    simetrico_aes.generar_clave()
    simetrico_chacha.generar_clave()

    mensaje = "Este es un mensaje secreto que será cifrado y descifrado."

    print("\nCifrando y descifrando con AES-GCM:")
    _, descifrado_aes = simetrico_aes.medir_tiempo(mensaje)
    assert mensaje == descifrado_aes, "Error en descifrado AES-GCM"

    print("\nCifrando y descifrando con ChaCha20:")
    _, descifrado_chacha = simetrico_chacha.medir_tiempo(mensaje)
    assert mensaje == descifrado_chacha, "Error en descifrado ChaCha20"


if __name__ == "__main__":
    simular_comunicacion()
