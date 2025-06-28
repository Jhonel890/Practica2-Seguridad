#Problema: Simula un intercambio de claves Diffie-Hellman entre dos partes. Alice y Bob generan sus claves privadas y públicas DH, calculan el secreto compartido y verifican que ambos llegan al mismo secreto.
#Conceptos a aplicar: Intercambio de claves Diffie-Hellman, secreto compartido.

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generar_parametros_dh():
    """
    Genera los parámetros del grupo Diffie-Hellman (primo y generador).
    Se comparten entre ambas partes.
    """
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())


def generar_claves_dh(parametros):
    """
    Genera un par de claves (privada y pública) DH a partir de los parámetros comunes.
    """
    clave_privada = parametros.generate_private_key()
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica


def derivar_secreto(clave_privada, clave_publica_peer):
    """
    A partir de la clave privada propia y la clave pública del otro,
    se genera el secreto compartido.
    """
    secreto_compartido = clave_privada.exchange(clave_publica_peer)

    # Opcional: derivar clave simétrica con KDF
    clave_final = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'intercambio DH',
        backend=default_backend()
    ).derive(secreto_compartido)

    return clave_final


def simular_intercambio_dh():
    print(" Simulando intercambio de claves Diffie-Hellman entre Alice y Bob...\n")

    # 1. Ambos comparten los mismos parámetros del grupo DH
    parametros = generar_parametros_dh()

    # 2. Generan sus pares de claves
    priv_alice, pub_alice = generar_claves_dh(parametros)
    priv_bob, pub_bob = generar_claves_dh(parametros)

    # 3. Intercambian claves públicas y derivan el secreto compartido
    secreto_alice = derivar_secreto(priv_alice, pub_bob)
    secreto_bob = derivar_secreto(priv_bob, pub_alice)

    # 4. Verifican que el secreto sea el mismo
    print(f"Secreto de Alice: {secreto_alice.hex()}")
    print(f"Secreto de Bob:   {secreto_bob.hex()}")

    assert secreto_alice == secreto_bob, " Los secretos no coinciden."
    print("\n Secreto compartido verificado correctamente.")

if __name__ == "__main__":
    simular_intercambio_dh()
