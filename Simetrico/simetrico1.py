#Problema: Simula una comunicación entre dos partes (Alice y Bob). Alice genera una clave simétrica, la comparte con Bob (puedes simular esto simplemente pasándola en el código, pero en la realidad sería un problema de intercambio de claves) y luego envía un mensaje cifrado a Bob. Bob usa la clave para descifrar el mensaje.
#Conceptos a aplicar: Modelo emisor/receptor, intercambio de claves (simulado), cifrado/descifrado.VS

from cryptography.fernet import Fernet
def generar_clave():
    return Fernet.generate_key()
def cifrar_mensaje(clave, mensaje):
    fernet = Fernet(clave)
    mensaje_cifrado = fernet.encrypt(mensaje.encode())
    return mensaje_cifrado
def descifrar_mensaje(clave, mensaje_cifrado):
    fernet = Fernet(clave)
    mensaje_descifrado = fernet.decrypt(mensaje_cifrado).decode()
    return mensaje_descifrado
def simular_comunicacion():
    clave = generar_clave()
    print(f"Alice ha generado una clave: {clave.decode()}")
    
    mensaje = "Hola Bob, este es un mensaje secreto."
    print(f"Alice envía el mensaje: {mensaje}")
    
    mensaje_cifrado = cifrar_mensaje(clave, mensaje)
    print(f"Mensaje cifrado enviado a Bob: {mensaje_cifrado.decode()}")
    
    mensaje_descifrado = descifrar_mensaje(clave, mensaje_cifrado)
    print(f"Bob ha descifrado el mensaje: {mensaje_descifrado}")
if __name__ == "__main__":
    simular_comunicacion()
