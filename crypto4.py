from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import base64

# Tamaños de clave e IV por algoritmo
TAMANIO_CLAVE = {'DES': 8, '3DES': 24, 'AES-256': 32}
TAMANIO_IV = {'DES': 8, '3DES': 8, 'AES-256': 16}
TAMANIO_BLOQUE = {'DES': 8, '3DES': 8, 'AES-256': 16}

# Solicita los datos de entrada desde la terminal
def solicitar_datos():
    clave = input("Ingrese la clave: ").encode()
    iv = input("Ingrese el IV: ").encode()
    texto = input("Ingrese el texto a cifrar: ").encode()
    return clave, iv, texto

# Ajusta la clave según el tamaño requerido
def ajustar_clave(clave, tamanio, algoritmo):
    if len(clave) < tamanio:
        clave += get_random_bytes(tamanio - len(clave))
    elif len(clave) > tamanio:
        clave = clave[:tamanio]
    
    if algoritmo == '3DES':
        clave = DES3.adjust_key_parity(clave) #ValueError
    
    return clave

# Ajusta el IV según el tamaño requerido
def ajustar_iv(iv, tamanio):
    if len(iv) < tamanio:
        iv += get_random_bytes(tamanio - len(iv))
    elif len(iv) > tamanio:
        iv = iv[:tamanio]
    return iv

# Función para cifrar y descifrar
def cifrar_descifrar(algoritmo, clave, iv, texto):
    try:
        tamanio_clave = TAMANIO_CLAVE[algoritmo]
        tamanio_iv = TAMANIO_IV[algoritmo]
        tamanio_bloque = TAMANIO_BLOQUE[algoritmo]

        clave = ajustar_clave(clave, tamanio_clave, algoritmo)
        iv = ajustar_iv(iv, tamanio_iv)

        print(f"Clave ajustada ({algoritmo}): {binascii.hexlify(clave).decode()}")
        print(f"IV ajustado ({algoritmo}): {binascii.hexlify(iv).decode()}")

        # Selección del cifrador
        if algoritmo == 'DES':
            cipher = DES.new(clave, DES.MODE_CBC, iv)
        elif algoritmo == '3DES':
            cipher = DES3.new(clave, DES3.MODE_CBC, iv)
        elif algoritmo == 'AES-256':
            cipher = AES.new(clave, AES.MODE_CBC, iv)
        else:
            raise ValueError("Algoritmo no soportado")

        # Cifrado
        texto_padded = pad(texto, tamanio_bloque)
        texto_cifrado = cipher.encrypt(texto_padded)
        print(f"Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
        print(f"Texto cifrado (Base64): {base64.b64encode(texto_cifrado).decode()}")

        # Descifrado
        if algoritmo == 'DES':
            decipher = DES.new(clave, DES.MODE_CBC, iv)
        elif algoritmo == '3DES':
            decipher = DES3.new(clave, DES3.MODE_CBC, iv)
        elif algoritmo == 'AES-256':
            decipher = AES.new(clave, AES.MODE_CBC, iv)

        texto_descifrado_padded = decipher.decrypt(texto_cifrado)
        texto_descifrado = unpad(texto_descifrado_padded, tamanio_bloque)
        print(f"Texto descifrado: {texto_descifrado.decode()}")

    except ValueError as e:
        print(f"No se pudo realizar el cifrado y descifrado con {algoritmo}: {e}")

# Ejecución del programa
def main():
    algoritmo = input("Seleccione el algoritmo (DES, 3DES, AES-256): ")
    clave, iv, texto = solicitar_datos()
    cifrar_descifrar(algoritmo, clave, iv, texto)

if __name__ == "__main__":
    main()
