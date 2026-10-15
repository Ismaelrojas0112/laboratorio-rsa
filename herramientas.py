"""
herramientas.py -- Funciones de apoyo para las demos.

  * Cifrado de textos de cualquier largo (por bloques) usando rsa_didactico.py,
    con relleno aleatorio opcional
  * Ataque de factorizacion (Pollard rho, variante de Brent)
  * Preparacion de la consola (UTF-8 y colores ANSI)
"""
import math
import os
import random
import secrets
import sys
import time
from typing import List, Tuple

import rsa_didactico as rsa


def preparar_consola():
    """Consola en UTF-8 y con colores ANSI (tambien en Windows 10/11).
    Solo hace falta en programas que imprimen en la terminal; hay que llamarla
    a proposito (importar este modulo ya no cambia nada)."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if os.name == "nt":
        os.system("")  # activa los codigos ANSI en la consola de Windows


def corto(numero: int, digitos: int = 24) -> str:
    """Muestra un entero grande de forma abreviada."""
    s = str(numero)
    return s if len(s) <= 2 * digitos else f"{s[:digitos]}...{s[-8:]} ({len(s)} digitos)"


# ===================================================================
# 1. Cifrar / descifrar textos de cualquier largo
# ===================================================================
def tamano_bloque(n: int) -> int:
    """Bytes por bloque: cada bloque debe cumplir M < n."""
    return max(1, (n.bit_length() - 1) // 8)


def _longitud_ps_minima(k: int) -> int:
    return 2 if k < 16 else 8


def capacidad_bloque(n: int, relleno: bool = False) -> int:
    """Bytes de texto que caben en un bloque (con relleno caben menos)."""
    k = tamano_bloque(n)
    return max(0, k - 2 - _longitud_ps_minima(k)) if relleno else k


def rellenar(datos: bytes, k: int) -> bytes:
    """Relleno aleatorio tipo PKCS#1 v1.5 simplificado, de exactamente k bytes:
        0x02 || PS (bytes aleatorios distintos de 0) || 0x00 || datos
    El 0x02 inicial garantiza que el bloque ocupa k bytes y que M < n."""
    ps = bytes(secrets.randbelow(255) + 1 for _ in range(k - 2 - len(datos)))
    return b"\x02" + ps + b"\x00" + datos


def quitar_relleno(bloque: bytes) -> bytes:
    """Inversa de `rellenar`. Lanza ValueError si el bloque no tiene el formato."""
    if len(bloque) < 3 or bloque[0] != 2:
        raise ValueError("Bloque sin relleno valido")
    i = bloque.find(b"\x00", 1)
    if i < 2:
        raise ValueError("Bloque sin relleno valido")
    return bloque[i + 1:]


def cifrar_texto(texto: str, publica: dict, relleno: bool = False) -> Tuple[List[int], List[int]]:
    """Divide el texto en bloques y cifra cada uno: C_i = M_i^e mod n.
    Devuelve (bloques cifrados, largo en bytes del texto de cada bloque).

    Sin relleno es RSA de libro: el mismo texto da siempre el mismo cifrado.
    Con relleno cada cifrado lleva bytes aleatorios y el resultado cambia en cada envio."""
    n = publica["n"]
    cap = capacidad_bloque(n, relleno)
    if cap < 1:
        raise ValueError("La clave es demasiado pequena para usar relleno")
    k = tamano_bloque(n)
    datos = texto.encode("utf-8")
    trozos = [datos[i:i + cap] for i in range(0, len(datos), cap)]
    cifrados = [rsa.cifrar(int.from_bytes(rellenar(t, k) if relleno else t, "big"), publica)
                for t in trozos]
    return cifrados, [len(t) for t in trozos]


def desempaquetar(m: int, k: int, relleno: bool, largo: int = None) -> bytes:
    """Entero descifrado -> bytes del texto (quita el relleno si lo hay)."""
    if relleno:
        return quitar_relleno(m.to_bytes(k, "big"))
    return m.to_bytes(largo if largo is not None else (m.bit_length() + 7) // 8, "big")


def descifrar_texto(bloques: list, largos: list, privada: dict, relleno: bool = False) -> str:
    """M_i = C_i^d mod n para cada bloque, y se vuelve a unir el texto."""
    k = tamano_bloque(privada["n"])
    datos = b"".join(desempaquetar(rsa.descifrar_crt(c, privada), k, relleno, l)
                     for c, l in zip(bloques, largos))
    return datos.decode("utf-8", errors="replace")


# ===================================================================
# 2. Criptoanalisis: factorizar n con Pollard rho (Brent)
# ===================================================================
def pollard_brent(n: int, tiempo_max: float = None, cancelar=None):
    """Devuelve un factor no trivial de n, o None si n es primo, se acaba el
    tiempo o se activa `cancelar` (un threading.Event)."""
    if n < 4:
        return None
    if n % 2 == 0:
        return 2
    raiz = math.isqrt(n)
    if raiz * raiz == n:           # cuadrado perfecto: rho puede no converger
        return raiz
    if rsa.es_probable_primo(n):
        return None
    inicio = time.perf_counter()

    def agotado():
        return ((cancelar is not None and cancelar.is_set()) or
                (tiempo_max is not None and time.perf_counter() - inicio > tiempo_max))

    while True:
        y, c, m = random.randrange(1, n), random.randrange(1, n), 128
        g, r, q = 1, 1, 1
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            if agotado():
                return None
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
                if agotado():
                    return None
            r *= 2
        if g == n:  # retroceder paso a paso
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if g != n:
            return g


def romper_clave(publica: dict, tiempo_max: float = None, cancelar=None):
    """Ataque completo: factoriza n, calcula phi y d. Devuelve la clave privada
    reconstruida (el mismo formato que rsa_didactico.generar_claves) o None."""
    p = pollard_brent(publica["n"], tiempo_max, cancelar)
    if p is None:
        return None
    return rsa.construir_privada(p, publica["n"] // p, publica["e"])
