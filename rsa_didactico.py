"""
rsa_didactico.py -- Implementacion didactica de RSA ("textbook RSA") desde cero.

Curso: Criptoanalisis -- Cifrado y Descifrado en RSA
Autor: Nolberto Ismael Rojas Carlos (UNI)

(Se llama rsa_didactico y no rsa para no chocar con la biblioteca `rsa` de PyPI.)

ADVERTENCIA: este codigo es con fines academicos. No usa relleno (padding)
OAEP ni protecciones contra canales laterales; NO debe usarse en produccion.
Para aplicaciones reales use una biblioteca como `cryptography`.

Nota sobre `pow`: las operaciones del informe (cifrar, descifrar) usan nuestra
`exp_modular`. Dentro de Miller-Rabin y del TCR se usa el `pow(a, b, n)` de
Python, que hace lo mismo pero en C; asi la generacion de claves de 2048 bits
tarda segundos y no minutos.
"""
import secrets
from math import gcd

# ===== 1. Aritmetica modular =====

def egcd(a: int, b: int):
    """Algoritmo de Euclides extendido: devuelve (g, x, y) con a*x + b*y = g."""
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inverso_modular(a: int, m: int) -> int:
    """Calcula a^(-1) mod m (existe solo si mcd(a, m) = 1)."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No existe inverso modular")
    return x % m


def exp_modular(base: int, exp: int, mod: int) -> int:
    """Exponenciacion rapida por cuadrados sucesivos (square-and-multiply).
    Equivalente a pow(base, exp, mod); se implementa para fines didacticos."""
    if mod <= 0 or exp < 0:
        raise ValueError("Se requiere mod > 0 y exp >= 0")
    resultado = 1 % mod
    base %= mod
    while exp > 0:
        if exp & 1:                 # bit = 1 -> multiplicar
            resultado = (resultado * base) % mod
        base = (base * base) % mod  # elevar al cuadrado
        exp >>= 1
    return resultado

# ===== 2. Generacion de primos (test de Miller-Rabin) =====

PRIMOS_PEQUENOS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


def es_probable_primo(n: int, rondas: int = 40) -> bool:
    """Test probabilistico de Miller-Rabin. Error <= 4^(-rondas)."""
    if n < 2:
        return False
    for p in PRIMOS_PEQUENOS:
        if n % p == 0:
            return n == p
    # n - 1 = 2^s * d con d impar
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rondas):
        a = secrets.randbelow(n - 3) + 2   # testigo en [2, n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False   # compuesto con certeza
    return True


def _revisar(cancelar):
    """`cancelar` es un threading.Event opcional para abortar desde otro hilo."""
    if cancelar is not None and cancelar.is_set():
        raise InterruptedError("Generacion de claves cancelada")


def generar_primo(bits: int, cancelar=None) -> int:
    """Genera un primo aleatorio de exactamente `bits` bits (bits >= 2)."""
    if bits < 2:
        raise ValueError("Un primo necesita al menos 2 bits")
    while True:
        _revisar(cancelar)
        # Se fuerzan el bit mas significativo (tamano) y el menos (impar)
        candidato = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if es_probable_primo(candidato):
            return candidato

# ===== 3. Generacion de claves, cifrado y descifrado =====

def construir_privada(p: int, q: int, e: int) -> dict:
    """Arma la clave privada a partir de los factores de n = p*q y de e.
    Incluye los parametros del TCR (dp, dq, qinv) y a `e` (para verificar el
    descifrado). Si p == q (n = p^2, caso degenerado) phi = p(p-1) y no hay TCR."""
    n = p * q
    phi = p * (p - 1) if p == q else (p - 1) * (q - 1)
    d = inverso_modular(e, phi)
    if p == q:
        dp = dq = qinv = None
    else:
        dp, dq, qinv = d % (p - 1), d % (q - 1), inverso_modular(q, p)
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq, "qinv": qinv}


def generar_claves(bits: int = 2048, e: int = 65537, cancelar=None):
    """Devuelve (clave_publica, clave_privada) para un modulo de `bits` bits."""
    if bits < 16 or bits % 2:
        raise ValueError("bits debe ser par y al menos 16")
    if e < 3 or e % 2 == 0:
        raise ValueError("e debe ser un entero impar mayor o igual que 3")
    while True:
        p = generar_primo(bits // 2, cancelar)
        q = generar_primo(bits // 2, cancelar)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1 and n.bit_length() == bits:
            break
    return {"n": n, "e": e}, construir_privada(p, q, e)


def cifrar(m: int, publica: dict) -> int:
    """C = M^e mod n"""
    if not 0 <= m < publica["n"]:
        raise ValueError("El mensaje debe cumplir 0 <= M < n")
    return exp_modular(m, publica["e"], publica["n"])


def descifrar(c: int, privada: dict) -> int:
    """M = C^d mod n"""
    if not 0 <= c < privada["n"]:
        raise ValueError("El cifrado debe cumplir 0 <= C < n")
    return exp_modular(c, privada["d"], privada["n"])


def descifrar_crt(c: int, privada: dict) -> int:
    """Descifrado con el Teorema Chino del Resto (~4 veces mas rapido).

    Verifica el resultado re-cifrandolo: un error de calculo en solo una de las
    dos mitades (ataque de Bellcore/Lenstra) permitiria a un atacante factorizar
    n con mcd(M' ^ e - C, n), asi que nunca se devuelve un valor sin comprobar."""
    n = privada["n"]
    if not 0 <= c < n:
        raise ValueError("El cifrado debe cumplir 0 <= C < n")
    if privada.get("qinv") is None:          # n = p^2: no se puede usar el TCR
        return descifrar(c, privada)
    p, q = privada["p"], privada["q"]
    m1 = pow(c, privada["dp"], p)
    m2 = pow(c, privada["dq"], q)
    h = (privada["qinv"] * (m1 - m2)) % p
    m = m2 + h * q
    e = privada.get("e")
    if e is not None and pow(m, e, n) != c:
        raise ArithmeticError("Fallo detectado en el descifrado CRT")
    return m

# ===== 4. Conversion texto <-> entero =====

def texto_a_entero(texto: str) -> int:
    return int.from_bytes(texto.encode("utf-8"), "big")


def entero_a_texto(numero: int, largo: int = None) -> str:
    """Inversa de texto_a_entero. Los bytes 0x00 del inicio no dejan huella en un
    entero; si el mensaje podia empezar por ellos, pasa su `largo` en bytes."""
    if largo is None:
        largo = (numero.bit_length() + 7) // 8
    return numero.to_bytes(largo, "big").decode("utf-8")

# ===== 5. Demostracion =====

if __name__ == "__main__":
    # (a) Ejemplo de juguete con primos pequenos
    p, q, e = 61, 53, 17
    n, phi = p * q, (p - 1) * (q - 1)
    d = inverso_modular(e, phi)
    M = 65
    C = exp_modular(M, e, n)
    print(f"[Juguete] p={p} q={q} n={n} phi={phi} e={e} d={d}")
    print(f"[Juguete] M={M} -> C={C} -> M'={exp_modular(C, d, n)}")

    # (b) Ejemplo real con clave de 2048 bits
    publica, privada = generar_claves(2048)
    mensaje = "Criptoanalisis UNI 2026: RSA funciona!"
    m = texto_a_entero(mensaje)
    c = cifrar(m, publica)
    recuperado = entero_a_texto(descifrar_crt(c, privada))
    print(f"\n[2048 bits] n tiene {publica['n'].bit_length()} bits")
    print(f"[2048 bits] Cifrado (hex, 64 primeros): {hex(c)[:66]}...")
    print(f"[2048 bits] Descifrado: {recuperado}")
    assert recuperado == mensaje
    assert descifrar(c, privada) == descifrar_crt(c, privada)
    print("Verificacion correcta: D(E(M)) = M")
