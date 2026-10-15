"""
pasos.py -- Calculos de RSA "paso a paso" (sin interfaz grafica).

Genera, para unos p, q, e y un mensaje M dados, la lista de pasos que se
muestran en la opcion 2 del laboratorio: n, phi(n), Euclides extendido,
cuadrados sucesivos, cifrado, descifrado, TCR y verificacion.
Usa las funciones de rsa_didactico.py (tu implementacion del informe).
"""
import math

import rsa_didactico as rsa

LIMITE = 10 ** 19      # p y q hasta 19 digitos (la tabla sigue siendo legible)
MAX_FILAS = 22         # una tabla mas larga se resume (primeras y ultimas filas)


# ---------------------------------------------------------------------------
# Validacion de lo que escribe el usuario
# ---------------------------------------------------------------------------
def _entero(texto, nombre):
    try:
        return int(texto.strip().replace(" ", "").replace("_", ""))
    except ValueError:
        raise ValueError(f"{nombre} debe ser un número entero.")


def validar(p_txt, q_txt, e_txt, m_txt):
    """Devuelve (p, q, e, M, texto). Lanza ValueError con un mensaje claro."""
    p, q, e = _entero(p_txt, "p"), _entero(q_txt, "q"), _entero(e_txt, "e")
    for nombre, v in (("p", p), ("q", q)):
        if v < 3 or v >= LIMITE:
            raise ValueError(f"{nombre} debe ser un primo impar menor que 10^19.")
        if not rsa.es_probable_primo(v):
            raise ValueError(f"{nombre} = {v} no es primo.")
    if p == q:
        raise ValueError("p y q deben ser primos distintos.")
    n, phi = p * q, (p - 1) * (q - 1)
    if not 1 < e < phi:
        raise ValueError(f"e debe cumplir 1 < e < φ(n) = {phi}.")
    g = math.gcd(e, phi)
    if g != 1:
        raise ValueError(f"e = {e} no sirve porque mcd(e, φ(n)) = {g}. "
                         f"Prueba con otro valor (por ejemplo 17 o 65537).")
    m_txt = m_txt.strip()
    if not m_txt:
        raise ValueError("Escribe un mensaje: un número o un texto corto.")
    if m_txt.isdigit():
        m, texto = int(m_txt), None
    else:
        texto = m_txt
        m = int.from_bytes(texto.encode("utf-8"), "big")
    if m >= n:
        raise ValueError(f"El mensaje, como número, vale {m} y debe ser menor que "
                         f"n = {n}. Usa un mensaje más corto o primos más grandes.")
    return p, q, e, m, texto


# ---------------------------------------------------------------------------
# Algoritmos con tabla
# ---------------------------------------------------------------------------
def euclides_extendido(phi, e):
    """Filas (cociente, resto, t). La fila con resto = mcd da t tal que e*t = mcd (mod phi)."""
    filas = [(None, phi, 0), (None, e, 1)]
    r0, t0, r1, t1 = phi, 0, e, 1
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
        filas.append((q, r1, t1))
    return filas


def cuadrados_sucesivos(base, exp, n):
    """Filas (i, bit, base^(2^i) mod n, acumulado) y el resultado base^exp mod n."""
    filas, acumulado, b, i = [], 1, base % n, 0
    while exp > 0:
        bit = exp & 1
        if bit:
            acumulado = acumulado * b % n
        filas.append((i, bit, b, acumulado))
        b = b * b % n
        exp >>= 1
        i += 1
    return filas, acumulado


def formatear_tabla(cabeceras, filas, resaltar=()):
    """Devuelve lineas [(texto, etiqueta)] con la tabla alineada en monoespacio."""
    cuerpo = [["—" if c is None else str(c) for c in f] for f in filas]
    indices = list(range(len(cuerpo)))
    if len(cuerpo) > MAX_FILAS:                     # resumir tablas largas
        indices = indices[:10] + [None] + indices[-5:]
    anchos = [max(len(str(h)), *(len(f[j]) for f in cuerpo)) for j, h in enumerate(cabeceras)]
    sep = "  "
    lineas = [(sep.join(str(h).center(a) for h, a in zip(cabeceras, anchos)), "tabla_cab"),
              (sep.join("─" * a for a in anchos), "tabla")]
    for k in indices:
        if k is None:
            lineas.append((sep.join("⋮".center(a) for a in anchos), "tabla"))
        else:
            fila = sep.join(c.rjust(a) for c, a in zip(cuerpo[k], anchos))
            lineas.append((fila + ("   ◀" if k in resaltar else ""),
                           "resalte" if k in resaltar else "tabla"))
    return lineas


# ---------------------------------------------------------------------------
# Construccion de los pasos
# ---------------------------------------------------------------------------
def _bits_texto(valor):
    b = bin(valor)[2:]
    return f"({b})₂" if len(b) <= 40 else f"un número de {len(b)} bits"


def construir_pasos(p, q, e, m, texto=None):
    """Devuelve una lista de (titulo, [(linea, etiqueta), ...])."""
    n, phi = p * q, (p - 1) * (q - 1)
    pasos = []

    pasos.append(("Paso 1 · Elegir dos primos distintos", [
        (f"p = {p}", "formula"),
        (f"q = {q}", "formula"),
        ("Los dos pasan el test de primalidad de Miller–Rabin.", "nota"),
        ("En la práctica p y q tienen unos 1024 bits (≈ 309 dígitos) cada uno.", "nota"),
    ]))

    pasos.append(("Paso 2 · Calcular el módulo n", [
        (f"n = p · q = {p} · {q} = {n}", "formula"),
        (f"n tiene {n.bit_length()} bits y es PÚBLICO: formará parte de las dos claves.", "nota"),
    ]))

    pasos.append(("Paso 3 · Calcular φ(n)", [
        (f"φ(n) = (p − 1)(q − 1) = {p - 1} · {q - 1} = {phi}", "formula"),
        ("Para calcular φ(n) hay que conocer p y q, por eso se mantiene SECRETO.", "nota"),
    ]))

    filas = euclides_extendido(phi, e)
    divisiones = [(f"{filas[i - 2][1]} = {filas[i][0]} · {filas[i - 1][1]} + {filas[i][1]}", "tabla")
                  for i in range(2, len(filas))]
    pasos.append(("Paso 4 · Elegir e (debe ser coprimo con φ(n))", [
        (f"e = {e}", "formula"),
        (f"Comprobamos mcd({e}, {phi}) con el algoritmo de Euclides:", "nota"),
        *divisiones,
        ("mcd = 1 ✓  →  e es válido", "resultado"),
    ]))

    fila_mcd = len(filas) - 2
    t = filas[fila_mcd][2]
    d = t % phi
    producto = e * d
    pasos.append(("Paso 5 · Calcular d = e⁻¹ mod φ(n)  (Euclides extendido)", [
        ("Se sigue el mismo algoritmo, llevando el coeficiente t de e en cada fila:", "nota"),
        *formatear_tabla(("i", "cociente q", "resto r", "t"),
                         [(i, *f) for i, f in enumerate(filas)], resaltar={fila_mcd}),
        (f"La fila con r = 1 da t = {t}   →   d = t mod φ(n) = {t} mod {phi} = {d}", "resultado"),
        (f"Comprobación: e · d = {e} · {d} = {producto} = {producto // phi} · {phi} + {producto % phi} ✓", "formula"),
    ]))

    pasos.append(("Paso 6 · Las dos claves", [
        (f"Clave pública:  (n, e) = ({n}, {e})", "resultado"),
        (f"Clave privada:  (n, d) = ({n}, {d})", "resultado"),
        ("Se publica (n, e). Se guardan en secreto d, p, q y φ(n).", "nota"),
    ]))

    cabecera_msg = ([(f"Mensaje «{texto}»  →  se convierte en el número M = {m}", "formula"),
                     ("(bytes UTF-8 leídos como un solo entero, big-endian)", "nota")]
                    if texto else [(f"Mensaje: M = {m}", "formula")])
    tabla_c, c = cuadrados_sucesivos(m, e, n)
    pasos.append(("Paso 7 · Cifrar con la clave pública:  C = M^e mod n", [
        *cabecera_msg,
        (f"e = {e} = {_bits_texto(e)}. Se eleva al cuadrado en cada bit y se multiplica donde el bit vale 1:", "nota"),
        *formatear_tabla(("i", "bit de e", "M^(2^i) mod n", "acumulado"), tabla_c),
        (f"C = {m}^{e} mod {n} = {c}", "resultado"),
    ]))

    tabla_d, m2 = cuadrados_sucesivos(c, d, n)
    pasos.append(("Paso 8 · Descifrar con la clave privada:  M = C^d mod n", [
        (f"d = {d} = {_bits_texto(d)}", "nota"),
        *formatear_tabla(("i", "bit de d", "C^(2^i) mod n", "acumulado"), tabla_d),
        (f"M = {c}^{d} mod {n} = {m2}", "resultado"),
    ]))

    priv = rsa.construir_privada(p, q, e)          # dp, dq y qinv, calculados una sola vez
    dp, dq, qinv = priv["dp"], priv["dq"], priv["qinv"]
    m_1, m_2 = rsa.exp_modular(c, dp, p), rsa.exp_modular(c, dq, q)
    h = qinv * (m_1 - m_2) % p
    m_crt = m_2 + h * q
    pasos.append(("Paso 9 · El mismo descifrado, más rápido, con el Teorema Chino del Resto", [
        ("Como el dueño de la clave conoce p y q, trabaja con números de la mitad de tamaño:", "nota"),
        (f"dp = d mod (p−1) = {dp}      dq = d mod (q−1) = {dq}      qinv = q⁻¹ mod p = {qinv}", "formula"),
        (f"m1 = C^dp mod p = {m_1}      m2 = C^dq mod q = {m_2}", "formula"),
        (f"h = qinv · (m1 − m2) mod p = {h}", "formula"),
        (f"M = m2 + h · q = {m_2} + {h} · {q} = {m_crt}", "resultado"),
    ]))

    recuperado = (m2.to_bytes((m2.bit_length() + 7) // 8, "big").decode("utf-8", errors="replace")
                  if texto else None)
    ok = m2 == m == m_crt
    pasos.append(("Paso 10 · Verificación", [
        (f"M original = {m}   |   M descifrado = {m2}   |   M con TCR = {m_crt}", "formula"),
        ("✓ Los tres coinciden: D(E(M)) = M" if ok else "✗ Algo salió mal: los valores no coinciden",
         "resultado" if ok else "error"),
        *([(f"Mensaje recuperado: «{recuperado}»", "resultado")] if texto else []),
    ]))
    return pasos
