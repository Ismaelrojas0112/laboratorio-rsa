"""
ataques.py -- Ataques contra el RSA "de libro de texto" (sin interfaz grafica).

  1. Exponente pequeno (e = 3): si M^e < n no hay reduccion modular y basta
     sacar la raiz e-esima de C. No hace falta factorizar n.
  2. Modulo comun: el mismo mensaje cifrado con dos exponentes coprimos y el
     mismo n se recupera con Euclides extendido, sin ninguna clave privada.
  3. Medida del tiempo de factorizacion y extrapolacion a claves mayores.

Las funciones demo_* devuelven listas de (linea, etiqueta), el mismo formato
que usa pasos.py, para mostrarlas en la ventana.
"""
import math
import statistics
import time

import herramientas as h
import rsa_didactico as rsa

# ---------------------------------------------------------------------------
# Matematica de los ataques
# ---------------------------------------------------------------------------
def raiz_entera(x: int, k: int) -> int:
    """Parte entera de la raiz k-esima de x (metodo de Newton con enteros)."""
    if x < 0 or k < 1:
        raise ValueError("Se requiere x >= 0 y k >= 1")
    if x < 2:
        return x
    r = 1 << -(-x.bit_length() // k)          # potencia de 2 >= la raiz
    while True:
        s = ((k - 1) * r + x // r ** (k - 1)) // k
        if s >= r:
            return r
        r = s


def ataque_e_pequeno(c: int, e: int, n: int):
    """Devuelve M si M^e < n (C = M^e en los enteros); si no, None."""
    m = raiz_entera(c, e)
    return m if m ** e == c and m < n else None


def ataque_modulo_comun(c1: int, c2: int, e1: int, e2: int, n: int):
    """Con mcd(e1, e2) = 1 existen a, b con a*e1 + b*e2 = 1, y entonces
    C1^a * C2^b = M^(a*e1 + b*e2) = M (mod n). Devuelve M o None."""
    g, a, b = rsa.egcd(e1, e2)
    if g != 1:
        return None
    try:
        return pow(c1, a, n) * pow(c2, b, n) % n   # el exponente negativo invierte mod n
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Demostraciones (devuelven lineas listas para mostrar)
# ---------------------------------------------------------------------------
def _texto_de(m: int) -> str:
    return m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8", errors="replace")


def demo_e_pequeno(texto: str, bits: int = 512, relleno: bool = False, cancelar=None):
    """Alice cifra `texto` para Bob, que usa e = 3. Eve intenta leerlo con la raiz cubica."""
    e = 3
    pub, _ = rsa.generar_claves(bits, e=e, cancelar=cancelar)
    n = pub["n"]
    bloques, _ = h.cifrar_texto(texto, pub, relleno)
    maximo = (n.bit_length() - 1) // (8 * e)
    lin = [("Ataque del exponente pequeño (e = 3)", "titulo"),
           (f"Clave pública de Bob: n de {n.bit_length()} bits, e = {e}", "formula"),
           (f"Alice envía «{texto}» {'CON' if relleno else 'SIN'} relleno aleatorio "
            f"({len(bloques)} bloque(s)).", "nota"),
           ("Eve solo conoce n, e y los cifrados C. Intenta calcular la raíz cúbica entera de C:", "nota")]
    recuperados = 0
    for i, c in enumerate(bloques, 1):
        lin.append((f"Bloque {i}:  C = {h.corto(c, 12)}", "tabla"))
        m = ataque_e_pequeno(c, e, n)
        if m is None:
            lin.append(("   ∛C no es un entero exacto: M³ superó a n y se «envolvió» módulo n.", "error"))
        else:
            recuperados += 1
            lin.append((f"   ∛C = {h.corto(m, 12)}  y  M³ = C exactamente  →  M recuperado", "formula"))
            lin.append((f"   Texto del bloque: «{_texto_de(m)}»", "resultado"))
    lin.append(("", "nota"))
    if recuperados == len(bloques):
        lin.append(("✗ El ataque funcionó: Eve leyó el mensaje sin factorizar n ni conocer d.", "error"))
        lin.append(("Causa: M³ < n, así que C = M³ sin reducción módulo n; una raíz cúbica ordinaria basta.", "nota"))
    elif relleno:
        lin.append(("✓ El ataque falló: el relleno aleatorio hace que M ocupe casi todo n, "
                    "y M³ siempre se reduce módulo n.", "ok"))
    else:
        lin.append((f"El ataque falló en algún bloque: con n de {n.bit_length()} bits solo son vulnerables "
                    f"los bloques de hasta {maximo} bytes (M³ < n).", "nota"))
        lin.append(("Prueba con un mensaje más corto.", "nota"))
    return lin


def demo_modulo_comun(texto: str, bits: int = 512, relleno: bool = False, cancelar=None):
    """Dos usuarios comparten n con exponentes distintos y reciben el mismo mensaje."""
    e1, e2 = 17, 65537
    while True:
        pub1, priv1 = rsa.generar_claves(bits, e=e1, cancelar=cancelar)
        if math.gcd(e2, (priv1["p"] - 1) * (priv1["q"] - 1)) == 1:
            break
    n = pub1["n"]
    pub2 = {"n": n, "e": e2}
    b1, _ = h.cifrar_texto(texto, pub1, relleno)
    b2, _ = h.cifrar_texto(texto, pub2, relleno)
    g, a, b = rsa.egcd(e1, e2)
    k = h.tamano_bloque(n)
    lin = [("Ataque del módulo común", "titulo"),
           (f"Alice y Bob comparten n ({n.bit_length()} bits) pero tienen e₁ = {e1} y e₂ = {e2}.", "formula"),
           (f"Se envía «{texto}» a los dos {'CON' if relleno else 'SIN'} relleno aleatorio.", "nota"),
           (f"Eve conoce n, e₁, e₂, C₁ y C₂.  Euclides extendido: {a}·{e1} + {b}·{e2} = {g}", "nota")]
    exitos = 0
    for i, (c1, c2) in enumerate(zip(b1, b2), 1):
        lin.append((f"Bloque {i}:  C₁ = {h.corto(c1, 10)}   C₂ = {h.corto(c2, 10)}", "tabla"))
        m = ataque_modulo_comun(c1, c2, e1, e2, n)
        try:
            datos = h.desempaquetar(m, k, relleno) if m is not None else None
        except (ValueError, OverflowError):
            datos = None
        lin.append((f"   M = C₁^({a}) · C₂^({b}) mod n", "formula"))
        if datos is None:
            lin.append(("   El resultado no tiene forma de mensaje válido.", "error"))
        else:
            exitos += 1
            lin.append((f"   Texto del bloque: «{datos.decode('utf-8', errors='replace')}»", "resultado"))
    lin.append(("", "nota"))
    recuperado = exitos == len(b1)
    if recuperado and not relleno:
        lin.append(("✗ El ataque funcionó: Eve leyó el mensaje sin ninguna clave privada.", "error"))
        lin.append(("Causa: M^(a·e₁ + b·e₂) = M^1. Además, quien conoce (e, d) de un n compartido "
                    "puede factorizarlo: nunca reutilices n.", "nota"))
    elif not recuperado and relleno:
        lin.append(("✓ El ataque falló: con relleno aleatorio los dos cifrados no contienen el mismo M, "
                    "así que la combinación da basura.", "ok"))
    else:
        lin.append(("Resultado inesperado: revisa la entrada.", "nota"))
    return lin


# ---------------------------------------------------------------------------
# Tiempo de factorizacion
# ---------------------------------------------------------------------------
def formatear_duracion(seg: float) -> str:
    if seg < 1e-3:
        return f"{seg * 1e6:.0f} µs"
    if seg < 1:
        return f"{seg * 1e3:.0f} ms"
    if seg < 60:
        return f"{seg:.1f} s"
    if seg < 3600:
        return f"{seg / 60:.1f} min"
    if seg < 86400:
        return f"{seg / 3600:.1f} horas"
    dias = seg / 86400
    if dias < 365.25:
        return f"{dias:.1f} días"
    anios = dias / 365.25
    return f"{anios:,.0f} años" if anios < 1e6 else f"{anios:.1e} años"


def benchmark_factorizacion(tamanos, tiempo_max=20.0, cancelar=None, progreso=None, repeticiones=3):
    """Rompe una clave de cada tamano (en bits de n). Devuelve [(bits, segundos | None)];
    segundos es la mediana de `repeticiones` ataques (None si no se rompio a tiempo)."""
    resultados = []
    for bits in tamanos:
        if cancelar is not None and cancelar.is_set():
            break
        pub, _ = rsa.generar_claves(bits, cancelar=cancelar)
        tiempos = []
        for _ in range(repeticiones):
            t0 = time.perf_counter()
            priv = h.romper_clave(pub, tiempo_max, cancelar)
            if cancelar is not None and cancelar.is_set():
                return resultados
            if priv is None:
                tiempos = None
                break
            tiempos.append(time.perf_counter() - t0)
            if tiempos[-1] > 2:           # no repetir lo que ya tarda mucho
                break
        fila = (bits, statistics.median(tiempos) if tiempos else None)
        resultados.append(fila)
        if progreso:
            progreso(fila)
    return resultados


def linea_benchmark(bits: int, seg, tiempo_max: float = None) -> str:
    if seg is None:
        lim = f" en {tiempo_max:.0f} s" if tiempo_max else ""
        return f"n de {bits:>4} bits  →  NO se rompió{lim}"
    return f"n de {bits:>4} bits  →  roto en {formatear_duracion(seg)}"


def estimar_tiempo(resultados, bits: int):
    """Extrapola con el coste de Pollard rho, ~ sqrt(p) = 2^(bits/4): el tiempo se
    duplica cada 4 bits de n. Parte de la medida mas grande y fiable (> 50 ms)."""
    validos = [(b, t) for b, t in resultados if t is not None]
    if not validos:
        return None
    fiables = [(b, t) for b, t in validos if t > 0.05] or validos[-1:]
    b0, t0 = fiables[-1]
    return t0 * 2.0 ** ((bits - b0) / 4)


def lineas_extrapolacion(resultados, objetivos=(128, 256, 512, 1024, 2048)):
    lin = [("", "nota"), ("Estimación para claves mayores (solo con Pollard rho: el tiempo se duplica cada 4 bits; es aproximada porque rho es aleatorio)", "titulo")]
    for b in objetivos:
        est = estimar_tiempo(resultados, b)
        if est is not None:
            lin.append((f"n de {b:>4} bits  →  ≈ {formatear_duracion(est)}", "tabla"))
    lin.append(("", "nota"))
    lin.append(("Edad del universo ≈ 1,4·10¹⁰ años. Con algoritmos mejores (criba general del cuerpo de números) "
                "las claves de 512 bits ya se factorizan en días con hardware común; las de 2048 bits siguen "
                "fuera de alcance.", "nota"))
    return lin
