"""
sesion_chat.py -- Logica del chat Alice / Eve / Bob (sin interfaz grafica).

Una SesionChat guarda las claves de los dos usuarios, lo que Eve ha logrado
romper y lo que ha visto pasar por el canal. La ventana (app.py) solo la
dibuja.

Reparto de hilos:
  * generar_par() e intentar_romper() son lentos: se llaman desde hilos de
    trabajo y NO tocan el estado de la sesion; devuelven su resultado.
  * Todo lo demas (registrar_*, cifrar, analizar_eve, descifrar) se llama
    desde el hilo de la interfaz.
  * cerrar() activa un Event que detiene la generacion de claves y los
    ataques en curso (al reiniciar o al salir de la pantalla).
"""
import threading
import time
from dataclasses import dataclass
from typing import List

import rsa_didactico as rsa
from herramientas import cifrar_texto, descifrar_texto, romper_clave

NOMBRES = ("Alice", "Bob")


def otro(nombre: str) -> str:
    return "Bob" if nombre == "Alice" else "Alice"


@dataclass
class Mensaje:
    origen: str
    destino: str
    texto: str
    bloques: List[int]
    largos: List[int]
    relleno: bool


class SesionChat:
    def __init__(self, bits: int, con_eve: bool = True, ataque_seg: float = 15):
        self.bits, self.con_eve, self.ataque_seg = bits, con_eve, ataque_seg
        self.pub, self.priv, self.claves_rotas = {}, {}, {}
        self.atacando = {}            # dueno -> instante (time.monotonic) en que Eve empezo
        self.vistos = {}              # destino -> cifrados que Eve ya vio pasar
        self.cancelar = threading.Event()

    # --- ciclo de vida -------------------------------------------------------
    @property
    def cancelada(self) -> bool:
        return self.cancelar.is_set()

    def cerrar(self):
        self.cancelar.set()

    @property
    def lista(self) -> bool:
        return all(n in self.pub and n in self.priv for n in NOMBRES)

    # --- trabajo pesado (hilos de trabajo; no modifican la sesion) ------------
    def generar_par(self):
        """Devuelve (publica, privada, segundos). Lanza InterruptedError si se cancela."""
        t0 = time.perf_counter()
        pub, priv = rsa.generar_claves(self.bits, cancelar=self.cancelar)
        return pub, priv, time.perf_counter() - t0

    def intentar_romper(self, publica: dict):
        """Eve intenta factorizar n. Devuelve (clave privada | None, segundos)."""
        t0 = time.perf_counter()
        privada = romper_clave(publica, self.ataque_seg, self.cancelar)
        return privada, time.perf_counter() - t0

    # --- estado (hilo de la interfaz) -----------------------------------------
    def registrar_claves(self, nombre: str, pub: dict, priv: dict):
        self.pub[nombre], self.priv[nombre] = pub, priv

    def empezar_ataque(self, dueno: str):
        self.atacando[dueno] = time.monotonic()

    def terminar_ataque(self, dueno: str, privada):
        self.atacando.pop(dueno, None)
        if privada is not None:
            self.claves_rotas[dueno] = privada

    def cifrar(self, origen: str, texto: str, relleno: bool = False) -> Mensaje:
        """Cifra con la clave PUBLICA del destinatario."""
        destino = otro(origen)
        if destino not in self.pub:
            raise RuntimeError("Las claves todavía no están listas")
        bloques, largos = cifrar_texto(texto, self.pub[destino], relleno)
        return Mensaje(origen, destino, texto, bloques, largos, relleno)

    def analizar_eve(self, msg: Mensaje):
        """Lo que Eve consigue con un mensaje interceptado. Devuelve
        (estado, texto, repetido): estado es "descifrado", "atacando" o "ilegible";
        `repetido` indica que ese mismo cifrado ya paso antes por el canal."""
        vistos = self.vistos.setdefault(msg.destino, set())
        clave_cifrado = tuple(msg.bloques)
        repetido = clave_cifrado in vistos
        vistos.add(clave_cifrado)
        clave = self.claves_rotas.get(msg.destino)
        if clave:
            return "descifrado", descifrar_texto(msg.bloques, msg.largos, clave, msg.relleno), repetido
        if msg.destino in self.atacando:
            return "atacando", None, repetido
        return "ilegible", None, repetido

    def descifrar(self, msg: Mensaje) -> str:
        """El destinatario descifra con SU clave privada."""
        return descifrar_texto(msg.bloques, msg.largos, self.priv[msg.destino], msg.relleno)
