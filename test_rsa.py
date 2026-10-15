"""
test_rsa.py -- Pruebas del laboratorio (solo biblioteca estandar).

Ejecutar:   python -m unittest -v          (desde esta carpeta)
"""
import math
import random
import threading
import unittest

import ataques
import herramientas as h
import pasos
import rsa_didactico as rsa
from sesion_chat import SesionChat


class TestAritmetica(unittest.TestCase):
    def test_egcd(self):
        for a, b in ((240, 46), (17, 3120), (65537, 12), (1, 1), (35, 15)):
            g, x, y = rsa.egcd(a, b)
            self.assertEqual(g, math.gcd(a, b))
            self.assertEqual(a * x + b * y, g)

    def test_inverso_modular(self):
        self.assertEqual(rsa.inverso_modular(17, 3120), 2753)
        for _ in range(50):
            m = random.randrange(3, 10 ** 6)
            a = random.randrange(1, m)
            if math.gcd(a, m) == 1:
                self.assertEqual(a * rsa.inverso_modular(a, m) % m, 1)

    def test_inverso_inexistente(self):
        with self.assertRaises(ValueError):
            rsa.inverso_modular(6, 9)

    def test_exp_modular_igual_a_pow(self):
        for _ in range(200):
            b, e, m = random.randrange(10 ** 30), random.randrange(10 ** 5), random.randrange(1, 10 ** 30)
            self.assertEqual(rsa.exp_modular(b, e, m), pow(b, e, m))
        self.assertEqual(rsa.exp_modular(5, 0, 1), 0)

    def test_exp_modular_argumentos_invalidos(self):
        with self.assertRaises(ValueError):
            rsa.exp_modular(2, -1, 7)
        with self.assertRaises(ValueError):
            rsa.exp_modular(2, 3, 0)


class TestPrimos(unittest.TestCase):
    def test_primos_conocidos(self):
        for p in (2, 3, 47, 53, 61, 65537, 2 ** 31 - 1, 2 ** 61 - 1, 2 ** 127 - 1):
            self.assertTrue(rsa.es_probable_primo(p), p)

    def test_compuestos_y_carmichael(self):
        for n in (0, 1, 4, 49, 91, 561, 41041, 825265, 321197185, 2 ** 61 + 1):
            self.assertFalse(rsa.es_probable_primo(n), n)

    def test_generar_primo(self):
        for bits in (2, 8, 64, 256):
            p = rsa.generar_primo(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(rsa.es_probable_primo(p))

    def test_generar_primo_invalido(self):
        with self.assertRaises(ValueError):
            rsa.generar_primo(1)


class TestClaves(unittest.TestCase):
    def test_ejemplo_del_informe(self):
        p, q, e = 61, 53, 17
        n, phi = p * q, (p - 1) * (q - 1)
        d = rsa.inverso_modular(e, phi)
        self.assertEqual((n, phi, d), (3233, 3120, 2753))
        self.assertEqual(rsa.exp_modular(65, e, n), 2790)
        self.assertEqual(rsa.exp_modular(2790, d, n), 65)

    def test_ida_y_vuelta(self):
        for bits in (16, 64, 256, 512):
            pub, priv = rsa.generar_claves(bits)
            self.assertEqual(pub["n"].bit_length(), bits)
            self.assertEqual(pub["n"], priv["p"] * priv["q"])
            for _ in range(5):
                m = random.randrange(pub["n"])
                c = rsa.cifrar(m, pub)
                self.assertEqual(rsa.descifrar(c, priv), m)
                self.assertEqual(rsa.descifrar_crt(c, priv), m)

    def test_bits_invalidos(self):
        for bits in (0, 8, 15, 33, 1025):
            with self.assertRaises(ValueError):
                rsa.generar_claves(bits)
        with self.assertRaises(ValueError):
            rsa.generar_claves(64, e=4)

    def test_rangos(self):
        pub, priv = rsa.generar_claves(64)
        for malo in (-1, pub["n"]):
            with self.assertRaises(ValueError):
                rsa.cifrar(malo, pub)
            with self.assertRaises(ValueError):
                rsa.descifrar(malo, priv)
            with self.assertRaises(ValueError):
                rsa.descifrar_crt(malo, priv)

    def test_crt_detecta_fallos(self):
        pub, priv = rsa.generar_claves(128)
        c = rsa.cifrar(12345, pub)
        danada = dict(priv, dp=(priv["dp"] + 2) % (priv["p"] - 1))   # un fallo solo en la mitad p
        with self.assertRaises(ArithmeticError):
            rsa.descifrar_crt(c, danada)

    def test_modulo_cuadrado(self):
        p = rsa.generar_primo(32)
        priv = rsa.construir_privada(p, p, 65537)
        c = rsa.exp_modular(99, 65537, p * p)
        self.assertEqual(rsa.descifrar_crt(c, priv), 99)

    def test_texto_con_ceros_iniciales(self):
        original = "\x00\x00hola"
        m = rsa.texto_a_entero(original)
        self.assertEqual(rsa.entero_a_texto(m, len(original.encode())), original)
        self.assertEqual(rsa.entero_a_texto(rsa.texto_a_entero("ñandú ✓")), "ñandú ✓")
        self.assertEqual(rsa.entero_a_texto(0), "")


class TestHerramientas(unittest.TestCase):
    TEXTO = "Criptoanálisis UNI 2026: ¡RSA funciona! " * 6

    def test_texto_por_bloques(self):
        for bits in (64, 128, 512):
            pub, priv = rsa.generar_claves(bits)
            for relleno in (False, True):
                bloques, largos = h.cifrar_texto(self.TEXTO, pub, relleno)
                self.assertGreater(len(bloques), 0)
                self.assertEqual(sum(largos), len(self.TEXTO.encode()))
                self.assertEqual(h.descifrar_texto(bloques, largos, priv, relleno), self.TEXTO)

    def test_determinismo_y_relleno(self):
        pub, priv = rsa.generar_claves(512)
        self.assertEqual(h.cifrar_texto("hola", pub)[0], h.cifrar_texto("hola", pub)[0])
        a, la = h.cifrar_texto("hola", pub, relleno=True)
        b, _ = h.cifrar_texto("hola", pub, relleno=True)
        self.assertNotEqual(a, b)
        self.assertEqual(h.descifrar_texto(a, la, priv, True), "hola")

    def test_clave_muy_pequena_con_relleno(self):
        pub, _ = rsa.generar_claves(16)
        with self.assertRaises(ValueError):
            h.cifrar_texto("hola", pub, relleno=True)

    def test_relleno_formato(self):
        bloque = h.rellenar(b"abc", 32)
        self.assertEqual(len(bloque), 32)
        self.assertEqual(h.quitar_relleno(bloque), b"abc")
        self.assertEqual(h.quitar_relleno(h.rellenar(b"a\x00b", 32)), b"a\x00b")
        with self.assertRaises(ValueError):
            h.quitar_relleno(b"\x01abc")

    def test_pollard_factoriza(self):
        for bits in (32, 48, 64):
            pub, priv = rsa.generar_claves(bits)
            f = h.pollard_brent(pub["n"], 30)
            self.assertIn(f, (priv["p"], priv["q"]))

    def test_pollard_casos_limite(self):
        self.assertIsNone(h.pollard_brent(1))
        self.assertIsNone(h.pollard_brent(2 ** 61 - 1))                 # primo: no termina nunca sin esto
        p = rsa.generar_primo(40)
        self.assertEqual(h.pollard_brent(p * p), p)                     # cuadrado perfecto
        self.assertEqual(h.pollard_brent(2 * 10 ** 9 + 2), 2)

    def test_pollard_cancelar(self):
        pub, _ = rsa.generar_claves(160)                                # imposible de romper aqui
        parar = threading.Event()
        parar.set()
        self.assertIsNone(h.pollard_brent(pub["n"], cancelar=parar))
        self.assertIsNone(h.pollard_brent(pub["n"], tiempo_max=0.2))

    def test_romper_clave_recupera_d(self):
        pub, priv = rsa.generar_claves(64)
        rota = h.romper_clave(pub, 30)
        self.assertEqual(rota["d"], priv["d"])
        c = rsa.cifrar(4242, pub)
        self.assertEqual(rsa.descifrar_crt(c, rota), 4242)

    def test_cancelar_generacion(self):
        parar = threading.Event()
        parar.set()
        with self.assertRaises(InterruptedError):
            rsa.generar_claves(2048, cancelar=parar)

    def test_corto(self):
        self.assertEqual(h.corto(12345), "12345")
        self.assertIn("digitos", h.corto(10 ** 100))


class TestAtaques(unittest.TestCase):
    def test_raiz_entera(self):
        for k in (2, 3, 5):
            for x in (0, 1, 2, 7, 8, 9, 10 ** 30, 123456789 ** k, 123456789 ** k - 1):
                r = ataques.raiz_entera(x, k)
                self.assertLessEqual(r ** k, x)
                self.assertGreater((r + 1) ** k, x)

    def test_e_pequeno(self):
        pub, _ = rsa.generar_claves(512, e=3)
        m = rsa.texto_a_entero("mensaje corto")
        self.assertEqual(ataques.ataque_e_pequeno(rsa.cifrar(m, pub), 3, pub["n"]), m)
        grande = random.randrange(pub["n"] // 2, pub["n"])               # M^3 >= n: el ataque no aplica
        self.assertIsNone(ataques.ataque_e_pequeno(rsa.cifrar(grande, pub), 3, pub["n"]))

    def test_modulo_comun(self):
        while True:
            pub, priv = rsa.generar_claves(256, e=17)
            if math.gcd(65537, (priv["p"] - 1) * (priv["q"] - 1)) == 1:
                break
        pub2 = {"n": pub["n"], "e": 65537}
        m = random.randrange(pub["n"])
        self.assertEqual(ataques.ataque_modulo_comun(rsa.cifrar(m, pub), rsa.cifrar(m, pub2), 17, 65537, pub["n"]), m)
        self.assertIsNone(ataques.ataque_modulo_comun(1, 1, 6, 9, pub["n"]))   # mcd(e1, e2) != 1

    def test_demos(self):
        def texto(lineas):
            return "\n".join(l for l, _ in lineas)
        self.assertIn("Hola Bob", texto(ataques.demo_e_pequeno("Hola Bob", 512, False)))
        self.assertIn("✓ El ataque falló", texto(ataques.demo_e_pequeno("Hola Bob", 512, True)))
        self.assertIn("✗ El ataque funcionó", texto(ataques.demo_e_pequeno("Hola Bob", 512, False)))
        self.assertIn("Hola Bob", texto(ataques.demo_modulo_comun("Hola Bob", 512, False)))
        self.assertIn("✗ El ataque funcionó", texto(ataques.demo_modulo_comun("Hola Bob", 512, False)))
        self.assertIn("✓ El ataque falló", texto(ataques.demo_modulo_comun("Hola Bob", 512, True)))
        self.assertIn("falló", texto(ataques.demo_e_pequeno("x" * 200, 512, False)))     # mensaje demasiado largo

    def test_formatear_duracion(self):
        self.assertEqual(ataques.formatear_duracion(0.5), "500 ms")
        self.assertEqual(ataques.formatear_duracion(90), "1.5 min")
        self.assertIn("años", ataques.formatear_duracion(1e12))

    def test_benchmark_y_estimacion(self):
        res = ataques.benchmark_factorizacion((32, 40), tiempo_max=10, repeticiones=1)
        self.assertEqual([b for b, _ in res], [32, 40])
        self.assertTrue(all(t is not None for _, t in res))
        e1, e2 = ataques.estimar_tiempo([(64, 1.0)], 68), ataques.estimar_tiempo([(64, 1.0)], 72)
        self.assertAlmostEqual(e1, 2.0)
        self.assertAlmostEqual(e2, 4.0)
        self.assertIsNone(ataques.estimar_tiempo([(64, None)], 128))


class TestPasos(unittest.TestCase):
    def test_validar(self):
        self.assertEqual(pasos.validar("61", "53", "17", "65"), (61, 53, 17, 65, None))
        self.assertEqual(pasos.validar("61", "53", "17", "A")[3], 65)
        for malo in (("60", "53", "17", "65"), ("61", "61", "17", "65"), ("61", "53", "3120", "65"),
                     ("61", "53", "16", "65"), ("61", "53", "17", ""), ("61", "53", "17", "9999"),
                     ("x", "53", "17", "65")):
            with self.assertRaises(ValueError):
                pasos.validar(*malo)

    def test_construir_pasos_ejemplo(self):
        todos = pasos.construir_pasos(61, 53, 17, 65)
        self.assertEqual(len(todos), 10)
        texto = "\n".join(l for _, lineas in todos for l, _ in lineas)
        self.assertIn("d = t mod φ(n) = -367 mod 3120 = 2753", texto)
        self.assertIn("C = 65^17 mod 3233 = 2790", texto)
        self.assertIn("Los tres coinciden", texto)


class TestSesionChat(unittest.TestCase):
    def sesion(self, bits=64):
        s = SesionChat(bits, con_eve=True, ataque_seg=30)
        for nombre in ("Alice", "Bob"):
            pub, priv, _ = s.generar_par()
            s.registrar_claves(nombre, pub, priv)
        return s

    def test_flujo_completo(self):
        s = self.sesion()
        self.assertTrue(s.lista)
        for relleno in (False, True):
            msg = s.cifrar("Alice", "hola Bob, ¿qué tal?", relleno)
            self.assertEqual((msg.origen, msg.destino), ("Alice", "Bob"))
            self.assertEqual(s.descifrar(msg), "hola Bob, ¿qué tal?")

    def test_eve_rompe_clave_debil(self):
        s = self.sesion()
        s.empezar_ataque("Bob")
        msg = s.cifrar("Alice", "secreto", False)
        self.assertEqual(s.analizar_eve(msg)[0], "atacando")
        privada, _ = s.intentar_romper(s.pub["Bob"])
        s.terminar_ataque("Bob", privada)
        for relleno in (False, True):
            estado, texto, _ = s.analizar_eve(s.cifrar("Alice", "secreto", relleno))
            self.assertEqual((estado, texto), ("descifrado", "secreto"))

    def test_eve_detecta_repeticiones_solo_sin_relleno(self):
        s = self.sesion()
        self.assertFalse(s.analizar_eve(s.cifrar("Alice", "hola", False))[2])
        self.assertTrue(s.analizar_eve(s.cifrar("Alice", "hola", False))[2])
        self.assertFalse(s.analizar_eve(s.cifrar("Alice", "hola", True))[2])
        self.assertFalse(s.analizar_eve(s.cifrar("Alice", "hola", True))[2])

    def test_clave_fuerte_resiste(self):
        s = SesionChat(192, ataque_seg=0.3)
        pub, _, _ = s.generar_par()
        privada, _ = s.intentar_romper(pub)
        self.assertIsNone(privada)

    def test_cancelar_y_claves_no_listas(self):
        s = SesionChat(64)
        with self.assertRaises(RuntimeError):
            s.cifrar("Alice", "hola")
        s.cerrar()
        self.assertTrue(s.cancelada)
        with self.assertRaises(InterruptedError):
            s.generar_par()


if __name__ == "__main__":
    unittest.main()
