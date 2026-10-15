# Laboratorio RSA (ventana de escritorio)

Un solo programa con tres opciones. Usa Python 3.8 o superior y **no necesita instalar nada**
(Tkinter viene incluido con Python en Windows y macOS). Desarrollado y probado con Python 3.13.

## Cómo ejecutarlo

Abre la carpeta `rsa_laboratorio` en tu IDE (VS Code o PyCharm) y ejecuta **solo `app.py`**:

```
python app.py
```

En Linux, si dice que falta `tkinter`: `sudo apt install python3-tk`.

Los botones se pueden usar con el teclado: **Tab** para moverse, **Enter** o **Espacio** para pulsar.

## Opción 1: Chat cifrado con espía

Tres terminales simuladas en la misma ventana: **Alice**, **Eve** (espía, solo lectura) y **Bob**.

1. Elige el tamaño de la clave y pulsa **Conectar**.
2. Escribe un mensaje en la caja de Alice o de Bob y pulsa Enter.
3. Mira qué ve cada uno: Alice y Bob muestran cómo cifran con la clave pública del otro y
   descifran con la suya; Eve muestra lo que intercepta y si logra romper la clave. Mientras
   factoriza, el semáforo de Eve muestra una barra con los segundos que lleva.

| Tamaño | Qué pasa (Pollard rho, 15 s) |
|---|---|
| 64 bits (débil) | Eve factoriza `n` en milisegundos, calcula `d` y lee todo en rojo. |
| 96 bits | Está al límite: rho tarda unos 7-9 s, así que suele caer justo a tiempo. |
| 128 y 256 bits | Eve intenta 15 s y se rinde: «RESISTIÓ ✓». |
| 512 bits | Igual. |
| 2048 bits (segura) | Igual; las claves tardan 1-3 s en generarse. |

«Resistió» solo significa que **este** ataque (Pollard rho) no alcanza. Con algoritmos mejores
(criba general del cuerpo de números) 128, 256 y 512 bits sí se rompen; 2048 bits no.

Casillas:

* **Eve intercepta el canal**: permite probar la conversación sin espía.
* **Relleno aleatorio en los mensajes**: sin relleno, enviar dos veces el mismo texto produce el
  mismo cifrado y Eve lo avisa («este MISMO cifrado ya pasó antes») aunque no pueda leerlo.
  Con relleno cada cifrado es distinto. Se puede cambiar entre un mensaje y otro.

**Reiniciar** genera claves nuevas y detiene los hilos de la sesión anterior.

## Opción 2: RSA paso a paso

Pon `p`, `q`, `e` y un mensaje (un número, o un texto corto como `A`) y pulsa **Iniciar**.
Avanza con **Siguiente paso** o pulsa **Mostrar todo**. Los 10 pasos son:
primos, `n`, `φ(n)`, comprobación de `e`, `d` con Euclides extendido, claves,
cifrado y descifrado con cuadrados sucesivos, descifrado con el TCR y verificación.

«Ejemplo del informe» carga p = 61, q = 53, e = 17, M = 65 (diapositivas 13 y 14).
Acepta primos de hasta 19 dígitos.

**Copiar** y **Guardar .txt** exportan los 10 pasos completos (aunque no los hayas mostrado todos),
para pegarlos en el informe.

## Opción 3: Ataques al RSA «de libro»

Muestra por qué el RSA sin relleno no es seguro aunque la clave sea grande (512 bits):

* **Exponente pequeño (e = 3)**: si el mensaje es corto, `M³ < n`, así que `C = M³` sin reducción
  y Eve lo recupera con una raíz cúbica entera, sin factorizar nada.
* **Módulo común**: dos usuarios con el mismo `n` y exponentes distintos (17 y 65537) reciben el mismo
  mensaje. Con Euclides extendido (`a·e₁ + b·e₂ = 1`) Eve calcula `C₁ᵃ · C₂ᵇ = M` sin ninguna clave privada.
* **Tiempo de factorización**: rompe claves de 32 a 88 bits, mide cuánto tarda y extrapola
  a 128, 256, 512, 1024 y 2048 bits (el tiempo de rho se duplica cada 4 bits de `n`). Tarda unos segundos.

Marca **Usar relleno aleatorio** en los dos primeros para ver cómo el relleno detiene el ataque.

## Archivos

| Archivo | Contenido |
|---|---|
| `app.py` | La ventana (menú, chat con espía, paso a paso, ataques) |
| `sesion_chat.py` | Lógica del chat (claves, cifrado, lo que ve Eve) sin interfaz |
| `pasos.py` | Los cálculos del paso a paso (sin interfaz) |
| `ataques.py` | Ataques de exponente pequeño y módulo común; medida de tiempos |
| `rsa_didactico.py` | Tu implementación de RSA del informe (antes `rsa.py`) |
| `herramientas.py` | Cifrado de textos por bloques (con relleno opcional) y el ataque de factorización de Eve |
| `test_rsa.py` | Pruebas automáticas |
| `requirements.txt` | Sin dependencias externas |

Pruebas (desde esta carpeta; tardan unos 3 s):

```
python -m unittest -v
```

`rsa.py` pasó a llamarse `rsa_didactico.py` para no chocar con la biblioteca `rsa` de PyPI.

Para cambiar cuánto tiempo intenta Eve romper una clave, edita `ATAQUE_SEG` al inicio de `app.py`.

Es RSA «de libro de texto» (sin OAEP), como en el informe: sirve para explicar, no para uso real.
El «relleno aleatorio» de las opciones 1 y 3 es una versión simplificada de PKCS#1 v1.5
(`0x02 ‖ bytes aleatorios ‖ 0x00 ‖ texto`) pensada para ver su efecto; no sustituye a OAEP.
