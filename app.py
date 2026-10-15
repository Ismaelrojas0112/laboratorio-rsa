"""
app.py -- Laboratorio RSA (ventana de escritorio con Tkinter)

Ejecutar:   python app.py          (no requiere instalar nada)

  Opcion 1: Chat cifrado con espia. Alice, Eve y Bob son tres "terminales"
            simuladas en la misma ventana. Cambia el tamano de la clave y
            observa si Eve puede leer la conversacion.
  Opcion 2: RSA paso a paso. Pon p, q, e y un mensaje y mira cada calculo.
  Opcion 3: Ataques al RSA "de libro": exponente pequeno, modulo comun y
            tiempo de factorizacion.

Usa tu implementacion de RSA (rsa_didactico.py) del informe.
"""
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog
from tkinter import font as tkfont
from tkinter import ttk

import ataques
import pasos
from herramientas import corto, preparar_consola
from sesion_chat import NOMBRES, SesionChat

ATAQUE_SEG = 15        # segundos que Eve intenta factorizar cada clave antes de rendirse
TAMANOS_BENCH = (32, 40, 48, 56, 64, 72, 80, 88)   # tamanos de n que mide la pantalla de ataques
BENCH_SEG = 20         # limite por ataque en esa medicion
BITS_ATAQUES = 512     # tamano de las claves de las demos de ataques

# ----------------------------- Paleta (azul pastel sobre fondo oscuro) -----
BG, PANEL, FONDO_TXT = "#1B2438", "#243049", "#101828"
FG, MUTED, TECNICO = "#E8EEF7", "#8FA0BC", "#7F93B3"
AZUL, MENTA, DURAZNO, ROSA, MANTEQUILLA = "#BCD3EE", "#C6EADB", "#FAD9CB", "#F7CFDC", "#F7EBBE"
ALERTA = "#F28B9B"
OSCURO = "#1F2A44"
F = {}                 # fuentes (se crean cuando existe la ventana)


def aclarar(color, f=0.18):
    r, g, b = (int(color[i:i + 2], 16) for i in (1, 3, 5))
    return "#%02x%02x%02x" % tuple(int(c + (255 - c) * f) for c in (r, g, b))


def crear_fuentes():
    libres = set(tkfont.families())
    mono = next((f for f in ("Consolas", "Menlo", "DejaVu Sans Mono", "Courier New") if f in libres), "Courier")
    sans = next((f for f in ("Segoe UI", "Helvetica Neue", "Calibri", "DejaVu Sans", "Arial") if f in libres),
                tkfont.nametofont("TkDefaultFont").actual("family"))
    serif = next((f for f in ("Georgia", "DejaVu Serif", "Times New Roman") if f in libres), sans)
    F.update(mono=(mono, 10), mono_b=(mono, 10, "bold"), mono_g=(mono, 11),
             ui=(sans, 10), ui_b=(sans, 10, "bold"), h1=(sans, 26, "bold"),
             h2=(sans, 15, "bold"), h3=(sans, 12, "bold"), peq=(sans, 9),
             icono=(serif, 40, "bold"))


def etiquetas_texto(txt):
    """Estilos del texto largo (paso a paso y ataques)."""
    mono = F["mono_g"][0]
    for etiqueta, kw in {
            "titulo": dict(foreground=AZUL, font=(F["h3"][0], 13, "bold"), spacing1=16, spacing3=6),
            "formula": dict(foreground=MENTA), "resultado": dict(foreground=MANTEQUILLA, font=(mono, 11, "bold")),
            "ok": dict(foreground=MENTA, font=(mono, 11, "bold")),
            "tabla": dict(foreground=FG, lmargin1=24, lmargin2=24),
            "tabla_cab": dict(foreground=AZUL, lmargin1=24, lmargin2=24, font=(mono, 11, "bold")),
            "resalte": dict(foreground=MANTEQUILLA, background="#2F3D5C", lmargin1=24, lmargin2=24),
            "nota": dict(foreground=TECNICO), "error": dict(foreground=ALERTA, font=(mono, 11, "bold"))}.items():
        txt.tag_config(etiqueta, **kw)


def area_texto(master):
    """Caja de texto de solo lectura con barra de desplazamiento y estilos."""
    cuerpo = tk.Frame(master, bg=FONDO_TXT, highlightthickness=1, highlightbackground="#33415F")
    cuerpo.pack(fill="both", expand=True, padx=18, pady=(0, 16))
    txt = tk.Text(cuerpo, bg=FONDO_TXT, fg=FG, font=F["mono_g"], wrap="word", relief="flat",
                  padx=18, pady=12, state="disabled", cursor="arrow", highlightthickness=0)
    barra = tk.Scrollbar(cuerpo, command=txt.yview, bg=PANEL, troughcolor=FONDO_TXT, relief="flat", bd=0)
    txt.config(yscrollcommand=barra.set)
    barra.pack(side="right", fill="y")
    txt.pack(side="left", fill="both", expand=True)
    etiquetas_texto(txt)
    return txt


# ----------------------------- Componentes ---------------------------------
class Boton(tk.Label):
    """Boton plano de color (funciona igual en Windows, macOS y Linux).
    Recibe el foco con Tab y se activa con Enter o Espacio."""

    def __init__(self, master, texto, comando, bg=AZUL, fg=OSCURO, **kw):
        super().__init__(master, text=texto, bg=bg, fg=fg, padx=14, pady=6, cursor="hand2",
                         font=F["ui_b"], takefocus=1, highlightthickness=2,
                         highlightbackground=bg, highlightcolor=FG, **kw)
        self._bg, self._fg, self._cmd, self._activo = bg, fg, comando, True
        self.bind("<Button-1>", self._click)
        self.bind("<Return>", self._click)
        self.bind("<space>", self._click)
        self.bind("<Enter>", lambda e: self._activo and self._pintar(aclarar(self._bg)))
        self.bind("<Leave>", lambda e: self._activo and self._pintar(self._bg))

    def _pintar(self, color):
        self.config(bg=color, highlightbackground=color)

    def _click(self, _):
        if self._activo:
            self.focus_set()
            self._cmd()

    def activar(self, si=True):
        self._activo = si
        self.config(fg=self._fg if si else MUTED, cursor="hand2" if si else "arrow",
                    takefocus=1 if si else 0)
        self._pintar(self._bg if si else "#34405A")

    def texto(self, t):
        self.config(text=t)


class Terminal(tk.Frame):
    """Una 'terminal' de solo lectura con titulo de color y, opcionalmente, una caja para escribir."""

    def __init__(self, master, titulo, subtitulo, color, escribible=False, al_enviar=None):
        super().__init__(master, bg=PANEL, highlightthickness=1, highlightbackground="#33415F")
        cab = tk.Frame(self, bg=PANEL)
        cab.pack(fill="x", padx=12, pady=(10, 6))
        tk.Label(cab, text=f" {titulo} ", bg=color, fg=OSCURO, font=F["h3"], padx=6).pack(side="left")
        tk.Label(cab, text=subtitulo, bg=PANEL, fg=MUTED, font=F["peq"]).pack(side="left", padx=10)
        puntos = tk.Frame(cab, bg=PANEL)
        puntos.pack(side="right")
        for c in (ROSA, MANTEQUILLA, MENTA):
            tk.Label(puntos, text="●", bg=PANEL, fg=c, font=F["peq"]).pack(side="left")

        cuerpo = tk.Frame(self, bg=FONDO_TXT)
        cuerpo.pack(fill="both", expand=True, padx=12)
        self.txt = tk.Text(cuerpo, bg=FONDO_TXT, fg=FG, font=F["mono"], wrap="word", relief="flat",
                           padx=10, pady=8, state="disabled", cursor="arrow", height=10, width=10,
                           highlightthickness=0, spacing1=1, spacing3=1)
        barra = tk.Scrollbar(cuerpo, command=self.txt.yview, bg=PANEL, troughcolor=FONDO_TXT, relief="flat", bd=0)
        self.txt.config(yscrollcommand=barra.set)
        barra.pack(side="right", fill="y")
        self.txt.pack(side="left", fill="both", expand=True)
        for etiqueta, kw in {"sistema": dict(foreground=MUTED), "tecnico": dict(foreground=TECNICO),
                             "yo": dict(foreground=AZUL, font=F["mono_b"]),
                             "otro": dict(foreground=MENTA, font=F["mono_b"]),
                             "alerta": dict(foreground=ALERTA, font=F["mono_b"]),
                             "seguro": dict(foreground=MENTA, font=F["mono_b"]),
                             "aviso": dict(foreground=MANTEQUILLA), "normal": dict(foreground=FG)}.items():
            self.txt.tag_config(etiqueta, **kw)

        self.entrada = None
        if escribible:
            fila = tk.Frame(self, bg=PANEL)
            fila.pack(fill="x", padx=12, pady=10)
            self.entrada = tk.Entry(fila, bg=FONDO_TXT, fg=FG, insertbackground=FG, relief="flat",
                                    font=F["mono_g"], disabledbackground="#182033", disabledforeground=MUTED,
                                    highlightthickness=1, highlightbackground="#33415F", highlightcolor=color)
            self.entrada.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
            self.entrada.bind("<Return>", lambda e: al_enviar())
            self.boton = Boton(fila, "Enviar", al_enviar, bg=color)
            self.boton.pack(side="right")
            self.habilitar(False)
        else:
            self.pie = tk.Frame(self, bg=PANEL)       # zona inferior libre (p. ej. el semaforo de Eve)
            self.pie.pack(fill="x", padx=12, pady=(6, 10))

    def habilitar(self, si):
        if self.entrada:
            self.entrada.config(state="normal" if si else "disabled")
            self.boton.activar(si)
            if si:
                self.entrada.focus_set()

    def limpiar(self):
        self.txt.config(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.config(state="disabled")

    def escribir(self, texto, etiqueta="normal"):
        self.txt.config(state="normal")
        self.txt.insert("end", texto + "\n", etiqueta)
        self.txt.config(state="disabled")
        self.txt.see("end")


class Encabezado(tk.Frame):
    def __init__(self, master, titulo, subtitulo, al_volver):
        super().__init__(master, bg=BG)
        Boton(self, "←  Menú", al_volver, bg="#34405A", fg=AZUL).pack(side="left")
        tk.Label(self, text=titulo, bg=BG, fg=FG, font=F["h2"]).pack(side="left", padx=16)
        tk.Label(self, text=subtitulo, bg=BG, fg=MUTED, font=F["ui"]).pack(side="left")


# ----------------------------- Pantalla: menu ------------------------------
class PantallaMenu(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=BG)
        centro = tk.Frame(self, bg=BG)
        centro.place(relx=0.5, rely=0.48, anchor="center")
        tk.Label(centro, text="Laboratorio RSA", bg=BG, fg=FG, font=F["h1"]).pack()
        tk.Label(centro, text="Criptoanálisis · Cifrado y descifrado en RSA", bg=BG, fg=MUTED,
                 font=F["ui"]).pack(pady=(2, 26))
        tarjetas = tk.Frame(centro, bg=BG)
        tarjetas.pack()
        self._tarjeta(tarjetas, "⇄", "Chat cifrado con espía",
                      "Alice y Bob conversan con RSA mientras\nEve intercepta el canal. Prueba distintos\n"
                      "tamaños de clave y mira si Eve los lee.", AZUL, app.ir_chat).pack(side="left", padx=10)
        self._tarjeta(tarjetas, "φ", "RSA paso a paso",
                      "Elige p, q, e y un mensaje y mira cada\ncálculo: n, φ(n), Euclides, cuadrados\n"
                      "sucesivos, cifrado y descifrado.", MENTA, app.ir_pasos).pack(side="left", padx=10)
        self._tarjeta(tarjetas, "⚠", "Ataques al RSA de libro",
                      "Exponente pequeño, módulo común y\ntiempo de factorización: por qué el\n"
                      "RSA sin relleno no es seguro.", DURAZNO, app.ir_ataques).pack(side="left", padx=10)

    @staticmethod
    def _tarjeta(master, icono, titulo, descripcion, color, comando):
        t = tk.Frame(master, bg=color, cursor="hand2", width=335, height=260, takefocus=1,
                     highlightthickness=2, highlightbackground=color, highlightcolor=FG)
        t.pack_propagate(False)
        hijos = [tk.Label(t, text=icono, bg=color, fg=OSCURO, font=F["icono"]),
                 tk.Label(t, text=titulo, bg=color, fg=OSCURO, font=F["h2"]),
                 tk.Label(t, text=descripcion, bg=color, fg="#34405A", font=F["ui"], justify="left")]
        hijos[0].pack(pady=(26, 0))
        hijos[1].pack(pady=(6, 8))
        hijos[2].pack()
        for w in [t, *hijos]:
            w.bind("<Button-1>", lambda e: comando())
            w.bind("<Enter>", lambda e: [x.config(bg=aclarar(color, .25)) for x in [t, *hijos]])
            w.bind("<Leave>", lambda e: [x.config(bg=color) for x in [t, *hijos]])
        t.bind("<Return>", lambda e: comando())
        t.bind("<space>", lambda e: comando())
        return t


# ----------------------------- Pantalla: chat con espia --------------------
class PantallaChat(tk.Frame):
    TAMANOS = {"64 bits  (clave débil)": 64, "96 bits  (al límite de Eve)": 96,
               "128 bits  (resiste a Eve)": 128, "256 bits  (resiste a Eve)": 256,
               "512 bits  (clave media)": 512, "2048 bits  (clave segura)": 2048}

    def __init__(self, master, app):
        super().__init__(master, bg=BG)
        self.app, self.sesion = app, None

        Encabezado(self, "Chat cifrado con espía", "Alice → (Eve) → Bob", app.ir_menu).pack(fill="x", padx=18, pady=(14, 8))

        ctl = tk.Frame(self, bg=BG)
        ctl.pack(fill="x", padx=18, pady=(0, 2))
        tk.Label(ctl, text="Tamaño de la clave:", bg=BG, fg=FG, font=F["ui"]).pack(side="left")
        self.cmb = ttk.Combobox(ctl, values=list(self.TAMANOS), state="readonly", width=26, font=F["ui"])
        self.cmb.current(len(self.TAMANOS) - 1)
        self.cmb.pack(side="left", padx=(8, 18))
        self.var_eve = tk.BooleanVar(value=True)
        self.var_relleno = tk.BooleanVar(value=False)
        for texto, var in (("Eve intercepta el canal", self.var_eve),
                           ("Relleno aleatorio en los mensajes", self.var_relleno)):
            tk.Checkbutton(ctl, text=texto, variable=var, bg=BG, fg=FG, selectcolor=FONDO_TXT,
                           activebackground=BG, activeforeground=FG, font=F["ui"],
                           highlightthickness=0).pack(side="left", padx=(0, 12))
        self.btn = Boton(ctl, "Conectar", self.conectar, bg=MENTA)
        self.btn.pack(side="left", padx=6)
        self.estado = tk.Label(self, text="Elige el tamaño de clave y pulsa Conectar.", bg=BG, fg=MUTED,
                               font=F["ui"], anchor="w")
        self.estado.pack(fill="x", padx=18, pady=(0, 8))

        zona = tk.Frame(self, bg=BG)
        zona.pack(fill="both", expand=True, padx=18, pady=(0, 16))
        for i in range(3):
            zona.columnconfigure(i, weight=1, uniform="col")
        zona.rowconfigure(0, weight=1)
        self.terms = {
            "Alice": Terminal(zona, "ALICE", "usuaria", AZUL, True, lambda: self.enviar("Alice")),
            "Eve": Terminal(zona, "EVE", "espía en el canal", ROSA),
            "Bob": Terminal(zona, "BOB", "usuario", MENTA, True, lambda: self.enviar("Bob")),
        }
        for i, nombre in enumerate(("Alice", "Eve", "Bob")):
            self.terms[nombre].grid(row=0, column=i, sticky="nsew", padx=6)

        # Semaforo de Eve: estado del ataque contra cada clave
        self.semaforo = {}
        for nombre in NOMBRES:
            etq = tk.Label(self.terms["Eve"].pie, text=f"Clave de {nombre}: —", bg=PANEL, fg=MUTED, font=F["ui"], anchor="w")
            etq.pack(fill="x")
            self.semaforo[nombre] = etq
        self.limpiar_todo()

    def destroy(self):
        if self.sesion is not None:
            self.sesion.cerrar()               # detiene la generacion de claves y los ataques
        super().destroy()

    # --- utilidades --------------------------------------------------------
    def vivo(self, s):
        if s is not self.sesion or s.cancelada:
            return False
        try:
            return bool(self.winfo_exists())
        except tk.TclError:
            return False

    def post(self, s, fn):
        """Ejecuta fn en el hilo de la interfaz si la sesion sigue vigente."""
        self.app.ui(lambda: fn() if self.vivo(s) else None)

    def limpiar_todo(self, inicial=True):
        for t in self.terms.values():
            t.limpiar()
            t.habilitar(False)
        for nombre, etq in self.semaforo.items():
            etq.config(text=f"Clave de {nombre}: —", fg=MUTED)
        if inicial:
            self.terms["Eve"].escribir("Eve está esperando en el canal…", "sistema")
            self.terms["Alice"].escribir("Sin conexión todavía.", "sistema")
            self.terms["Bob"].escribir("Sin conexión todavía.", "sistema")

    def marcar(self, nombre, texto, color):
        self.semaforo[nombre].config(text=f"Clave de {nombre}: {texto}", fg=color)

    # --- conexion: generar claves e intercambiar las publicas ----------------
    def conectar(self):
        if self.sesion is not None:
            self.sesion.cerrar()               # los hilos de la sesion anterior se detienen
        bits = self.TAMANOS[self.cmb.get()]
        s = self.sesion = SesionChat(bits, self.var_eve.get(), ATAQUE_SEG)
        self.limpiar_todo(inicial=False)
        self.terms["Eve"].escribir("Eve está en el canal." if s.con_eve else
                                   "Eve NO está conectada: no ve nada.", "sistema")
        self.btn.texto("Reiniciar")
        self.estado.config(text=f"Generando claves RSA de {bits} bits…", fg=MANTEQUILLA)
        threading.Thread(target=self._generar, args=(s,), daemon=True).start()

    def _generar(self, s):
        try:
            for nombre in NOMBRES:
                self.post(s, lambda n=nombre: self.terms[n].escribir(f"Generando claves RSA de {s.bits} bits…", "sistema"))
                pub, priv, dt = s.generar_par()

                def registrar(n=nombre, pub=pub, priv=priv, dt=dt):
                    s.registrar_claves(n, pub, priv)       # solo si la sesion sigue vigente
                    t = self.terms[n]
                    t.escribir(f"  n = {corto(pub['n'], 10)}", "tecnico")
                    t.escribir(f"  e = {pub['e']}", "tecnico")
                    t.escribir(f"  d = {corto(priv['d'], 6)}  (secreta)", "tecnico")
                    t.escribir(f"  listo en {dt:.2f} s", "sistema")
                self.post(s, registrar)
        except InterruptedError:
            return
        except Exception as ex:
            texto = f"Error al generar las claves: {ex}"
            self.post(s, lambda: self.estado.config(text=texto, fg=ALERTA))
            return
        self.post(s, lambda: self._intercambiar(s))

    def _intercambiar(self, s):
        for yo in NOMBRES:
            otro = "Bob" if yo == "Alice" else "Alice"
            t = self.terms[yo]
            t.escribir("", "sistema")
            t.escribir(f"→ envío mi clave PÚBLICA (n, e) a {otro}", "aviso")
            t.escribir(f"← recibí la clave pública de {otro} (n de {s.bits} bits)", "aviso")
        eve = self.terms["Eve"]
        if s.con_eve:
            for dueno in NOMBRES:
                p = s.pub[dueno]
                eve.escribir("", "sistema")
                eve.escribir(f"Intercepté la clave PÚBLICA de {dueno}:", "normal")
                eve.escribir(f"  n = {corto(p['n'], 10)}", "tecnico")
                eve.escribir(f"  e = {p['e']}", "tecnico")
                eve.escribir(f"  Intento factorizar n (máx. {s.ataque_seg} s)…", "aviso")
                s.empezar_ataque(dueno)
                self.marcar(dueno, "factorizando…", MANTEQUILLA)
                threading.Thread(target=self._atacar, args=(s, dueno, dict(p)), daemon=True).start()
            self._cuenta_atras(s)
        for t in (self.terms["Alice"], self.terms["Bob"]):
            t.escribir("", "sistema")
            t.escribir("Canal listo. Escribe un mensaje.", "seguro")
        self.terms["Alice"].habilitar(True)
        self.terms["Bob"].habilitar(True)
        self.estado.config(text=f"Canal listo · claves de {s.bits} bits", fg=MENTA)

    # --- criptoanalisis: Eve intenta factorizar n ----------------------------
    def _cuenta_atras(self, s):
        """Actualiza el semaforo de Eve mientras factoriza: barra y segundos."""
        if not self.vivo(s):
            return
        ahora = time.monotonic()
        for dueno, inicio in list(s.atacando.items()):
            seg = ahora - inicio
            llenos = min(10, int(10 * seg / s.ataque_seg))
            self.marcar(dueno, f"factorizando… {'█' * llenos}{'░' * (10 - llenos)} "
                               f"{min(seg, s.ataque_seg):.0f}/{s.ataque_seg} s", MANTEQUILLA)
        if s.atacando:
            self.after(250, lambda: self._cuenta_atras(s))

    def _atacar(self, s, dueno, publica):
        try:
            privada, dt = s.intentar_romper(publica)
        except Exception:
            return
        if s.cancelada:
            return
        bits = publica["n"].bit_length()

        def fin():
            s.terminar_ataque(dueno, privada)
            eve = self.terms["Eve"]
            eve.escribir("", "sistema")
            if privada is None:
                eve.escribir(f"Me rindo con la clave de {dueno}: tras {dt:.0f} s no pude "
                             f"factorizar un n de {bits} bits.", "seguro")
                self.marcar(dueno, "RESISTIÓ ✓", MENTA)
            else:
                eve.escribir(f"¡ROTA la clave de {dueno} en {dt:.3f} s!", "alerta")
                eve.escribir(f"  p = {privada['p']}", "alerta")
                eve.escribir(f"  q = {privada['q']}", "alerta")
                eve.escribir(f"  d = {privada['d']}", "alerta")
                eve.escribir(f"  Ahora puedo leer todo lo que le envíen a {dueno}.", "alerta")
                self.marcar(dueno, f"ROTA en {dt:.3f} s ✗", ALERTA)
        self.post(s, fin)

    # --- enviar un mensaje -------------------------------------------------
    def enviar(self, origen):
        s = self.sesion
        term = self.terms[origen]
        if s is None or not s.lista or term.entrada is None or str(term.entrada["state"]) == "disabled":
            return
        texto = term.entrada.get().strip()
        if not texto:
            return
        try:
            msg = s.cifrar(origen, texto, self.var_relleno.get())
        except (ValueError, RuntimeError) as ex:
            term.escribir(f"No se pudo cifrar: {ex}", "alerta")
            return
        term.entrada.delete(0, "end")
        extra = f" (+{len(msg.bloques) - 1} bloques)" if len(msg.bloques) > 1 else ""
        term.escribir("", "sistema")
        term.escribir(f"{origen}: {texto}", "yo")
        if msg.relleno:
            term.escribir("  relleno aleatorio:  M = 0x02 ‖ PS ‖ 0x00 ‖ texto", "tecnico")
        term.escribir(f"  cifro con la clave PÚBLICA de {msg.destino}:  C = M^e mod n", "tecnico")
        term.escribir(f"  envío C = {corto(msg.bloques[0], 10)}{extra}", "tecnico")
        retraso = 500
        if s.con_eve:
            self.after(retraso, lambda: self.vivo(s) and self._eve_ve(s, msg))
            retraso += 600
        self.after(retraso, lambda: self.vivo(s) and self._entregar(s, msg))

    def _eve_ve(self, s, msg):
        eve = self.terms["Eve"]
        estado, texto, repetido = s.analizar_eve(msg)
        eve.escribir("", "sistema")
        eve.escribir(f"Mensaje {msg.origen} → {msg.destino}", "normal")
        eve.escribir(f"  C = {corto(msg.bloques[0], 10)}  ({len(msg.bloques)} bloque(s))", "tecnico")
        if repetido:
            eve.escribir("  ⚠ Este MISMO cifrado ya pasó antes: sé que el mensaje se repitió, aunque no lo lea "
                         "(RSA sin relleno es determinista).", "aviso")
        if estado == "descifrado":
            eve.escribir(f'  DESCIFRADO por Eve: "{texto}"', "alerta")
        elif estado == "atacando":
            eve.escribir(f"  Aún no puedo leerlo: sigo intentando romper la clave de {msg.destino}…", "aviso")
        else:
            eve.escribir(f"  No puedo leerlo: no tengo la clave privada de {msg.destino}.", "seguro")

    def _entregar(self, s, msg):
        t = self.terms[msg.destino]
        t.escribir("", "sistema")
        t.escribir(f"  recibí C = {corto(msg.bloques[0], 10)}", "tecnico")
        t.escribir("  descifro con MI clave privada:  M = C^d mod n", "tecnico")
        try:
            t.escribir(f"{msg.origen}: {s.descifrar(msg)}", "otro")
        except (ValueError, ArithmeticError) as ex:
            t.escribir(f"  No pude descifrar el mensaje: {ex}", "alerta")


# ----------------------------- Pantalla: RSA paso a paso -------------------
class PantallaPasos(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=BG)
        self.pasos, self.indice = [], 0
        Encabezado(self, "RSA paso a paso", "cada cálculo, uno por uno", app.ir_menu).pack(fill="x", padx=18, pady=(14, 8))

        form = tk.Frame(self, bg=PANEL)
        form.pack(fill="x", padx=18, pady=(0, 8))
        self.campos = {}
        for i, (nombre, etiqueta, ancho, defecto) in enumerate([
                ("p", "p (primo)", 14, "61"), ("q", "q (primo)", 14, "53"),
                ("e", "e (exponente público)", 10, "17"), ("m", "Mensaje (número o texto)", 22, "65")]):
            tk.Label(form, text=etiqueta, bg=PANEL, fg=MUTED, font=F["peq"]).grid(row=0, column=i, sticky="w", padx=(14, 4), pady=(10, 0))
            ent = tk.Entry(form, width=ancho, bg=FONDO_TXT, fg=FG, insertbackground=FG, relief="flat", font=F["mono_g"],
                           highlightthickness=1, highlightbackground="#33415F", highlightcolor=AZUL)
            ent.insert(0, defecto)
            ent.grid(row=1, column=i, sticky="w", padx=(14, 4), pady=(2, 12), ipady=5)
            ent.bind("<Return>", lambda e: self.iniciar())
            self.campos[nombre] = ent
        Boton(form, "Ejemplo del informe", self.ejemplo, bg="#34405A", fg=AZUL).grid(row=1, column=4, padx=(14, 4))
        self.btn_iniciar = Boton(form, "Iniciar  ▶", self.iniciar, bg=MENTA)
        self.btn_iniciar.grid(row=1, column=5, padx=4)
        form.columnconfigure(6, weight=1)

        nav = tk.Frame(self, bg=BG)
        nav.pack(fill="x", padx=18, pady=(0, 8))
        self.btn_sig = Boton(nav, "Siguiente paso  ▶", self.siguiente, bg=AZUL)
        self.btn_sig.pack(side="left")
        self.btn_todo = Boton(nav, "Mostrar todo", self.mostrar_todo, bg=DURAZNO)
        self.btn_todo.pack(side="left", padx=8)
        self.btn_copiar = Boton(nav, "Copiar", self.copiar, bg="#34405A", fg=AZUL)
        self.btn_copiar.pack(side="left")
        self.btn_guardar = Boton(nav, "Guardar .txt", self.guardar, bg="#34405A", fg=AZUL)
        self.btn_guardar.pack(side="left", padx=8)
        self.progreso = tk.Label(nav, text="", bg=BG, fg=MUTED, font=F["ui"])
        self.progreso.pack(side="left", padx=12)
        self.error = tk.Label(nav, text="", bg=BG, fg=ALERTA, font=F["ui_b"])
        self.error.pack(side="left", padx=12)
        for b in (self.btn_sig, self.btn_todo, self.btn_copiar, self.btn_guardar):
            b.activar(False)

        self.txt = area_texto(self)
        self._mensaje_inicial()

    def _mensaje_inicial(self):
        self._poner("Elige p, q, e y un mensaje (o usa el ejemplo del informe) y pulsa Iniciar.\n"
                    "Después avanza con «Siguiente paso» para ver cada cálculo, o pulsa «Mostrar todo».", "nota", limpiar=True)

    def _poner(self, texto, etiqueta, limpiar=False):
        self.txt.config(state="normal")
        if limpiar:
            self.txt.delete("1.0", "end")
        self.txt.insert("end", texto + "\n", etiqueta)
        self.txt.config(state="disabled")

    def ejemplo(self):
        for nombre, valor in zip("pqem", ("61", "53", "17", "65")):
            self.campos[nombre].delete(0, "end")
            self.campos[nombre].insert(0, valor)
        self.iniciar()

    def iniciar(self):
        try:
            p, q, e, m, texto = pasos.validar(*(self.campos[k].get() for k in "pqem"))
        except ValueError as ex:
            self.error.config(text=f"⚠ {ex}")
            return
        self.error.config(text="")
        self.pasos, self.indice = pasos.construir_pasos(p, q, e, m, texto), 0
        self.txt.config(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.config(state="disabled")
        self.btn_copiar.activar(True)
        self.btn_guardar.activar(True)
        self.siguiente()

    def siguiente(self):
        if self.indice >= len(self.pasos):
            return
        titulo, lineas = self.pasos[self.indice]
        inicio = self.txt.index("end-1c")
        self._poner(titulo, "titulo")
        for linea, etiqueta in lineas:
            self._poner(linea, etiqueta)
        self.indice += 1
        self.txt.yview(inicio)
        hecho = self.indice >= len(self.pasos)
        self.progreso.config(text=f"Paso {self.indice} de {len(self.pasos)}" + ("  ·  ✓ completado" if hecho else ""))
        self.btn_sig.activar(not hecho)
        self.btn_todo.activar(not hecho)

    def mostrar_todo(self):
        while self.indice < len(self.pasos):
            self.siguiente()

    # --- exportar: todos los pasos, se hayan mostrado ya o no ----------------
    def _texto_completo(self):
        partes = []
        for titulo, lineas in self.pasos:
            partes.append(titulo)
            partes.extend(linea for linea, _ in lineas)
            partes.append("")
        return "\n".join(partes)

    def copiar(self):
        if not self.pasos:
            return
        self.clipboard_clear()
        self.clipboard_append(self._texto_completo())
        self.error.config(text="")
        self.progreso.config(text="Copiado al portapapeles ✓")

    def guardar(self):
        if not self.pasos:
            return
        ruta = filedialog.asksaveasfilename(parent=self, defaultextension=".txt", initialfile="rsa_paso_a_paso.txt",
                                            filetypes=[("Texto", "*.txt"), ("Todos los archivos", "*.*")])
        if not ruta:
            return
        try:
            with open(ruta, "w", encoding="utf-8") as f:
                f.write(self._texto_completo())
            self.error.config(text="")
            self.progreso.config(text=f"Guardado en {ruta}")
        except OSError as ex:
            self.error.config(text=f"⚠ No se pudo guardar: {ex}")


# ----------------------------- Pantalla: ataques al RSA de libro -----------
class PantallaAtaques(tk.Frame):
    ATAQUES = {"Exponente pequeño (e = 3)": "e3",
               "Módulo común (dos e, mismo n)": "modulo",
               "Tiempo de factorización": "tiempo"}

    def __init__(self, master, app):
        super().__init__(master, bg=BG)
        self.app, self.cancelar = app, threading.Event()
        Encabezado(self, "Ataques al RSA de libro", "por qué hace falta relleno", app.ir_menu).pack(fill="x", padx=18, pady=(14, 8))

        form = tk.Frame(self, bg=PANEL)
        form.pack(fill="x", padx=18, pady=(0, 8))
        tk.Label(form, text="Ataque", bg=PANEL, fg=MUTED, font=F["peq"]).grid(row=0, column=0, sticky="w", padx=(14, 4), pady=(10, 0))
        self.cmb = ttk.Combobox(form, values=list(self.ATAQUES), state="readonly", width=30, font=F["ui"])
        self.cmb.current(0)
        self.cmb.grid(row=1, column=0, sticky="w", padx=(14, 4), pady=(2, 12))
        self.cmb.bind("<<ComboboxSelected>>", lambda e: self._ajustar())
        tk.Label(form, text="Mensaje que envía Alice", bg=PANEL, fg=MUTED, font=F["peq"]).grid(row=0, column=1, sticky="w", padx=(14, 4), pady=(10, 0))
        self.ent = tk.Entry(form, width=26, bg=FONDO_TXT, fg=FG, insertbackground=FG, relief="flat", font=F["mono_g"],
                            disabledbackground="#182033", disabledforeground=MUTED,
                            highlightthickness=1, highlightbackground="#33415F", highlightcolor=AZUL)
        self.ent.insert(0, "Hola Bob")
        self.ent.grid(row=1, column=1, sticky="w", padx=(14, 4), pady=(2, 12), ipady=5)
        self.ent.bind("<Return>", lambda e: self.ejecutar())
        self.var_relleno = tk.BooleanVar(value=False)
        self.chk = tk.Checkbutton(form, text="Usar relleno aleatorio", variable=self.var_relleno, bg=PANEL, fg=FG,
                                  selectcolor=FONDO_TXT, activebackground=PANEL, activeforeground=FG,
                                  disabledforeground=MUTED, font=F["ui"], highlightthickness=0)
        self.chk.grid(row=1, column=2, padx=(14, 4), pady=(2, 12))
        self.btn = Boton(form, "Ejecutar  ▶", self.ejecutar, bg=MENTA)
        self.btn.grid(row=1, column=3, padx=(14, 4), pady=(2, 12))
        self.estado = tk.Label(form, text="", bg=PANEL, fg=MUTED, font=F["ui"])
        self.estado.grid(row=1, column=4, padx=10)

        self.txt = area_texto(self)
        self._poner("Elige un ataque y pulsa Ejecutar. Marca «relleno aleatorio» para ver cómo lo detiene.\n\n"
                    "• Exponente pequeño: con e = 3 y un mensaje corto, C = M³ sin reducción módulo n.\n"
                    "• Módulo común: el mismo n con dos exponentes distintos revela el mensaje.\n"
                    "• Tiempo de factorización: mide cuánto tarda romper claves pequeñas y extrapola.", "nota", limpiar=True)

    def destroy(self):
        self.cancelar.set()
        super().destroy()

    def _ajustar(self):
        medir = self.ATAQUES[self.cmb.get()] == "tiempo"
        self.ent.config(state="disabled" if medir else "normal")
        self.chk.config(state="disabled" if medir else "normal")

    def _poner(self, texto, etiqueta, limpiar=False):
        self.txt.config(state="normal")
        if limpiar:
            self.txt.delete("1.0", "end")
        self.txt.insert("end", texto + "\n", etiqueta)
        self.txt.config(state="disabled")
        self.txt.see("end")

    def _post(self, cancelar, fn):
        """Ejecuta fn en el hilo de la interfaz si esta ejecucion sigue vigente."""
        self.app.ui(lambda: fn() if not cancelar.is_set() else None)

    def ejecutar(self):
        modo = self.ATAQUES[self.cmb.get()]
        texto = self.ent.get().strip()
        if modo != "tiempo" and not texto:
            self.estado.config(text="⚠ Escribe un mensaje.", fg=ALERTA)
            return
        self.cancelar.set()                       # detiene una ejecucion anterior
        self.cancelar = cancelar = threading.Event()
        self._poner("Midiendo el tiempo de factorización (puede tardar unos segundos)…" if modo == "tiempo"
                    else f"Generando claves de {BITS_ATAQUES} bits…", "nota", limpiar=True)
        self.estado.config(text="Ejecutando…", fg=MANTEQUILLA)
        threading.Thread(target=self._trabajo, args=(cancelar, modo, texto, self.var_relleno.get()),
                         daemon=True).start()

    def _trabajo(self, cancelar, modo, texto, relleno):
        lineas = []
        try:
            if modo == "tiempo":
                def fila(f):
                    linea = ataques.linea_benchmark(f[0], f[1], BENCH_SEG)
                    self._post(cancelar, lambda: self._poner(linea, "tabla"))
                res = ataques.benchmark_factorizacion(TAMANOS_BENCH, BENCH_SEG, cancelar, fila)
                if not cancelar.is_set():
                    lineas = ataques.lineas_extrapolacion(res)
            else:
                demo = ataques.demo_e_pequeno if modo == "e3" else ataques.demo_modulo_comun
                lineas = demo(texto, BITS_ATAQUES, relleno, cancelar)
        except InterruptedError:
            return
        except Exception as ex:
            lineas = [(f"Error: {ex}", "error")]
        self._post(cancelar, lambda: self._terminar(lineas, modo))

    def _terminar(self, lineas, modo):
        if modo != "tiempo":
            self._poner("", "nota", limpiar=True)
        for linea, etiqueta in lineas:
            self._poner(linea, etiqueta)
        self.estado.config(text="Listo", fg=MENTA)


# ----------------------------- Aplicacion ----------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Laboratorio RSA · Criptoanálisis")
        self.geometry("1360x800")
        self.minsize(1120, 680)
        self.configure(bg=BG)
        crear_fuentes()
        estilo = ttk.Style(self)
        try:
            estilo.theme_use("clam")
        except tk.TclError:
            pass
        estilo.configure("TCombobox", fieldbackground=FONDO_TXT, background=PANEL, foreground=FG,
                         arrowcolor=AZUL, bordercolor="#33415F", lightcolor=PANEL, darkcolor=PANEL, padding=4)
        estilo.map("TCombobox", fieldbackground=[("readonly", FONDO_TXT)], foreground=[("readonly", FG)],
                   selectbackground=[("readonly", FONDO_TXT)], selectforeground=[("readonly", FG)])
        self.option_add("*TCombobox*Listbox.background", PANEL)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", AZUL)
        self.option_add("*TCombobox*Listbox.selectForeground", OSCURO)
        self.cola = queue.Queue()
        self.pantalla = None
        # Pie fijo (se empaqueta antes que las pantallas para quedar siempre abajo)
        pie = tk.Frame(self, bg=PANEL)
        pie.pack(side="bottom", fill="x")
        tk.Frame(pie, bg="#33415F", height=1).pack(fill="x")
        tk.Label(pie, text="φ(n) = (p − 1)(q − 1)   ·   Laboratorio RSA · Criptoanálisis · UNI   ·   "
                           "Copyright © 2026 Ismael Rojas", bg=PANEL, fg=MUTED, font=F["peq"], pady=5).pack()
        self.ir_menu()
        self.after(30, self._sondear)

    def ui(self, fn):
        """Los hilos de trabajo dejan aqui lo que debe ejecutarse en la interfaz."""
        self.cola.put(fn)

    def _sondear(self):
        while True:
            try:
                fn = self.cola.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except Exception as ex:                  # un error de un hilo no debe congelar la ventana
                print("Error en la interfaz:", ex, file=sys.stderr)
        self.after(30, self._sondear)

    def _mostrar(self, clase):
        if self.pantalla is not None:
            self.pantalla.destroy()
        self.pantalla = clase(self, self)
        self.pantalla.pack(fill="both", expand=True)

    def ir_menu(self): self._mostrar(PantallaMenu)
    def ir_chat(self): self._mostrar(PantallaChat)
    def ir_pasos(self): self._mostrar(PantallaPasos)
    def ir_ataques(self): self._mostrar(PantallaAtaques)


if __name__ == "__main__":
    preparar_consola()
    try:                                              # pantallas de alta resolucion en Windows
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    App().mainloop()
