#!/usr/bin/env python3
"""Genera el sitio estático de herramientas.jorgelaborda.es."""
import html, os, sys

OUT = sys.argv[1]
BASE = "https://herramientas.jorgelaborda.es"
EMAIL = "herramientas@jorgelaborda.es"
YEAR = "2026"

TOOLS = [
    {
        "slug": "jano-lab",
        "name": "Jano Lab",
        "tagline": "Gestión de acciones y cambios en webs, con medición de su impacto.",
        "state": "En uso",
        "access": "cerrado",
        "access_label": "Acceso cerrado",
        "summary": "Registra cada acción que se hace en una web, con su objetivo medible, y comprueba después si lo consiguió.",
        "what": [
            "Jano Lab es el panel desde el que gestiono todas las webs con las que trabajo. Cada acción nace con una hipótesis, una métrica, una línea base y un objetivo, y la herramienta programa revisiones para comprobar si se cumplió.",
            "Cada cambio concreto queda registrado con su valor anterior, el nuevo y cómo revertirlo, sea de SEO, desarrollo, diseño, sistemas, legal o mantenimiento. Así cualquier subida o caída se puede explicar mirando el historial.",
        ],
        "features": [
            "Acciones con código de trabajo único, objetivo medible y revisiones automáticas.",
            "Historial de cambios con antes, después y cómo deshacerlo.",
            "Auditorías con metodología propia y reauditoría comparada.",
            "Conexión con Crawl Lab para el rastreo y con la analítica propia para medir.",
        ],
        "who": "Lo uso a diario con mis webs y las de mis clientes.",
        "how_access": [
            "No tiene registro público.",
            "Si eres cliente, puedes pedir acceso de solo lectura a tus webs: verás las acciones, los cambios y su resultado.",
        ],
        "cta": "Pedir acceso de cliente",
    },
    {
        "slug": "crawl-lab",
        "name": "Crawl Lab",
        "tagline": "Análisis de logs del servidor para ver cómo rastrean los bots una web.",
        "state": "En uso",
        "access": "cerrado",
        "access_label": "Acceso cerrado",
        "summary": "Cruza los logs del servidor con el sitemap para saber qué rastrean Googlebot y los bots de IA, y qué se quedan sin ver.",
        "what": [
            "Crawl Lab procesa los logs de Apache o Nginx y los sitemaps de una web y muestra cómo se comportan los bots sobre ella: Googlebot, Bingbot y también GPTBot, ClaudeBot o PerplexityBot.",
            "Clasifica cada URL por tipo de página (home, categoría, producto, post, paginación, búsqueda…) para detectar dónde se va el presupuesto de rastreo, qué URLs del sitemap nunca se visitan y qué páginas pesadas se rastrean poco.",
            "Con los datos anonimizados de las webs que lo permiten, compara el rastreo antes y después de cada actualización de Google.",
        ],
        "features": [
            "Importación automática de los logs de cada web una vez al mes.",
            "Separación entre bots de buscadores y bots de IA.",
            "Cobertura del sitemap: URLs rastreadas, no rastreadas y fuera del sitemap.",
            "Descarga de los resultados completos en CSV, incluso con más de 500.000 URLs.",
        ],
        "who": "Es una herramienta interna: la uso para analizar las webs con las que trabajo.",
        "how_access": [
            "No admite altas ni cuentas externas.",
            "Si quieres un análisis de logs de tu web, o te interesa el estudio de las actualizaciones de Google, escríbeme y lo vemos.",
        ],
        "cta": "Pedir un análisis de logs",
    },
    {
        "slug": "gnomon-lab",
        "name": "Gnomon Lab",
        "tagline": "Analítica web propia, sin cookies.",
        "state": "En desarrollo",
        "access": "cerrado",
        "access_label": "Acceso cerrado",
        "summary": "Mide visitas y conversiones sin guardar nada en el navegador del usuario, para poder quitar el banner de cookies.",
        "what": [
            "Gnomon Lab es una analítica web que no usa cookies ni guarda nada en el dispositivo de quien visita la web. Los visitantes únicos se cuentan con un identificador que cambia cada día y no permite reconocer a nadie al día siguiente, y la IP no se guarda.",
            "Sustituye a Google Analytics, no a Search Console. Sus datos alimentan las líneas base y las revisiones de Jano Lab, y si la web no usa nada más que lo requiera, permite prescindir del banner de cookies.",
        ],
        "features": [
            "Script de menos de 2 KB, sin cookies ni almacenamiento local.",
            "Plugin de WordPress que envía los datos a través de la propia web.",
            "Filtrado de bots y métricas por URL, origen y dispositivo.",
            "Datos alojados en un servidor propio en la Unión Europea.",
        ],
        "who": "Primero lo usaré en mis webs; después estará disponible para clientes de Jano Lab.",
        "how_access": [
            "Todavía no está disponible.",
            "Si quieres probarlo en tu web cuando esté listo, escríbeme y te aviso.",
        ],
        "cta": "Avísame cuando esté listo",
    },
    {
        "slug": "sincro-lab",
        "name": "Sincro Lab",
        "tagline": "Gestión de reservas para apartamentos turísticos.",
        "state": "En uso",
        "access": "cerrado",
        "access_label": "Acceso cerrado",
        "summary": "Channel manager y PMS, pensado para el móvil, que sincroniza reservas de Booking, Airbnb y la web directa a través de Beds24.",
        "what": [
            "Sincro Lab reúne en una sola pantalla las reservas de todos los canales (Booking.com, Airbnb, la web propia y las directas) usando la API de Beds24, y las coloca en el calendario de cada apartamento.",
            "Permite mover a un huésped entre apartamentos iguales sin tocar el precio, fijar tarifas por día, estancias mínimas y días sin entrada o salida, y enviar mensajes automáticos en el idioma de cada huésped.",
        ],
        "features": [
            "Calendario por apartamento con reservas de todos los canales.",
            "Precios y restricciones por día.",
            "Bandeja de mensajes y mensajes programados.",
            "En español y pensada primero para el móvil.",
        ],
        "who": "Está en uso con un primer alojamiento de apartamentos turísticos.",
        "how_access": [
            "No tiene registro público.",
            "Si gestionas apartamentos turísticos con Beds24 y te interesa, escríbeme y te enseño cómo funciona.",
        ],
        "cta": "Solicitar una demostración",
    },
]

ICON = '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg"><rect width="32" height="32" rx="7" fill="#0f766e"/><path d="M19.6 8.4a5 5 0 0 0-6.4 6.2l-5 5a1.8 1.8 0 0 0 2.6 2.6l5-5a5 5 0 0 0 6.2-6.4l-2.9 2.9-2.4-.4-.4-2.4z" fill="#fff"/></svg>'

def esc(s):
    return html.escape(s, quote=True)

def mailto(tool, subject):
    from urllib.parse import quote
    body = (f"Hola Jorge,\n\nMe gustaría {subject[0].lower() + subject[1:]} de {tool['name']}.\n\n"
            "Nombre:\nWeb o empresa:\nPara qué lo necesito:\n")
    return f"mailto:{EMAIL}?subject={quote(subject + ' · ' + tool['name'])}&body={quote(body)}"

def page(title, desc, path, body, depth):
    root = "../" * depth or "./"
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(desc)}">
<link rel="canonical" href="{BASE}{path}">
<meta property="og:type" content="website">
<meta property="og:locale" content="es_ES">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(desc)}">
<meta property="og:url" content="{BASE}{path}">
<link rel="icon" href="{root}favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="{root}assets/styles.css">
</head>
<body>
<a class="skip" href="#contenido">Saltar al contenido</a>
<header class="site-header">
  <div class="wrap header-row">
    <a class="brand" href="{root}">Herramientas <span>· Jorge Laborda</span></a>
    <a class="header-link" href="https://jorgelaborda.es/">jorgelaborda.es</a>
  </div>
</header>
<main id="contenido">
{body}
</main>
<footer class="site-footer">
  <div class="wrap">
    <p>Herramientas creadas por <a href="https://jorgelaborda.es/">Jorge Laborda</a>. Para cualquier duda, escribe a <a href="mailto:{EMAIL}">{EMAIL}</a>.</p>
    <p>Esta web no usa cookies.</p>
  </div>
</footer>
</body>
</html>
"""

def badge(tool):
    return f'<span class="badge badge-{tool["access"]}">{esc(tool["access_label"])}</span>'

def index():
    cards = "\n".join(f"""    <li class="card">
      <h2><a href="{t['slug']}/">{esc(t['name'])}</a></h2>
      <p class="card-tagline">{esc(t['tagline'])}</p>
      <p>{esc(t['summary'])}</p>
      <p class="meta">{badge(t)} <span class="state">{esc(t['state'])}</span></p>
    </li>""" for t in TOOLS)
    body = f"""<section class="hero">
  <div class="wrap">
    <h1>Herramientas propias</h1>
    <p class="lead">Prefiero construir mis propias herramientas antes que adaptar mi trabajo a las de otros. Así sé exactamente qué miden, dónde están los datos y puedo cambiarlas cuando el trabajo lo pide.</p>
    <p>Estas son las que he creado. Cada una tiene su página con para qué sirve, si el acceso es abierto o cerrado y cómo pedirlo.</p>
  </div>
</section>
<section class="wrap">
  <ul class="grid">
{cards}
  </ul>
</section>"""
    return page("Herramientas de Jorge Laborda",
                "Herramientas creadas por Jorge Laborda: Jano Lab, Crawl Lab, Gnomon Lab y Sincro Lab. Qué hace cada una y cómo acceder.",
                "/", body, 0)

def tool_page(t):
    what = "\n".join(f"    <p>{esc(p)}</p>" for p in t["what"])
    feats = "\n".join(f"      <li>{esc(f)}</li>" for f in t["features"])
    how = "\n".join(f"      <p>{esc(p)}</p>" for p in t["how_access"])
    others = "\n".join(f'      <li><a href="../{o["slug"]}/">{esc(o["name"])}</a> · {esc(o["tagline"])}</li>' for o in TOOLS if o is not t)
    body = f"""<article class="wrap tool">
  <p class="crumbs"><a href="../">Herramientas</a> / {esc(t['name'])}</p>
  <h1>{esc(t['name'])}</h1>
  <p class="lead">{esc(t['tagline'])}</p>
  <p class="meta">{badge(t)} <span class="state">{esc(t['state'])}</span></p>

  <section>
    <h2>Para qué sirve</h2>
{what}
    <ul class="features">
{feats}
    </ul>
    <p class="who">{esc(t['who'])}</p>
  </section>

  <section class="access" aria-labelledby="acceso">
    <h2 id="acceso">Acceso</h2>
    <dl class="access-facts">
      <dt>Tipo de acceso</dt><dd>{'Abierto' if t['access'] == 'abierto' else 'Cerrado'}</dd>
      <dt>Estado</dt><dd>{esc(t['state'])}</dd>
    </dl>
    <div class="access-how">
{how}
      <p><a class="button" href="{esc(mailto(t, t['cta']))}">{esc(t['cta'])}</a></p>
      <p class="small">Se abrirá tu correo con un mensaje para <a href="mailto:{EMAIL}">{EMAIL}</a>.</p>
    </div>
  </section>

  <nav class="others" aria-label="Otras herramientas">
    <h2>Otras herramientas</h2>
    <ul>
{others}
    </ul>
  </nav>
</article>"""
    return page(f"{t['name']} · Herramientas de Jorge Laborda", f"{t['name']}: {t['summary']}",
                f"/{t['slug']}/", body, 1)

def notfound():
    body = """<section class="hero"><div class="wrap">
  <h1>Esta página no existe</h1>
  <p class="lead">Puede que la herramienta haya cambiado de dirección.</p>
  <p><a class="button" href="/">Ver todas las herramientas</a></p>
</div></section>"""
    return page("Página no encontrada · Herramientas de Jorge Laborda", "Página no encontrada.", "/404.html", body, 0).replace('href="./', 'href="/')

def write(rel, content):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)

write("index.html", index())
for t in TOOLS:
    write(f"{t['slug']}/index.html", tool_page(t))
write("404.html", notfound())
write("favicon.svg", ICON)
write("robots.txt", f"User-agent: *\nAllow: /\n\nSitemap: {BASE}/sitemap.xml\n")
urls = ["/"] + [f"/{t['slug']}/" for t in TOOLS]
write("sitemap.xml", '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
      + "".join(f"  <url><loc>{BASE}{u}</loc></url>\n" for u in urls) + "</urlset>\n")
print("ok", len(urls), "páginas")
