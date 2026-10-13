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
            "Si eres cliente, puedes pedir con este formulario acceso de solo lectura a tus webs: verás las acciones, los cambios y su resultado.",
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
            "Si quieres un análisis de logs de tu web, o te interesa el estudio de las actualizaciones de Google, rellena el formulario y lo vemos.",
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
            "Si quieres probarlo en tu web cuando esté listo, rellena el formulario y te aviso.",
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
            "Si gestionas apartamentos turísticos con Beds24 y te interesa, rellena el formulario y te enseño cómo funciona.",
        ],
        "cta": "Solicitar una demostración",
    },
]

CUR = ' aria-current="page"'
MAIN = "https://jorgelaborda.es"
LOGO = MAIN + "/wp-content/uploads/2022/12/cropped-Joorge-logo.png"
ICON_PNG = MAIN + "/wp-content/uploads/2022/12/cropped-cropped-Joorge-logo-270x270.png"
PRIVACY = MAIN + "/politica-de-privacidad/"

MENU = [
    ("Consultor SEO Granada", MAIN + "/consultor-seo-granada/"),
    ("Mantenimiento WordPress Granada", MAIN + "/mantenimiento-wordpress-granada/"),
    ("Herramientas", "/"),
    ("Sobre mí", MAIN + "/sobre-mi/"),
    ("Contacto", MAIN + "/contacto/"),
]

SOURCES = ["Google u otro buscador", "LinkedIn", "Podcast", "Blog de jorgelaborda.es",
           "Recomendación de alguien", "Ya soy cliente", "Otro"]

def esc(s):
    return html.escape(s, quote=True)

def page(title, desc, path, body, noindex=False):
    menu = "\n".join(
        f'        <li><a href="{esc(u)}"{CUR if u == "/" and path == "/" else ""}>{esc(n)}</a></li>'
        for n, u in MENU)
    robots = '<meta name="robots" content="noindex, follow">\n' if noindex else ""
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(desc)}">
{robots}<link rel="canonical" href="{BASE}{path}">
<meta property="og:type" content="website">
<meta property="og:locale" content="es_ES">
<meta property="og:site_name" content="Jorge Laborda">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(desc)}">
<meta property="og:url" content="{BASE}{path}">
<link rel="icon" href="{ICON_PNG}">
<link rel="stylesheet" href="/assets/styles.css">
</head>
<body>
<a class="skip" href="#contenido">Saltar al contenido</a>
<header class="site-header">
  <div class="wrap header-row">
    <a class="logo" href="{MAIN}/"><img src="{LOGO}" alt="Jorge Laborda" width="200" height="59"></a>
    <nav class="main-nav" aria-label="Menú principal">
      <details class="menu-toggle">
        <summary>Menú</summary>
        <ul>
{menu}
        </ul>
      </details>
      <ul class="menu-wide">
{menu}
      </ul>
    </nav>
  </div>
</header>
<main id="contenido">
{body}
</main>
<footer class="site-footer">
  <div class="wrap footer-row">
    <div>
      <img src="{LOGO}" alt="" width="160" height="47" class="footer-logo">
      <p><a href="mailto:hola@jorgelaborda.es">hola@jorgelaborda.es</a> · <a href="https://linkedin.com/in/jorge-laborda-web">LinkedIn</a></p>
    </div>
    <ul class="footer-links">
      <li><a href="{MAIN}/">jorgelaborda.es</a></li>
      <li><a href="{MAIN}/contacto/">Contacto</a></li>
      <li><a href="{PRIVACY}">Política de privacidad</a></li>
    </ul>
  </div>
  <div class="wrap"><p class="copy">© {YEAR} Jorge Laborda · Esta web no usa cookies.</p></div>
</footer>
</body>
</html>
"""

def badge(tool):
    return f'<span class="badge badge-{tool["access"]}">{esc(tool["access_label"])}</span>'

def index():
    cards = "\n".join(f"""    <li class="card">
      <h2><a href="/{t['slug']}/">{esc(t['name'])}</a></h2>
      <p class="card-tagline">{esc(t['tagline'])}</p>
      <p>{esc(t['summary'])}</p>
      <p class="meta">{badge(t)} <span class="state">{esc(t['state'])}</span></p>
    </li>""" for t in TOOLS)
    body = f"""<section class="hero">
  <div class="wrap">
    <h1>Herramientas propias</h1>
    <p class="lead">Prefiero construir mis propias herramientas antes que adaptar mi trabajo a las de otros. Así sé exactamente qué miden, dónde están los datos y puedo cambiarlas cuando el trabajo lo pide.</p>
    <p>Estas son las que he creado. Cada una tiene su página con para qué sirve, si el acceso es abierto o cerrado y un formulario para solicitarlo.</p>
  </div>
</section>
<section class="wrap">
  <ul class="grid">
{cards}
  </ul>
</section>"""
    return page("Herramientas de Jorge Laborda",
                "Herramientas creadas por Jorge Laborda: Jano Lab, Crawl Lab, Gnomon Lab y Sincro Lab. Qué hace cada una y cómo solicitar acceso.",
                "/", body)

def field(name, label, type_="text", auto="", required=True, extra="", hint=""):
    req = " required" if required else ""
    ac = f' autocomplete="{auto}"' if auto else ""
    opt = "" if required else ' <span class="opt">(opcional)</span>'
    h = f'<small id="{name}-ayuda">{esc(hint)}</small>' if hint else ""
    desc = f' aria-describedby="{name}-ayuda"' if hint else ""
    return f"""        <p class="f"><label for="{name}">{esc(label)}{opt}</label>
        <input id="{name}" name="{name}" type="{type_}"{ac}{req}{extra}{desc}>{h}</p>"""

def form(t):
    sources = "\n".join(f'            <option>{esc(s)}</option>' for s in SOURCES)
    return f"""    <form class="request" method="post" action="/solicitar.php" data-request>
      <input type="hidden" name="herramienta" value="{t['slug']}">
      <input type="hidden" name="t" value="">
      <input type="hidden" name="s" value="">
      <div class="trap" aria-hidden="true">
        <label for="empresa_web_{t['slug']}">No rellenes este campo</label>
        <input id="empresa_web_{t['slug']}" name="empresa_web" type="text" tabindex="-1" autocomplete="off">
      </div>

      <fieldset>
        <legend>Tus datos</legend>
{field("nombre", "Nombre y apellidos", auto="name", extra=' maxlength="120"')}
{field("email", "Email", "email", auto="email", extra=' maxlength="160"')}
{field("telefono", "Teléfono", "tel", auto="tel", extra=' maxlength="30" pattern="[0-9 +]{9,30}"', hint="Con prefijo si no es de España.")}
      </fieldset>

      <fieldset>
        <legend>Datos de facturación</legend>
{field("razon_social", "Nombre fiscal o razón social", auto="organization", extra=' maxlength="160"')}
{field("nif", "NIF / CIF", extra=' maxlength="20"')}
{field("direccion", "Dirección", auto="street-address", extra=' maxlength="200"')}
        <div class="row">
{field("cp", "Código postal", auto="postal-code", extra=' maxlength="10"')}
{field("ciudad", "Población", auto="address-level2", extra=' maxlength="80"')}
        </div>
        <div class="row">
{field("provincia", "Provincia", auto="address-level1", extra=' maxlength="80"')}
{field("pais", "País", auto="country-name", extra=' maxlength="80" value="España"')}
        </div>
      </fieldset>

      <fieldset>
        <legend>Sobre la solicitud</legend>
{field("web", "Web donde quieres usar " + t["name"], "url", auto="url", extra=' maxlength="200" placeholder="https://"')}
        <p class="f"><label for="origen">¿Cómo me has conocido?</label>
          <select id="origen" name="origen" required>
            <option value="">Elige una opción</option>
{sources}
          </select></p>
        <p class="f"><label for="motivo">¿Para qué quieres usar {esc(t["name"])}?</label>
        <textarea id="motivo" name="motivo" rows="5" minlength="20" maxlength="3000" required></textarea></p>
      </fieldset>

      <p class="f check"><input id="privacidad" name="privacidad" type="checkbox" value="1" required>
        <label for="privacidad">He leído y acepto la <a href="{PRIVACY}">política de privacidad</a>.</label></p>
      <p class="legal">Responsable: Jorge Laborda. Finalidad: estudiar tu solicitud de acceso y contactar contigo. No se ceden datos a terceros salvo obligación legal. Puedes ejercer tus derechos escribiendo a {EMAIL}.</p>
      <p><button class="button" type="submit">{esc(t['cta'])}</button></p>
      <noscript><p class="small">Para enviar el formulario necesitas tener JavaScript activado.</p></noscript>
    </form>
    <script src="/assets/form.js" defer></script>"""

def tool_page(t):
    what = "\n".join(f"    <p>{esc(p)}</p>" for p in t["what"])
    feats = "\n".join(f"      <li>{esc(f)}</li>" for f in t["features"])
    how = "\n".join(f"    <p>{esc(p)}</p>" for p in t["how_access"])
    others = "\n".join(f'      <li><a href="/{o["slug"]}/">{esc(o["name"])}</a> · {esc(o["tagline"])}</li>' for o in TOOLS if o is not t)
    body = f"""<article class="wrap tool">
  <p class="crumbs"><a href="/">Herramientas</a> / {esc(t['name'])}</p>
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

  <section class="access" id="acceso" aria-labelledby="acceso-titulo">
    <h2 id="acceso-titulo">Acceso</h2>
    <dl class="access-facts">
      <dt>Tipo de acceso</dt><dd>{'Abierto' if t['access'] == 'abierto' else 'Cerrado'}</dd>
      <dt>Estado</dt><dd>{esc(t['state'])}</dd>
    </dl>
{how}
    <h3>Solicitar acceso</h3>
{form(t)}
  </section>

  <nav class="others" aria-label="Otras herramientas">
    <h2>Otras herramientas</h2>
    <ul>
{others}
    </ul>
  </nav>
</article>"""
    return page(f"{t['name']} · Herramientas de Jorge Laborda", f"{t['name']}: {t['summary']}",
                f"/{t['slug']}/", body)

def thanks(t):
    body = f"""<section class="hero"><div class="wrap">
  <h1>Solicitud enviada</h1>
  <p class="lead">Gracias. He recibido tu solicitud de acceso a {esc(t['name'])} y te responderé por email.</p>
  <p><a class="button" href="/{t['slug']}/">Volver a {esc(t['name'])}</a> &nbsp; <a href="/">Ver todas las herramientas</a></p>
</div></section>"""
    return page(f"Solicitud enviada · {t['name']}", "Solicitud de acceso enviada.", f"/{t['slug']}/gracias/", body, noindex=True)

def notfound():
    body = """<section class="hero"><div class="wrap">
  <h1>Esta página no existe</h1>
  <p class="lead">Puede que la herramienta haya cambiado de dirección.</p>
  <p><a class="button" href="/">Ver todas las herramientas</a></p>
</div></section>"""
    return page("Página no encontrada · Herramientas de Jorge Laborda", "Página no encontrada.", "/404.html", body, noindex=True)

def error_template():
    body = """<section class="hero"><div class="wrap">
  <h1>No se ha podido enviar</h1>
  {ERRORES}
  <p><a class="button" href="javascript:history.back()">Volver al formulario</a></p>
  <p class="small">Tus datos siguen en el formulario. Si el problema continúa, escribe a <a href="mailto:herramientas@jorgelaborda.es">herramientas@jorgelaborda.es</a>.</p>
</div></section>"""
    return page("No se ha podido enviar · Herramientas de Jorge Laborda", "Error al enviar la solicitud.", "/solicitar.php", body, noindex=True)

def write(rel, content):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)

write("index.html", index())
for t in TOOLS:
    write(f"{t['slug']}/index.html", tool_page(t))
    write(f"{t['slug']}/gracias/index.html", thanks(t))
write("404.html", notfound())
write("privado/plantilla-error.html", error_template())
write("robots.txt", f"User-agent: *\nDisallow: /privado/\n\nSitemap: {BASE}/sitemap.xml\n")
urls = ["/"] + [f"/{t['slug']}/" for t in TOOLS]
write("sitemap.xml", '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
      + "".join(f"  <url><loc>{BASE}{u}</loc></url>\n" for u in urls) + "</urlset>\n")
write("privado/herramientas.php", "<?php\n// Generado por build.py: herramientas que aceptan solicitudes.\nreturn [\n"
      + "".join(f"  '{t['slug']}' => '{t['name']}',\n" for t in TOOLS) + "];\n")
print("ok", len(urls), "páginas")
