# herramientas.jorgelaborda.es

Sitio estático (HTML + CSS, sin JavaScript ni cookies) con el listado de herramientas y una página por cada una:

- `/` listado
- `/jano-lab/`, `/crawl-lab/`, `/gnomon-lab/`, `/sincro-lab/`
- `sitemap.xml`, `robots.txt`, `404.html`

Los textos se generan con `build.py` (rama `catalogo` del repo `herramientas`). Para cambiar un texto, edita la lista `TOOLS` y vuelve a ejecutar `python3 build.py .`

## Publicarlo en Coolify (el VPS donde ya está Jano Lab)

1. **DNS**: en el proveedor del dominio jorgelaborda.es, crea un registro `A` llamado `herramientas` que apunte a la IP del VPS de Coolify (la misma que usa `jano-lab.jorgelaborda.es`). Si el subdominio ya existía apuntando al hosting antiguo, cámbialo.
2. **Coolify** → New Resource → Public/Private Repository → `jorgelab-gif/herramientas`, rama `catalogo`, Build Pack **Dockerfile**, puerto 80.
3. Dominio: `https://herramientas.jorgelaborda.es`. Coolify saca el certificado HTTPS solo.
4. Deploy.

Alternativa sin Coolify: sube el contenido de esta carpeta (sin `Dockerfile`, `nginx.conf`, `.dockerignore`, `wordpress/`, `LEEME.md`) a la raíz del subdominio en cualquier hosting.

## Tarjeta en la home de jorgelaborda.es (WordPress)

- `wordpress/tarjeta-bloques.html`: bloques nativos de Gutenberg, toman los estilos del tema. En la home: menú ⋮ → Editor de código → pega el contenido donde quieras la tarjeta → Salir del editor de código.
- `wordpress/tarjeta-html-personalizado.html`: alternativa para pegar en un bloque «HTML personalizado» si el tema no usa Gutenberg o la primera opción no se ve bien.
