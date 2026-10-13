# herramientas.jorgelaborda.es

Listado de herramientas con una página por herramienta y un formulario de solicitud de acceso en cada una.
HTML estático + PHP para el formulario. Pensado para el hosting de Banahosting (cPanel), el mismo que jorgelaborda.es.

## Subirlo a Banahosting

1. **cPanel → Dominios**: si no existe, crea el subdominio `herramientas.jorgelaborda.es`. Anota su carpeta raíz (normalmente `public_html/herramientas` o `herramientas.jorgelaborda.es`).
2. **cPanel → Estado de SSL/TLS** → marca el subdominio → **Ejecutar AutoSSL**. Esto arregla el `ERR_SSL_PROTOCOL_ERROR`. Si AutoSSL falla, revisa en la zona DNS que `herramientas` apunta a la IP de Banahosting (la misma que `jorgelaborda.es`) y no al VPS de Coolify.
3. **cPanel → Cuentas de correo**: comprueba que existe `herramientas@jorgelaborda.es`. Es el remitente y el destinatario de las solicitudes.
4. **Administrador de archivos** → entra en la carpeta del subdominio, borra lo que haya, sube `herramientas-banahosting.zip` y pulsa **Extraer**. Tienen que quedar `index.html`, `assets/`, `privado/`, `.htaccess`, etc. directamente en la raíz (no dentro de otra carpeta).
5. Abre https://herramientas.jorgelaborda.es/ y envía una solicitud de prueba desde cualquier herramienta.

`privado/config.php` va ya relleno en el zip: destinatario, copia oculta a jorgelabordat@gmail.com y la clave que firma los formularios. No está en GitHub porque ese repo es público.

## Antispam del formulario

- Campo trampa oculto: si un bot lo rellena, se le dice que todo fue bien y no se envía nada.
- Sello de tiempo firmado que la página pide con JavaScript: sin él, o si el formulario se envía en menos de 4 segundos, se rechaza.
- Solo se aceptan envíos desde herramientas.jorgelaborda.es.
- Máximo 5 solicitudes por hora y por IP (se guarda un hash, no la IP).
- El motivo no puede llevar más de dos enlaces.

## Cambiar textos o colores

- Textos: lista `TOOLS` en `build.py`, luego `python3 build.py .` y vuelve a subir los HTML.
- Colores: variables al principio de `assets/styles.css`.

## Tarjeta en la home de jorgelaborda.es (WordPress)

- `wordpress/tarjeta-bloques.html`: bloques de Gutenberg, toman el estilo de GeneratePress. En la home: menú ⋮ → Editor de código → pega donde quieras la tarjeta → Salir del editor de código.
- `wordpress/tarjeta-html-personalizado.html`: alternativa para un bloque «HTML personalizado».
