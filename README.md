# herramientas

Backend para el sitio herramientas.jorgelaborda.es.

Descripción
Este proyecto es el backend de una plataforma de herramientas, desarrollado en Node.js con Express. Está optimizado para funcionar en hostings compartidos y utiliza MySQL como base de datos. Incluye autenticación por JWT, validaciones, protección contra ataques de fuerza bruta, gestión de usuarios y auditorías, y envío de emails de verificación.

Funcionalidades principales
Registro y login de usuarios con validación y verificación por email.
Autenticación mediante JWT.
Gestión y seguimiento de auditorías web.
Base de datos MySQL gestionada con pools de conexión optim
Rate limiting para endpoints generales y de autenticación.
Envío de emails mediante Nodemailer.
Middleware para subida segura de archivos (`.log .log y )..gz
Endpoints protegidos y estructurados para facilitar la integración con el frontend.
Mane robusto de errores y shutdown graceful.
Instal
Clona el repositorio:
Clona el repositorio:

bash
git clone https://github.com/jorgelab-gif/herramientas.git
cd herramientas
Instala dependencias:

bash
npm install
Configura tu archivo .env con las variables necesarias (consulta el ejemplo en .env).

Inicia el servidor:

bash
npm run dev
Endpoints principales
POST /api/register — Registro de usuarios
POST /api/login — Login de usuarios
GET /verify-email/:token — Verificación de email
POST /api/audit — Solicitud de auditoría (requiere autenticación)
GET /api/audits — Listado de auditorías del usuario autenticado
GET /api/audit/:id — Detalle de auditoría específica (requiere autenticación)
GET /health — Health check del backend
Configuración de producción
Incluye un archivo ecosystem.config.js para despliegue con PM2 en modo cluster, logs y variables de entorno.

Dependencias principales
express
mysql2
bcryptjs
jsonwebtoken
express-validator
nodemailer
cors
express-rate-limit
multer
dotenv
Licencia
MIT
