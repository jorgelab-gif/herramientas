# herramientas

# Herramientas SEO - Análisis de Logs y Auditorías Web

## Descripción General

Plataforma web completa para análisis SEO que combina **auditorías técnicas automatizadas** y **análisis avanzado de logs de Apache**. Permite a los usuarios obtener insights profundos sobre el comportamiento de crawlers, indexación, errores técnicos y rendimiento SEO de sus sitios web.

## Arquitectura del Sistema

### Backend (Node.js/Express)
- **Servidor**: Express.js optimizado para VPS/hosting compartido
- **Base de Datos**: MySQL con pools de conexión
- **Autenticación**: JWT con verificación por email
- **Seguridad**: Rate limiting, validaciones, protección anti-bot
- **Procesamiento**: Análisis asíncrono de archivos y datos

### Frontend (HTML/CSS/JavaScript)
- **Diseño**: Sistema visual oscuro profesional con verde como color principal
- **Responsivo**: Adaptado para desktop, tablet y móvil
- **Interactivo**: Dashboard dinámico con estadísticas en tiempo real
- **UX**: Formularios inteligentes con validación y feedback

### Módulo de Análisis de Logs (`analizador-logs.js`)
Motor especializado para procesar logs de Apache y extraer métricas SEO avanzadas.

## Funcionalidades Principales

### 1. Sistema de Usuarios
- **Registro con verificación por email**
- **Login seguro con protección anti-bot**
- **Gestión de sesiones con JWT**
- **Dashboard personalizado por usuario**

### 2. Auditorías SEO Automatizadas
- **Configuración flexible**: Profundidad de crawl, user agent, opciones específicas
- **Análisis técnico**: Meta tags, imágenes, enlaces, estructura
- **Reportes detallados**: Puntuaciones, recomendaciones priorizadas
- **Seguimiento histórico**: Comparación temporal de métricas

### 3. Análisis Avanzado de Logs Apache

#### Capacidades de Procesamiento
- **Formatos soportados**: Archivos `.log` y `.gz` comprimidos
- **Volumen**: Procesamiento eficiente de millones de líneas
- **Parsing inteligente**: Combined Log Format de Apache
- **Detección automática**: Identificación de +20 tipos de bots/crawlers

#### Métricas y Análisis Generados

**Análisis de Crawlers**
- Identificación y clasificación de bots (Googlebot, Bingbot, etc.)
- Patrones de crawleo por bot y frecuencia
- Distribución temporal de actividad
- URLs más crawleadas por cada bot

**Análisis de Indexación**
- Comparación sitemap vs. URLs crawleadas
- URLs en sitemap no visitadas por bots
- URLs crawleadas no declaradas en sitemap
- Porcentaje de cobertura de indexación

**Análisis Técnico**
- Distribución de códigos de respuesta HTTP
- Identificación de errores 404, 500, etc.
- Análisis por directorios y secciones
- Consumo de ancho de banda por sección

**Patrones de Comportamiento**
- Actividad por horas del día
- Tendencias por días de la semana
- Picos de tráfico y crawleo
- Correlación entre tráfico humano y bots

### 4. Procesamiento de Sitemaps
- **Descarga automática** desde URL
- **Parsing XML** robusto
- **Validación** de estructura
- **Límites de seguridad** (15,000 URLs máx.)

## Flujo de Trabajo Típico

### Para Auditorías SEO:
1. Usuario se registra/logea
2. Configura nueva auditoría (URL, opciones)
3. Sistema procesa análisis técnico
4. Genera reporte con puntuaciones y recomendaciones
5. Usuario puede ver histórico y comparar resultados

### Para Análisis de Logs:
1. Usuario sube archivo de logs (.log/.gz)
2. Opcionalmente proporciona URL del sitemap
3. Sistema procesa archivo en background
4. Analizador extrae patrones, errores y métricas
5. Genera dashboard interactivo con insights

## Estructura de Base de Datos

```sql
-- Gestión de usuarios
users (id, email, password_hash, verified, verification_token, created_at)

-- Auditorías SEO
audits (id, user_id, url, config, results, status, created_at)

-- Análisis de logs
log_analyses (id, user_id, filename, sitemap_url, results, status, created_at)
```

## Configuración Técnica

### Variables de Entorno (.env)
```bash
# Servidor
PORT=3000
NODE_ENV=production
JWT_SECRET=tu_jwt_secret_seguro

# Base de datos MySQL
DB_HOST=localhost
DB_NAME=herramientas_db
DB_USER=herramientas_user
DB_PASS=tu_password
DB_PORT=3306

# Email SMTP
EMAIL_USER=herramientas@tudominio.es
EMAIL_PASS=tu_app_password
SMTP_HOST=mail.tudominio.es
SMTP_PORT=465

# URLs
BASE_URL=https://herramientas.tudominio.es
FRONTEND_URL=https://herramientas.tudominio.es
```

### Dependencias Principales
```json
{
  "express": "^4.21.2",
  "mysql2": "^3.6.5",
  "bcryptjs": "^2.4.3",
  "jsonwebtoken": "^9.0.2",
  "nodemailer": "^6.10.1",
  "express-rate-limit": "^7.5.1",
  "express-validator": "^7.2.1",
  "multer": "^2.0.2",
  "cors": "^2.8.5"
}
```

## Endpoints API Principales

### Autenticación
- `POST /api/register` - Registro de usuario
- `POST /api/login` - Login
- `GET /verify-email/:token` - Verificación email

### Auditorías SEO
- `POST /api/audit` - Crear nueva auditoría
- `GET /api/audits` - Listar auditorías del usuario
- `GET /api/audit/:id` - Obtener auditoría específica

### Análisis de Logs
- `POST /api/analyze-log` - Subir y procesar archivo de logs
- `GET /api/log-analyses` - Listar análisis del usuario
- `GET /api/log-analysis/:id` - Obtener resultado específico

### Sistema
- `GET /health` - Health check del servidor

## Características Avanzadas del Analizador de Logs

### Detección Inteligente de Bots
```javascript
// Patrones reconocidos automáticamente:
- Googlebot (y variantes: Images, News, etc.)
- Bingbot, Yandex, Baidu, DuckDuck
- Crawlers SEO: Ahrefs, SEMrush, Screaming Frog
- Social: Facebook, Twitter, LinkedIn
- Monitoreo: Pingdom, UptimeRobot
- Genéricos: Curl, Wget, scrapers
```

### Normalización de URLs
- Eliminación de fragmentos (#)
- Ordenación de parámetros query
- Detección de URLs duplicadas
- Manejo de mayúsculas/minúsculas

### Análisis Temporal Avanzado
- Distribución por horas (0-23h)
- Patrones semanales y mensuales
- Detección de picos de actividad
- Correlaciones entre eventos

## Casos de Uso Principales

1. **SEO Técnico**: Auditorías regulares para detectar problemas técnicos
2. **Análisis de Crawleo**: Entender cómo los bots ven tu sitio
3. **Optimización de Sitemap**: Identificar URLs no indexadas
4. **Monitoreo de Errores**: Seguimiento de 404s y problemas técnicos
5. **Análisis de Rendimiento**: Consumo de recursos por sección
6. **Investigación Competitiva**: Patrones de crawleo comparativos

## Instalación y Despliegue

### Desarrollo Local
```bash
git clone [repositorio]
cd herramientas-backend
npm install
cp .env.example .env
# Configurar variables de entorno
npm run dev
```

### Producción (PM2)
```bash
npm install -g pm2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

### VPS/Hosting Compartido
- Configurar Node.js environment
- Subir archivos al directorio web
- Configurar variables en .htaccess
- Inicializar base de datos MySQL

## Métricas y Reportes Generados

### Dashboard de Logs
- **Total de peticiones** y distribución bot/humano
- **Top 10 crawlers** más activos
- **URLs más crawleadas** con métricas detalladas
- **Códigos de estado** con distribución visual
- **Actividad por horas** con gráfico temporal
- **Errores detectados** con priorización
- **Análisis de sitemap** con porcentaje de cobertura

### Alertas y Recomendaciones
- URLs en sitemap no crawleadas (posibles problemas de indexación)
- Errores 404 frecuentes (contenido que necesita redirect)
- Picos anómalos de crawleo (posible penalización)
- Secciones con alta tasa de errores
- Oportunidades de optimización de sitemap

## Seguridad y Rendimiento

### Medidas de Seguridad
- **Rate limiting** configurable por endpoint
- **Validación exhaustiva** de inputs
- **Protección anti-bot** con captcha matemático
- **Sanitización** de archivos subidos
- **Encriptación** de contraseñas con bcrypt

### Optimizaciones de Rendimiento
- **Pool de conexiones** MySQL optimizado
- **Procesamiento asíncrono** de archivos grandes
- **Compresión** de respuestas
- **Caching** inteligente de resultados
- **Cleanup automático** de archivos temporales

## Monitoreo y Logs

### Health Checks
- Estado del servidor
- Conexión a base de datos
- Uso de memoria
- Tiempo de actividad

### Logs del Sistema
- Errores de procesamiento
- Actividad de usuarios
- Performance de queries
- Alertas de seguridad

## Roadmap y Mejoras Futuras

### Funcionalidades Planificadas
- **Análisis comparativo** entre períodos
- **Alertas automáticas** por email
- **API externa** para integraciones
- **Dashboard de analytics** en tiempo real
- **Exportación** de datos (CSV, PDF)
- **Análisis de logs Nginx** además de Apache

### Integraciones Posibles
- Google Search Console
- Google Analytics
- Herramientas de SEO (Ahrefs, SEMrush)
- Sistemas de monitoreo (New Relic)
- Slack/Discord para notificaciones

## Licencia y Soporte

**Licencia**: MIT  
**Autor**: Jorge Laborda (jorgelaborda.es)  
**Soporte**: herramientas@jorgelaborda.es

---

Este README proporciona una visión completa del proyecto, desde la arquitectura técnica hasta los casos de uso prácticos, facilitando tanto el desarrollo continuo como la comprensión del valor que aporta la herramienta para profesionales SEO.
