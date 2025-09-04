# Mejoras de Conectividad VPS - Backend Optimizado

## Resumen de Mejoras Implementadas

Este documento detalla las mejoras realizadas en el archivo `server.js` para optimizar la conectividad y funcionamiento en un VPS de producción.

## 1. Configuración CORS Mejorada

### ✅ Antes
```javascript
app.use(cors({
  origin: process.env.FRONTEND_URL || BASE_URL,
  credentials: true,
  maxAge: 300
}));
```

### ✅ Después
```javascript
const allowedOrigins = [
  process.env.FRONTEND_URL,
  BASE_URL,
  'https://herramientas.jorgelaborda.es',
  'https://www.herramientas.jorgelaborda.es'
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Permitir requests sin origin (aplicaciones móviles, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`CORS: Origen bloqueado: ${origin}`);
      callback(new Error('No permitido por CORS'));
    }
  },
  credentials: true,
  maxAge: 86400, // 24 horas de cache
  exposedHeaders: ['Content-Length', 'X-Request-ID'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'X-Request-ID'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));
```

### Mejoras:
- ✅ Lista de orígenes permitidos configurables
- ✅ Logging de orígenes bloqueados para debugging
- ✅ Cache de 24 horas para opciones de CORS
- ✅ Headers expuestos y métodos específicos

## 2. Manejo de Errores y Timeouts Mejorado

### ✅ Nodemailer con Timeouts Optimizados
```javascript
const transporter = nodemailer.createTransport({
  // ... configuración anterior
  connectionTimeout: 20000, // 20s para VPS
  greetingTimeout: 20000,
  socketTimeout: 30000, // 30s para VPS
  pool: true,
  maxConnections: 5,
  maxMessages: 100,
  tls: {
    rejectUnauthorized: false // Para algunos VPS con certificados auto-firmados
  }
});
```

### ✅ Base de Datos con Retry Inteligente
```javascript
const safeQuery = async (query, params = [], retries = 3) => {
  // Logging detallado con IDs únicos
  // Backoff exponencial con límite
  // Información detallada de errores SQL
};
```

## 3. Logging Detallado para Debugging

### ✅ Sistema de Logging con Request IDs
- Cada request tiene un ID único para tracking
- Logging de duración de requests
- Logging detallado de errores con contexto
- Información de IP, User-Agent y metadatos

### ✅ Logs de Base de Datos
- ID único para cada query
- Tiempo de ejecución
- Información detallada de errores SQL
- Estrategia de reintentos visible

## 4. Optimización del Procesamiento de Logs

### ✅ Función processLogFile Mejorada
```javascript
const processLogFile = async (analysisId, filePath, sitemapUrl) => {
  const processId = `proc_${analysisId}_${Date.now()}`;
  
  // Logging detallado del proceso
  // Verificación de existencia de archivos
  // Limpieza automática de archivos temporales
  // Manejo de errores robusto
  // Métricas de rendimiento
};
```

### Mejoras:
- ✅ ID único para cada proceso de análisis
- ✅ Verificación de existencia de archivos
- ✅ Logging de métricas de rendimiento
- ✅ Limpieza automática de archivos temporales
- ✅ Manejo de errores con stack traces completos

## 5. Rutas de Archivos Temporales Optimizadas

### ✅ Directorio Temporal Específico
```javascript
const TEMP_DIR = process.env.TEMP_DIR || path.join(os.tmpdir(), 'herramientas-logs');

// Creación automática del directorio si no existe
if (!existsSync(TEMP_DIR)) {
  mkdirSync(TEMP_DIR, { recursive: true });
}
```

### ✅ Nombres de Archivo Únicos
```javascript
filename: function (req, file, cb) {
  const userId = req.user?.id || 'anon';
  const timestamp = Date.now();
  const randomSuffix = crypto.randomBytes(6).toString('hex');
  const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
  cb(null, `${userId}_${timestamp}_${randomSuffix}_${sanitizedName}`);
}
```

### ✅ Limpieza Periódica Automática
```javascript
// Limpieza cada 6 horas de archivos > 24 horas
setInterval(cleanupTempFiles, 6 * 60 * 60 * 1000);
```

## 6. Validación de Archivos Mejorada

### ✅ Validación Robusta
```javascript
const isValidLogFile = (file) => {
  const validExtensions = ['.log', '.gz', '.txt'];
  const validMimeTypes = [
    'text/plain',
    'application/gzip',
    'application/x-gzip',
    'text/x-log'
  ];
  
  const ext = path.extname(file.originalname).toLowerCase();
  const hasValidExtension = validExtensions.includes(ext);
  const hasValidMimeType = validMimeTypes.includes(file.mimetype) || file.mimetype.includes('text');
  
  return hasValidExtension && (hasValidMimeType || ext === '.log');
};
```

### Mejoras:
- ✅ Validación por extensión Y tipo MIME
- ✅ Soporte para archivos .txt adicionales
- ✅ Logging de validación para debugging
- ✅ Limpieza automática en caso de archivos inválidos

## 7. Middleware de Seguridad y Monitoreo

### ✅ Headers de Seguridad
```javascript
app.use((req, res, next) => {
  res.set({
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Powered-By': 'Herramientas-VPS'
  });
  next();
});
```

### ✅ Request Logging Middleware
- Tracking de todos los requests con IDs únicos
- Medición de tiempo de respuesta
- Logging de IP y User-Agent
- Headers X-Request-ID para tracking

## 8. Manejo de Errores Avanzado

### ✅ Error Handler Detallado
```javascript
app.use((err, req, res, next) => {
  const errorId = crypto.randomBytes(6).toString('hex');
  
  // Logging completo con contexto
  console.error(`[${errorId}] Error no manejado:`, {
    message: err.message,
    code: err.code,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id
  });
  
  // Manejo específico por tipo de error
});
```

## 9. Graceful Shutdown Mejorado

### ✅ Cierre Graceful Robusto
```javascript
const gracefulShutdown = (signal) => {
  console.log(`\n${signal} recibido. Iniciando cierre graceful...`);
  
  const shutdownTimeout = setTimeout(() => {
    console.error('Timeout en cierre graceful, forzando salida...');
    process.exit(1);
  }, 30000); // 30 segundos timeout
  
  // Cierre ordenado de recursos
};
```

### ✅ Manejo de Excepciones No Capturadas
- Handler para `uncaughtException`
- Handler para `unhandledRejection`
- Logging detallado con timestamps
- Estrategia de recovery inteligente

## 10. Límites y Configuración VPS

### ✅ Límites Optimizados para VPS
```javascript
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 200 * 1024 * 1024, // 200MB máximo para VPS
    files: 1
  }
});
```

## Variables de Entorno Recomendadas

```env
# Configuración VPS
PORT=3000
TEMP_DIR=/home/app/temp
NODE_ENV=production

# Base de datos
DB_HOST=localhost
DB_USER=herramientas_user
DB_PASS=strong_password_here
DB_NAME=herramientas_db
DB_PORT=3306

# CORS y Frontend
FRONTEND_URL=https://herramientas.jorgelaborda.es
BASE_URL=https://herramientas.jorgelaborda.es

# Email (timeouts optimizados para VPS)
SMTP_HOST=mail.jorgelaborda.es
SMTP_PORT=465
EMAIL_USER=herramientas@jorgelaborda.es
EMAIL_PASS=app_password_here

# Seguridad
JWT_SECRET=very_secure_jwt_secret_here
```

## Beneficios para VPS de Producción

1. **🚀 Mejor Rendimiento**
   - Timeouts optimizados para latencia de VPS
   - Pool de conexiones mejorado
   - Limpieza automática de recursos

2. **🔧 Debugging Mejorado**
   - Request IDs únicos para tracking
   - Logs detallados con contexto
   - Métricas de rendimiento

3. **🛡️ Mayor Seguridad**
   - Headers de seguridad estándar
   - Validación robusta de archivos
   - CORS configurado correctamente

4. **📊 Monitoreo**
   - Health check endpoint mejorado
   - Logs estructurados para análisis
   - Error tracking con IDs únicos

5. **💪 Robustez**
   - Reintentos inteligentes con backoff
   - Graceful shutdown mejorado
   - Manejo de excepciones no capturadas

6. **🧹 Mantenimiento Automático**
   - Limpieza periódica de archivos temporales
   - Gestión automática de recursos
   - Prevención de memory leaks

## Deployment en VPS

Para desplegar en VPS, asegúrate de:

1. Instalar dependencias: `npm install --production`
2. Configurar variables de entorno apropiadas
3. Crear directorio temporal con permisos correctos
4. Configurar proxy reverso (nginx) si es necesario
5. Configurar proceso manager (PM2 recomendado)
6. Configurar firewall para puerto 3000

## Monitoreo Recomendado

- Logs centralizados (journald, syslog)
- Monitoreo de memoria y CPU
- Alertas por errores frecuentes
- Monitoreo de espacio en disco (especialmente /tmp)

---

**Versión:** 2.0 VPS Optimizada  
**Fecha:** Enero 2025  
**Compatibilidad:** Node.js 16+, MySQL 8.0+
