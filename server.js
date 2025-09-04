// server.js - Versión optimizada para VPS con analizador de logs
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const multer = require('multer');
const AnalizadorLogs = require('./lib/analizador-logs');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { existsSync, mkdirSync } = require('fs');
const zlib = require('zlib');
const { promisify } = require('util');
const gunzip = promisify(zlib.gunzip);

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// Configuración
const JWT_SECRET = process.env.JWT_SECRET || 'tu_jwt_secret_muy_seguro_aqui';
const EMAIL_USER = process.env.EMAIL_USER || 'herramientas@jorgelaborda.es';
const EMAIL_PASS = process.env.EMAIL_PASS || 'tu-app-password';
const BASE_URL = process.env.BASE_URL || 'https://herramientas.jorgelaborda.es';

// Configuración MySQL
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'herramientas_user',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'herramientas_db',
  port: process.env.DB_PORT || 3306,
  connectionLimit: 10,
  supportBigNumbers: true,
  bigNumberStrings: true
};

// Configuración de multer optimizada para VPS

// Asegurar directorio temporal específico para la aplicación
const TEMP_DIR = process.env.TEMP_DIR || path.join(os.tmpdir(), 'herramientas-logs');
if (!existsSync(TEMP_DIR)) {
  try {
    mkdirSync(TEMP_DIR, { recursive: true });
    console.log(`Directorio temporal creado: ${TEMP_DIR}`);
  } catch (error) {
    console.error('Error creando directorio temporal:', error.message);
  }
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, TEMP_DIR);
  },
  filename: function (req, file, cb) {
    const userId = req.user?.id || 'anon';
    const timestamp = Date.now();
    const randomSuffix = crypto.randomBytes(6).toString('hex');
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, `${userId}_${timestamp}_${randomSuffix}_${sanitizedName}`);
  }
});

// Validación mejorada de archivos
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

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 200 * 1024 * 1024, // 200MB máximo para VPS
    files: 1
  },
  fileFilter: function (req, file, cb) {
    console.log('Validando archivo:', {
      originalname: file.originalname,
      mimetype: file.mimetype,
      size: file.size
    });
    
    if (isValidLogFile(file)) {
      cb(null, true);
    } else {
      const error = new Error(`Archivo no válido: ${file.originalname}. Solo se permiten archivos .log, .gz o .txt`);
      error.code = 'INVALID_FILE_TYPE';
      cb(error);
    }
  }
});

// Middleware básico
app.use(express.json({ limit: '2mb' }));

// Configuración CORS optimizada para VPS de producción
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

// Middleware de logging para requests (útil en VPS para debugging)
app.use((req, res, next) => {
  const requestId = crypto.randomBytes(6).toString('hex');
  const startTime = Date.now();
  
  req.requestId = requestId;
  res.set('X-Request-ID', requestId);
  
  console.log(`[${requestId}] ${req.method} ${req.path}:`, {
    ip: req.ip,
    userAgent: req.get('User-Agent')?.substring(0, 100),
    contentLength: req.get('Content-Length') || 0
  });
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    console.log(`[${requestId}] Response ${res.statusCode} en ${duration}ms`);
  });
  
  next();
});

// Headers de seguridad adicionales para VPS
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

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Intenta en 15 minutos.' }
});
app.use(limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: { error: 'Demasiados intentos de autenticación. Intenta en 15 minutos.' }
});

// Servir archivos estáticos
app.use(express.static('public'));

// Crear pool de conexiones MySQL
const db = mysql.createPool(dbConfig);
const promiseDb = db.promise();

// Query segura con mejor logging para debugging en VPS
const safeQuery = async (query, params = [], retries = 3) => {
  const startTime = Date.now();
  const queryId = crypto.randomBytes(4).toString('hex');
  
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      console.log(`[${queryId}] Query intento ${attempt}/${retries}:`, {
        query: query.replace(/\s+/g, ' ').trim().substring(0, 100),
        params: params.length,
        attempt
      });
      
      const result = await promiseDb.execute(query, params);
      const duration = Date.now() - startTime;
      
      console.log(`[${queryId}] Query exitosa en ${duration}ms`);
      return result;
    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`[${queryId}] Query falló (intento ${attempt}/${retries}) en ${duration}ms:`, {
        error: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState
      });
      
      if (attempt === retries) {
        console.error(`[${queryId}] Query falló definitivamente después de ${retries} intentos`);
        throw error;
      }
      
      const backoffDelay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
      console.log(`[${queryId}] Reintentando en ${backoffDelay}ms...`);
      await new Promise(resolve => setTimeout(resolve, backoffDelay));
    }
  }
};

// Configurar nodemailer con mejor manejo de timeouts para VPS
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'mail.jorgelaborda.es',
  port: parseInt(process.env.SMTP_PORT) || 465,
  secure: true,
  connectionTimeout: 20000, // 20s para VPS
  greetingTimeout: 20000,
  socketTimeout: 30000, // 30s para VPS
  pool: true,
  maxConnections: 5,
  maxMessages: 100,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false // Para algunos VPS con certificados auto-firmados
  }
});

// Inicializar base de datos
const initDatabase = async () => {
  try {
    console.log('Inicializando base de datos...');
    
    // Tabla de usuarios
    await safeQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        verified BOOLEAN DEFAULT FALSE,
        verification_token VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_verification_token (verification_token)
      ) ENGINE=InnoDB
    `);

    // Tabla de auditorías
    await safeQuery(`
      CREATE TABLE IF NOT EXISTS audits (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        url TEXT NOT NULL,
        config JSON,
        results JSON,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user_id (user_id),
        INDEX idx_status (status),
        INDEX idx_created_at (created_at),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      ) ENGINE=InnoDB
    `);

    // Tabla de análisis de logs
    await safeQuery(`
      CREATE TABLE IF NOT EXISTS log_analyses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        filename VARCHAR(255),
        sitemap_url TEXT,
        results JSON,
        status ENUM('processing', 'completed', 'failed') DEFAULT 'processing',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user_id (user_id),
        INDEX idx_status (status),
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      ) ENGINE=InnoDB
    `);

    console.log('Base de datos inicializada correctamente');
  } catch (error) {
    console.error('Error inicializando base de datos:', error);
  }
};

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acceso requerido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
    req.user = user;
    next();
  });
};

// Validaciones
const registerValidation = [
  body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
  body('password')
    .isLength({ min: 8 }).withMessage('La contraseña debe tener al menos 8 caracteres')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('La contraseña debe contener al menos una mayúscula, una minúscula y un número')
];

const loginValidation = [
  body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
  body('password').notEmpty().withMessage('Contraseña requerida')
];

const auditValidation = [
  body('url').isURL({ protocols: ['http', 'https'] }).withMessage('URL inválida'),
  body('config').optional().isObject().withMessage('Configuración debe ser un objeto válido')
];

// Función para verificar CAPTCHA
const verifyCaptcha = async (captchaToken) => {
  return captchaToken === 'valid_captcha_token';
};

// Función para enviar email
const sendVerificationEmail = async (email, token) => {
  const verificationUrl = `${BASE_URL}/verify-email/${token}`;
  
  const mailOptions = {
    from: EMAIL_USER,
    to: email,
    subject: 'Verifica tu cuenta - Herramientas Jorge Laborda',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>¡Bienvenido a Herramientas Jorge Laborda!</h2>
        <p>Gracias por registrarte. Para completar tu registro, por favor verifica tu dirección de email haciendo clic en el siguiente enlace:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationUrl}" 
             style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Verificar Email
          </a>
        </div>
        <p>Si no puedes hacer clic en el botón, copia y pega este enlace en tu navegador:</p>
        <p style="word-break: break-all;">${verificationUrl}</p>
        <p style="color: #666; font-size: 14px; margin-top: 30px;">
          Este enlace expirará en 24 horas. Si no solicitaste esta verificación, puedes ignorar este email.
        </p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Error enviando email:', error.message);
    return false;
  }
};

// ENDPOINTS DE AUTENTICACIÓN

// POST /api/register
app.post('/api/register', authLimiter, registerValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Datos inválidos', 
        details: errors.array() 
      });
    }

    const { email, password, captcha } = req.body;

    if (!await verifyCaptcha(captcha)) {
      return res.status(400).json({ error: 'CAPTCHA inválido' });
    }

    const [existingUsers] = await safeQuery('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }

    const password_hash = await bcrypt.hash(password, 12);
    const verification_token = crypto.randomBytes(32).toString('hex');

    await safeQuery(
      'INSERT INTO users (email, password_hash, verification_token) VALUES (?, ?, ?)',
      [email, password_hash, verification_token]
    );

    const emailSent = await sendVerificationEmail(email, verification_token);
    
    res.status(201).json({ 
      message: 'Usuario registrado exitosamente',
      emailSent,
      note: 'Por favor verifica tu email antes de iniciar sesión'
    });

  } catch (error) {
    console.error('Error en registro:', error.message);
    res.status(500).json({ error: 'Error procesando registro' });
  }
});

// GET /verify-email/:token
app.get('/verify-email/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const [result] = await safeQuery(
      'UPDATE users SET verified = TRUE, verification_token = NULL WHERE verification_token = ?',
      [token]
    );

    if (result.affectedRows === 0) {
      return res.status(400).send('Token de verificación inválido o expirado');
    }

    res.send(`
      <div style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h2 style="color: #28a745;">Email verificado exitosamente</h2>
        <p>Tu cuenta ha sido verificada. Ya puedes iniciar sesión.</p>
        <a href="login.html"
           style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px;">
          Iniciar Sesión
        </a>
      </div>
    `);
  } catch (error) {
    console.error('Error verificando email:', error.message);
    res.status(500).send('Error interno del servidor');
  }
});

// POST /api/login
app.post('/api/login', authLimiter, loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      error: 'Datos inválidos', 
      details: errors.array() 
    });
  }

  const { email, password } = req.body;

  try {
    const [users] = await safeQuery(
      'SELECT id, email, password_hash, verified FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = users[0];
    if (!user.verified) {
      return res.status(401).json({ 
        error: 'Email no verificado',
        message: 'Por favor verifica tu email antes de iniciar sesión'
      });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (error) {
    console.error('Error en login:', error.message);
    res.status(500).json({ error: 'Error procesando login' });
  }
});

// ENDPOINTS DE AUDITORÍAS SEO

// POST /api/audit
app.post('/api/audit', authenticateToken, auditValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      error: 'Datos inválidos', 
      details: errors.array() 
    });
  }

  const { url, config = {} } = req.body;
  const userId = req.user.id;

  try {
    const [result] = await safeQuery(
      'INSERT INTO audits (user_id, url, config, status) VALUES (?, ?, ?, ?)',
      [userId, url, JSON.stringify(config), 'pending']
    );

    const auditId = result.insertId;

    // Procesamiento asíncrono simulado
    setTimeout(async () => {
      try {
        const mockResults = {
          performance: {
            score: Math.floor(Math.random() * 40) + 60,
            metrics: {
              fcp: Math.floor(Math.random() * 2000) + 1000,
              lcp: Math.floor(Math.random() * 3000) + 2000,
              cls: Math.random() * 0.1
            }
          },
          accessibility: {
            score: Math.floor(Math.random() * 30) + 70,
            issues: Math.floor(Math.random() * 10)
          },
          seo: {
            score: Math.floor(Math.random() * 20) + 80,
            recommendations: Math.floor(Math.random() * 5)
          }
        };

        await safeQuery(
          'UPDATE audits SET results = ?, status = ? WHERE id = ?',
          [JSON.stringify(mockResults), 'completed', auditId]
        );
      } catch (error) {
        console.error('Error procesando auditoría:', error.message);
        await safeQuery(
          'UPDATE audits SET status = ? WHERE id = ?',
          ['failed', auditId]
        );
      }
    }, 3000);

    res.status(201).json({
      message: 'Auditoría iniciada exitosamente',
      auditId,
      status: 'pending'
    });
  } catch (error) {
    console.error('Error creando auditoría:', error.message);
    res.status(500).json({ error: 'Error creando auditoría' });
  }
});

// GET /api/audits
app.get('/api/audits', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10));
  const offset = (page - 1) * limit;

  try {
    const [countResult] = await safeQuery(
      'SELECT COUNT(*) as total FROM audits WHERE user_id = ?',
      [userId]
    );

    const [audits] = await safeQuery(
      `SELECT id, url, config, results, status, created_at
       FROM audits 
       WHERE user_id = ? 
       ORDER BY created_at DESC 
       LIMIT ? OFFSET ?`,
      [userId, limit, offset]
    );

    const formattedAudits = audits.map(audit => {
      let config, results;
      try {
        config = audit.config ? JSON.parse(audit.config) : {};
        results = audit.results ? JSON.parse(audit.results) : null;
      } catch (parseError) {
        console.error('Error parsing JSON:', parseError);
        config = {};
        results = null;
      }
      
      return { ...audit, config, results };
    });

    res.json({
      audits: formattedAudits,
      pagination: {
        page,
        limit,
        total: countResult[0].total,
        totalPages: Math.ceil(countResult[0].total / limit)
      }
    });
  } catch (error) {
    console.error('Error obteniendo auditorías:', error.message);
    res.status(500).json({ error: 'Error obteniendo auditorías' });
  }
});

// GET /api/audit/:id
app.get('/api/audit/:id', authenticateToken, async (req, res) => {
  const auditId = parseInt(req.params.id);
  const userId = req.user.id;

  if (!auditId || auditId <= 0) {
    return res.status(400).json({ error: 'ID de auditoría inválido' });
  }

  try {
    const [audits] = await safeQuery(
      'SELECT * FROM audits WHERE id = ? AND user_id = ?',
      [auditId, userId]
    );

    if (audits.length === 0) {
      return res.status(404).json({ error: 'Auditoría no encontrada' });
    }

    const audit = audits[0];
    let config, results;
    
    try {
      config = audit.config ? JSON.parse(audit.config) : {};
      results = audit.results ? JSON.parse(audit.results) : null;
    } catch (parseError) {
      console.error('Error parsing JSON:', parseError);
      config = {};
      results = null;
    }

    res.json({ ...audit, config, results });
  } catch (error) {
    console.error('Error obteniendo auditoría:', error.message);
    res.status(500).json({ error: 'Error obteniendo auditoría' });
  }
});

// ENDPOINTS PARA ANALIZADOR DE LOGS

// Función para procesar archivo de log usando el módulo completo
// Función optimizada para procesar archivo de log de forma asíncrona
const processLogFile = async (analysisId, filePath, sitemapUrl) => {
  const processId = `proc_${analysisId}_${Date.now()}`;
  const startTime = Date.now();
  
  try {
    console.log(`[${processId}] Iniciando procesamiento:`, {
      analysisId,
      filePath,
      sitemapUrl: sitemapUrl || 'No proporcionado',
      fileExists: existsSync(filePath),
      fileSize: existsSync(filePath) ? (await fs.stat(filePath)).size : 'N/A'
    });
    
    // Verificar que el archivo existe
    if (!existsSync(filePath)) {
      throw new Error(`Archivo no encontrado: ${filePath}`);
    }
    
    // Actualizar estado a procesando
    await safeQuery(
      'UPDATE log_analyses SET status = ? WHERE id = ?',
      ['processing', analysisId]
    );
    
    const analizador = new AnalizadorLogs();
    
    console.log(`[${processId}] Ejecutando análisis completo...`);
    const resultados = await analizador.procesarAnalisisCompleto(filePath, sitemapUrl);
    
    const processingTime = Date.now() - startTime;
    console.log(`[${processId}] Análisis completado en ${processingTime}ms:`, {
      tipoResultados: typeof resultados,
      tamañoResultados: JSON.stringify(resultados).length,
      tieneDatos: !!resultados
    });
    
    await safeQuery(
      'UPDATE log_analyses SET results = ?, status = ? WHERE id = ?',
      [JSON.stringify(resultados), 'completed', analysisId]
    );
    
    console.log(`[${processId}] Análisis ${analysisId} completado exitosamente en ${processingTime}ms`);
    
    // Limpiar archivo temporal después del procesamiento exitoso
    try {
      await fs.unlink(filePath);
      console.log(`[${processId}] Archivo temporal eliminado: ${filePath}`);
    } catch (unlinkError) {
      console.warn(`[${processId}] No se pudo eliminar archivo temporal:`, unlinkError.message);
    }
    
  } catch (error) {
    const processingTime = Date.now() - startTime;
    console.error(`[${processId}] Error procesando análisis ${analysisId} después de ${processingTime}ms:`, {
      error: error.message,
      stack: error.stack,
      filePath,
      analysisId
    });
    
    try {
      await safeQuery(
        'UPDATE log_analyses SET status = ? WHERE id = ?',
        ['failed', analysisId]
      );
    } catch (updateError) {
      console.error(`[${processId}] Error actualizando estado de fallo:`, updateError.message);
    }
    
    // Intentar limpiar archivo temporal incluso en caso de error
    try {
      if (existsSync(filePath)) {
        await fs.unlink(filePath);
        console.log(`[${processId}] Archivo temporal eliminado después de error`);
      }
    } catch (unlinkError) {
      console.warn(`[${processId}] No se pudo eliminar archivo temporal después de error:`, unlinkError.message);
    }
    
    throw error; // Re-throw para logging adicional si es necesario
  }
};

// POST /api/analyze-log - Subir y procesar archivo de log con validaciones mejoradas
app.post('/api/analyze-log', authenticateToken, upload.single('logFile'), async (req, res) => {
  const requestId = crypto.randomBytes(6).toString('hex');
  const userId = req.user.id;
  const { sitemapUrl } = req.body;
  const startTime = Date.now();

  console.log(`[${requestId}] Nueva solicitud de análisis de log:`, {
    userId,
    sitemapUrl: sitemapUrl || 'No proporcionado',
    hasFile: !!req.file
  });

  if (!req.file) {
    console.warn(`[${requestId}] Solicitud rechazada: No hay archivo`);
    return res.status(400).json({ error: 'No se ha subido ningún archivo' });
  }

  // Validaciones adicionales del archivo
  const fileStats = await fs.stat(req.file.path).catch(() => null);
  if (!fileStats) {
    console.error(`[${requestId}] Error: Archivo no accesible después de la subida`);
    return res.status(500).json({ error: 'Error accediendo al archivo subido' });
  }

  console.log(`[${requestId}] Archivo validado:`, {
    originalName: req.file.originalname,
    fileName: req.file.filename,
    size: fileStats.size,
    mimetype: req.file.mimetype,
    path: req.file.path
  });

  if (fileStats.size === 0) {
    console.warn(`[${requestId}] Archivo vacío rechazado`);
    try {
      await fs.unlink(req.file.path);
    } catch (e) {}
    return res.status(400).json({ error: 'El archivo está vacío' });
  }

  try {
    const [result] = await safeQuery(
      'INSERT INTO log_analyses (user_id, filename, sitemap_url, status) VALUES (?, ?, ?, ?)',
      [userId, req.file.originalname, sitemapUrl || null, 'pending']
    );

    const analysisId = result.insertId;
    console.log(`[${requestId}] Análisis creado con ID: ${analysisId}`);

    // Procesar archivo de forma asíncrona con mejor manejo de errores
    processLogFile(analysisId, req.file.path, sitemapUrl)
      .then(() => {
        console.log(`[${requestId}] Procesamiento completado para análisis ${analysisId}`);
      })
      .catch(err => {
        console.error(`[${requestId}] Error en procesamiento asíncrono:`, {
          error: err.message,
          analysisId,
          stack: err.stack
        });
      });

    const responseTime = Date.now() - startTime;
    console.log(`[${requestId}] Respuesta enviada en ${responseTime}ms`);

    res.status(201).json({
      message: 'Análisis de log iniciado',
      analysisId,
      status: 'pending',
      requestId
    });

  } catch (error) {
    const responseTime = Date.now() - startTime;
    console.error(`[${requestId}] Error creando análisis en ${responseTime}ms:`, {
      error: error.message,
      code: error.code,
      userId,
      filename: req.file.originalname
    });
    
    // Limpiar archivo en caso de error
    try {
      await fs.unlink(req.file.path);
      console.log(`[${requestId}] Archivo temporal limpiado después de error`);
    } catch (unlinkError) {
      console.warn(`[${requestId}] No se pudo limpiar archivo temporal:`, unlinkError.message);
    }
    
    res.status(500).json({ 
      error: 'Error iniciando análisis',
      requestId
    });
  }
});

// GET /api/log-analyses - Obtener análisis del usuario
app.get('/api/log-analyses', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [analyses] = await safeQuery(
      'SELECT id, filename, sitemap_url, status, created_at FROM log_analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
      [userId]
    );

    res.json({ analyses });
  } catch (error) {
    console.error('Error obteniendo análisis:', error);
    res.status(500).json({ error: 'Error obteniendo análisis' });
  }
});

// GET /api/log-analysis/:id - Obtener resultado específico
app.get('/api/log-analysis/:id', authenticateToken, async (req, res) => {
  const analysisId = parseInt(req.params.id);
  const userId = req.user.id;

  try {
    const [analyses] = await safeQuery(
      'SELECT * FROM log_analyses WHERE id = ? AND user_id = ?',
      [analysisId, userId]
    );

    if (analyses.length === 0) {
      return res.status(404).json({ error: 'Análisis no encontrado' });
    }

    const analysis = analyses[0];
    let results = null;
    
    if (analysis.results) {
  try {
    // Para JSONs muy grandes, verificar si ya es un objeto
    if (typeof analysis.results === 'object') {
      results = analysis.results;
    } else {
      results = JSON.parse(analysis.results);
    }
  } catch (e) {
    console.error('Error parsing results JSON:', e);
    results = null;
  }
}

    res.json({ ...analysis, results });
  } catch (error) {
    console.error('Error obteniendo análisis:', error);
    res.status(500).json({ error: 'Error obteniendo análisis' });
  }
});

// Health check
app.get('/health', async (req, res) => {
  const healthStatus = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024)
  };

  try {
    await safeQuery('SELECT 1');
    healthStatus.database = 'connected';
  } catch (error) {
    healthStatus.database = 'error';
    healthStatus.status = 'DEGRADED';
  }

  res.json(healthStatus);
});

// Middleware de manejo de errores mejorado para VPS
app.use((err, req, res, next) => {
  const errorId = crypto.randomBytes(6).toString('hex');
  const timestamp = new Date().toISOString();
  
  console.error(`[${errorId}] Error no manejado en ${timestamp}:`, {
    message: err.message,
    code: err.code,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id
  });
  
  // Errores específicos de multer
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      console.warn(`[${errorId}] Archivo demasiado grande rechazado`);
      return res.status(413).json({ 
        error: 'Archivo demasiado grande (máximo 200MB)',
        errorId
      });
    }
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({ 
        error: 'Campo de archivo inesperado',
        errorId
      });
    }
    return res.status(400).json({ 
      error: 'Error en la subida de archivo',
      details: err.message,
      errorId
    });
  }
  
  // Error de archivo no válido personalizado
  if (err.code === 'INVALID_FILE_TYPE') {
    return res.status(400).json({ 
      error: err.message,
      errorId
    });
  }
  
  // Errores de CORS
  if (err.message === 'No permitido por CORS') {
    return res.status(403).json({ 
      error: 'Origen no permitido por política CORS',
      errorId
    });
  }
  
  // Error genérico del servidor
  res.status(500).json({ 
    error: 'Error interno del servidor',
    errorId,
    timestamp
  });
});

// Manejar rutas no encontradas
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

// Inicializar servidor
const server = app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en puerto ${PORT}`);
  console.log(`Base de datos MySQL: ${dbConfig.host}:${dbConfig.port}/${dbConfig.database}`);
  console.log(`Directorio temporal: ${TEMP_DIR}`);
  
  initDatabase().catch(err => console.error('Error inicializando DB:', err.message));
});

// Limpieza periódica de archivos temporales órfanos para VPS
const cleanupTempFiles = async () => {
  try {
    const files = await fs.readdir(TEMP_DIR);
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 horas
    let cleanedCount = 0;
    
    for (const file of files) {
      try {
        const filePath = path.join(TEMP_DIR, file);
        const stats = await fs.stat(filePath);
        
        if (now - stats.mtime.getTime() > maxAge) {
          await fs.unlink(filePath);
          cleanedCount++;
          console.log(`Archivo temporal limpiado: ${file}`);
        }
      } catch (err) {
        console.warn(`Error limpiando archivo temporal ${file}:`, err.message);
      }
    }
    
    if (cleanedCount > 0) {
      console.log(`Limpieza periódica completada: ${cleanedCount} archivos eliminados`);
    }
  } catch (err) {
    console.error('Error en limpieza periódica:', err.message);
  }
};

// Ejecutar limpieza cada 6 horas
setInterval(cleanupTempFiles, 6 * 60 * 60 * 1000);

// Ejecutar limpieza inicial después de 5 minutos del arranque
setTimeout(cleanupTempFiles, 5 * 60 * 1000);

// Graceful shutdown mejorado para VPS
const gracefulShutdown = (signal) => {
  console.log(`\n${signal} recibido. Iniciando cierre graceful...`);
  const shutdownTimeout = setTimeout(() => {
    console.error('Timeout en cierre graceful, forzando salida...');
    process.exit(1);
  }, 30000); // 30 segundos timeout
  
  server.close((err) => {
    clearTimeout(shutdownTimeout);
    if (err) {
      console.error('Error cerrando servidor HTTP:', err.message);
      return process.exit(1);
    }
    
    console.log('Servidor HTTP cerrado');
    
    // Cerrar pool de base de datos
    db.end((dbErr) => {
      if (dbErr) {
        console.error('Error cerrando pool de base de datos:', dbErr.message);
        return process.exit(1);
      }
      
      console.log('Pool de base de datos cerrado');
      console.log('Cierre graceful completado');
      process.exit(0);
    });
  });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Manejo de errores no capturados para VPS
process.on('uncaughtException', (err) => {
  console.error('Excepción no capturada:', {
    error: err.message,
    stack: err.stack,
    timestamp: new Date().toISOString()
  });
  
  // Intentar cierre graceful
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Promise rechazada no manejada:', {
    reason: reason?.message || reason,
    promise: promise?.toString(),
    timestamp: new Date().toISOString()
  });
  
  // En producción, es mejor loggear y continuar en lugar de matar el proceso
  // a menos que sea crítico
});

module.exports = app;









