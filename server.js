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

// Configuración de multer para subida de archivos
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, '/tmp/')
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB máximo
  },
  fileFilter: function (req, file, cb) {
    if (file.originalname.match(/\.(log|gz)$/)) {
      cb(null, true);
    } else {
      cb(new Error('Solo se permiten archivos .log y .gz'));
    }
  }
});

// Middleware básico
app.use(express.json({ limit: '2mb' }));
app.use(cors({
  origin: process.env.FRONTEND_URL || BASE_URL,
  credentials: true,
  maxAge: 300
}));

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

const safeQuery = async (query, params = [], retries = 2) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const result = await promiseDb.execute(query, params);
      return result;
    } catch (error) {
      console.error(`Query falló (intento ${attempt}/${retries}):`, error.message);
      if (attempt === retries) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
};

// Configurar nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'mail.jorgelaborda.es',
  port: parseInt(process.env.SMTP_PORT) || 465,
  secure: true,
  connectionTimeout: 10000,
  socketTimeout: 10000,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
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
const processLogFile = async (analysisId, filePath, sitemapUrl) => {
  try {
    console.log(`Procesando análisis ${analysisId}: ${filePath}`);
    
    const analizador = new AnalizadorLogs();
    const resultados = await analizador.procesarAnalisisCompleto(filePath, sitemapUrl);

console.log('Tipo de resultados:', typeof resultados);
console.log('Resultados:', resultados);    
await safeQuery(
  'UPDATE log_analyses SET results = ?, status = ? WHERE id = ?',
  [JSON.stringify(resultados), 'completed', analysisId]
);
    
    console.log(`Análisis ${analysisId} completado exitosamente`);
  } catch (error) {
    console.error(`Error procesando análisis ${analysisId}:`, error);
    await safeQuery(
      'UPDATE log_analyses SET status = ? WHERE id = ?',
      ['failed', analysisId]
    );
  }
};

// POST /api/analyze-log - Subir y procesar archivo de log
app.post('/api/analyze-log', authenticateToken, upload.single('logFile'), async (req, res) => {
  const userId = req.user.id;
  const { sitemapUrl } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: 'No se ha subido ningún archivo' });
  }

  try {
    const [result] = await safeQuery(
      'INSERT INTO log_analyses (user_id, filename, sitemap_url, status) VALUES (?, ?, ?, ?)',
      [userId, req.file.originalname, sitemapUrl || null, 'processing']
    );

    const analysisId = result.insertId;

    // Procesar archivo de forma asíncrona
    processLogFile(analysisId, req.file.path, sitemapUrl).catch(err => 
      console.error('Error procesando log:', err)
    );

    res.status(201).json({
      message: 'Análisis de log iniciado',
      analysisId,
      status: 'processing'
    });

  } catch (error) {
    console.error('Error creando análisis:', error);
    res.status(500).json({ error: 'Error iniciando análisis' });
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
        console.log('Tipo de analysis.results:', typeof analysis.results);
console.log('Contenido analysis.results:', analysis.results);
results = JSON.parse(analysis.results);
      } catch (e) {
        console.error('Error parsing results JSON:', e);
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

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error('Error no manejado:', err.message);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'Archivo demasiado grande (máximo 100MB)' });
    }
    return res.status(400).json({ error: 'Error en la subida de archivo' });
  }
  
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Manejar rutas no encontradas
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

// Inicializar servidor
const server = app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en puerto ${PORT}`);
  console.log(`Base de datos MySQL: ${dbConfig.host}:${dbConfig.port}/${dbConfig.database}`);
  
  initDatabase().catch(err => console.error('Error inicializando DB:', err.message));
});

// Graceful shutdown simplificado
process.on('SIGTERM', () => {
  console.log('SIGTERM recibido, cerrando servidor...');
  server.close(() => {
    db.end();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT recibido, cerrando servidor...');
  server.close(() => {
    db.end();
    process.exit(0);
  });
});

module.exports = app;








