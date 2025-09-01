// server.js - VERSIÓN OPTIMIZADA para hostings compartidos (cPanel/Banahosting)
require('dotenv').config();

// Cargar configuración específica para producción
if (process.env.NODE_ENV === 'production') {
  require('dotenv').config({ path: '.env.production', override: true });
}

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración - Compatible con .htaccess y .env
const JWT_SECRET = process.env.JWT_SECRET || process.env.JWT || 'tu_jwt_secret_muy_seguro_aqui';
const EMAIL_USER = process.env.EMAIL_USER || 'tu-email@gmail.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'tu-app-password';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// Configuración MySQL
const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_NAME = process.env.DB_NAME || 'herramientas_db';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASS = process.env.DB_PASS || '';
const DB_PORT = process.env.DB_PORT || 3306;

// VARIABLES GLOBALES para tracking
let isShuttingDown = false;
let activeConnections = new Set();
let activeTimeouts = new Set();

// Middleware básico
app.use(express.json({ 
  limit: '2mb',
  strict: true 
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3001',
  credentials: true,
  maxAge: 300
}));

// Rate limiting conservador para hosting compartido
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Intenta en 15 minutos.' }
});
app.use(limiter);

// Rate limiting específico para auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  skipSuccessfulRequests: true,
  message: { error: 'Demasiados intentos de autenticación. Intenta en 15 minutos.' }
});

// Configuración MySQL OPTIMIZADA para hostings compartidos
const dbConfig = {
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
  port: DB_PORT,
  
  // CONFIGURACIÓN OPTIMIZADA para MySQL2
  connectionLimit: 3,        // Máximo 3 conexiones simultáneas
  queueLimit: 5,            // Máximo 5 en cola
  acquireTimeout: 15000,    // 15s para obtener conexión
  
  // CONFIGURACIÓN ROBUSTA
  ssl: false,
  supportBigNumbers: true,
  bigNumberStrings: true,
  
  // TIMEOUTS
  idleTimeout: 300000,      // 5 minutos idle antes de cerrar conexión
  
  // RECONEXIÓN
  reconnect: true
};

// Crear pool de conexiones
let db;
const createDatabasePool = () => {
  try {
    db = mysql.createPool(dbConfig);
    
    db.on('connection', (connection) => {
      console.log(`Nueva conexión MySQL: ${connection.threadId}`);
      activeConnections.add(connection.threadId);
    });
    
    db.on('error', (err) => {
      console.error('Error en pool MySQL:', err.code);
      if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.log('Recreando pool MySQL...');
        createDatabasePool();
      }
    });
    
    console.log('Pool MySQL creado correctamente');
  } catch (error) {
    console.error('Error creando pool MySQL:', error);
  }
};

createDatabasePool();

// Promisify con mejor error handling
const promiseDb = db.promise();

// Función para queries con retry automático
const safeQuery = async (query, params = [], retries = 2) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const result = await promiseDb.execute(query, params);
      return result;
    } catch (error) {
      console.error(`Query falló (intento ${attempt}/${retries}):`, error.message);
      
      if (attempt === retries) {
        throw error;
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
};

// Configurar nodemailer
const transporter = nodemailer.createTransport({
  host: 'mail.jorgelaborda.es',
  port: 465,
  secure: true,
  connectionTimeout: 10000,
  socketTimeout: 10000,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

// Función para limpiar timeouts activos
const clearActiveTimeouts = () => {
  activeTimeouts.forEach(timeoutId => {
    clearTimeout(timeoutId);
  });
  activeTimeouts.clear();
  console.log(`Limpiados ${activeTimeouts.size} timeouts activos`);
};

// Función para crear timeout trackeable
const createSafeTimeout = (callback, delay) => {
  if (isShuttingDown) return null;
  
  const timeoutId = setTimeout(() => {
    activeTimeouts.delete(timeoutId);
    if (!isShuttingDown) {
      callback();
    }
  }, delay);
  
  activeTimeouts.add(timeoutId);
  return timeoutId;
};

// Inicializar base de datos
const initDatabase = async () => {
  if (isShuttingDown) return;
  
  try {
    console.log('Inicializando base de datos...');
    
    // Crear tabla de usuarios
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

    // Crear tabla de auditorías
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

    console.log('Base de datos inicializada correctamente');
  } catch (error) {
    console.error('Error inicializando base de datos:', error);
  }
};

// Middleware de autenticación JWT
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

// Función para enviar email con timeout
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
    const emailPromise = transporter.sendMail(mailOptions);
    const timeoutPromise = new Promise((_, reject) => {
      createSafeTimeout(() => reject(new Error('Email timeout')), 15000);
    });
    
    await Promise.race([emailPromise, timeoutPromise]);
    return true;
  } catch (error) {
    console.error('Error enviando email:', error.message);
    return false;
  }
};

// ENDPOINTS

// POST /api/register
app.post('/api/register', authLimiter, registerValidation, async (req, res) => {
  if (isShuttingDown) {
    return res.status(503).json({ error: 'Servidor en mantenimiento' });
  }

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

    const [existingUsers] = await safeQuery(
      'SELECT id FROM users WHERE email = ?', 
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }

    const saltRounds = 12;
    const password_hash = await bcrypt.hash(password, saltRounds);
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
  if (isShuttingDown) {
    return res.status(503).send('Servidor en mantenimiento');
  }

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
  if (isShuttingDown) {
    return res.status(503).json({ error: 'Servidor en mantenimiento' });
  }

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
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Error en login:', error.message);
    res.status(500).json({ error: 'Error procesando login' });
  }
});

// POST /api/audit
app.post('/api/audit', authenticateToken, auditValidation, async (req, res) => {
  if (isShuttingDown) {
    return res.status(503).json({ error: 'Servidor en mantenimiento' });
  }

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

    // Procesamiento asíncrono mejorado
    const processAudit = async () => {
      if (isShuttingDown) return;
      
      try {
        await new Promise(resolve => createSafeTimeout(resolve, 3000));
        
        if (isShuttingDown) return;

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

        if (!isShuttingDown) {
          await safeQuery(
            'UPDATE audits SET results = ?, status = ? WHERE id = ?',
            [JSON.stringify(mockResults), 'completed', auditId]
          );
        }
      } catch (error) {
        console.error('Error procesando auditoría:', error.message);
        if (!isShuttingDown) {
          await safeQuery(
            'UPDATE audits SET status = ? WHERE id = ?',
            ['failed', auditId]
          );
        }
      }
    };

    processAudit().catch(err => console.error('Error en processAudit:', err.message));

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
  if (isShuttingDown) {
    return res.status(503).json({ error: 'Servidor en mantenimiento' });
  }

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
      
      return {
        ...audit,
        config,
        results
      };
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
  if (isShuttingDown) {
    return res.status(503).json({ error: 'Servidor en mantenimiento' });
  }

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

    const formattedAudit = {
      ...audit,
      config,
      results
    };

    res.json(formattedAudit);
  } catch (error) {
    console.error('Error obteniendo auditoría:', error.message);
    res.status(500).json({ error: 'Error obteniendo auditoría' });
  }
});

// Health check
app.get('/health', async (req, res) => {
  const healthStatus = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    activeConnections: activeConnections.size,
    activeTimeouts: activeTimeouts.size,
    isShuttingDown
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
  
  if (isShuttingDown) {
    return res.status(503).json({ error: 'Servidor en mantenimiento' });
  }
  
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Manejar rutas no encontradas
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  console.log(`Recibido ${signal}. Iniciando apagado graceful...`);
  isShuttingDown = true;

  server.close(() => {
    console.log('Servidor HTTP cerrado');
  });

  console.log(`Limpiando ${activeTimeouts.size} timeouts activos...`);
  clearActiveTimeouts();

  setTimeout(() => {
    console.log(`Cerrando ${activeConnections.size} conexiones DB...`);
    
    db.end((err) => {
      if (err) {
        console.error('Error cerrando pool MySQL:', err.message);
      } else {
        console.log('Pool MySQL cerrado correctamente');
      }
      
      console.log('Proceso terminado limpiamente');
      process.exit(0);
    });
  }, 5000);

  setTimeout(() => {
    console.log('Forzando terminación después de 10 segundos');
    process.exit(1);
  }, 10000);
};

// Inicializar servidor
const server = app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en puerto ${PORT}`);
  console.log(`Configuración de email: ${EMAIL_USER}`);
  console.log(`JWT Secret configurado: ${JWT_SECRET.length > 20 ? 'Sí' : 'Débil - cambiar en producción'}`);
  console.log(`Base de datos MySQL: ${DB_HOST}:${DB_PORT}/${DB_NAME}`);
  console.log(`Pool configurado: ${dbConfig.connectionLimit} conexiones max`);
  
  initDatabase().catch(err => console.error('Error post-init DB:', err.message));
});

// Configurar timeouts del servidor
server.keepAliveTimeout = 30000;
server.headersTimeout = 35000;

// Event listeners para graceful shutdown
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (error) => {
  console.error('Excepción no capturada:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Promesa rechazada no manejada:', reason);
});

module.exports = app;