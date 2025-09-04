module.exports = {
  apps: [{
    name: 'herramientas-backend',
    script: 'server.js',
    cwd: '/var/www/herramientas-backend',
    
    // Configuración de instancias optimizada para VPS
    instances: process.env.PM2_INSTANCES || 'max',
    exec_mode: 'cluster',
    
    // Variables de entorno de producción
    env: {
      NODE_ENV: 'production',
      PORT: 3000,
      // Configuración específica de VPS
      UV_THREADPOOL_SIZE: 16,
      NODE_OPTIONS: '--max-old-space-size=1024',
      // Configuración de timeouts
      REQUEST_TIMEOUT: 30000,
      DB_CONNECTION_LIMIT: 10,
      // Optimizaciones de memoria y CPU
      NODE_ENV_MODE: 'cluster'
    },
    
    // Configuración de memoria y reinicio
    max_memory_restart: '768M',
    memory_limit: '1024M',
    
    // Configuración de logs mejorada
    log_file: '/var/log/pm2/herramientas-backend-combined.log',
    out_file: '/var/log/pm2/herramientas-backend-out.log',
    error_file: '/var/log/pm2/herramientas-backend-error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    combine_logs: true,
    
    // Configuración de restart inteligente
    autorestart: true,
    watch: false,
    max_restarts: 10,
    min_uptime: '10s',
    restart_delay: 4000,
    
    // Configuración de health checks
    health_check_grace_period: 3000,
    health_check_fatal_timeout: 10000,
    
    // Configuración avanzada
    kill_timeout: 5000,
    listen_timeout: 3000,
    
    // Script hooks para mantenimiento
    post_update: ['npm install', 'npm run build'],
    
    // Configuración de monitoreo
    monitoring: false, // Desactivar PM2 Plus por defecto
    
    // Variables específicas para diferentes entornos
    env_development: {
      NODE_ENV: 'development',
      PORT: 3001,
      watch: true,
      ignore_watch: [
        'node_modules',
        'logs',
        'temp',
        '*.log'
      ]
    },
    
    env_staging: {
      NODE_ENV: 'staging',
      PORT: 3002,
      instances: 1,
      max_memory_restart: '512M'
    },
    
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      instances: 'max',
      max_memory_restart: '768M'
    }
  }],
  
  // Configuración de deployment
  deploy: {
    production: {
      user: 'app',
      host: ['herramientas.jorgelaborda.es'],
      ref: 'origin/main',
      repo: 'git@github.com:username/herramientas-backend.git',
      path: '/var/www/herramientas-backend',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': '',
      'ssh_options': 'StrictHostKeyChecking=no'
    }
  }
};
