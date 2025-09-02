module.exports = {
  apps: [{
    name: 'herramientas-backend',
    script: 'server.js',
    cwd: '/var/www/herramientas-backend',
    instances: 2,
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    max_memory_restart: '512M',
    log_file: '/var/log/pm2/herramientas-backend.log',
    out_file: '/var/log/pm2/herramientas-backend-out.log',
    error_file: '/var/log/pm2/herramientas-backend-error.log',
    autorestart: true,
    watch: false,
    max_restarts: 10,
    min_uptime: '10s'
  }]
};
