# Guía de Deployment - Herramientas Backend VPS

Esta guía proporciona instrucciones paso a paso para deployar el backend de Herramientas Jorge Laborda en un VPS de producción.

## 📋 Requisitos Previos

### Servidor VPS
- **OS**: Ubuntu 20.04 LTS o superior / CentOS 8+
- **RAM**: Mínimo 2GB, Recomendado 4GB+
- **CPU**: Mínimo 2 cores
- **Almacenamiento**: 20GB+ disponible
- **Red**: Puerto 80, 443 y puerto de aplicación (3000) abiertos

### Software Requerido
- Node.js 18+ LTS
- MySQL 8.0+
- PM2
- Nginx (opcional pero recomendado)
- Git
- SSL Certificate (Let's Encrypt recomendado)

## 🚀 Instalación Paso a Paso

### 1. Preparación del Servidor

#### Actualizar el sistema
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install curl wget git unzip build-essential -y
```

#### Crear usuario de aplicación
```bash
sudo adduser app
sudo usermod -aG sudo app
su - app
```

#### Instalar Node.js (usando NodeSource)
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version  # Verificar instalación
npm --version
```

#### Instalar PM2 globalmente
```bash
sudo npm install -g pm2
pm2 --version  # Verificar instalación
```

### 2. Configuración de MySQL

#### Instalar MySQL
```bash
sudo apt install mysql-server -y
sudo mysql_secure_installation
```

#### Configurar base de datos
```bash
sudo mysql -u root -p
```

```sql
-- Crear base de datos y usuario
CREATE DATABASE herramientas_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'herramientas_user'@'localhost' IDENTIFIED BY 'PASSWORD_SUPER_SEGURA_AQUI';
GRANT ALL PRIVILEGES ON herramientas_db.* TO 'herramientas_user'@'localhost';
FLUSH PRIVILEGES;

-- Verificar creación
SHOW DATABASES;
SELECT User, Host FROM mysql.user WHERE User = 'herramientas_user';
EXIT;
```

#### Optimizar configuración MySQL para VPS
```bash
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
```

Agregar/modificar estas líneas:
```ini
[mysqld]
# Configuración optimizada para VPS
innodb_buffer_pool_size = 512M
innodb_log_file_size = 128M
max_connections = 100
query_cache_size = 64M
query_cache_type = 1
thread_cache_size = 8
table_open_cache = 2000
sort_buffer_size = 2M
read_buffer_size = 1M
innodb_flush_method = O_DIRECT
```

```bash
sudo systemctl restart mysql
sudo systemctl enable mysql
```

### 3. Deployment de la Aplicación

#### Crear directorio de aplicación
```bash
sudo mkdir -p /var/www
sudo chown app:app /var/www
cd /var/www
```

#### Clonar repositorio (o subir archivos)
```bash
# Opción 1: Desde Git
git clone https://github.com/tu-usuario/herramientas-backend.git
cd herramientas-backend

# Opción 2: Subir archivos manualmente
mkdir herramientas-backend
cd herramientas-backend
# Subir archivos via SCP/SFTP
```

#### Instalar dependencias
```bash
npm install --production
```

#### Configurar variables de entorno
```bash
cp .env.example .env  # Si existe
nano .env
```

Configurar `.env`:
```env
# Configuración VPS Producción
NODE_ENV=production
PORT=3000

# Base de datos
DB_HOST=localhost
DB_USER=herramientas_user
DB_PASS=PASSWORD_SUPER_SEGURA_AQUI
DB_NAME=herramientas_db
DB_PORT=3306

# URLs y CORS
BASE_URL=https://herramientas.jorgelaborda.es
FRONTEND_URL=https://herramientas.jorgelaborda.es

# Email (configurar según tu proveedor)
SMTP_HOST=mail.jorgelaborda.es
SMTP_PORT=465
EMAIL_USER=herramientas@jorgelaborda.es
EMAIL_PASS=tu_app_password_aqui

# Seguridad
JWT_SECRET=tu_jwt_secret_super_seguro_aqui_min_32_caracteres

# Configuración VPS específica
TEMP_DIR=/home/app/temp
PM2_INSTANCES=max
UV_THREADPOOL_SIZE=16
```

#### Crear directorios necesarios
```bash
sudo mkdir -p /var/log/pm2
sudo mkdir -p /home/app/temp
sudo chown app:app /var/log/pm2
sudo chown app:app /home/app/temp
chmod 755 /home/app/temp
```

### 4. Configuración de Nginx (Recomendado)

#### Instalar Nginx
```bash
sudo apt install nginx -y
```

#### Configurar virtual host
```bash
sudo nano /etc/nginx/sites-available/herramientas-backend
```

```nginx
server {
    listen 80;
    server_name herramientas.jorgelaborda.es www.herramientas.jorgelaborda.es;
    
    # Redirigir HTTP a HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name herramientas.jorgelaborda.es www.herramientas.jorgelaborda.es;

    # Configuración SSL (configurar después con Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/herramientas.jorgelaborda.es/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/herramientas.jorgelaborda.es/privkey.pem;
    
    # Configuración SSL moderna
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    
    # Headers de seguridad
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Configuración del proxy
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Configuración para archivos estáticos
    location /public {
        alias /var/www/herramientas-backend/public;
        expires 1M;
        add_header Cache-Control "public, immutable";
    }
    
    # Límites de upload para logs
    client_max_body_size 200M;
    client_body_timeout 300s;
    
    # Logging
    access_log /var/log/nginx/herramientas-access.log;
    error_log /var/log/nginx/herramientas-error.log;
}
```

#### Habilitar sitio
```bash
sudo ln -s /etc/nginx/sites-available/herramientas-backend /etc/nginx/sites-enabled/
sudo nginx -t  # Verificar configuración
sudo systemctl reload nginx
sudo systemctl enable nginx
```

### 5. Configurar SSL con Let's Encrypt

#### Instalar Certbot
```bash
sudo apt install certbot python3-certbot-nginx -y
```

#### Obtener certificado SSL
```bash
sudo certbot --nginx -d herramientas.jorgelaborda.es -d www.herramientas.jorgelaborda.es
```

#### Configurar renovación automática
```bash
sudo crontab -e
```
Agregar línea:
```bash
0 12 * * * /usr/bin/certbot renew --quiet
```

### 6. Iniciar la Aplicación

#### Configurar PM2 para inicio automático
```bash
pm2 startup
# Ejecutar el comando que muestra PM2
```

#### Iniciar aplicación
```bash
cd /var/www/herramientas-backend
pm2 start ecosystem.config.js --env production
pm2 save  # Guardar configuración actual
```

#### Verificar estado
```bash
pm2 status
pm2 logs herramientas-backend
```

## 🛠️ Scripts de Utilidad

Los scripts `start.sh`, `restart.sh` y `logs.sh` están disponibles en el directorio del proyecto para facilitar las operaciones comunes.

### Uso de Scripts
```bash
# Iniciar aplicación
./start.sh

# Reiniciar aplicación
./restart.sh

# Ver logs en tiempo real
./logs.sh
```

## 📊 Monitoreo y Mantenimiento

### Comandos PM2 Útiles
```bash
# Ver estado de procesos
pm2 status

# Ver logs en tiempo real
pm2 logs

# Ver métricas del sistema
pm2 monit

# Reiniciar aplicación
pm2 restart herramientas-backend

# Recargar aplicación (zero downtime)
pm2 reload herramientas-backend

# Parar aplicación
pm2 stop herramientas-backend

# Ver información detallada
pm2 describe herramientas-backend
```

### Monitoreo de Sistema
```bash
# Uso de CPU y memoria
htop

# Espacio en disco
df -h

# Estado de servicios
systemctl status nginx
systemctl status mysql
systemctl status pm2-app

# Logs del sistema
journalctl -f
tail -f /var/log/nginx/herramientas-error.log
```

### Backup Automático de Base de Datos
```bash
# Crear script de backup
sudo nano /home/app/backup-db.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/home/app/backups"
DB_NAME="herramientas_db"
DB_USER="herramientas_user"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

mysqldump -u $DB_USER -p$DB_PASS $DB_NAME > $BACKUP_DIR/herramientas_backup_$DATE.sql

# Mantener solo los últimos 7 backups
find $BACKUP_DIR -name "herramientas_backup_*.sql" -type f -mtime +7 -delete

echo "Backup completado: herramientas_backup_$DATE.sql"
```

```bash
chmod +x /home/app/backup-db.sh

# Programar backup diario
crontab -e
0 2 * * * /home/app/backup-db.sh
```

## 🔧 Troubleshooting Común

### 1. Aplicación no inicia

**Síntomas**: PM2 muestra estado "errored" o "stopped"

**Soluciones**:
```bash
# Ver logs detallados
pm2 logs herramientas-backend --lines 50

# Verificar puerto disponible
sudo netstat -tlnp | grep :3000

# Verificar permisos
ls -la /var/www/herramientas-backend
ls -la /home/app/temp

# Verificar variables de entorno
pm2 env 0
```

### 2. Error de conexión a base de datos

**Síntomas**: "Error: connect ECONNREFUSED" en logs

**Soluciones**:
```bash
# Verificar estado MySQL
sudo systemctl status mysql

# Verificar conectividad
mysql -u herramientas_user -p -h localhost herramientas_db

# Verificar configuración
cat /var/www/herramientas-backend/.env | grep DB_

# Reiniciar MySQL si necesario
sudo systemctl restart mysql
```

### 3. Error 502 Bad Gateway (Nginx)

**Síntomas**: Nginx muestra "502 Bad Gateway"

**Soluciones**:
```bash
# Verificar que PM2 está funcionando
pm2 status

# Verificar configuración Nginx
sudo nginx -t

# Ver logs de Nginx
sudo tail -f /var/log/nginx/herramientas-error.log

# Reiniciar servicios
pm2 restart herramientas-backend
sudo systemctl reload nginx
```

### 4. Alto uso de memoria

**Síntomas**: PM2 reinicia frecuentemente por memoria

**Soluciones**:
```bash
# Ver uso de memoria
pm2 monit

# Ajustar límite en ecosystem.config.js
max_memory_restart: '1024M'

# Verificar memory leaks
pm2 logs | grep "memory"

# Reiniciar con configuración actualizada
pm2 reload ecosystem.config.js
```

### 5. Problemas con archivos temporales

**Síntomas**: Error al procesar logs, espacio en disco lleno

**Soluciones**:
```bash
# Verificar espacio
df -h

# Limpiar directorio temporal
sudo find /home/app/temp -type f -mtime +1 -delete

# Verificar permisos
ls -la /home/app/temp

# Reconfigurar directorio temporal
export TEMP_DIR=/home/app/temp
pm2 restart herramientas-backend
```

### 6. Problemas de SSL/HTTPS

**Síntomas**: Certificado expirado, errores SSL

**Soluciones**:
```bash
# Verificar certificado
sudo certbot certificates

# Renovar manualmente
sudo certbot renew

# Verificar configuración Nginx
sudo nginx -t

# Reiniciar Nginx
sudo systemctl reload nginx
```

## 📈 Optimizaciones de Rendimiento

### 1. Configuración de Sistema
```bash
# Aumentar límites de archivos abiertos
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimizar kernel para aplicaciones web
echo "net.core.somaxconn = 65536" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 2. Configuración Node.js
```bash
# En .env agregar:
UV_THREADPOOL_SIZE=16
NODE_OPTIONS=--max-old-space-size=1024
```

### 3. Configuración PM2 Avanzada
```bash
# Usar todas las CPUs disponibles
pm2 start ecosystem.config.js --env production

# Activar modo cluster
instances: 'max' # en ecosystem.config.js
```

## 🔐 Configuraciones de Seguridad Adicionales

### 1. Firewall (UFW)
```bash
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw status
```

### 2. Fail2Ban
```bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 3. Actualizaciones Automáticas de Seguridad
```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

## 📞 Soporte y Mantenimiento

### Logs Importantes
- **Aplicación**: `/var/log/pm2/herramientas-backend-*.log`
- **Nginx**: `/var/log/nginx/herramientas-*.log`
- **MySQL**: `/var/log/mysql/error.log`
- **Sistema**: `journalctl -u nginx`, `journalctl -u mysql`

### Contacto
Para soporte técnico o consultas:
- **Email**: support@jorgelaborda.es
- **Documentación**: Ver archivos MEJORAS_VPS.md y README.md

---

**Última actualización**: Enero 2025  
**Versión**: 1.0.0  
**Compatibilidad**: Ubuntu 20.04+, Node.js 18+, MySQL 8.0+
