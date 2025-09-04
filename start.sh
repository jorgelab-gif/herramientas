#!/bin/bash
# Script para iniciar la aplicación Herramientas Backend
# Versión optimizada para VPS de producción

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
APP_NAME="herramientas-backend"
APP_DIR="/var/www/herramientas-backend"
ECOSYSTEM_FILE="ecosystem.config.js"
ENVIRONMENT=${1:-production}
LOG_DIR="/var/log/pm2"
TEMP_DIR="/home/app/temp"

echo -e "${BLUE}=== Herramientas Backend - Script de Inicio ===${NC}"
echo -e "${BLUE}Fecha: $(date)${NC}"
echo -e "${BLUE}Entorno: $ENVIRONMENT${NC}"
echo ""

# Función para logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar si PM2 está instalado
if ! command -v pm2 &> /dev/null; then
    log_error "PM2 no está instalado. Instálalo con: npm install -g pm2"
    exit 1
fi

# Verificar si el directorio de la aplicación existe
if [ ! -d "$APP_DIR" ]; then
    log_error "Directorio de aplicación no encontrado: $APP_DIR"
    exit 1
fi

# Cambiar al directorio de la aplicación
cd $APP_DIR
log_info "Cambiando al directorio: $APP_DIR"

# Verificar archivo de configuración
if [ ! -f "$ECOSYSTEM_FILE" ]; then
    log_error "Archivo de configuración no encontrado: $ECOSYSTEM_FILE"
    exit 1
fi

# Crear directorios necesarios
log_info "Verificando directorios necesarios..."
sudo mkdir -p $LOG_DIR 2>/dev/null || mkdir -p $LOG_DIR 2>/dev/null || log_warn "No se pudo crear directorio de logs: $LOG_DIR"
mkdir -p $TEMP_DIR 2>/dev/null || log_warn "No se pudo crear directorio temporal: $TEMP_DIR"

# Verificar permisos
if [ ! -w "$TEMP_DIR" ]; then
    log_warn "Sin permisos de escritura en directorio temporal: $TEMP_DIR"
fi

# Verificar variables de entorno
log_info "Verificando configuración..."
if [ ! -f ".env" ]; then
    log_warn "Archivo .env no encontrado. Usando variables de entorno del sistema."
fi

# Verificar estado actual de PM2
log_info "Verificando estado actual de PM2..."
CURRENT_STATUS=$(pm2 jlist 2>/dev/null | jq -r ".[] | select(.name==\"$APP_NAME\") | .pm2_env.status" 2>/dev/null || echo "not_found")

if [ "$CURRENT_STATUS" = "online" ]; then
    log_warn "La aplicación $APP_NAME ya está ejecutándose"
    echo -e "${YELLOW}¿Quieres reiniciarla? [y/N]${NC}"
    read -r RESTART_CONFIRM
    if [[ $RESTART_CONFIRM =~ ^[Yy]$ ]]; then
        log_info "Reiniciando aplicación..."
        pm2 restart $APP_NAME --env $ENVIRONMENT
    else
        log_info "Manteniendo aplicación actual"
        pm2 status $APP_NAME
        exit 0
    fi
elif [ "$CURRENT_STATUS" = "stopped" ] || [ "$CURRENT_STATUS" = "errored" ]; then
    log_info "La aplicación está en estado: $CURRENT_STATUS. Reiniciando..."
    pm2 restart $APP_NAME --env $ENVIRONMENT
else
    log_info "Iniciando nueva instancia de la aplicación..."
    pm2 start $ECOSYSTEM_FILE --env $ENVIRONMENT
fi

# Verificar que se inició correctamente
sleep 3
FINAL_STATUS=$(pm2 jlist 2>/dev/null | jq -r ".[] | select(.name==\"$APP_NAME\") | .pm2_env.status" 2>/dev/null || echo "not_found")

if [ "$FINAL_STATUS" = "online" ]; then
    log_info "✅ Aplicación iniciada correctamente"
    
    # Mostrar información del proceso
    echo ""
    echo -e "${BLUE}=== Información del Proceso ===${NC}"
    pm2 describe $APP_NAME | grep -E "(status|pid|cpu|memory|restart time)"
    
    # Mostrar últimas líneas del log
    echo ""
    echo -e "${BLUE}=== Últimas líneas del log ===${NC}"
    pm2 logs $APP_NAME --lines 10 --nostream
    
    # Información adicional
    echo ""
    echo -e "${GREEN}=== Aplicación Lista ===${NC}"
    echo -e "${GREEN}• Estado:${NC} Online"
    echo -e "${GREEN}• Entorno:${NC} $ENVIRONMENT"
    echo -e "${GREEN}• Puerto:${NC} 3000 (por defecto)"
    echo -e "${GREEN}• Logs:${NC} pm2 logs $APP_NAME"
    echo -e "${GREEN}• Monitoreo:${NC} pm2 monit"
    echo -e "${GREEN}• Estado:${NC} pm2 status"
    
else
    log_error "❌ Error al iniciar la aplicación"
    echo ""
    echo -e "${RED}=== Información de Error ===${NC}"
    pm2 logs $APP_NAME --lines 20 --nostream
    echo ""
    log_error "Revisa los logs para más detalles: pm2 logs $APP_NAME"
    exit 1
fi

# Guardar configuración PM2 para reinicio automático
log_info "Guardando configuración PM2..."
pm2 save

echo ""
echo -e "${GREEN}✅ Script de inicio completado exitosamente${NC}"
echo -e "${BLUE}Para ver logs en tiempo real: ./logs.sh${NC}"
echo -e "${BLUE}Para reiniciar: ./restart.sh${NC}"
echo ""