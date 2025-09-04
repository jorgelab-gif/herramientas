#!/bin/bash
# Script para reiniciar la aplicación Herramientas Backend
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
ENVIRONMENT=${1:-production}
RESTART_MODE=${2:-graceful}

echo -e "${BLUE}=== Herramientas Backend - Script de Reinicio ===${NC}"
echo -e "${BLUE}Fecha: $(date)${NC}"
echo -e "${BLUE}Entorno: $ENVIRONMENT${NC}"
echo -e "${BLUE}Modo: $RESTART_MODE${NC}"
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

# Verificar si la aplicación existe
APP_EXISTS=$(pm2 jlist 2>/dev/null | jq -r ".[] | select(.name==\"$APP_NAME\") | .name" 2>/dev/null || echo "")

if [ -z "$APP_EXISTS" ]; then
    log_error "La aplicación $APP_NAME no está registrada en PM2"
    echo -e "${YELLOW}¿Quieres iniciarla? [Y/n]${NC}"
    read -r START_CONFIRM
    if [[ ! $START_CONFIRM =~ ^[Nn]$ ]]; then
        log_info "Iniciando aplicación..."
        exec ./start.sh $ENVIRONMENT
    else
        log_info "Cancelado por el usuario"
        exit 0
    fi
fi

# Cambiar al directorio de la aplicación
if [ -d "$APP_DIR" ]; then
    cd $APP_DIR
    log_info "Cambiando al directorio: $APP_DIR"
fi

# Mostrar estado actual
log_info "Estado actual de la aplicación:"
pm2 describe $APP_NAME | grep -E "(status|pid|cpu|memory|uptime|restart time)" || log_warn "No se pudo obtener información detallada"
echo ""

# Ejecutar reinicio según el modo
log_info "Reiniciando aplicación en modo: $RESTART_MODE"

case $RESTART_MODE in
    "graceful"|"reload")
        log_info "Ejecutando reinicio graceful (zero downtime)..."
        pm2 reload $APP_NAME --env $ENVIRONMENT
        ;;
    "hard"|"restart")
        log_info "Ejecutando reinicio hard (con downtime temporal)..."
        pm2 restart $APP_NAME --env $ENVIRONMENT
        ;;
    "stop-start")
        log_info "Ejecutando stop/start completo..."
        pm2 stop $APP_NAME
        sleep 2
        pm2 start $APP_NAME --env $ENVIRONMENT
        ;;
    *)
        log_warn "Modo desconocido '$RESTART_MODE', usando graceful por defecto"
        pm2 reload $APP_NAME --env $ENVIRONMENT
        ;;
esac

# Verificar que el reinicio fue exitoso
log_info "Verificando estado después del reinicio..."
sleep 5

FINAL_STATUS=$(pm2 jlist 2>/dev/null | jq -r ".[] | select(.name==\"$APP_NAME\") | .pm2_env.status" 2>/dev/null || echo "not_found")

if [ "$FINAL_STATUS" = "online" ]; then
    log_info "✅ Reinicio completado exitosamente"
    
    # Información del proceso después del reinicio
    echo ""
    echo -e "${BLUE}=== Información Post-Reinicio ===${NC}"
    NEW_PID=$(pm2 jlist 2>/dev/null | jq -r ".[] | select(.name==\"$APP_NAME\") | .pid" 2>/dev/null || echo "N/A")
    NEW_UPTIME=$(pm2 jlist 2>/dev/null | jq -r ".[] | select(.name==\"$APP_NAME\") | .pm2_env.pm_uptime" 2>/dev/null || echo "N/A")
    
    echo -e "${GREEN}• Estado:${NC} Online"
    echo -e "${GREEN}• PID:${NC} $NEW_PID"
    echo -e "${GREEN}• Iniciado:${NC} $(date -d @$(($NEW_UPTIME / 1000)) 2>/dev/null || echo "N/A")"
    
    # Mostrar últimas líneas del log
    echo ""
    echo -e "${BLUE}=== Últimas líneas del log ===${NC}"
    pm2 logs $APP_NAME --lines 10 --nostream
    
    # Verificar conectividad (si curl está disponible)
    if command -v curl &> /dev/null; then
        echo ""
        log_info "Verificando conectividad..."
        sleep 2
        if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ | grep -q "200\|404\|302"; then
            log_info "✅ Aplicación responde correctamente"
        else
            log_warn "⚠️  La aplicación podría no estar respondiendo correctamente"
        fi
    fi
    
else
    log_error "❌ Error en el reinicio de la aplicación"
    echo ""
    echo -e "${RED}=== Información de Error ===${NC}"
    pm2 describe $APP_NAME || log_error "No se pudo obtener información de la aplicación"
    
    echo ""
    log_error "Últimos logs de error:"
    pm2 logs $APP_NAME --lines 20 --nostream
    
    echo ""
    log_error "Revisa los logs para más detalles: pm2 logs $APP_NAME"
    exit 1
fi

# Guardar configuración actualizada
log_info "Guardando configuración PM2..."
pm2 save

echo ""
echo -e "${GREEN}✅ Script de reinicio completado exitosamente${NC}"
echo -e "${BLUE}Modos de reinicio disponibles:${NC}"
echo -e "  ${BLUE}• ./restart.sh [entorno] graceful${NC}  - Reinicio sin downtime (por defecto)"
echo -e "  ${BLUE}• ./restart.sh [entorno] hard${NC}      - Reinicio con downtime temporal"
echo -e "  ${BLUE}• ./restart.sh [entorno] stop-start${NC} - Stop/Start completo"
echo ""
echo -e "${BLUE}Para ver logs en tiempo real: ./logs.sh${NC}"
echo ""