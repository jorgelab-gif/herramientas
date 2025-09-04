#!/bin/bash
# Script para visualizar logs de la aplicación Herramientas Backend
# Versión optimizada para VPS de producción

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuración
APP_NAME="herramientas-backend"
LOG_DIR="/var/log/pm2"
NGINX_LOG_DIR="/var/log/nginx"
MODE=${1:-realtime}
LINES=${2:-50}
LOG_TYPE=${3:-all}

echo -e "${BLUE}=== Herramientas Backend - Visor de Logs ===${NC}"
echo -e "${BLUE}Fecha: $(date)${NC}"
echo -e "${BLUE}Modo: $MODE${NC}"
echo -e "${BLUE}Líneas: $LINES${NC}"
echo -e "${BLUE}Tipo: $LOG_TYPE${NC}"
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

# Función para mostrar ayuda
show_help() {
    echo -e "${CYAN}Uso: ./logs.sh [MODO] [LÍNEAS] [TIPO]${NC}"
    echo ""
    echo -e "${PURPLE}MODOS disponibles:${NC}"
    echo -e "  ${BLUE}realtime${NC}  - Ver logs en tiempo real (por defecto)"
    echo -e "  ${BLUE}history${NC}   - Ver historial de logs"
    echo -e "  ${BLUE}errors${NC}    - Ver solo errores"
    echo -e "  ${BLUE}summary${NC}   - Resumen del estado y últimos logs"
    echo -e "  ${BLUE}nginx${NC}     - Ver logs de Nginx"
    echo -e "  ${BLUE}system${NC}    - Ver logs del sistema"
    echo ""
    echo -e "${PURPLE}TIPOS de logs:${NC}"
    echo -e "  ${BLUE}all${NC}       - Todos los logs (por defecto)"
    echo -e "  ${BLUE}out${NC}       - Solo logs de salida"
    echo -e "  ${BLUE}error${NC}     - Solo logs de error"
    echo -e "  ${BLUE}pm2${NC}       - Logs de PM2"
    echo ""
    echo -e "${PURPLE}Ejemplos:${NC}"
    echo -e "  ${CYAN}./logs.sh${NC}                    # Logs en tiempo real"
    echo -e "  ${CYAN}./logs.sh history 100${NC}        # Últimas 100 líneas"
    echo -e "  ${CYAN}./logs.sh errors${NC}             # Solo errores"
    echo -e "  ${CYAN}./logs.sh nginx${NC}              # Logs de Nginx"
    echo ""
}

# Verificar si PM2 está instalado
if ! command -v pm2 &> /dev/null; then
    log_error "PM2 no está instalado. Instálalo con: npm install -g pm2"
    exit 1
fi

# Verificar argumentos
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    show_help
    exit 0
fi

# Verificar si la aplicación existe
APP_EXISTS=$(pm2 jlist 2>/dev/null | jq -r ".[] | select(.name==\"$APP_NAME\") | .name" 2>/dev/null || echo "")

if [ -z "$APP_EXISTS" ] && [ "$MODE" != "nginx" ] && [ "$MODE" != "system" ]; then
    log_error "La aplicación $APP_NAME no está registrada en PM2"
    log_info "Apps disponibles:"
    pm2 list
    exit 1
fi

# Función para mostrar información del sistema
show_system_info() {
    echo -e "${PURPLE}=== Información del Sistema ===${NC}"
    echo -e "${GREEN}• Uso de CPU:${NC}"
    top -bn1 | grep "Cpu(s)" | head -1 | awk '{print $2 $3}' | sed 's/%us,/ usuario,/' | sed 's/%sy/ sistema/'
    
    echo -e "${GREEN}• Uso de Memoria:${NC}"
    free -h | grep "Mem:" | awk '{printf "Usado: %s / %s (%s)\n", $3, $2, $3/$2*100"%"}'
    
    echo -e "${GREEN}• Espacio en Disco:${NC}"
    df -h / | tail -1 | awk '{printf "Usado: %s / %s (%s)\n", $3, $2, $5}'
    
    echo -e "${GREEN}• Uptime del Sistema:${NC} $(uptime -p)"
    echo ""
}

# Función para mostrar resumen de PM2
show_pm2_summary() {
    echo -e "${PURPLE}=== Estado de PM2 ===${NC}"
    pm2 status
    echo ""
    
    if [ ! -z "$APP_EXISTS" ]; then
        echo -e "${PURPLE}=== Información Detallada de $APP_NAME ===${NC}"
        pm2 describe $APP_NAME | grep -E "(status|pid|cpu|memory|uptime|restart time|instances)"
        echo ""
    fi
}

# Función principal para mostrar logs
show_logs() {
    case $MODE in
        "realtime")
            log_info "Mostrando logs en tiempo real (Ctrl+C para salir)..."
            echo -e "${YELLOW}=== Logs en Tiempo Real ===${NC}"
            if [ "$LOG_TYPE" = "out" ]; then
                pm2 logs $APP_NAME --out
            elif [ "$LOG_TYPE" = "error" ]; then
                pm2 logs $APP_NAME --err
            else
                pm2 logs $APP_NAME
            fi
            ;;
            
        "history")
            log_info "Mostrando últimas $LINES líneas de logs..."
            echo -e "${YELLOW}=== Historial de Logs ===${NC}"
            if [ "$LOG_TYPE" = "out" ]; then
                pm2 logs $APP_NAME --lines $LINES --nostream --out
            elif [ "$LOG_TYPE" = "error" ]; then
                pm2 logs $APP_NAME --lines $LINES --nostream --err
            else
                pm2 logs $APP_NAME --lines $LINES --nostream
            fi
            ;;
            
        "errors")
            log_info "Mostrando solo errores..."
            echo -e "${RED}=== Logs de Error ===${NC}"
            pm2 logs $APP_NAME --err --lines $LINES --nostream
            echo ""
            
            # Buscar errores en archivos de log
            if [ -f "$LOG_DIR/herramientas-backend-error.log" ]; then
                echo -e "${RED}=== Errores Recientes en Archivo ===${NC}"
                tail -n $LINES "$LOG_DIR/herramientas-backend-error.log" 2>/dev/null || log_warn "No se pudo leer archivo de errores"
            fi
            ;;
            
        "summary")
            show_system_info
            show_pm2_summary
            
            log_info "Últimos logs de la aplicación:"
            echo -e "${YELLOW}=== Últimos Logs ===${NC}"
            pm2 logs $APP_NAME --lines 20 --nostream
            ;;
            
        "nginx")
            if [ ! -d "$NGINX_LOG_DIR" ]; then
                log_error "Directorio de logs de Nginx no encontrado: $NGINX_LOG_DIR"
                exit 1
            fi
            
            log_info "Mostrando logs de Nginx..."
            echo -e "${CYAN}=== Logs de Acceso de Nginx ===${NC}"
            if [ -f "$NGINX_LOG_DIR/herramientas-access.log" ]; then
                tail -n $LINES "$NGINX_LOG_DIR/herramientas-access.log"
            elif [ -f "$NGINX_LOG_DIR/access.log" ]; then
                tail -n $LINES "$NGINX_LOG_DIR/access.log"
            else
                log_warn "No se encontraron logs de acceso de Nginx"
            fi
            
            echo ""
            echo -e "${RED}=== Logs de Error de Nginx ===${NC}"
            if [ -f "$NGINX_LOG_DIR/herramientas-error.log" ]; then
                tail -n $LINES "$NGINX_LOG_DIR/herramientas-error.log"
            elif [ -f "$NGINX_LOG_DIR/error.log" ]; then
                tail -n $LINES "$NGINX_LOG_DIR/error.log"
            else
                log_warn "No se encontraron logs de error de Nginx"
            fi
            ;;
            
        "system")
            log_info "Mostrando logs del sistema..."
            echo -e "${CYAN}=== Logs del Sistema (journalctl) ===${NC}"
            
            echo -e "${BLUE}• Nginx:${NC}"
            sudo journalctl -u nginx --lines 10 --no-pager 2>/dev/null || log_warn "No se pudieron obtener logs de nginx"
            
            echo ""
            echo -e "${BLUE}• MySQL:${NC}"
            sudo journalctl -u mysql --lines 10 --no-pager 2>/dev/null || log_warn "No se pudieron obtener logs de mysql"
            
            echo ""
            echo -e "${BLUE}• Sistema general:${NC}"
            sudo journalctl --since "1 hour ago" --lines 10 --no-pager 2>/dev/null || log_warn "No se pudieron obtener logs del sistema"
            ;;
            
        *)
            log_error "Modo desconocido: $MODE"
            show_help
            exit 1
            ;;
    esac
}

# Capturar Ctrl+C para salir graciosamente
trap 'echo -e "\n${YELLOW}Saliendo...${NC}"; exit 0' INT

# Ejecutar función principal
show_logs

echo ""
echo -e "${GREEN}=== Comandos Útiles ===${NC}"
echo -e "${BLUE}• Ver estado:${NC} pm2 status"
echo -e "${BLUE}• Monitoreo:${NC} pm2 monit"
echo -e "${BLUE}• Reiniciar:${NC} ./restart.sh"
echo -e "${BLUE}• Ayuda:${NC} ./logs.sh --help"
echo ""