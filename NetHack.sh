#!/data/data/com.termux/files/usr/bin/bash

exec > >(tee -a malware_analyzer.log) 2>&1
export LANG=en_US.UTF-8

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables globales
API_KEY=""

show_banner() {
    clear
    echo -e "${PURPLE}"
    echo "       █████╗    ██╗   ██╗"
    echo "      ██╔══██╗   ██║   ██║"
    echo "      ███████║   ██║   ██║"
    echo "      ██╔══██║   ╚██╗ ██╔╝"
    echo "      ██║  ██║██╗ ╚████╔╝ "
    echo "      ╚═╝  ╚═╝╚═╝  ╚═══╝  "
    echo -e "└───────────────────────────────────────┘${NC}"
    echo -e "${CYAN}┌─[${RED}A-R${CYAN}]─[${YELLOW}Termux${CYAN}]"
    echo -e "${CYAN}└──╼ ${GREEN}by ${PURPLE}AldazUnlock${NC}"
    echo -e "${BLUE}------------------------------------------------${NC}"
  
    echo ""
}

install_requirements() {
    echo -e "${YELLOW}[*] Verificando e instalando requisitos...${NC}"
    # Instalar dependencias del primer script
    bash requisitos/0.sh
    
    # Instalar dependencias del analizador de malware
    echo -e "${YELLOW}[*] Instalando dependencias del analizador...${NC}"
    missing=0
    for pkg in curl jq base64 openssl proot-distro; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo "Instalando $pkg..."
            pkg install -y $pkg || { echo -e "${RED}Fallo al instalar $pkg. Saliendo.${NC}"; exit 1; }
            missing=1
        fi
    done
    
    if [ $missing -eq 1 ]; then
        echo -e "${GREEN}[+] Dependencias instaladas exitosamente.${NC}"
    else
        echo -e "${GREEN}[+] Todas las dependencias ya están instaladas.${NC}"
    fi
    sleep 2
}

show_main_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 ${PURPLE}MENÚ PRINCIPAL - TST                 ${GREEN}║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}║  ${CYAN}[1] ${YELLOW}Herramientas de Red WiFi                            ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[2] ${YELLOW}Analizador de Malware/VirusTotal                    ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[3] ${YELLOW}Kit de Seguridad y Privacidad                       ${GREEN}║${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║  ${RED}[99] ${YELLOW}Salir del programa                               ${GREEN}║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p " [*] Seleccione una opción: " choice

        case $choice in
            1)
                show_wifi_menu
                ;;
            2)
                show_malware_menu
                ;;
            3)
                show_security_toolkit
                ;;
            99)
                echo -e "${RED}Saliendo...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Opción inválida. Por favor, seleccione nuevamente.${NC}"
                sleep 2
                ;;
        esac
    done
}

show_wifi_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 ${PURPLE}HERRAMIENTAS DE RED WiFi             ${GREEN}║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}║  ${CYAN}[1] Configurar tarjeta de red                       ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[2] Escanear redes WiFi                             ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[3] Crear redes WiFi masivas                         ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[4] Espiar tráfico de red local                     ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[5] Extraer HandShake de una red WiFi               ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[6] Inhibir redes WiFi/dispositivos                 ${GREEN}║${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║  ${RED}[0] Volver al menú principal                      ${GREEN}║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p " [*] Seleccione una opción: " wifi_choice

        case $wifi_choice in
            1) bash requisitos/1.sh ;;
            2) bash requisitos/2.sh ;;
            3) bash requisitos/3.sh ;;
            4) bash requisitos/4.sh ;;
            5) bash requisitos/5.sh ;;
            6) bash requisitos/6.sh ;;
            0) return ;;
            *) 
                echo -e "${RED}Opción inválida.${NC}"
                sleep 2
                ;;
        esac
    done
}

show_malware_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 ${PURPLE}ANALIZADOR DE MALWARE                ${GREEN}║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}║  ${CYAN}[1] Analizar URL con VirusTotal                     ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[2] Analizar archivo con VirusTotal                 ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[3] Configurar API Key de VirusTotal                ${GREEN}║${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║  ${RED}[0] Volver al menú principal                      ${GREEN}║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p " [*] Seleccione una opción: " malware_choice

        case $malware_choice in
            1)
                if [ -z "$API_KEY" ]; then
                    echo -e "${RED}Primero configure su API Key de VirusTotal${NC}"
                    sleep 2
                    continue
                fi
                read -p "Ingresa la URL a analizar: " url
                analyze_url "$url"
                read -p "Presiona Enter para continuar..."
                ;;
            2)
                if [ -z "$API_KEY" ]; then
                    echo -e "${RED}Primero configure su API Key de VirusTotal${NC}"
                    sleep 2
                    continue
                fi
                read -p "Ingresa la ruta del archivo a analizar: " file
                analyze_file "$file"
                read -p "Presiona Enter para continuar..."
                ;;
            3)
                get_virustotal_api
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}Opción inválida.${NC}"
                sleep 2
                ;;
        esac
    done
}

show_security_toolkit() {
    while true; do
        show_banner
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 ${PURPLE}KIT DE SEGURIDAD                     ${GREEN}║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}║  ${CYAN}[1] Manejar seguridad de sesiones y cookies         ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[2] Crear entorno sandbox                          ${GREEN}║${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║  ${RED}[0] Volver al menú principal                      ${GREEN}║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p " [*] Seleccione una opción: " toolkit_choice

        case $toolkit_choice in
            1)
                handle_session_security
                ;;
            2)
                create_sandbox
                read -p "Presiona Enter para continuar..."
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}Opción inválida.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Funciones del analizador de malware (las mismas que en tu script original)
analyze_url() {
    local url=$1
    if [[ ! $url =~ ^https?://.* ]]; then
        echo -e "${RED}Formato de URL inválido.${NC}"
        return
    fi
    echo -e "${YELLOW}Analizando URL: $url${NC}"
    local response=$(curl -s "https://www.virustotal.com/api/v3/urls" \
        -H "x-apikey:$API_KEY" \
        -F "url=$url")
    local status=$(echo $response | jq -r '.error.message // ""')
    if [ "$status" != "" ]; then
        echo -e "${RED}Error: $status${NC}"
        return
    fi
    local analysis_id=$(echo $response | jq -r '.data.id')
    echo -e "${YELLOW}Esperando análisis... (esto puede tomar unos minutos)${NC}"
    
    local dots=0
    while true; do
        local report=$(curl -s "https://www.virustotal.com/api/v3/analyses/$analysis_id" \
            -H "x-apikey:$API_KEY")
        local status=$(echo $report | jq -r '.data.attributes.status')
        
        # Animación de puntos
        printf "\rAnalizando [%s]" "$(printf '%*s' $dots | tr ' ' '.')"
        ((dots++))
        if [ $dots -gt 3 ]; then
            dots=0
        fi
        
        if [ "$status" == "completed" ]; then
            break
        fi
        sleep 5
    done
    printf "\r%*s\r" "${COLUMNS:-$(tput cols)}" ""
    
    echo -e "${GREEN}Resultados del análisis para URL: $url${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${CYAN}Motores maliciosos: ${RED}$(echo $report | jq -r '.data.attributes.stats.malicious')${NC}"
    echo -e "${CYAN}Motores no detectados: ${GREEN}$(echo $report | jq -r '.data.attributes.stats.undetected')${NC}"
    echo -e "${BLUE}=============================================${NC}"
}

analyze_file() {
    local file=$1
    if [ ! -f "$file" ]; then
        echo -e "${RED}Archivo no encontrado.${NC}"
        return
    fi
    echo -e "${YELLOW}Analizando archivo: $file${NC}"
    local file_data=$(base64 -w 0 "$file")
    local response=$(curl -s "https://www.virustotal.com/api/v3/files" \
        -H "x-apikey:$API_KEY" \
        -F "file=<$file")
    local status=$(echo $response | jq -r '.error.message // ""')
    if [ "$status" != "" ]; then
        echo -e "${RED}Error: $status${NC}"
        return
    fi
    local analysis_id=$(echo $response | jq -r '.data.id')
    echo -e "${YELLOW}Esperando análisis... (esto puede tomar unos minutos)${NC}"
    
    local dots=0
    while true; do
        local report=$(curl -s "https://www.virustotal.com/api/v3/analyses/$analysis_id" \
            -H "x-apikey:$API_KEY")
        local status=$(echo $report | jq -r '.data.attributes.status')
        
        # Animación de puntos
        printf "\rAnalizando [%s]" "$(printf '%*s' $dots | tr ' ' '.')"
        ((dots++))
        if [ $dots -gt 3 ]; then
            dots=0
        fi
        
        if [ "$status" == "completed" ]; then
            break
        fi
        sleep 10  # Aumentado el tiempo para análisis de archivos
    done
    printf "\r%*s\r" "${COLUMNS:-$(tput cols)}" ""
    
    echo -e "${GREEN}Resultados del análisis para archivo: $file${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${CYAN}Motores maliciosos: ${RED}$(echo $report | jq -r '.data.attributes.stats.malicious')${NC}"
    echo -e "${CYAN}Motores no detectados: ${GREEN}$(echo $report | jq -r '.data.attributes.stats.undetected')${NC}"
    echo -e "${BLUE}=============================================${NC}"
}

handle_session_security() {
    while true; do
        show_banner
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 ${PURPLE}SEGURIDAD DE SESIONES                ${GREEN}║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}║  ${CYAN}[1] Borrar cookies                                  ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[2] Usar modo incógnito                             ${GREEN}║${NC}"
        echo -e "${GREEN}║  ${CYAN}[3] Verificar conexiones activas                    ${GREEN}║${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║  ${RED}[0] Volver al menú anterior                       ${GREEN}║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p " [*] Seleccione una opción: " sec_choice

        case $sec_choice in
            1)
                if [ -d ~/.termux/share/cookies ]; then
                    rm -rf ~/.termux/share/cookies
                    echo -e "${GREEN}Cookies borradas correctamente.${NC}"
                else
                    echo -e "${YELLOW}No se encontraron cookies para borrar.${NC}"
                fi
                sleep 2
                ;;
            2)
                echo -e "${YELLOW}Abriendo navegador en modo incógnito...${NC}"
                termux-open-url --incognito "https://www.google.com"
                sleep 2
                ;;
            3)
                echo -e "${YELLOW}Verificando conexiones activas...${NC}"
                netstat -tuln
                read -p "Presiona Enter para continuar..."
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}Opción inválida.${NC}"
                sleep 1
                ;;
        esac
    done
}

create_sandbox() {
    echo -e "${YELLOW}Preparando entorno sandbox...${NC}"
    if ! command -v proot-distro >/dev/null 2>&1; then
        echo -e "${CYAN}Instalando proot-distro...${NC}"
        pkg install -y proot-distro
    fi
    
    if proot-distro list | grep -q "debian"; then
        echo -e "${GREEN}Entorno Debian ya existe.${NC}"
    else
        echo -e "${CYAN}Creando entorno Debian...${NC}"
        proot-distro install debian || {
            echo -e "${RED}Error al instalar Debian.${NC}"
            return 1
        }
    fi
    
    echo -e "${GREEN}Iniciando entorno Debian...${NC}"
    echo -e "${YELLOW}Escribe 'exit' para salir del entorno sandbox${NC}"
    proot-distro login debian
}

get_virustotal_api() {
    echo -e "${YELLOW}Para usar VirusTotal, necesitas una API key.${NC}"
    echo -e "${CYAN}1. Obtener una API key gratuita de: ${BLUE}https://www.virustotal.com${NC}"
    echo -e "${CYAN}2. Ingresar tu clave API a continuación${NC}"
    echo ""
    read -p "Ingresa tu clave API de VirusTotal: " API_KEY
    echo -e "${GREEN}API Key configurada correctamente.${NC}"
    sleep 2
}

# Inicio del programa
install_requirements
show_main_menu