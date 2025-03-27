
#!/data/data/com.termux/files/usr/bin/bash

# ===== CONFIGURACIÓN INICIAL =====
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

# ===== TUTORIAL =====
show_tutorial() {
    show_banner
    echo -e "${YELLOW}[ TUTORIAL ]${NC}"
    echo ""
    echo "1. Para analizar URLs/archivos necesitarás:"
    echo "   - Una API key gratuita de VirusTotal"
    echo "   - Obtén una en: https://www.virustotal.com/gui/my-apikey"
    echo ""
    echo "2. Escaneo Android:"
    echo "   - Busca archivos sospechosos en tu dispositivo"
    echo "   - Puedes analizarlos directamente con VirusTotal"
    echo ""
    echo "3. Limpieza de seguridad:"
    echo "   - Elimina caché y cookies temporales"
    echo ""
    echo -e "${GREEN}Presiona Enter para volver al menú...${NC}"
    read
}

# ===== INSTALACIÓN DE DEPENDENCIAS =====
install_deps() {
    echo -e "${YELLOW}[+] Actualizando paquetes...${NC}"
    pkg update -y && pkg upgrade -y
    
    echo -e "${YELLOW}[+] Instalando dependencias...${NC}"
    for pkg in curl jq openssl termux-api nmap git; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo -e "${BLUE}[~] Instalando $pkg...${NC}"
            pkg install -y $pkg || {
                echo -e "${RED}[-] Error al instalar $pkg.${NC}"
                exit 1
            }
        fi
    done
    echo -e "${GREEN}[+] Dependencias instaladas.${NC}"
}

# ===== FUNCIONES DE VIRUSTOTAL =====
validate_api_key() {
    [[ "$API_KEY" =~ ^[a-zA-Z0-9]{64}$ ]] || {
        echo -e "${RED}[-] API Key inválida (debe tener 64 caracteres).${NC}"
        return 1
    }
}

analyze_url() {
    [ -z "$API_KEY" ] && {
        echo -e "${YELLOW}[?] Ingrese su API Key de VirusTotal:${NC}"
        read -s API_KEY
        validate_api_key || return
    }

    read -p "Ingrese la URL a analizar: " url
    [[ "$url" =~ ^https?:// ]] || {
        echo -e "${RED}[-] URL inválida. Use http:// o https://${NC}"
        return
    }

    echo -e "${YELLOW}[~] Analizando URL...${NC}"
    response=$(curl -s --max-time 30 -H "x-apikey: $API_KEY" -F "url=$url" "https://www.virustotal.com/api/v3/urls")
    
    analysis_id=$(echo "$response" | jq -r '.data.id')
    [ -z "$analysis_id" ] && {
        error=$(echo "$response" | jq -r '.error.message')
        echo -e "${RED}[-] Error: ${error:-"Falló la conexión"}${NC}"
        return
    }

    echo -e "${BLUE}[~] ID de análisis: $analysis_id${NC}"
    while true; do
        report=$(curl -s --max-time 30 -H "x-apikey: $API_KEY" "https://www.virustotal.com/api/v3/analyses/$analysis_id")
        status=$(echo "$report" | jq -r '.data.attributes.status')
        
        case "$status" in
            "completed")
                echo -e "${GREEN}[+] Resultados:${NC}"
                echo "Maliciosos: $(echo "$report" | jq -r '.data.attributes.stats.malicious')"
                echo "Inofensivos: $(echo "$report" | jq -r '.data.attributes.stats.undetected')"
                echo "Enlace: https://www.virustotal.com/gui/url/$analysis_id"
                break
                ;;
            "queued")
                sleep 10
                ;;
            *)
                echo -e "${RED}[-] Error en el análisis.${NC}"
                break
                ;;
        esac
    done
}

# ===== MENÚ PRINCIPAL =====
main_menu() {
    show_banner
    echo -e "${GREEN}[1] Analizar URL con VirusTotal"
    echo -e "[2] Escanear dispositivo"
    echo -e "[3] Limpieza de seguridad"
    echo -e "[4] Tutorial"
    echo -e "[5] Salir${NC}"
    echo ""
    
    read -p "Seleccione una opción: " choice
    
    case $choice in
        1) analyze_url ;;
        2) scan_android ;;
        3) clean_system ;;
        4) show_tutorial ;;
        5) exit 0 ;;
        *) echo -e "${RED}[-] Opción inválida${NC}" ;;
    esac
    
    read -p "Presione Enter para continuar..."
    main_menu
}

# ===== INICIO =====
install_deps
main_menu
