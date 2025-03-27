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

validate_api_key() {
    [[ "$API_KEY" =~ ^[a-zA-Z0-9]{64}$ ]] || {
        echo -e "${RED}[-] API Key inválida (debe tener 64 caracteres).${NC}"
        return 1
    }
}

scan_android() {
    show_banner
    echo -e "${YELLOW}[ ESCANEO ANDROID ]${NC}"
    echo ""

    # Verificar permisos de almacenamiento
    if [ ! -r /sdcard ] || [ ! -w /sdcard ]; then
        echo -e "${RED}[-] Error: Termux no tiene permisos de almacenamiento.${NC}"
        echo -e "${YELLOW}[?] Solicitando permisos...${NC}"
        
        termux-setup-storage
        sleep 3  

        if [ ! -r /sdcard ] || [ ! -w /sdcard ]; then
            echo -e "${RED}[-] No se concedieron los permisos. Saliendo...${NC}"
            sleep 2
            return
        else
            echo -e "${GREEN}[+] Permisos concedidos correctamente.${NC}"
        fi
    fi

    echo -e "${GREEN}[1] Escanear directorios comunes (rápido)"
    echo -e "[2] Escanear todo el almacenamiento (lento)"
    echo -e "[3] Buscar archivos sospechosos por nombre"
    echo -e "[4] Analizar archivo con VirusTotal"
    echo -e "[5] Volver al menú principal${NC}"
    echo ""

    read -p "Seleccione una opción: " scan_choice

    case $scan_choice in
        1)
            targets=("/sdcard/Download" "/sdcard/DCIM" "/sdcard/Android/media")
            suspicious_files=$(find "${targets[@]}" -type f -name "*.apk" -o -name "*.exe" -o -name "*.bat" -o -name "*.jar" 2>/dev/null)
            ;;
        2)
            suspicious_files=$(find /sdcard -type f -name "*.apk" -o -name "*.exe" -o -name "*.bat" -o -name "*.jar" 2>/dev/null)
            ;;
        3)
            read -p "Ingrese nombre/patrón de archivo (ej: *hack*): " pattern
            suspicious_files=$(find /sdcard -type f -name "$pattern" 2>/dev/null)
            ;;
        4)
            analyze_file_with_virustotal
            return
            ;;
        5)
            return
            ;;
        *)
            echo -e "${RED}[-] Opción inválida${NC}"
            return
            ;;
    esac

    if [ -z "$suspicious_files" ]; then
        echo -e "${GREEN}[+] No se encontraron archivos sospechosos.${NC}"
    else
        echo -e "${RED}[!] Archivos sospechosos encontrados:${NC}"
        echo "$suspicious_files"
        echo ""

        read -p "¿Desea analizar algún archivo con VirusTotal? (s/n): " analyze_choice
        if [[ "$analyze_choice" =~ [sSyY] ]]; then
            analyze_file_with_virustotal
        fi
    fi

    read -p "Presione Enter para continuar..."
}

clean_system() {
    show_banner
    echo -e "${YELLOW}[ LIMPIEZA DE SEGURIDAD ]${NC}"
    echo ""
    
    echo -e "${GREEN}[1] Limpiar caché de Termux"
    echo -e "[2] Eliminar archivos temporales"
    echo -e "[3] Limpiar registros"
    echo -e "[4] Volver al menú${NC}"
    echo ""
    
    read -p "Seleccione una opción: " clean_choice
    
    case $clean_choice in
        1) rm -rf ~/.cache/* ;;
        2) find /sdcard -type f -name "*.tmp" -o -name "*.temp" -delete 2>/dev/null ;;
        3) rm -f ~/.bash_history ;;
        4) return ;;
        *) echo -e "${RED}[-] Opción inválida${NC}" ;;
    esac
    
    read -p "Presione Enter para continuar..."
}

main_menu() {
    while true; do
        show_banner
        echo -e "${GREEN}[1] Escanear dispositivo"
        echo -e "[2] Limpieza de seguridad"
        echo -e "[3] Salir${NC}"
        echo ""
        
        read -p "Seleccione una opción: " choice
        
        case $choice in
            1) scan_android ;;
            2) clean_system ;;
            3) exit 0 ;;
            *) echo -e "${RED}[-] Opción inválida${NC}" ;;
        esac
    done
}

# ===== INICIO =====
install_deps
main_menu
