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

# ===== ESCANEO ANDROID (OPCIÓN 2 COMPLETA) =====
scan_android() {
    show_banner
    echo -e "${YELLOW}[ ESCANEO ANDROID ]${NC}"
    echo ""
    
    # Verificar permisos
    if [ ! -r /sdcard ]; then
        echo -e "${RED}[-] Error: Termux no tiene permisos de almacenamiento${NC}"
        echo -e "${YELLOW}[?] Concede permisos manualmente desde:"
        echo -e "    Ajustes → Aplicaciones → Termux → Permisos → Almacenamiento${NC}"
        echo ""
        read -p "Presiona Enter después de conceder los permisos..."
    fi

    echo -e "${GREEN}[1] Escanear directorios comunes (rápido)"
    echo -e "[2] Escanear todo el almacenamiento (lento)"
    echo -e "[3] Buscar archivos sospechosos por nombre"
    echo -e "[4] Analizar archivo específico con VirusTotal"
    echo -e "[5] Volver al menú principal${NC}"
    echo ""
    
    read -p "Seleccione una opción: " scan_choice
    
    case $scan_choice in
        1)
            echo -e "${YELLOW}[~] Escaneando directorios comunes...${NC}"
            suspicious_files=$(find /sdcard/Download /sdcard/DCIM /sdcard/Android/media -type f \( -name "*.apk" -o -name "*.exe" -o -name "*.bat" \) -exec ls -lh {} + 2>/dev/null)
            ;;
        2)
            echo -e "${YELLOW}[~] Escaneando todo el almacenamiento...${NC}"
            suspicious_files=$(find /sdcard -type f \( -name "*.apk" -o -name "*.exe" -o -name "*.bat" \) -exec ls -lh {} + 2>/dev/null)
            ;;
        3)
            read -p "Ingrese nombre/patrón de archivo a buscar (ej: malware*): " pattern
            suspicious_files=$(find /sdcard -type f -name "$pattern" -exec ls -lh {} + 2>/dev/null)
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
}

analyze_file_with_virustotal() {
    [ -z "$API_KEY" ] && {
        echo -e "${YELLOW}[?] Ingrese su API Key de VirusTotal:${NC}"
        read -s API_KEY
        validate_api_key || return
    }

    read -p "Ingrese la ruta completa del archivo a analizar: " file_path
    [ -f "$file_path" ] || {
        echo -e "${RED}[-] Archivo no encontrado.${NC}"
        return
    }

    file_size=$(stat -c %s "$file_path")
    if [ "$file_size" -gt 650000000 ]; then
        echo -e "${RED}[-] El archivo es demasiado grande (máximo 650MB).${NC}"
        return
    fi

    echo -e "${YELLOW}[~] Subiendo archivo a VirusTotal...${NC}"
    response=$(curl -s --max-time 120 -H "x-apikey: $API_KEY" --form "file=@$file_path" "https://www.virustotal.com/api/v3/files")
    
    analysis_id=$(echo "$response" | jq -r '.data.id')
    [ -z "$analysis_id" ] && {
        error=$(echo "$response" | jq -r '.error.message')
        echo -e "${RED}[-] Error: ${error:-"Falló la conexión"}${NC}"
        return
    }

    echo -e "${BLUE}[~] ID de análisis: $analysis_id${NC}"
    echo -e "${YELLOW}[~] Esperando resultados...${NC}"
    
    while true; do
        report=$(curl -s --max-time 30 -H "x-apikey: $API_KEY" "https://www.virustotal.com/api/v3/analyses/$analysis_id")
        status=$(echo "$report" | jq -r '.data.attributes.status')
        
        case "$status" in
            "completed")
                echo -e "${GREEN}[+] Resultados:${NC}"
                malicious=$(echo "$report" | jq -r '.data.attributes.stats.malicious')
                undetected=$(echo "$report" | jq -r '.data.attributes.stats.undetected')
                
                if [ "$malicious" -gt 0 ]; then
                    echo -e "${RED}[!] ARCHIVO MALICIOSO DETECTADO${NC}"
                else
                    echo -e "${GREEN}[+] Archivo limpio${NC}"
                fi
                
                echo "Motores que lo detectaron como malicioso: $malicious"
                echo "Motores que no encontraron amenazas: $undetected"
                sha256=$(echo "$report" | jq -r '.meta.file_info.sha256')
                echo "Enlace: https://www.virustotal.com/gui/file/$sha256"
                break
                ;;
            "queued")
                echo -n "."
                sleep 15
                ;;
            *)
                echo -e "${RED}[-] Error en el análisis.${NC}"
                break
                ;;
        esac
    done
}

# ===== LIMPIEZA DE SEGURIDAD =====
clean_system() {
    show_banner
    echo -e "${YELLOW}[ LIMPIEZA DE SEGURIDAD ]${NC}"
    echo ""
    
    echo -e "${GREEN}[1] Limpiar caché de aplicaciones"
    echo -e "[2] Eliminar archivos temporales"
    echo -e "[3] Limpiar logs del sistema"
    echo -e "[4] Volver al menú principal${NC}"
    echo ""
    
    read -p "Seleccione una opción: " clean_choice
    
    case $clean_choice in
        1)
            echo -e "${YELLOW}[~] Limpiando caché...${NC}"
            rm -rf /data/data/com.termux/files/usr/var/cache/*
            echo -e "${GREEN}[+] Caché limpiado.${NC}"
            ;;
        2)
            echo -e "${YELLOW}[~] Eliminando temporales...${NC}"
            find /sdcard/ -type f \( -name "*.tmp" -o -name "*.temp" -o -name "*.bak" \) -delete 2>/dev/null
            echo -e "${GREEN}[+] Archivos temporales eliminados.${NC}"
            ;;
        3)
            echo -e "${YELLOW}[~] Limpiando logs...${NC}"
            rm -f /data/data/com.termux/files/usr/var/log/*
            echo -e "${GREEN}[+] Logs limpiados.${NC}"
            ;;
        4)
            return
            ;;
        *)
            echo -e "${RED}[-] Opción inválida${NC}"
            ;;
    esac
}

# ===== MENÚ PRINCIPAL =====
main_menu() {
    while true; do
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
    done
}

# ===== INICIO =====
install_deps
main_menu
