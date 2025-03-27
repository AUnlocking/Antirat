#!/data/data/com.termux/files/usr/bin/bash

# ===== CONFIGURACIÓN INICIAL =====
exec > >(tee -a malware_analyzer.log) 2>&1
export LANG=en_US.UTF-8

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ===== INSTALACIÓN DE DEPENDENCIAS =====
install_deps() {
    echo -e "${YELLOW}[+] Actualizando paquetes...${NC}"
    pkg update -y && pkg upgrade -y
    
    echo -e "${YELLOW}[+] Instalando dependencias principales...${NC}"
    for pkg in curl jq openssl proot-distro termux-api nmap git; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo -e "${BLUE}[~] Instalando $pkg...${NC}"
            pkg install -y $pkg || {
                echo -e "${RED}[-] Error al instalar $pkg.${NC}"
                exit 1
            }
        fi
    done
    
    echo -e "${GREEN}[+] Dependencias instaladas correctamente.${NC}"
}

# ===== FUNCIONES DE VIRUSTOTAL =====
validate_api_key() {
    [[ "$API_KEY" =~ ^[a-zA-Z0-9]{64}$ ]] || {
        echo -e "${RED}[-] API Key inválida. Debe tener 64 caracteres alfanuméricos.${NC}"
        return 1
    }
}

get_virustotal_api() {
    echo -e "${YELLOW}[?] Ingrese su API Key de VirusTotal:${NC}"
    read -s API_KEY
    validate_api_key || {
        echo -e "${RED}[-] API Key incorrecta. Vuelva a intentarlo.${NC}"
        return 1
    }
}

analyze_url() {
    [ -z "$API_KEY" ] && get_virustotal_api || return

    local url=$1
    [[ "$url" =~ ^https?:// ]] || {
        echo -e "${RED}[-] Formato de URL inválido. Use http:// o https://${NC}"
        return
    }

    echo -e "${YELLOW}[~] Analizando URL: $url${NC}"
    local response=$(curl -s --max-time 30 \
        -H "x-apikey: $API_KEY" \
        -F "url=$url" "https://www.virustotal.com/api/v3/urls")

    local error=$(echo "$response" | jq -r '.error.message // ""')
    if [ -n "$error" ]; then
        echo -e "${RED}[-] Error de API: $error${NC}"
        return
    fi

    local analysis_id=$(echo "$response" | jq -r '.data.id')
    echo -e "${BLUE}[~] ID de análisis: $analysis_id${NC}"
    echo -e "${YELLOW}[~] Esperando resultados... (Puede tardar unos minutos)${NC}"

    while true; do
        local report=$(curl -s --max-time 30 \
            -H "x-apikey: $API_KEY" \
            "https://www.virustotal.com/api/v3/analyses/$analysis_id")

        case $(echo "$report" | jq -r '.data.attributes.status') in
            "completed")
                echo -e "${GREEN}[+] Resultados para ${BLUE}$url${GREEN}:${NC}"
                echo "🔴 Maliciosos: $(echo "$report" | jq -r '.data.attributes.stats.malicious')"
                echo "🟢 Inofensivos: $(echo "$report" | jq -r '.data.attributes.stats.undetected')"
                echo "🔵 Enlace: https://www.virustotal.com/gui/url/$analysis_id"
                break
                ;;
            "queued")
                sleep 10
                ;;
            *)
                echo -e "${RED}[-] Error en el análisis.${NC}"
                return
                ;;
        esac
    done
}

analyze_file() {
    [ -z "$API_KEY" ] && get_virustotal_api || return

    local file=$1
    [ ! -f "$file" ] && {
        echo -e "${RED}[-] Archivo no encontrado.${NC}"
        return
    }

    local filesize=$(stat -c %s "$file")
    [ "$filesize" -gt 33554432 ] && {
        echo -e "${RED}[-] El archivo excede 32MB (límite de VirusTotal).${NC}"
        return
    }

    echo -e "${YELLOW}[~] Codificando archivo (base64)...${NC}"
    local file_data=$(base64 -w 0 "$file") || {
        echo -e "${RED}[-] Error al codificar el archivo.${NC}"
        return
    }

    echo -e "${YELLOW}[~] Subiendo a VirusTotal...${NC}"
    local response=$(curl -s --max-time 60 \
        -H "x-apikey: $API_KEY" \
        -F "file=$file_data" "https://www.virustotal.com/api/v3/files")

    local error=$(echo "$response" | jq -r '.error.message // ""')
    [ -n "$error" ] && {
        echo -e "${RED}[-] Error de API: $error${NC}"
        return
    }

    local analysis_id=$(echo "$response" | jq -r '.data.id')
    echo -e "${GREEN}[+] Análisis iniciado correctamente.${NC}"
    echo -e "${BLUE}[~] ID de análisis: $analysis_id${NC}"
    echo -e "${YELLOW}[+] Puedes verificar los resultados más tarde con:${NC}"
    echo "curl -s -H 'x-apikey: $API_KEY' 'https://www.virustotal.com/api/v3/analyses/$analysis_id' | jq"
}

# ===== FUNCIONES SIN API KEY =====
scan_android() {
    echo -e "${YELLOW}[+] Iniciando escaneo de malware en Android...${NC}"
    
    declare -a suspicious_dirs=(
        "/sdcard/Download"
        "/sdcard/Android/data"
        "$HOME"
        "/data/app"
    )

    echo -e "${BLUE}[~] Buscando archivos potencialmente maliciosos...${NC}"
    find "${suspicious_dirs[@]}" -type f \( -iname "*.apk" -o -iname "*.dex" \) \
        -size -10M -print0 | while IFS= read -r -d $'\0' file; do
        echo -e "${RED}[!] Posible archivo malicioso encontrado:${NC} $file"
        read -p "¿Deseas analizarlo con VirusTotal? (y/N): " choice
        if [[ "$choice" =~ [yY] ]]; then
            analyze_file "$file"
        fi
    done

    echo -e "${GREEN}[+] Escaneo completado.${NC}"
}

clean_system() {
    echo -e "${YELLOW}[+] Limpiando caché y archivos temporales...${NC}"
    rm -rf ~/.cache/* ~/tmp/*
    [ -d ~/.termux/share/cookies ] && rm -rf ~/.termux/share/cookies
    echo -e "${GREEN}[+] Limpieza completada.${NC}"
}

sandbox_mode() {
    echo -e "${YELLOW}[+] Iniciando entorno sandbox Debian...${NC}"
    if ! command -v proot-distro >/dev/null; then
        pkg install proot-distro -y
    fi
    
    if ! proot-distro list | grep -q "debian"; then
        proot-distro install debian
    fi
    
    echo -e "${GREEN}[+] Entorno sandbox listo. Ejecuta comandos en Debian:${NC}"
    proot-distro login debian
}

# ===== MENÚ PRINCIPAL =====
main_menu() {
    clear
    echo -e "${BLUE}
    ███╗   ███╗ █████╗ ██╗  ██╗ █████╗ ██████╗ ███████╗
    ████╗ ████║██╔══██╗██║  ██║██╔══██╗██╔══██╗██╔════╝
    ██╔████╔██║███████║███████║███████║██████╔╝█████╗  
    ██║╚██╔╝██║██╔══██║██╔══██║██╔══██║██╔══██╗██╔══╝  
    ██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██║██║  ██║███████╗
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    ${NC}"
    
    echo -e "${GREEN}[1] Analizar URL/Archivo con VirusTotal"
    echo -e "[2] Escanear dispositivo en busca de malware"
    echo -e "[3] Entorno Sandbox (Debian)"
    echo -e "[4] Limpieza de seguridad"
    echo -e "[5] Salir${NC}"
    
    read -p "Seleccione una opción: " choice
    
    case $choice in
        1)
            echo -e "${GREEN}[1] Analizar URL"
            echo -e "[2] Analizar archivo${NC}"
            read -p "Opción: " vt_choice
            
            case $vt_choice in
                1) 
                    read -p "Ingrese la URL a analizar: " url
                    analyze_url "$url"
                    ;;
                2)
                    read -p "Ingrese la ruta del archivo: " file
                    analyze_file "$file"
                    ;;
                *) 
                    echo -e "${RED}[-] Opción inválida.${NC}"
                    ;;
            esac
            ;;
        2)
            scan_android
            ;;
        3)
            sandbox_mode
            ;;
        4)
            clean_system
            ;;
        5)
            echo -e "${GREEN}[+] Saliendo del programa.${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[-] Opción no válida. Intente nuevamente.${NC}"
            ;;
    esac
    
    read -p "Presione Enter para continuar..."
    main_menu
}

# ===== INICIO DEL PROGRAMA =====
install_deps
main_menu
