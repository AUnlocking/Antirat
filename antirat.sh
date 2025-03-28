
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


# Función para instalar dependencias
install_deps() {
    echo "Verificando dependencias..."
    missing=0
    for pkg in curl jq base64 openssl; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo "Instalando $pkg..."
            pkg install -y $pkg || { echo "Fallo al instalar $pkg. Saliendo."; exit 1; }
            missing=1
        fi
    done
    if [ $missing -eq 1 ]; then
        echo "Dependencias instaladas exitosamente."
    else
        echo "Todas las dependencias ya están instaladas."
    fi
}

# Función para analizar una URL
analyze_url() {
    local url=$1
    if [[ ! $url =~ ^https?://.* ]]; then
        echo "Formato de URL inválido."
        return
    fi
    local response=$(curl -s "https://www.virustotal.com/api/v3/urls" \
        -H "x-apikey:$API_KEY" \
        -F "url=$url")
    local status=$(echo $response | jq -r '.error.message // ""')
    if [ "$status" != "" ]; then
        echo "Error: $status"
        return
    fi
    local analysis_id=$(echo $response | jq -r '.data.id')
    echo "Esperando análisis..."
    while true; do
        local report=$(curl -s "https://www.virustotal.com/api/v3/analyses/$analysis_id" \
            -H "x-apikey:$API_KEY")
        local status=$(echo $report | jq -r '.data.attributes.status')
        if [ "$status" == "completed" ]; then
            break
        fi
        sleep 5
    done
    echo "Análisis para URL: $url"
    echo "Malicioso: $(echo $report | jq -r '.data.attributes.stats.malicious')"
    echo "No detectado: $(echo $report | jq -r '.data.attributes.stats.undetected')"
}

# Función para analizar un archivo
analyze_file() {
    local file=$1
    if [ ! -f "$file" ]; then
        echo "Archivo no encontrado."
        return
    fi
    local file_data=$(base64 $file)
    local response=$(curl -s "https://www.virustotal.com/api/v3/files" \
        -H "x-apikey:$API_KEY" \
        -F "file=$file_data")
    local status=$(echo $response | jq -r '.error.message // ""')
    if [ "$status" != "" ]; then
        echo "Error: $status"
        return
    fi
    local analysis_id=$(echo $response | jq -r '.data.id')
    echo "Esperando análisis..."
    while true; do
        local report=$(curl -s "https://www.virustotal.com/api/v3/analyses/$analysis_id" \
            -H "x-apikey:$API_KEY")
        local status=$(echo $report | jq -r '.data.attributes.status')
        if [ "$status" == "completed" ]; then
            break
        fi
        sleep 5
    done
    echo "Análisis para archivo: $file"
    echo "Malicioso: $(echo $report | jq -r '.data.attributes.stats.malicious')"
    echo "No detectado: $(echo $report | jq -r '.data.attributes.stats.undetected')"
}

# Función para manejar la seguridad de sesiones y cookies
handle_session_security() {
    show_banner
    echo "Opciones de seguridad de sesiones y cookies:"
    echo "1. Borrar cookies"
    echo "2. Usar modo incógnito"
    echo "3. Volver al menú principal"
    read -p "Seleccione una opción: " choice
    case $choice in
        1)
            if [ -d ~/.termux/share/cookies ]; then
                rm -rf ~/.termux/share/cookies
                echo "Cookies borradas."
            else
                echo "Directorio de cookies no encontrado."
            fi
            sleep 2
            ;;
        2)
            echo "Abriendo navegador en modo incógnito..."
            termux-open-url --incognito "https://www.google.com"
            sleep 2
            ;;
        3)
            return
            ;;
        *)
            echo "Opción inválida."
            sleep 1
            ;;
    esac
    handle_session_security
}

# Función para crear un entorno sandbox
create_sandbox() {
    if ! command -v proot-distro >/dev/null 2>&1; then
        echo "proot-distro no encontrado. Instalando..."
        pkg install -y proot-distro
    fi
    if proot-distro list | grep -q "debian"; then
        echo "Entorno Debian ya existe."
    else
        echo "Creando entorno Debian..."
        proot-distro install debian
    fi
    echo "Ingresando al entorno Debian..."
    proot-distro login debian
}

# Función para solicitar API Key de VirusTotal
get_virustotal_api() {
    read -p "Ingresa tu clave API de VirusTotal: " API_KEY
    echo
}

# Script principal
install_deps

while true; do
    show_banner
    read -p "Selecciona una opción [1-3]: " choice

    case $choice in
        1)
            get_virustotal_api
            echo "1. Analizar URL"
            echo "2. Analizar archivo"
            echo "3. Volver al menú principal"
            read -p "Seleccione una opción: " vt_choice
            case $vt_choice in
                1)
                    read -p "Ingresa la URL a analizar: " url
                    analyze_url "$url"
                    ;;
                2)
                    read -p "Ingresa la ruta del archivo a analizar: " file
                    analyze_file "$file"
                    ;;
                3)
                    continue
                    ;;
                *)
                    echo "Opción inválida."
                    ;;
            esac
            read -p "Presiona Enter para continuar..."
            ;;
        2)
            echo "1. Manejar seguridad de sesiones y cookies"
            echo "2. Crear entorno sandbox"
            echo "3. Volver al menú principal"
            read -p "Seleccione una opción: " toolkit_choice
            case $toolkit_choice in
                1)
                    handle_session_security
                    ;;
                2)
                    create_sandbox
                    read -p "Presiona Enter para continuar..."
                    ;;
                3)
                    continue
                    ;;
                *)
                    echo "Opción inválida."
                    sleep 1
                    ;;
            esac
            ;;
        3)
            echo "Saliendo..."
            break
            ;;
        *)
            echo "Opción inválida. Por favor, selecciona nuevamente."
            sleep 1
            ;;
    esac
done
