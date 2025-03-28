# Termux Security Toolkit (TST) 🔐

![Banner](https://via.placeholder.com/800x200?text=Termux+Security+Toolkit+-+NetHack.sh+by+AldazUnlock)

Herramienta todo-en-uno para análisis de seguridad en Termux con capacidades de análisis de malware, auditoría WiFi y protección de privacidad.

## 🌟 Características

### 🦠 Análisis de Malware
- Escaneo de URLs/archivos con **VirusTotal API**
- Detección de motores maliciosos
- Informes detallados en formato JSON

### 📶 Herramientas WiFi
- Escaneo de redes cercanas
- Extracción de **Handshake WPA/WPA2**
- Modo monitor e inyección de paquetes
- Generación de redes ficticias

### 🕵️ Kit de Privacidad
- Gestión avanzada de **cookies/sesiones**
- Entorno **sandbox** con Debian (proot-distro)
- Verificación de conexiones activas

## 🚀 Instalación en Termux

```bash
# 1. Actualizar paquetes
pkg update && pkg upgrade -y

# 2. Instalar dependencias
pkg install -y git bash curl jq openssl proot-distro tmux

# 3. Clonar repositorio
git clone https://github.com/AUnlocking/Antirat.git
cd Antirat

# 4. Dar permisos de ejecución
chmod +x NetHack.sh
 #5. Ejecutar

./NetHack.sh
