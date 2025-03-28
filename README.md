# Termux Security (TS) 🔐

![TEAM HACKING]()

Suite de seguridad todo-en-uno para Termux con análisis de malware, auditoría WiFi y protección de privacidad.

## 🌟 Características Principales

### 🦠 Análisis de Malware
- Escaneo de URLs/archivos con **VirusTotal API**
- Detección de motores maliciosos
- Informes detallados en JSON
- Ejemplo de análisis:
  
  ![Escaneo VirusTotal](https://i.postimg.cc/T38CNggD/Screenshot-20250327-194240.png)

### 📶 Herramientas WiFi
- Escaneo de redes con `iwlist`
- Extracción de handshake WPA/WPA2
- Modo monitor con `aircrack-ng`
- Deauthentication attacks

### 🕵️ Kit de Privacidad
- Gestión de cookies/sesiones
- Sandbox con Debian (proot-distro)
- Verificación de conexiones activas

## 🚀 Instalación

```bash
# 1. Actualizar paquetes
pkg update && pkg upgrade -y

# 2. Instalar dependencias
pkg install -y git curl jq openssl proot-distro tmux wireless-tools

# 3. Clonar repositorio
git clone https://github.com/AUnlocking/Antirat.git
cd Antirat

# 4. Permisos de ejecución
chmod +x NetHack.sh

# 5. Ejecutar
./NetHack.sh
