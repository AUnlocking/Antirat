# 🔍 ANTI-RAT Tool for Termux

```bash
# Instalación rápida (copia y pega en Termux)
git clone https://github.com/AUnlocking/Antirat.git && chmod +x antirat.sh && ./antirat.sh
```

## 📌 Características Principales
- ✅ Escaneo de URLs/archivos con VirusTotal
- ✅ Detección de malware en Android
- ✅ Herramientas de limpieza de seguridad
- ✅ Interfaz intuitiva con menú interactivo

## 🔧 Requisitos Automáticos
El script instalará todo lo necesario:
```bash
pkg install -y curl jq openssl termux-api nmap git
```

## 🚀 Uso Básico
1. Obtén API Key gratuita de VirusTotal:
```bash
xdg-open https://www.virustotal.com/gui/my-apikey
```

2. Ejecuta el analizador:
```bash
./antirat.sh
```

## 📋 Opciones del Menú
```text
[1] Analizar URL 📡
[2] Escanear dispositivo 📱 
[3] Limpieza de seguridad 🧹
[4] Tutorial ❓
[5] Salir 🚪
```

## 📊 Estadísticas de Análisis
```bash
# Ver registros de análisis
cat malware_analyzer.log
```

## 🌐 Soporte y Actualizaciones
```bash
# Actualizar script
git clone https://github.com/AUnlocking/Antirat.git
```

📌 **Nota**: La API gratuita de VirusTotal permite 4 análisis por minuto.

✉️ **Contacto**: [@AldazUnlock en GitHub](https://wa.me/message/TOJNCVY7RLSYJ1)

---

💡 **Tip**: Mantén Termux actualizado para mejor rendimiento:
```bash
pkg update && pkg upgrade -y
```
