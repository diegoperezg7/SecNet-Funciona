# 🛡️ SecNet-TFG

## 📝 Descripción

**SecNet-Funciona** es un sistema integral de seguridad de red que proporciona detección, análisis y respuesta automatizada a incidentes de seguridad. Está diseñado para funcionar en entornos Kali Linux y ofrece una interfaz web para la gestión y visualización de alertas en tiempo real. Su objetivo es facilitar la respuesta ante amenazas, el análisis forense y el bloqueo automático/manual de IPs maliciosas, integrando herramientas como Suricata y SQLite para una gestión eficiente de incidentes.

## 🚀 Características Principales

- ⚡ **Detección de alertas en tiempo real** en la interfaz de red (por defecto, eth0)
- 🏷️ **Clasificación de alertas** en tres niveles de severidad (1: baja, 2: media, 3: alta)
- 🌐 **Interfaz web** para visualización y gestión centralizada de alertas
- 🔒 **Bloqueo automatizado y manual de IPs maliciosas**
- 🧑‍💻 **Análisis forense** de incidentes registrados
- 🛠️ **Integración con Suricata** para la detección avanzada de amenazas
- 💾 **Base de datos SQLite** para almacenamiento eficiente de eventos y alertas
- 📊 **Gráficas y estadísticas** en dashboard para el monitoreo (requiere Chart.js)
- 📬 **Resumen diario** de incidentes y principales atacantes

## 🖥️ Requisitos del Sistema

- 🐧 Kali Linux
- 🐍 Python 3.8+
- 🐘 PHP 7.4+
- 🛰️ Suricata
- 🗃️ SQLite3
- 🔥 iptables
- 🐳 Docker (opcional)

## 🗂️ Estructura del Proyecto

```
SecNet/
├── web-interface/          # Interfaz web
├── python-responder/       # Sistema de respuesta automatizada
├── suricata/               # Configuración de Suricata
├── database/               # Base de datos SQLite
└── logs/                   # Archivos de registro
```

## ⚙️ Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/diegoperezg7/SecNet-Funciona.git
   cd SecNet-Funciona/secnet-v2-main
   ```

2. **Instalar dependencias:**
   ```bash
   # Dependencias de Python
   pip install -r requirements.txt

   # Dependencias de PHP
   composer install
   ```

3. **Configurar Suricata:**
   ```bash
   sudo cp suricata/rules/local.rules /etc/suricata/rules/
   sudo systemctl restart suricata
   ```

4. **Iniciar el sistema:**
   ```bash
   # Iniciar el responder de Python
   python3 python-responder/responder.py

   # Iniciar la interfaz web
   php -S localhost:8000 -t web-interface
   ```

## 🕹️ Uso

1. Accede a la interfaz web desde tu navegador:
    ```
    http://localhost:8000
    ```
2. 🖥️ Las alertas se mostrarán automáticamente en tiempo real en el dashboard.
3. 🚫 Para bloquear una IP manualmente:
   - Navega a la sección "IPs Bloqueadas".
   - Haz clic en "Bloquear IP".
   - Ingresa la IP y el motivo.

## ⚒️ Configuración

### 📶 Severidad de Alertas

Las alertas se clasifican en tres niveles:
- 🟢 **Severidad 1 (Baja):** Tráfico normal o interno.
- 🟡 **Severidad 2 (Media):** Actividad sospechosa.
- 🔴 **Severidad 3 (Alta):** Amenazas confirmadas.

### 📜 Reglas de Suricata

Las reglas personalizadas se encuentran en `suricata/rules/local.rules`. Puedes modificarlas según las necesidades de tu organización.

## 🤝 Contribución

1. Haz fork del repositorio.
2. Crea una rama para tu feature (`git checkout -b feature/TuFeature`).
3. Realiza commit de tus cambios (`git commit -m 'Agrega mi feature'`).
4. Haz push a la rama (`git push origin feature/TuFeature`).
5. Abre un Pull Request.

## 📝 Licencia

Este proyecto está bajo la Licencia MIT - consulta el archivo [LICENSE](secnet-v2-main/LICENSE) para más detalles.

## 📫 Contacto

Diego Pérez García - [@diegoperezg7](https://github.com/diegoperezg7)

Repositorio: [https://github.com/diegoperezg7/SecNet-Funciona](https://github.com/diegoperezg7/SecNet-Funciona)
