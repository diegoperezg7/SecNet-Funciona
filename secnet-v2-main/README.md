# SecNet - Sistema Automatizado de Respuesta y Análisis Forense para Incidentes de Seguridad en Red

## Descripción
SecNet es un sistema integral de seguridad de red que proporciona detección, análisis y respuesta automatizada a incidentes de seguridad. El sistema está diseñado para funcionar en entornos Kali Linux y ofrece una interfaz web para la gestión y visualización de alertas en tiempo real.

## Características Principales
- Detección de alertas en tiempo real en la interfaz eth0
- Clasificación de alertas en tres niveles de severidad (1: baja, 2: media, 3: alta)
- Interfaz web para visualización y gestión de alertas
- Sistema de respuesta automatizada con bloqueo de IPs maliciosas
- Análisis forense de incidentes
- Integración con Suricata para detección de amenazas
- Base de datos SQLite para almacenamiento de alertas

## Requisitos del Sistema
- Kali Linux
- Python 3.8+
- PHP 7.4+
- Suricata
- SQLite3
- iptables
- Docker (opcional)

## Estructura del Proyecto
```
SecNet/
├── web-interface/          # Interfaz web
├── python-responder/       # Sistema de respuesta automatizada
├── suricata/              # Configuración de Suricata
├── database/              # Base de datos SQLite
└── logs/                  # Archivos de registro
```

## Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/tu-usuario/SecNet.git
cd SecNet
```

2. Instalar dependencias:
```bash
# Dependencias de Python
pip install -r requirements.txt

# Dependencias de PHP
composer install
```

3. Configurar Suricata:
```bash
sudo cp suricata/rules/local.rules /etc/suricata/rules/
sudo systemctl restart suricata
```

4. Iniciar el sistema:
```bash
# Iniciar el responder de Python
python3 python-responder/responder.py

# Iniciar la interfaz web
php -S localhost:8000 -t web-interface
```

## Uso

1. Acceder a la interfaz web:
```
http://localhost:8000
```

2. Las alertas se mostrarán automáticamente en tiempo real en el dashboard.

3. Para bloquear una IP manualmente:
   - Navegar a la sección "IPs Bloqueadas"
   - Hacer clic en "Bloquear IP"
   - Ingresar la IP y el motivo

## Configuración

### Severidad de Alertas
Las alertas se clasifican en tres niveles:
- Severidad 1 (Baja): Tráfico normal o interno
- Severidad 2 (Media): Actividad sospechosa
- Severidad 3 (Alta): Amenazas confirmadas

### Reglas de Suricata
Las reglas personalizadas se encuentran en `suricata/rules/local.rules`. Se pueden modificar según las necesidades específicas.

## Contribución
1. Fork el repositorio
2. Crear una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abrir un Pull Request

## Licencia
Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## Contacto
Tu Nombre - [@tu_twitter](https://twitter.com/tu_twitter) - email@ejemplo.com

Link del proyecto: [https://github.com/tu-usuario/SecNet](https://github.com/tu-usuario/SecNet)
