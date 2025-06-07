FROM python:3.9-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el archivo de requerimientos para instalar dependencias
COPY requirements.txt .

# Instala dependencias necesarias para compilar python-iptables y otras librerías
RUN apt-get update && apt-get install -y \
    gcc \
    iptables \
    iptables-persistent \
    netfilter-persistent \
    libc-dev \
    python3-dev \
    libffi-dev \
    kmod \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*  # Limpia la cache de apt para reducir el tamaño de la imagen

# Configura iptables-persistent para guardar reglas automáticamente
RUN echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' | debconf-set-selections && \
    echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' | debconf-set-selections

# Crea directorios necesarios para módulos de kernel
RUN mkdir -p /lib/modules/$(uname -r) && \
    touch /lib/modules/$(uname -r)/modules.builtin && \
    touch /lib/modules/$(uname -r)/modules.order

# Instala las dependencias de Python especificadas en el archivo requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Crea el directorio de la base de datos con los permisos adecuados
RUN mkdir -p /app/database && \
    chmod -R 777 /app/database && \
    touch /app/database/alerts.db && \
    chmod 666 /app/database/alerts.db

# Crea directorio para reglas de iptables
RUN mkdir -p /etc/iptables && \
    chmod 755 /etc/iptables && \
    touch /etc/iptables/rules.v4 && \
    chmod 644 /etc/iptables/rules.v4

# Copia los archivos necesarios
COPY --chmod=755 startup.sh .
COPY responder.py .

# Asegura que el usuario no root pueda escribir en el directorio
RUN chown -R 1000:1000 /app/database /etc/iptables && \
    useradd -m appuser && \
    chown -R appuser:appuser /app

# Cambia al usuario no root
USER root

# Configura el comando de inicio para ejecutar el script startup.sh
ENTRYPOINT ["/app/startup.sh"]

# Define el comando predeterminado (se sobrescribe por el ENTRYPOINT)
CMD ["python", "responder.py"]
