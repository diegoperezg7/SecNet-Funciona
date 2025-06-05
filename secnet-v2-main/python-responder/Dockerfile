FROM python:3.9-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el archivo de requerimientos para instalar dependencias
COPY requirements.txt .

# Instala dependencias necesarias para compilar python-iptables y otras librerías
RUN apt-get update && apt-get install -y \
    gcc \
    iptables \
    libc-dev \
    python3-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*  # Limpia la cache de apt para reducir el tamaño de la imagen

# Instala las dependencias de Python especificadas en el archivo requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Crea el directorio de la base de datos con los permisos adecuados
RUN mkdir -p /app/database && \
    chmod -R 777 /app/database && \
    touch /app/database/alerts.db && \
    chmod 666 /app/database/alerts.db

# Asegura que el usuario no root pueda escribir en el directorio
RUN chown -R 1000:1000 /app/database
RUN useradd -m appuser && \
    chown -R appuser:appuser /app

# Cambia al usuario no root
USER appuser

# Copia el archivo python-responder
COPY responder.py .

# Define el comando predeterminado para ejecutar el script responder.py
CMD ["python", "responder.py"]
