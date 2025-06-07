# Usar una imagen base más completa para tener acceso a herramientas de red
FROM python:3.9-slim

# Variables de entorno para configuración
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    TZ=Etc/UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia el archivo de requerimientos para instalar dependencias
COPY requirements.txt .

# Instala dependencias necesarias para compilar python-iptables, nftables y otras librerías
RUN set -ex \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-utils \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        software-properties-common \
        wget \
    # Dependencias del sistema
    && apt-get install -y --no-install-recommends \
        gcc \
        iptables \
        iptables-persistent \
        nftables \
        netfilter-persistent \
        libc-dev \
        python3-dev \
        libffi-dev \
        kmod \
        procps \
        iproute2 \
        ipset \
        iputils-ping \
        net-tools \
        vim-tiny \
        less \
        jq \
        file \
        sqlite3 \
        libmnl-dev \
        libnftnl-dev \
        libxtables-dev \
        libnetfilter-queue-dev \
        libnetfilter-conntrack-dev \
        python3-nftables \
    # Intentar instalar módulos del kernel, pero continuar si falla
    && { \
        KERNEL_HEADERS=linux-headers-$(uname -r | sed 's/-[a-z]*$//') && \
        KERNEL_MODULES=linux-modules-extra-$(uname -r | sed 's/-[a-z]*$//') && \
        if apt-cache show "$KERNEL_HEADERS" >/dev/null 2>&1; then \
            apt-get install -y --no-install-recommends "$KERNEL_HEADERS" "$KERNEL_MODULES" || echo "Warning: Could not install kernel headers, continuing anyway"; \
        else \
            echo "Warning: Kernel headers not available for $(uname -r), continuing without them"; \
        fi; \
    } \
    # Limpieza
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/*

# Configura iptables-persistent para guardar reglas automáticamente
RUN echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' | debconf-set-selections \
    && echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' | debconf-set-selections

# Crea directorios necesarios para módulos de kernel y configuración
RUN set -ex \
    && mkdir -p /lib/modules/$(uname -r) \
    && touch /lib/modules/$(uname -r)/modules.builtin \
    && touch /lib/modules/$(uname -r)/modules.order \
    && depmod -a || true \
    # Crear directorios necesarios para ipset y iptables
    && mkdir -p /run/xtables.lock /run/ipset \
    && chmod 1777 /run/xtables.lock /run/ipset \
    # Asegurar que los directorios de configuración existen
    && mkdir -p /etc/iptables /etc/ipset \
    && chmod 755 /etc/iptables /etc/ipset

# Configura el sistema de logs
RUN set -ex \
    && mkdir -p /var/log/responder \
    && touch /var/log/responder/responder.log \
    && chmod 666 /var/log/responder/responder.log

# Crea directorio para iptables (la inicialización se hará en el entrypoint)
RUN mkdir -p /etc/iptables && chmod 755 /etc/iptables

# Crear directorio para ipset si no existe
RUN mkdir -p /etc/ipset

# Puerto para la API
EXPOSE 5000

# Configurar ipset al iniciar
RUN echo 'create -exist blocklist hash:ip family inet hashsize 1024 maxelem 65536' > /etc/ipset.conf
RUN echo 'create -exist blocklist6 hash:ip family inet6 hashsize 1024 maxelem 65536' >> /etc/ipset.conf

# Configurar iptables al iniciar
RUN echo '#!/bin/sh' > /usr/local/bin/init-iptables
RUN echo 'ipset restore -f /etc/ipset.conf' >> /usr/local/bin/init-iptables
RUN echo 'iptables -I INPUT -m set --match-set blocklist src -j DROP' >> /usr/local/bin/init-iptables
RUN echo 'iptables -I FORWARD -m set --match-set blocklist src -j DROP' >> /usr/local/bin/init-iptables
RUN echo 'iptables -I FORWARD -m set --match-set blocklist dst -j DROP' >> /usr/local/bin/init-iptables
RUN echo 'iptables -I DOCKER-USER -m set --match-set blocklist src -j DROP' >> /usr/local/bin/init-iptables
RUN echo 'iptables -I DOCKER-USER -m set --match-set blocklist dst -j DROP' >> /usr/local/bin/init-iptables
RUN chmod +x /usr/local/bin/init-iptables

# Ejecutar init-iptables al arrancar
RUN echo '/usr/local/bin/init-iptables' >> /root/.bashrc

# Configura directorios de la aplicación
RUN set -ex \
    # Directorio de la base de datos
    && mkdir -p /app/database \
    && touch /app/database/responder.db \
    # Directorio de configuración
    && mkdir -p /app/config \
    # Directorio de logs
    && mkdir -p /app/logs \
    # Permisos
    && chmod -R 777 /app/database /app/logs /app/config \
    # Crea usuario no privilegiado
    && groupadd -r appuser -g 1000 \
    && useradd -u 1000 -r -g appuser -s /sbin/nologin -c "App User" appuser \
    && chown -R appuser:appuser /app

# La configuración de iptables se manejará en el script de inicio
# para evitar problemas de permisos durante el build

# Instalar las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia los archivos de la aplicación
COPY --chmod=755 startup.sh .
COPY responder.py .

# Hacer ejecutables los scripts
RUN chmod +x /app/startup.sh

# Asegura que los archivos sean propiedad del usuario de la aplicación
RUN chown -R appuser:appuser /app /etc/iptables /etc/ipset /run/xtables.lock /run/ipset \
    # Asegurar que los directorios temporales tengan los permisos correctos
    && chmod 1777 /tmp /var/tmp

# Cambia al usuario no root
USER appuser

# Expone el puerto si es necesario (ajusta según tus necesidades)
# EXPOSE 8000

# Configura el comando de inicio
ENTRYPOINT ["/app/startup.sh"]

# Define el comando predeterminado (se sobrescribe por el ENTRYPOINT)
CMD ["python", "responder.py"]
