# ---------------------------------------------------------------------
# suricata/Dockerfile
# Imagen basada en Ubuntu 20.04 con la última versión estable de Suricata
# ---------------------------------------------------------------------
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependencias y Suricata desde el PPA oficial
RUN apt-get update && \
    apt-get install -y software-properties-common ca-certificates && \
    add-apt-repository ppa:oisf/suricata-stable && \
    apt-get update && \
    apt-get install -y suricata && \
    rm -rf /var/lib/apt/lists/*

# Crear directorios para reglas y logs
RUN mkdir -p /etc/suricata/rules /var/log/suricata

# Copiar configuración y reglas locales
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY rules/local.rules /etc/suricata/rules/local.rules

# Ajustar permisos
RUN chmod 644 /etc/suricata/suricata.yaml && \
    chmod 644 /etc/suricata/rules/local.rules

# Punto de entrada para arrancar Suricata en modo IDS
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]
