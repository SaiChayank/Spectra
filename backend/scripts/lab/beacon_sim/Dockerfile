# Lab-only image for the set-B beacon simulator. Packages are installed at build time; the run has no internet.
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump openssl \
 && rm -rf /var/lib/apt/lists/* \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=lab.example" -keyout /app-key.pem -out /app-cert.pem 2>/dev/null \
 && mkdir /app && mv /app-key.pem /app/key.pem && mv /app-cert.pem /app/cert.pem && chmod 644 /app/*.pem
COPY server.py client.py simsched.py /app/
