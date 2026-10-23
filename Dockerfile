# [ZAFİYET-16] A05/A06: eski temel imaj, root kullanıcı, HEALTHCHECK yok.
# Trivy'nin yapılandırma taraması bunları yakalamalı.
FROM python:3.10-slim

WORKDIR /uygulama
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .

ENV PORT=5000
EXPOSE 5000
CMD ["python", "app.py"]
