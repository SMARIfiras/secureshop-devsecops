# syntax=docker/dockerfile:1
FROM node:20-slim

RUN groupadd -r appuser && useradd -r -g appuser --create-home appuser

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY index.js .

USER appuser

EXPOSE 8006

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
  CMD node -e "require('http').get('http://localhost:8006/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "index.js"]
