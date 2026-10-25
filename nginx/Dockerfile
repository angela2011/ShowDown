FROM node:22-alpine AS frontend-build

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/index.html ./
COPY frontend/vite.config.js frontend/proxy.config.js ./
COPY frontend/src ./src

# Copy optional public assets without copying local .env or node_modules.
COPY frontend/public* ./public/

RUN npm run build


FROM nginx:1.27-alpine

# Defaults for local Docker Compose.
# Terraform overrides these in Azure.
ENV API_HOST=api
ENV API_PORT=8000

ENV NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx
ENV NGINX_ENVSUBST_FILTER="^API_(HOST|PORT)$"

COPY nginx/nginx.conf /etc/nginx/templates/nginx.conf.template
COPY --from=frontend-build /frontend/dist /usr/share/nginx/html

EXPOSE 80