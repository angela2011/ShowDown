FROM nginx:1.27-alpine

# Defaults for local Docker Compose.
# Azure overrides these through the container's environment variables.
ENV API_HOST=api
ENV API_PORT=8000

# Generate the full nginx.conf when the container starts.
ENV NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx
ENV NGINX_ENVSUBST_FILTER="^API_(HOST|PORT)$"

COPY nginx.conf /etc/nginx/templates/nginx.conf.template

EXPOSE 80