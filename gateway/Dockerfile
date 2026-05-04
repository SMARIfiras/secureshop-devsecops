# syntax=docker/dockerfile:1
# Hadolint: use specific version tag, not latest
FROM nginx:1.28-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom config
COPY nginx.conf /etc/nginx/conf.d/secureshop.conf

# Nginx runs as nginx user by default in official image (already non-root)
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
