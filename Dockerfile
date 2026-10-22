# BreakPhish pilot image. Runs the API + console + auth in one process via tsx.
# For a larger deployment you'd precompile TS to JS and run plain node; for the
# pilot, running through tsx keeps the image simple.

FROM node:22-slim

WORKDIR /app

# Install deps first for better layer caching.
COPY package.json ./
RUN npm install --no-audit --no-fund

# App source (web/, src/, db/ …). .dockerignore keeps node_modules/.git out.
COPY . .

# The app reads PORT / PUBLIC_BASE_URL etc. from the environment at runtime.
ENV PORT=4000
EXPOSE 4000

# Basic healthcheck hits the endpoint the load balancer / proxy also uses.
HEALTHCHECK --interval=30s --timeout=4s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Give Node more heap headroom (droplet has ~4 GB) so a mail/notification burst
# doesn't OOM-kill the container. Tune down if the droplet is smaller.
ENV NODE_OPTIONS="--max-old-space-size=2560"
CMD ["npm", "run", "api"]
