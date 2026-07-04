FROM node:24-slim
WORKDIR /app

# --legacy-peer-deps: openapi-typescript@7 peer-depends on TS ^5.x; this repo
# is on TS 6 (dev-only codegen tool, not part of the runtime bundle — safe).
COPY package.json package-lock.json ./
RUN npm ci --legacy-peer-deps

COPY . .

EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
