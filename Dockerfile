FROM node:20-alpine
RUN apk add --no-cache python3 py3-requests
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
ENV PORT=80
EXPOSE 80
CMD ["node", "server.js"]
