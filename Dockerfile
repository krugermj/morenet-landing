FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
COPY logo.png /usr/share/nginx/html/logo.png
COPY nex.png /usr/share/nginx/html/nex.png
EXPOSE 80
