FROM nginx:alpine
COPY public/index.html /usr/share/nginx/html/index.html
COPY public/logo.png /usr/share/nginx/html/logo.png
COPY public/nex.png /usr/share/nginx/html/nex.png
EXPOSE 80
