map $http_upgrade $grafana_connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80;
    listen [::]:80;
    server_name nodemonitor.synergy-network.io;

    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name nodemonitor.synergy-network.io;

    ssl_certificate /etc/letsencrypt/live/nodemonitor.synergy-network.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nodemonitor.synergy-network.io/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    access_log /var/log/nginx/nodemonitor.synergy-network.io.access.log;
    error_log /var/log/nginx/nodemonitor.synergy-network.io.error.log;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $grafana_connection_upgrade;
        proxy_read_timeout 300;
        proxy_send_timeout 300;
    }
}
