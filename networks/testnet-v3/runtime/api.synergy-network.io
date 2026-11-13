# Global API Router - Compliant with Synergy_Network_Master_Config_FULL.md
# Section 6.2: Global API Router with path-based routing
# Note: upstream testnet_api is defined in synergy-network.io-subdomains.conf

server {
    listen 80;
    listen [::]:80;
    server_name api.synergy-network.io;

    root /var/www/letsencrypt;

    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        try_files $uri =404;
    }

    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.synergy-network.io;

    ssl_certificate /etc/letsencrypt/live/synergy-network.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/synergy-network.io/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    location /testnet/ {
        proxy_pass http://testnet_api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /healthz { return 200 "ok\n"; }
    location /readyz  { return 200 "ready\n"; }
    location /version { return 200 "api-router-v1\n"; }
}
