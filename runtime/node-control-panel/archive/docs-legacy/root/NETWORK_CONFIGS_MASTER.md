# Synergy Network — Master Network, Ports, and Nginx Configuration

**Version:** FINAL v1.0 (Consolidated)  
**Status:** Authoritative / Implementation‑Binding  
**Scope:** Global + Testnet  
**Excluded:** Testnet, Mainnet‑Beta, Mainnet  

> This document is the single source of truth binding DNS, nginx, service ports,
> SDK configuration, and operational security rules for Synergy Network.

---

## 1. Canonical DNS & Endpoint URLs

### 1.1 Global (Environment‑Agnostic)

| Purpose | URL |
|------|-----|
| Global API Router | https://api.synergy-network.io |
| Global RPC Router | https://rpc.synergy-network.io |
| Global WS Router | wss://ws.synergy-network.io |
| Explorer Hub | https://explorer.synergy-network.io |
| Indexer Hub | https://indexer.synergy-network.io |
| Validator Portal | https://validators.synergy-network.io |
| Status Page | https://status.synergy-network.io |
| Static CDN | https://assets.synergy-network.io |
| Developer Docs | https://docs.synergy-network.io |
| Bootnode 1 | bootnode1.synergy-network.io |

---

### 1.2 Testnet (Authoritative)

| Surface | URL |
|------|-----|
| Core RPC | https://testnet-core-rpc.synergy-network.io |
| Core WS | wss://testnet-core-ws.synergy-network.io |
| EVM RPC | https://testnet-evm-rpc.synergy-network.io |
| EVM WS | wss://testnet-evm-ws.synergy-network.io |
| REST API | https://testnet-api.synergy-network.io |
| Explorer UI | https://testnet-explorer.synergy-network.io |
| Explorer API | https://testnet-atlas-api.synergy-network.io |
| Indexer API | https://testnet-indexer.synergy-network.io |
| Faucet | https://testnet-faucet.synergy-network.io |
| Wallet API | https://testnet-wallet-api.synergy-network.io |
| SXCP API | https://testnet-sxcp-api.synergy-network.io |
| SXCP WS | wss://testnet-sxcp-ws.synergy-network.io |
| SynQ Verify | https://testnet-synq-verify.synergy-network.io |

---

## 2. Canonical Port Allocation

### 2.1 L1 Node (Testnet)

| Purpose | Port |
|-----|----:|
| P2P | 38638 |
| Core RPC | 48638 |
| Core WS | 58638 |
| Metrics | 9090 (localhost only) |

---

### 2.2 EVM RPC (Testnet)

| Purpose | Port |
|-----|----:|
| HTTP | 8545 |
| WS | 8546 |

---

### 2.3 Microservices (Testnet)

| Service | Port |
|------|----:|
| Portal API | 3001 |
| Faucet | 3002 |
| Wallet API | 3003 |
| Indexer Ingest | 3010 |
| Indexer API | 3011 |
| Explorer API | 3020 |
| SynQ Verify | 3030 |
| SXCP API | 3040 |
| SXCP WS | 3041 |
| Aegis Verify | 3050 |
| Aegis KMS | 3051 (PRIVATE, mTLS ONLY) |

---

## 3. Nginx — Testnet Upstream Map

```nginx
upstream testnet_core_rpc       { server 127.0.0.1:48638; }
upstream testnet_core_ws        { server 127.0.0.1:58638; }

upstream testnet_evm_rpc        { server 127.0.0.1:8545; }
upstream testnet_evm_ws         { server 127.0.0.1:8546; }

upstream testnet_api            { server 127.0.0.1:3001; }
upstream testnet_explorer_ui    { server 127.0.0.1:80; }
upstream testnet_explorer_api   { server 127.0.0.1:3020; }
upstream testnet_indexer_api    { server 127.0.0.1:3011; }
upstream testnet_wallet_api     { server 127.0.0.1:3003; }
upstream testnet_faucet         { server 127.0.0.1:3002; }

upstream testnet_sxcp_api       { server 127.0.0.1:3040; }
upstream testnet_sxcp_ws        { server 127.0.0.1:3041; }

upstream testnet_synq_verify    { server 127.0.0.1:3030; }
```

---

## 4. Nginx — Shared Proxy & WebSocket Headers

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_http_version 1.1;
```

---

## 5. Nginx — Testnet VHost Map (Exact DNS Match)

### 5.1 Core RPC / WS

```nginx
server {
    listen 443 ssl http2;
    server_name testnet-core-rpc.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_core_rpc; }
}

server {
    listen 443 ssl http2;
    server_name testnet-core-ws.synergy-network.io;
    include snippets/ssl.conf;
    location / {
        proxy_pass http://testnet_core_ws;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

### 5.2 EVM RPC / WS

```nginx
server {
    listen 443 ssl http2;
    server_name testnet-evm-rpc.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_evm_rpc; }
}

server {
    listen 443 ssl http2;
    server_name testnet-evm-ws.synergy-network.io;
    include snippets/ssl.conf;
    location / {
        proxy_pass http://testnet_evm_ws;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

### 5.3 APIs, Explorer, Indexer

```nginx
server {
    listen 443 ssl http2;
    server_name testnet-api.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_api; }
}

server {
    listen 443 ssl http2;
    server_name testnet-explorer.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_explorer_ui; }
}

server {
    listen 443 ssl http2;
    server_name testnet-atlas-api.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_explorer_api; }
}

server {
    listen 443 ssl http2;
    server_name testnet-indexer.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_indexer_api; }
}
```

### 5.4 Wallet, Faucet, SXCP, SynQ

```nginx
server {
    listen 443 ssl http2;
    server_name testnet-wallet-api.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_wallet_api; }
}

server {
    listen 443 ssl http2;
    server_name testnet-faucet.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_faucet; }
}

server {
    listen 443 ssl http2;
    server_name testnet-sxcp-api.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_sxcp_api; }
}

server {
    listen 443 ssl http2;
    server_name testnet-sxcp-ws.synergy-network.io;
    include snippets/ssl.conf;
    location / {
        proxy_pass http://testnet_sxcp_ws;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}

server {
    listen 443 ssl http2;
    server_name testnet-synq-verify.synergy-network.io;
    include snippets/ssl.conf;
    location / { proxy_pass http://testnet_synq_verify; }
}
```

---

## 6. Global Router VHosts (Path‑Based Routing)

### 6.1 Global RPC Router

```nginx
server {
    listen 443 ssl http2;
    server_name rpc.synergy-network.io;
    include snippets/ssl.conf;

    location /testnet/ {
        proxy_pass http://testnet_core_rpc/;
    }

    location /healthz { return 200 "ok\n"; }
    location /readyz  { return 200 "ready\n"; }
    location /version { return 200 "rpc-router-v1\n"; }
}
```

### 6.2 Global API Router

```nginx
server {
    listen 443 ssl http2;
    server_name api.synergy-network.io;
    include snippets/ssl.conf;

    location /testnet/ {
        proxy_pass http://testnet_api/;
    }

    location /healthz { return 200 "ok\n"; }
    location /readyz  { return 200 "ready\n"; }
    location /version { return 200 "api-router-v1\n"; }
}
```

### 6.3 Global WebSocket Router

```nginx
server {
    listen 443 ssl http2;
    server_name ws.synergy-network.io;
    include snippets/ssl.conf;

    location /testnet/ {
        proxy_pass http://testnet_core_ws/;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

---

## 7. Security & Hard Rules

- All public services: **443 only**
- P2P ports: **DNS‑only, never proxied**
- Aegis KMS: **NEVER public**
- Metrics: **localhost only**
- Mainnet writes: **explicit routing required**
- If it’s not in this document, **it is not official**

---

## 8. Change Control

- This file is the **binding contract** between DNS, nginx, and services
- All future environments MUST extend this document
- No silent overrides permitted

