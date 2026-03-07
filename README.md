# CyberHub-S1

## Group members
- Pannawat Rakrodjit
- Amornrat Ngamsompon
- Khammika Suttichart
- Siriprapa Sombatkham

## Services
| Service | Container | Port |
|---------|-----------|------|
| Strapi (App) | CyberHub-App | 8040 → 1337 |
| PostgreSQL (DB) | CyberHub-Database | 5432 |
| pgAdmin (Admin) | CyberHub-Admin | 8080 |
| Caddy (Reverse Proxy) | CyberHub-Caddy | 80, 443 |

## Setup

### 1. Copy environment file
```sh
cp env.simple .env
```

### 2. Add local domain to hosts file
```sh
echo "127.0.0.1 cyberhub-s1.local" | sudo tee -a /etc/hosts
```

## Running all services
```sh
# Background mode (recommended)
docker compose up -d

# Monitoring mode
docker compose up
```

## Stopping all services
```sh
docker compose down
```

## Accessing services
- **Strapi** → https://cyberhub-s1.local
- **Strapi Admin Panel** → https://cyberhub-s1.local/admin
- **pgAdmin** → http://localhost:8080

## Project structure
```
CyberHub-S1/
├── docker-compose.yaml   # Main compose file
├── db.yaml               # PostgreSQL service
├── app.yaml              # Strapi service
├── admin.yaml            # pgAdmin service
├── caddy.yaml            # Caddy reverse proxy
├── Caddyfile             # Caddy configuration
├── .env                  # Environment variables (ไม่ commit)
└── env.simple            # Environment template
```