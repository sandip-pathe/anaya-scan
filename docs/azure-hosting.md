# Azure Hosting Guide — AnaYa

Deploy AnaYa on an **Azure B2s VM** (~$15/month) using Docker Compose + Caddy for automatic HTTPS.  
Total estimated cost: **$15–18/month** well within Azure $100 student credits.

---

## Prerequisites

| Item | Details |
|------|---------|
| Azure account | [Azure for Students](https://azure.microsoft.com/en-in/free/students/) — $100 free credits, no credit card |
| Domain name (optional) | E.g. `anaya.yourdomain.com`. If you don't have one, use the VM's IP with [nip.io](https://nip.io) (e.g. `20.1.2.3.nip.io`) |
| GitHub App | Already created (App ID, private key, webhook secret) |
| OpenAI API key | For LLM scanner (optional) |

---

## Step 1 — Create the Azure VM

### Via Azure Portal

1. Go to [portal.azure.com](https://portal.azure.com) → **Create a resource → Virtual Machine**
2. Fill in:

| Setting | Value |
|---------|-------|
| Subscription | Azure for Students |
| Resource group | `anaya-rg` (create new) |
| VM name | `anaya-vm` |
| Region | **Central India** (closest to target users) |
| Image | **Ubuntu Server 24.04 LTS — x64 Gen2** |
| Size | **Standard_B2s** (2 vCPU, 4 GB RAM — ~$15/mo) |
| Authentication | SSH public key |
| Username | `azureuser` |
| SSH key | Generate new or use existing |
| Inbound ports | Allow **SSH (22), HTTP (80), HTTPS (443)** |

3. Under **Disks** → OS disk type: **Standard SSD** (default is fine)
4. Under **Networking** → Create a new public IP (static)
5. Click **Review + Create → Create**
6. Download the SSH key `.pem` file

### Via Azure CLI (faster)

```bash
# Login
az login

# Create resource group
az group create --name anaya-rg --location centralindia

# Create VM
az vm create \
  --resource-group anaya-rg \
  --name anaya-vm \
  --image Ubuntu2404 \
  --size Standard_B2s \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-sku Standard \
  --os-disk-size-gb 30

# Open ports
az vm open-port --resource-group anaya-rg --name anaya-vm --port 80 --priority 1001
az vm open-port --resource-group anaya-rg --name anaya-vm --port 443 --priority 1002
```

### Get your VM's public IP

```bash
az vm show -d --resource-group anaya-rg --name anaya-vm --query publicIps -o tsv
```

---

## Step 2 — SSH into the VM

```bash
# From your local machine (use the IP from Step 1)
ssh azureuser@<YOUR_VM_IP>

# If using downloaded .pem key:
ssh -i ~/Downloads/anaya-vm_key.pem azureuser@<YOUR_VM_IP>
```

---

## Step 3 — Install Docker & Docker Compose

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sudo sh

# Add your user to docker group (no sudo needed)
sudo usermod -aG docker $USER

# Install Docker Compose plugin
sudo apt install -y docker-compose-plugin

# Apply group change (or log out and back in)
newgrp docker

# Verify
docker --version
docker compose version
```

---

## Step 4 — Clone the Repo

```bash
# Clone your repo
git clone https://github.com/<YOUR_USERNAME>/anaya.git
cd anaya
```

If the repo is private, use a [Personal Access Token](https://github.com/settings/tokens):

```bash
git clone https://<PAT>@github.com/<YOUR_USERNAME>/anaya.git
```

---

## Step 5 — Configure Environment

Create the `.env` file:

```bash
cat > .env << 'EOF'
# ── GitHub App ──────────────────────────────────────
GITHUB_APP_ID=2721322
GITHUB_WEBHOOK_SECRET=your-webhook-secret-here

# ── Database ────────────────────────────────────────
DATABASE_URL=postgresql+asyncpg://anaya:anaya@postgres:5432/anaya

# ── Redis ───────────────────────────────────────────
REDIS_URL=redis://redis:6379/0

# ── Application ────────────────────────────────────
APP_ENV=production
APP_PORT=8000
APP_SECRET_KEY=generate-a-random-string-here

# ── LLM Scanner (optional) ─────────────────────────
# OPENAI_API_KEY=sk-...your-key...
# OPENAI_MODEL=gpt-4o-mini

# ── Private Key ────────────────────────────────────
# Option A: Mount the file (default — place private-key.pem in repo root)
# Option B: Paste the full PEM content here (no file needed):
# GITHUB_PRIVATE_KEY_CONTENT=-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----
EOF
```

Copy your GitHub App private key:

```bash
# Option A: Copy from local machine
scp private-key.pem azureuser@<YOUR_VM_IP>:~/anaya/private-key.pem

# Option B: Paste PEM content directly into .env as GITHUB_PRIVATE_KEY_CONTENT
```

Generate a random secret key:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
# Paste the output as APP_SECRET_KEY in .env
```

---

## Step 6 — Update docker-compose.yml for Production

Create a production override:

```bash
cat > docker-compose.prod.yml << 'EOF'
services:
  anaya-api:
    command: uvicorn anaya.api.app:create_app --factory --host 0.0.0.0 --port 8000 --workers 2
    ports:
      - "8000:8000"
    volumes:
      - ./private-key.pem:/app/private-key.pem:ro
    # Remove dev volume mounts (code is baked into image)
    restart: unless-stopped

  anaya-worker:
    volumes:
      - ./private-key.pem:/app/private-key.pem:ro
    restart: unless-stopped

  postgres:
    ports: []  # Don't expose DB externally
    restart: unless-stopped

  redis:
    ports: []  # Don't expose Redis externally
    restart: unless-stopped

  caddy:
    image: caddy:2-alpine
    container_name: anaya-caddy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - anaya-api
    restart: unless-stopped
    networks:
      - anaya-net

volumes:
  caddy_data:
  caddy_config:
EOF
```

---

## Step 7 — Configure Caddy (Reverse Proxy + Auto HTTPS)

### Option A: With a custom domain

Point your domain's DNS A record to your VM's public IP, then:

```bash
cat > Caddyfile << 'EOF'
anaya.yourdomain.com {
    reverse_proxy anaya-api:8000
}
EOF
```

Caddy will automatically obtain and renew Let's Encrypt TLS certificates.

### Option B: Without a domain (IP + nip.io)

```bash
cat > Caddyfile << 'EOF'
:80 {
    reverse_proxy anaya-api:8000
}
EOF
```

This serves on plain HTTP at port 80. For GitHub webhooks, HTTPS isn't strictly required but is recommended.

### Option C: Without a domain (IP only, no Caddy)

If you don't want Caddy at all, just expose port 8000 directly:

```bash
# Open port 8000 on Azure NSG
az vm open-port --resource-group anaya-rg --name anaya-vm --port 8000 --priority 1003
```

Then use `http://<YOUR_VM_IP>:8000` as your webhook URL.

---

## Step 8 — Build & Launch

```bash
cd ~/anaya

# Build images
docker compose -f docker-compose.yml -f docker-compose.prod.yml build

# Start everything
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Check all services are running
docker compose ps
```

Expected output:
```
NAME              STATUS                   PORTS
anaya-api         running (healthy)        0.0.0.0:8000->8000/tcp
anaya-caddy       running                  0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
anaya-postgres    running (healthy)
anaya-redis       running (healthy)
anaya-worker      running
```

### Verify health

```bash
# If using Caddy with domain:
curl https://anaya.yourdomain.com/health

# If using IP directly:
curl http://<YOUR_VM_IP>:8000/health
```

Expected: `{"status": "ok"}`

---

## Step 9 — Update GitHub App Webhook URL

1. Go to [github.com/settings/apps](https://github.com/settings/apps) → your AnaYa app → **General**
2. Update **Webhook URL** to:
   - With domain: `https://anaya.yourdomain.com/webhooks/github`
   - Without domain: `http://<YOUR_VM_IP>:8000/webhooks/github`
3. Click **Save changes**

### Verify webhook delivery

1. Go to **Advanced** tab in your GitHub App settings
2. Click **Redeliver** on a recent delivery, or push a commit to a PR
3. Check the response is `200 OK`

---

## Step 10 — Test End-to-End

```bash
# On the VM, check API logs
docker compose logs -f anaya-api --tail 50

# In another terminal, push a commit to a PR in an installed repo
# Then verify:
# ✅ Webhook received (API logs show PR event)
# ✅ Check Run created on the PR
# ✅ PR comment posted with violation table
# ✅ Scan recorded in database:
docker compose exec postgres psql -U anaya -c "SELECT id, repo, pr_number, status FROM scan_runs;"
```

---

## Operations Cheat Sheet

### View logs

```bash
docker compose logs -f anaya-api      # API logs
docker compose logs -f anaya-worker   # Worker/scan logs
docker compose logs -f caddy          # Caddy/HTTPS logs
```

### Restart services

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml restart
```

### Pull updates & redeploy

```bash
cd ~/anaya
git pull origin main
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Database backup

```bash
docker compose exec postgres pg_dump -U anaya anaya > backup_$(date +%Y%m%d).sql
```

### Monitor resource usage

```bash
docker stats
```

---

## Cost Breakdown

| Resource | Monthly Cost |
|----------|-------------|
| Azure B2s VM (2 vCPU, 4 GB RAM) | ~$15.33 |
| 30 GB Standard SSD | ~$1.20 |
| Public IP (static) | ~$2.63 |
| Bandwidth (5 GB outbound) | Free |
| **Total** | **~$19/month** |

With $100 student credits, you get **~5 months** of hosting free.

### Save money

- **Stop the VM** when not in use: `az vm deallocate --resource-group anaya-rg --name anaya-vm`
- **Start it back**: `az vm start --resource-group anaya-rg --name anaya-vm`
- When deallocated, you only pay for disk storage (~$1.20/month)

---

## Troubleshooting

### Webhook returns 502

```bash
# Check if API is running
docker compose ps
docker compose logs anaya-api --tail 20

# Restart if needed
docker compose restart anaya-api
```

### Database connection errors

```bash
# Check postgres is healthy
docker compose exec postgres pg_isready -U anaya

# If migration needed, the tables auto-create on first scan
```

### Caddy can't get TLS certificate

- Ensure your domain's DNS A record points to the VM IP
- Ensure ports 80 and 443 are open in Azure NSG
- Check: `docker compose logs caddy`

### Out of memory

```bash
# Check memory usage
free -h
docker stats --no-stream

# Reduce Celery concurrency in docker-compose.prod.yml:
# command: celery -A anaya.worker.celery_app worker --loglevel=info --concurrency=1
```

### SSH connection refused

- Check Azure NSG allows port 22
- Verify VM is running: `az vm show -d -g anaya-rg -n anaya-vm --query powerState`

---

## Security Hardening (Optional)

```bash
# Enable UFW firewall
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Disable password auth (SSH key only)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Auto-update security patches
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```
