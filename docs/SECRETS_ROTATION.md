# Secrets Rotation Procedure

**Fréquence recommandée :** tous les 90 jours ou immédiatement après un incident de sécurité.

Cette procédure suppose que les secrets sont chiffrés avec `sops` et qu'une clé `age` est disponible dans `secrets/age.key`. Utilise toujours le wrapper `./scripts/docker-compose-sops.sh` pour recharger les services afin de garantir que l'environnement est provisionné avec les valeurs déchiffrées.

---

## 1. Préparer l'environnement

```bash
cd /opt/autollm-trader  # adapter si besoin
export SOPS_AGE_KEY_FILE=secrets/age.key
```

Vérifie que tu peux déchiffrer le fichier courant :

```bash
sops --decrypt .env.enc | head -n 5
```

---

## 2. Faire une sauvegarde

```bash
cp .env .env.backup.$(date +%Y%m%d)
cp .env.enc .env.enc.backup.$(date +%Y%m%d)
```

---

## 3. Rotation des secrets applicatifs

### 3.1 JWT / Authentification

```bash
NEW_JWT_SECRET=$(openssl rand -base64 64)
NEW_REFRESH_SECRET=$(openssl rand -base64 64)

sops --decrypt .env.enc \
  | sed -E "s/^JWT_SECRET=.*/JWT_SECRET=${NEW_JWT_SECRET}/" \
  | sed -E "s/^REFRESH_TOKEN_SECRET=.*/REFRESH_TOKEN_SECRET=${NEW_REFRESH_SECRET}/" \
  > .env
```

### 3.2 Mots de passe base de données

```bash
NEW_DB_PASSWORD=$(openssl rand -base64 32)
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${NEW_DB_PASSWORD}/" .env
```

Si tu utilises un utilisateur en lecture seule, n'oublie pas de régénérer son mot de passe.

### 3.3 Redis & caches

```bash
NEW_REDIS_PASSWORD=$(openssl rand -base64 24)
sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=${NEW_REDIS_PASSWORD}/" .env
```

### 3.4 Grafana et VNC

```bash
openssl rand -base64 32 > secrets/grafana_admin_password.txt
chmod 600 secrets/grafana_admin_password.txt
sed -i "s/^GF_SECURITY_ADMIN_PASSWORD=.*/GF_SECURITY_ADMIN_PASSWORD=$(cat secrets/grafana_admin_password.txt)/" .env

openssl rand -base64 16 > secrets/vnc_password.txt
chmod 600 secrets/vnc_password.txt
sed -i "s/^VNC_PASSWORD=.*/VNC_PASSWORD=$(cat secrets/vnc_password.txt)/" .env
```

---

## 4. Ré‑encryptage avec SOPS

```bash
sops --encrypt .env > .env.enc
chmod 600 .env .env.enc
chown trader:trader .env .env.enc
```

---

## 5. Redéploiement des services

```bash
./scripts/docker-compose-sops.sh down
./scripts/docker-compose-sops.sh up -d
```

Vérifie ensuite l'état des conteneurs et des migrations si nécessaire.

---

## 6. Nettoyage et audit

1. Supprime les fichiers temporaires et sauvegardes après validation.
2. Mets à jour le gestionnaire de mots de passe de l'équipe avec les nouveaux secrets.
3. Ajoute une entrée d'audit (ticket, changelog, etc.) décrivant la rotation.

---

## 7. Checklist post-rotation

- [ ] Tous les services démarrent correctement (`docker compose ps`)
- [ ] Les connexions Grafana/Redis/Postgres fonctionnent avec les nouveaux secrets
- [ ] Les tests critiques passent (`make test-critical` si disponible)
- [ ] Les anciens secrets sont révoqués/détruits

> 💡 Conseil : automatise ces rotations via Ansible/Terraform + `sops` dès que possible.
