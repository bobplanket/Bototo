# 🚀 Instructions de Déploiement VPS

## Résumé Rapide

```bash
# Sur le VPS (connecté en SSH)
cd /opt/autollm-trader/Bototo
git fetch origin && git reset --hard origin/main
chmod +x infra/deploy-and-verify.sh
./infra/deploy-and-verify.sh
```

## Ce que fait le script automatiquement

1. ✅ Met à jour le code depuis Git
2. ✅ Nettoie le cache Docker
3. ✅ Configure automatiquement `.env` avec vos identifiants IBKR et Redis Upstash
4. ✅ Construit toutes les images Docker
5. ✅ Démarre les services dans le bon ordre (infrastructure → monitoring → apps)
6. ✅ Vérifie la santé de chaque service
7. ✅ Configure le service systemd
8. ✅ Affiche un résumé complet

## Prérequis (déjà présents sur votre VPS)

- Docker et Docker Compose installés
- Repository cloné dans `/opt/autollm-trader/Bototo`
- Service systemd `autollm-stack` configuré

## Configuration des Secrets

Le script utilise automatiquement ces valeurs depuis votre `.env` existant :

### IBKR Paper Trading
- `IB_USERID`: oobudw311
- `IB_PASSWORD`: cocsap-qijtA4-vodkih  
- `IB_ACCOUNT`: DUN122374

### Redis Upstash (avec TLS)
- `REDIS_HOST`: boss-sole-21915.upstash.io
- `REDIS_TLS_ENABLED`: true
- Les identifiants sont conservés depuis votre `.env`

### APIs Externes
- `OPENAI_API_KEY`: Votre clé OpenAI
- `FINNHUB_API_KEY`: Votre clé Finnhub

## Vérification Post-Déploiement

### 1. Vérifier que tous les conteneurs tournent
```bash
cd /opt/autollm-trader/Bototo/infra
docker compose ps
```

Tous les services critiques doivent afficher "Up".

### 2. Tester le Health Check
```bash
curl https://185.216.25.212.nip.io/health
```

Devrait retourner : `{"status":"ok"}`

### 3. Consulter les logs
```bash
cd /opt/autollm-trader/Bototo/infra
docker compose logs -f gateway-api
docker compose logs -f risk-manager
docker compose logs -f execution-ib
```

### 4. Vérifier le service systemd
```bash
sudo systemctl status autollm-stack
```

## Services Disponibles

| Service | URL | Description |
|---------|-----|-------------|
| Health Check | https://185.216.25.212.nip.io/health | Vérification rapide |
| API Docs | https://185.216.25.212.nip.io/docs | Documentation Swagger |
| Grafana | https://185.216.25.212.nip.io/grafana/ | Dashboards & Monitoring |
| Prometheus | http://localhost:9090 | Métriques (accès local) |

## Dépannage

### Les conteneurs ne démarrent pas
```bash
# Voir les logs d'un service spécifique
cd /opt/autollm-trader/Bototo/infra
docker compose logs <nom-du-service>

# Redémarrer un service
docker compose restart <nom-du-service>
```

### Le health check échoue
```bash
# Vérifier les logs du gateway
docker compose logs -f gateway-api

# Vérifier que Redis fonctionne
docker compose exec gateway-api curl -v http://localhost:8000/health
```

### Erreurs de connexion Redis
Le script configure automatiquement Redis avec TLS pour Upstash. Si vous avez des erreurs :
```bash
# Vérifier la variable TLS dans .env
grep REDIS_TLS_ENABLED /opt/autollm-trader/Bototo/.env
# Devrait afficher: REDIS_TLS_ENABLED=true
```

### Reconstruction complète
```bash
cd /opt/autollm-trader/Bototo
docker compose -f infra/docker-compose.yml down -v
./infra/deploy-and-verify.sh
```

## Commandes Utiles

```bash
# Arrêter tous les services
cd /opt/autollm-trader/Bototo/infra
docker compose down

# Démarrer tous les services
docker compose up -d

# Voir l'utilisation des ressources
docker stats

# Nettoyer les images inutilisées
docker system prune -a

# Redémarrer via systemd
sudo systemctl restart autollm-stack
sudo systemctl status autollm-stack
```

## Notes Importantes

- **Mode Paper Trading** : Le système est configuré en mode simulation (LIVE=0)
- **Pas de trades réels** : Tous les ordres vont vers le paper trading IBKR
- **TLS Redis** : Le système utilise `rediss://` pour se connecter à Upstash
- **Monitoring** : Grafana démarre avec le mot de passe de votre `.env`

## Support

Si vous rencontrez des problèmes :

1. Vérifiez les logs : `docker compose logs -f`
2. Vérifiez le statut : `docker compose ps`
3. Relancez le script : `./infra/deploy-and-verify.sh`
4. Consultez le script de vérification : `./infra/verify-stack.sh`

---

**Dernière mise à jour** : 2025-10-05  
**Version** : 1.0.0