# 🔍 VulnScope — Vulnerability Intelligence Dashboard

> Intelligence en vulnérabilités en temps réel. Scanne les CVE connues (NVD/NIST) pour tes logiciels et affiche un rapport de sévérité avec probabilités d'exploitation (EPSS).

![VulnScope v2.0](https://img.shields.io/badge/VulnScope-v2.0-00e5a0?style=flat-square) ![Python](https://img.shields.io/badge/Python-FastAPI-3776ab?style=flat-square) ![React](https://img.shields.io/badge/React-18+-61dafb?style=flat-square) ![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## 🎯 Features

- ✅ **Recherche CVE temps réel** — Interroge l'API NVD du NIST gratuitement
- ✅ **Scoring CVSS 3.1** — Code couleur (Critical/High/Medium/Low) avec vectorString traduit en français
- ✅ **EPSS Integration** — Probabilité d'exploitation réelle par FIRST EPSS
- ✅ **Presets rapides** — OpenSSH, Apache, Nginx, MySQL, Docker, WordPress, etc.
- ✅ **Barre de sévérité visuelle** — Distribution des vulnérabilités d'un coup d'œil
- ✅ **Détails expandables** — Description, références, vecteur CVSS pour chaque CVE
- ✅ **Mode démo** — Fallback avec données d'exemple si le backend est indisponible
- ✅ **Dark theme professionnel** — Design moderne cyan/noir, responsive
- ✅ **"Patch immédiat"** — Badge alertant si CVSS ≥ 8.0 + EPSS > 50%

## 📐 Architecture

```
vulnscope/
├── backend/
│   ├── main.py                  # API FastAPI (NVD NIST)
│   ├── requirements.txt          # Dépendances Python
│   └── README.md                 # Instructions backend
├── frontend/
│   ├── src/
│   │   └── App.jsx              # Dashboard React + Vite
│   ├── public/
│   ├── package.json             # Dépendances Node
│   ├── vite.config.js           # Config Vite
│   └── README.md                 # Instructions frontend
├── README.md                     # Ce fichier
└── .gitignore
```

## 🏗️ Stack Technique

| Composant | Techno | Pourquoi |
|-----------|--------|----------|
| **Backend** | Python 3.10+ + FastAPI | API async rapide, facile à maintenir |
| **API CVE** | NVD NIST (gratuit) | Base officielle, pas de clé d'API requise |
| **Frontend** | React 18 + Vite | Stack moderne, bundle ultra-rapide |
| **Données Exploit** | FIRST EPSS (gratuit) | Probabilité d'exploitation réelle |
| **Déploiement Back** | Render | Hébergement gratuit, GitHub sync |
| **Déploiement Front** | Netlify / GitHub Pages | Hosting gratuit pour React |

## 🚀 Quickstart

### Prérequis
- Python 3.10+
- Node.js 18+
- Git + GitHub

### 1️⃣ Backend (Render)

```bash
# Clone & cd
git clone https://github.com/[ton-compte]/vulnscope-api.git
cd vulnscope-api

# Installe dépendances
pip install -r requirements.txt

# Test en local
uvicorn main:app --reload

# Visite http://localhost:8000/docs pour les endpoints
```

**Déploiement sur Render :**
1. Pousse le code sur GitHub
2. Connecte le repo sur [Render](https://render.com)
3. **Build Command** : `pip install -r requirements.txt`
4. **Start Command** : `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Deploy → note l'URL `https://vulnscope-api-2.onrender.com`
6. Configure un health check : cron-job.org qui ping `/api/health` toutes les 14 min

### 2️⃣ Frontend (Netlify)

```bash
# Crée un projet Vite
npm create vite@latest vulnscope-front -- --template react
cd vulnscope-front

# Copie src/App.jsx depuis ce repo
# ⚠️ Change API_BASE (ligne 4) par ton URL Render

# Test en local
npm run dev

# Build pour production
npm run build
```

**Déploiement sur Netlify :**
1. Pousse le code sur GitHub
2. Connecte le repo sur [Netlify](https://netlify.com)
3. **Build Command** : `npm run build`
4. **Publish Directory** : `dist`
5. Deploy → site live `https://vulnscope-[xxx].netlify.app`

## 📖 Usage

### Recherche manuelle
1. Entre un nom de logiciel : `openssh`, `apache`, `mysql`
2. Clique **Scanner** ou appuie sur Entrée
3. Attend les résultats temps réel de l'API NVD

### Presets rapides
Clique sur un bouton preset pour scanner instantanément :
- OpenSSH
- Apache HTTP Server
- Nginx
- MySQL
- Linux Kernel
- Docker
- WordPress
- PostgreSQL

### Interprétation des résultats

**Score CVSS**
- 🔴 **9.0-10.0** : CRITICAL — Patch immédiatement
- 🟠 **7.0-8.9** : HIGH — Patch cette semaine
- 🟡 **4.0-6.9** : MEDIUM — Patch ce mois-ci
- 🟢 **0.1-3.9** : LOW — Patch lors de la maintenance

**Badge PATCH IMMÉDIAT 🚨**
Apparaît si : **CVSS ≥ 8.0** ET **EPSS > 50%** (exploitée activement)

**Vectoreur CVSS (badges)**
Chaque CVE affiche son contexte d'attaque :
- 🌐 **AV** (Vecteur) : Réseau, Adjacent, Local, Physique
- 🔑 **PR** (Privilèges) : Aucun requis, Faibles, Élevés
- ⚡ **UI** (Interaction) : Aucune requise, Requise
- 🟢 **AC** (Complexité) : Faible, Élevée
- 📦 **S** (Portée) : Inchangée, Modifiée

**EPSS Score**
- Score 0-100 : Probabilité qu'une exploit publique existe
- Vert 🟢 : < 20% (peu probable)
- Jaune 🟡 : 20-50% (modéré)
- Rouge 🔴 : > 50% (très probable, active exploitation)

## 🔄 API Endpoints

### `GET /api/scan`

Scanne les CVE pour un logiciel donné.

**Paramètres :**
```
?keyword=openssh        # Logiciel à chercher
&days=120               # Période de recherche (défaut: 120 jours)
```

**Réponse :**
```json
{
  "keyword": "openssh",
  "total": 6,
  "stats": {
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 1
  },
  "results": [
    {
      "id": "CVE-2024-6387",
      "description": "Signal handler race condition...",
      "score": 9.8,
      "severity": "CRITICAL",
      "published": "2024-07-01",
      "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"]
    }
  ]
}
```

### `GET /api/health`

Vérifie que le backend fonctionne.

**Réponse :**
```json
{
  "status": "ok",
  "service": "VulnScope API",
  "version": "2.0",
  "timestamp": "2024-04-16T10:30:00.000Z"
}
```

## 🛠️ Développement

### Modifier le frontend
```bash
cd frontend
npm run dev    # Hot-reload en localhost:5173
```

### Modifier le backend
```bash
cd backend
uvicorn main:app --reload    # Rechargement auto sur http://localhost:8000
```

### Tester les endpoints
```bash
# Backend API docs
curl http://localhost:8000/docs

# Scan test
curl "http://localhost:8000/api/scan?keyword=openssh"

# Health check
curl http://localhost:8000/api/health
```

## 📋 Roadmap (Évolutions possibles)

- [ ] Export PDF du rapport de vulnérabilités
- [ ] Inventaire d'actifs persistant (sauvegarde ta stack en DB)
- [ ] Alertes automatiques par email (nouvelles CVE critiques détectées)
- [ ] Intégration MITRE ATT&CK (mapping CVE → techniques d'attaque)
- [ ] Historique des scans avec graphiques d'évolution
- [ ] Authentification + Dashboards multi-utilisateurs
- [ ] Webhooks pour CI/CD (scanner automatiquement avant deploy)

## 🐛 Troubleshooting

### Le backend met du temps à démarrer sur Render
Render éteint les services gratuits après 15 min d'inactivité. Configure un **cron-job** pour ping `/api/health` toutes les 14 min.

### "CORS error" au frontend
Assure-toi que `API_BASE` dans `frontend/src/App.jsx` (ligne 4) pointe vers ton URL Render, pas `http://localhost`.

### Aucune CVE trouvée
C'est normal si le logiciel n'existe pas ou s'il n'y a pas de CVE publique. Essaie avec les presets (OpenSSH, Apache, etc.).

### EPSS data missing
L'API FIRST EPSS peut être lente ou indisponible. Le frontend affiche "EPSS: N/A" et continue quand même.

## 📝 Licence

MIT © 2024

## 👤 Auteur

**Honoré Avekor**  
Bachelor SIN2 @ EPSI Toulouse  
[GitHub](https://github.com/Honore20) · [Portfolio](https://honore20.github.io/)

---

## 📚 Ressources

- [NVD NIST API Docs](https://nvd.nist.gov/developers/vulnerabilities)
- [FIRST EPSS](https://www.first.org/epss)
- [CVSS 3.1 Spec](https://www.first.org/cvss/v3.1/specification-document)
- [FastAPI Docs](https://fastapi.tiangolo.com)
- [React + Vite](https://vitejs.dev/guide/ssr.html)

---

**VulnScope v2.0** — Sécurité par l'intelligence. 🛡️
