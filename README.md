# Cyber_analyse

# Détecteur réseau hybride (code + IA locale)

Outil de détection d'intrusion qui capture le trafic réseau avec **tcpdump**,
détecte les attaques (**scan de ports**, **brute-force**) par analyse du trafic,
et utilise un **LLM local** pour expliquer les menaces en français.

Projet personnel d'apprentissage en cybersécurité défensive (blue team / SOC).

---

## Objectif

Reproduire le principe d'un outil de supervision de sécurité (type SIEM) :
surveiller un réseau en continu, détecter les comportements d'attaque, et
produire des alertes claires et horodatées, avec une explication en langage
naturel.

##  Architecture : détection hybride

Le choix clé du projet : **ne pas faire analyser chaque paquet par le LLM**
(trop lent et source de faux positifs). À la place :

```
tcpdump ──► DÉTECTION PAR CODE ──► si menace ──► LLM explique
(capture)   (règles, instantané)               (optionnel)
```

- **Le code** détecte les menaces par comptage (rapide, fiable, factuel).
- **Le LLM** n'intervient que pour **expliquer** les menaces détectées.

→ Rapide (pas d'appel IA sur du trafic normal) et fiable (le code ne fabrique
pas de fausses menaces).

## Ce qui est détecté

| Menace | Méthode de détection |
|---|---|
| **Scan de ports** | une IP source qui vise ≥ N ports différents (SYN) |
| **Brute-force** | une IP qui se connecte ≥ N fois au même port (SYN) |

Seuils réglables (`SEUIL_SCAN`, `SEUIL_BRUTEFORCE`).

## Réduction des faux positifs

Plusieurs filtres, ajoutés après observation du trafic réel :

1. **Paquets SYN uniquement** → on compte les *tentatives de connexion*, pas
   les réponses (évite d'accuser la machine victime de ses propres réponses).
2. **Exclusion du multicast/broadcast** (SSDP, mDNS...) → trafic de découverte
   normal, ignoré.
3. **Liste blanche automatique** → les IP locales de la machine (via `ip a`) et
   les ports de services légitimes (ex. agent Wazuh 1514/1515) sont exclus.

## Technologies

- **Python 3** (capture via `subprocess`, parsing regex, requêtes HTTP)
- **tcpdump** (capture réseau)
- **Ollama** (LLM local, gratuit) — ou une **API** (OpenAI...) au choix
- Modèle IA spécialisé via un **Modelfile** (agent de cyberdéfense en français)

## Installation

```bash
# 1. tcpdump
sudo apt install tcpdump -y

# 2. Ollama (LLM local) + un modèle
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:1b

# 3. Créer l'agent cyberdef (voir Modelfile)
ollama create cyberdef -f Modelfile
```

## Utilisation

```bash
# Surveillance EN CONTINU (boucle, Ctrl+C pour arrêter)
sudo python3 detect.py monitor

# Une seule capture + analyse
sudo python3 detect.py live eth0 300

# Analyser un fichier de capture
python3 detect.py capture.txt
```

Sortie d'exemple (chaîne d'attaque réelle détectée) :
```
[24/11/2026 20:47:12] [!] 1 menace(s) detectee(s) :
   - SCAN DE PORTS : l'IP 192.168.1.40 a vise 99 ports differents (ex: 21, 22, 23, 25, 53...).

[24/11/2026 20:47:48] [!] 1 menace(s) detectee(s) :
   - BRUTE-FORCE possible : l'IP 192.168.1.40 s'est connectee 24 fois au port 22.
```

## Configuration

En haut de `detect.py` :

```python
MOTEUR = "ollama"          # "ollama" (local) ou "api" (distant)
SEUIL_SCAN = 10            # ports différents pour déclencher "scan"
SEUIL_BRUTEFORCE = 10      # connexions au même port pour "brute-force"
UTILISER_LLM = True        # False = détection code seule (ultra rapide)
```

## Environnement de test

- 2 machines virtuelles sur un réseau isolé (VirtualBox)
- **Kali** (attaquant) : `nmap`, `hydra`
- **Victime** : exécute le détecteur
- Attaques testées : scan de ports (`nmap`), brute-force SSH (`hydra`)

## Améliorations possibles

- Niveaux de gravité calculés par le code (Faible / Moyen / Élevé / Critique)
- Enregistrement des alertes dans un fichier journal
- Détection d'autres attaques (exfiltration, flood/DoS)
- Lecture directe de fichiers `.pcap`
