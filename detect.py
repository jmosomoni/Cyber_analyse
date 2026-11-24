#!/usr/bin/env python3
"""
detect.py - Detecteur reseau hybride : code + LLM
-------------------------------------------------
1. Capture le trafic (tcpdump).
2. Le CODE analyse vite : compte les ports/connexions par IP -> detecte
   scan de ports et brute-force instantanement.
3. Le LLM n'intervient QUE si une menace est detectee, pour l'expliquer.

Modes :
    sudo python3 detect.py live              # 1 capture puis analyse
    sudo python3 detect.py monitor           # surveillance EN CONTINU (boucle)
    sudo python3 detect.py monitor eth0 100  # continu, 100 paquets par cycle
    python3 detect.py capture.txt            # analyse un fichier
"""

import sys
import re
import json
import subprocess
import urllib.request
from collections import defaultdict
from datetime import datetime


def horodatage():
    """Renvoie la date et l'heure actuelles au format jour/mois/annee heure:min:sec."""
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")

# ===================== CONFIGURATION =====================
MOTEUR = "ollama"              # "ollama" (local, gratuit) ou "api" (distant)

# -- Config Ollama (LLM local) --
MODELE_OLLAMA = "cyberdef"
URL_OLLAMA = "http://localhost:11434/api/generate"

# -- Config API distante (OpenAI, etc.) -- utilisee seulement si MOTEUR = "api"
API_URL = "https://api.openai.com/v1/chat/completions"
API_CLE = "METS_TA_CLE_ICI"
API_MODELE = "gpt-4o-mini"

INTERFACE = "eth0"
NB_PAQUETS = 200

SEUIL_SCAN = 10        # une IP qui vise >= 10 ports differents = scan
SEUIL_BRUTEFORCE = 10  # >= 10 connexions vers le MEME port = brute-force

UTILISER_LLM = True    # False = detection par code seule (ultra rapide)

# Liste blanche : trafic legitime a NE PAS signaler comme attaque.
# Les IP de la machine sont ajoutees AUTOMATIQUEMENT au demarrage (voir mes_ip_locales).
IP_DE_CONFIANCE = []   # tu peux en ajouter manuellement (ex: le serveur Wazuh)
PORTS_DE_CONFIANCE = [
    "1514", "1515",   # agent Wazuh (envoi des logs au serveur)
]
# =========================================================

# On capture AUSSI les flags TCP (pour ne garder que les SYN = tentatives de connexion)
MOTIF = re.compile(
    r"IP (\d+\.\d+\.\d+\.\d+)\.\d+ > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]+)\]"
)


def est_multicast_ou_broadcast(ip):
    """Vrai si l'IP est du multicast (224-239.x) ou du broadcast -> trafic normal a ignorer."""
    premier = int(ip.split(".")[0])
    return 224 <= premier <= 239 or ip == "255.255.255.255"


def mes_ip_locales():
    """Recupere automatiquement les IP de cette machine (via 'ip a', sinon 'hostname -I')."""
    ips = []
    # Methode 1 : ip -4 addr
    try:
        r = subprocess.run(["ip", "-4", "addr"], capture_output=True, text=True)
        for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout):
            ip = m.group(1)
            if ip != "127.0.0.1" and ip not in ips:   # on ignore le loopback
                ips.append(ip)
    except Exception:
        pass
    # Methode 2 (plan B) : hostname -I, si 'ip' n'a rien donne
    if not ips:
        try:
            r = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
            for ip in r.stdout.split():
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and ip != "127.0.0.1":
                    ips.append(ip)
        except Exception:
            pass
    return ips


def capturer(interface, nb_paquets):
    commande = ["tcpdump", "-i", interface, "-nn", "-c", str(nb_paquets)]
    try:
        r = subprocess.run(commande, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("Erreur : tcpdump non installe."); sys.exit(1)
    if r.returncode != 0 and not r.stdout:
        print("Erreur tcpdump :", r.stderr.strip())
        print("Astuce : lance avec sudo."); sys.exit(1)
    return r.stdout


def detecter(capture):
    """Le CODE analyse la capture et detecte les menaces (instantane)."""
    ports_vises = defaultdict(set)
    connexions = defaultdict(int)

    for ligne in capture.splitlines():
        m = MOTIF.search(ligne)
        if m:
            src, dst, port, flags = m.group(1), m.group(2), m.group(3), m.group(4)
            # On ne compte QUE les SYN purs = tentatives de connexion (pas les reponses [S.])
            if flags != "S":
                continue
            # On ignore le trafic multicast/broadcast (SSDP, mDNS... = normal)
            if est_multicast_ou_broadcast(dst):
                continue
            # Liste blanche : on ignore notre propre machine et les ports de services connus
            if src in IP_DE_CONFIANCE:
                continue
            if port in PORTS_DE_CONFIANCE:
                continue
            ports_vises[src].add(port)
            connexions[(src, port)] += 1

    menaces = []
    for src, ports in ports_vises.items():
        if len(ports) >= SEUIL_SCAN:
            # Quelques ports en exemple (triÃ©s par numÃ©ro, les 5 premiers)
            exemples = sorted(ports, key=int)[:5]
            apercu = ", ".join(exemples)
            suite = "..." if len(ports) > 5 else ""
            menaces.append(
                f"SCAN DE PORTS : l'IP {src} a vise {len(ports)} ports differents "
                f"(ex: {apercu}{suite})."
            )
    for (src, port), n in connexions.items():
        if n >= SEUIL_BRUTEFORCE:
            menaces.append(
                f"BRUTE-FORCE possible : l'IP {src} s'est connectee {n} fois au port {port}."
            )
    return menaces


def expliquer_avec_llm(menaces):
    """Aiguille vers Ollama ou l'API selon MOTEUR."""
    resume = "\n".join(menaces)
    consigne = (
        "Tu es un analyste cybersecurite. Menaces detectees :\n\n" + resume +
        "\n\nExplique en francais, risque + recommandation. Sois concis."
    )
    if MOTEUR == "api":
        return _appeler_api(consigne)
    return _appeler_ollama(consigne)


def _appeler_ollama(consigne):
    donnees = json.dumps({
        "model": MODELE_OLLAMA,
        "prompt": consigne,
        "stream": False,
        "options": {"num_predict": 200},   # limite la reponse a ~200 mots = BEAUCOUP plus rapide
    }).encode("utf-8")
    requete = urllib.request.Request(
        URL_OLLAMA, data=donnees, headers={"Content-Type": "application/json"},
    )
    # timeout : si le LLM rame plus de 60s, on abandonne (ne bloque pas la surveillance)
    with urllib.request.urlopen(requete, timeout=60) as rep:
        return json.loads(rep.read()).get("response", "(pas de reponse)")


def _appeler_api(consigne):
    donnees = json.dumps({
        "model": API_MODELE,
        "messages": [{"role": "user", "content": consigne}],
    }).encode("utf-8")
    requete = urllib.request.Request(
        API_URL, data=donnees,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_CLE}",
        },
    )
    with urllib.request.urlopen(requete, timeout=60) as rep:
        return json.loads(rep.read())["choices"][0]["message"]["content"]


def traiter(capture):
    """Detecte sur une capture et affiche le resultat."""
    menaces = detecter(capture)
    maintenant = horodatage()
    if not menaces:
        print(f"[{maintenant}] [OK] Trafic normal, aucune menace.")
        return
    print(f"[{maintenant}] [!] {len(menaces)} menace(s) detectee(s) :")
    for m in menaces:
        print("   - " + m)
    if UTILISER_LLM:
        print("\n[i] Analyse IA...")
        try:
            print(expliquer_avec_llm(menaces))
        except Exception as e:
            print(f"(LLM indisponible : {e} - les menaces ci-dessus restent valides)")


def surveillance_continue(interface, nb_paquets):
    """Boucle sans fin : capture -> detecte -> recommence. Ctrl+C pour arreter."""
    print("=" * 60)
    print(f"  SURVEILLANCE CONTINUE sur {interface} (Ctrl+C pour arreter)")
    print("=" * 60)
    cycle = 0
    try:
        while True:
            cycle += 1
            print(f"\n--- Cycle {cycle} : capture de {nb_paquets} paquets ---")
            capture = capturer(interface, nb_paquets)
            traiter(capture)
    except KeyboardInterrupt:
        print("\n\n[i] Surveillance arretee. Bonne journee !")


def main():
    # Ajoute AUTOMATIQUEMENT les IP de cette machine a la liste blanche
    locales = mes_ip_locales()
    for ip in locales:
        if ip not in IP_DE_CONFIANCE:
            IP_DE_CONFIANCE.append(ip)
    if locales:
        print(f"[i] IP locales ajoutees a la liste blanche : {', '.join(locales)}")

    if len(sys.argv) > 1 and sys.argv[1] == "monitor":
        interface = sys.argv[2] if len(sys.argv) > 2 else INTERFACE
        nb = int(sys.argv[3]) if len(sys.argv) > 3 else NB_PAQUETS
        surveillance_continue(interface, nb)
        return

    # mode "live" (une seule fois) ou fichier
    if len(sys.argv) > 1 and sys.argv[1] == "live":
        interface = sys.argv[2] if len(sys.argv) > 2 else INTERFACE
        nb = int(sys.argv[3]) if len(sys.argv) > 3 else NB_PAQUETS
        capture = capturer(interface, nb)
    elif len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8", errors="ignore") as f:
            capture = f.read()
    else:
        capture = sys.stdin.read()

    print("=" * 60)
    print("  DETECTEUR RESEAU HYBRIDE (code + LLM)")
    print("=" * 60)
    traiter(capture.strip())
    print("=" * 60)


if __name__ == "__main__":
    main()
