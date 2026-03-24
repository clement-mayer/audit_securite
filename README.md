# Audit Sécurité Email & Fichiers 

Ce projet est un outil en ligne de commande (CLI) développé en Python. Il permet d'automatiser l'analyse de sécurité d'un répertoire, avec une spécialisation dans la détection de phishing au sein des fichiers d'e-mails (.eml).

## Fonctionnalités

### 1. Scan de fichiers (`scan`)
* **Analyse de texte** : Lit et affiche le contenu des fichiers `.txt`.
* **Quarantaine automatique** : Détecte les fichiers `.exe`, retire leurs droits d'exécution (via `chmod`) et les déplace dans un dossier `/quarantine`.

### 2. Analyse d'emails (`scan-emails`)
* **Détection de Spam** : Recherche de mots-clés suspects (free, gagné, bitcoin, etc.).
* **Vérification SSL/TLS** : Analyse les liens HTTPS contenus dans le mail et vérifie la validité du certificat SSL.
* **Contrôle de l'Émetteur** : Alerte si un certificat provient d'une autorité de certification jugée "faible" ou gratuite (ex: Let's Encrypt) dans un contexte bancaire.
* **Anti-Impersonnalisation** : Vérifie si des marques connues (Vinci, PayPal, Banques) sont citées alors que l'adresse de l'expéditeur ne correspond pas au domaine officiel.
* **Analyse des Pièces Jointes** : Identifie les extensions dangereuses et les techniques de "double extension" (ex: `facture.pdf.exe`).

## Arborescence du projet

```text
PythonProject/
├── audit_securite/
│   ├── __init__.py
│   └── main.py          # Logique principale (Typer)
├── .gitignore           # Exclusion du venv et des caches
├── requirements.txt     # Dépendances (typer, certifi)
└── setup.py             # Configuration d'installation
```
## Installation

### 1.Cloner le projet
git clone [https://github.com/votre-utilisateur/audit-securite.git](https://github.com/votre-utilisateur/audit-securite.git)
cd audit-securite

### 2.Créer un environnement virtuel
python -m venv .venv
Activer l'environnement :
Sur Windows : .venv\Scripts\activate
Sur macOS/Linux : source .venv/bin/activate

### 3.Installer les dépendances
pip install -r requirements.txt

### 4.Installer l'outil localement
pip install -e .

