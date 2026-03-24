import os
import shutil
import stat
import typer
from email import policy
from email.parser import BytesParser
import re
import certifi
import ssl
import socket
from urllib.parse import urlparse

app = typer.Typer()

def check_ssl_certificate(domain: str):
    domain = clean_domain(domain)
    if not domain:
        return False, None

    # On utilise le contexte par défaut qui est déjà configuré pour la sécurité maximale
    context = ssl.create_default_context(cafile=certifi.where())

    try:
        # Timeout légèrement plus long pour éviter les faux négatifs sur réseaux lents
        with socket.create_connection((domain, 443), timeout=10) as sock:
            # L'argument server_hostname est CRUCIAL pour le SNI (Let's Encrypt en a besoin)
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                if cert:
                    return True, cert
                return False, None

    except (ssl.SSLError, socket.timeout, socket.error, Exception) as e:
        # Debug: print(f"Erreur pour {domain}: {e}")
        return False, None

def extract_links(text: str):
    return re.findall(r"https?://[^\s\"'>]+", text)

def clean_domain(domain: str):
    return domain.split(":")[0]


@app.command()
def scan(chemin: str):

    if not os.path.isdir(chemin):
        typer.echo(f"Directory not found: {chemin}")
        raise typer.Exit(code=1)

    quarantine_dir = os.path.join(chemin, "quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)

    for fichier in os.listdir(chemin):
        file_path = os.path.join(chemin, fichier)

        if os.path.isfile(file_path):

            #lire les fichiers .txt
            if fichier.lower().endswith(".txt"):
                typer.echo(f"\n Reading {fichier}")
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        print(f.read())
                except Exception as e:
                    typer.echo(f"Cannot read {fichier}: {e}")

            #gérer les fichiers .exe
            elif fichier.lower().endswith(".exe"):
                typer.echo(f" Quarantining {fichier}")

                # Remove execution rights
                current_permissions = os.stat(file_path).st_mode
                os.chmod(
                    file_path,
                    current_permissions & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH
                )


                shutil.move(file_path, os.path.join(quarantine_dir, fichier))

    typer.echo("\n Scan finished")


@app.command("scan-emails")
def scanemails(chemin: str):
    """Scan .eml files and detect SPAM emails"""

    if not os.path.isdir(chemin):
        typer.echo(f"Directory not found: {chemin}")
        raise typer.Exit(code=1)

    spam_keywords = [
        "free", "win", "lottery", "urgent",
        "click", "bitcoin", "money", "prize", "gagné", "cadeau"
    ]

    dangerous_attachments = [
        ".exe", ".js", ".bat", ".cmd", ".scr",
        ".zip", ".rar", ".iso"
    ]

    trusted_domains = {
        "vinci": ["vinci-autoroutes.com"],
        "banque populaire": ["banquepopulaire.fr"],
        "credit agricole": ["credit-agricole.fr"],
        "societe generale": ["societegenerale.fr"],
        "paypal": ["paypal.com"],
        "orange": ["orange.fr"],
        "edf": ["edf.fr"],
        "amazon": ["amazon.fr", "amazon.com"]
    }

    untrusted_ca = [
        "Let's Encrypt",
        "WoSign",
        "StartCom",
        "TrustCor"
    ]

    typer.echo(f"\nScanning emails in: {chemin}")

    for fichier in os.listdir(chemin):
        if not fichier.lower().endswith(".eml"):
            continue

        score = 0
        reasons = []

        file_path = os.path.join(chemin, fichier)

        try:
            with open(file_path, "rb") as f:
                msg = BytesParser(policy=policy.default).parse(f)

            subject = msg["subject"] or ""
            sender = msg["from"] or ""
            body = ""

            # Lire le contenu texte
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_content()
            else:
                body = msg.get_content()

            content = (subject + body).lower()

            links = extract_links(content)

            for link in links:
                parsed = urlparse(link)
                domain = parsed.netloc.lower()

                #HTTP = suspect direct
                if parsed.scheme == "http":
                    score += 1
                    reasons.append(f"insecure HTTP link: {link}")

                #HTTPS check
                elif parsed.scheme == "https":
                    valid, cert = check_ssl_certificate(domain)

                    if not valid:
                        score += 1
                        reasons.append(f"invalid SSL certificate: {domain}")
                    else:
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        org = issuer.get('organizationName', '')

                        if any(ca in org for ca in untrusted_ca):
                            score += 1
                            reasons.append(f"untrusted certificate issuer: {org}")


            for word in spam_keywords:
                if word in content:
                    score += 0.5
                    reasons.append(f"spam keyword: {word}")


            for brand, domains in trusted_domains.items():
                if brand in content.lower():
                    if not any(domain in sender for domain in domains):
                        score += 1
                        reasons.append(f"suspected {brand} impersonation")


            for part in msg.iter_attachments():
                filename = (part.get_filename() or "").lower()

                # Double extension
                if filename.count(".") >= 2:
                    score += 1
                    reasons.append(f"double extension attachment: {filename}")

                # Extension dangereuse
                for ext in dangerous_attachments:
                    if filename.endswith(ext):
                        score += 1
                        reasons.append(f"dangerous attachment: {filename}")

            if score >= 1:
                typer.echo(f"\033[0;31mSPAM\033[0;34m {fichier}\033[0;37m")
                for r in reasons:
                    typer.echo(f"   - {r}")
            else:
                typer.echo(f"\033[0;32mClean\033[0;34m {fichier}\033[0;37m")

        except Exception as e:
            typer.echo(f"Error reading {fichier}: {e}")

    typer.echo("\nEmail scan finished")



def main():
    app()
