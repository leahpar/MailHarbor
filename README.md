# MailHarbor

Un serveur SMTP minimaliste développé en PHP avec Symfony pour la réception d'emails pour des domaines personnalisés.

## Objectif du projet

Créer un service simple permettant de recevoir des emails adressés à `*@votredomaine.com` et de les stocker localement. Ce projet est conçu pour être:
- Léger et minimaliste
- Facile à maintenir
- Compatible avec les serveurs SMTP standards

## Caractéristiques

- Réception des emails uniquement (pas d'envoi)
- Support des commandes SMTP de base (HELO/EHLO, MAIL FROM, RCPT TO, DATA)
- Stockage des emails dans un format accessible
- Intégration avec Symfony pour faciliter la gestion

## Prérequis

- PHP 8.0+
- Symfony 6.x
- Extension socket PHP activée
- Accès aux ports réseau (port 25 par défaut)
- Enregistrement MX sur le domaine cible

## Architecture

### Composants principaux

1. **Socket Listener**: Service qui écoute sur le port 25 et accepte les connexions entrantes
2. **SMTP Handler**: Gère le dialogue du protocole SMTP
3. **Email Parser**: Parse les emails reçus via le protocole SMTP
4. **Storage Manager**: Stocke les emails reçus

### Flux de fonctionnement

1. Un mail est envoyé à une adresse sur votre domaine
2. Votre serveur SMTP l'accepte via le protocole standard
3. L'email est parsé et stocké localement
4. La connexion est fermée proprement

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/username/smtp-server-light.git
cd smtp-server-light

# Installer les dépendances
composer install

# Configurer l'application
cp .env.example .env
# Éditer le fichier .env selon vos besoins
```

## Utilisation

```bash
# Démarrer le serveur SMTP
php bin/console app:smtp:start

# Vérifier les logs
tail -f var/log/smtp.log

# Lister les emails reçus
php bin/console app:email:list
```

## Limitations et avertissements

- Ce serveur est conçu pour un usage personnel/projet, pas pour un usage en production avec des volumes importants
- Pas de support TLS/SSL dans cette version initiale
- Fonctionnalités anti-spam minimales
- Nécessite des droits d'administrateur pour écouter sur le port 25 (standard SMTP)

## Évolutions possibles

- Ajout du support TLS
- Interface web pour consulter les emails
- Filtrage basique d'emails
- Routage vers différents dossiers selon les adresses destinataires

  
