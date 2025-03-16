# TODO

## Configuration initiale

- [D] Créer le squelette du projet Symfony (`symfony new <project name>`)
- [D] Configurer l'environnement de développement
- [D] Mettre en place le système de logs
- [D] Créer les fichiers de configuration spécifiques au projet

## Implémentation du serveur SMTP

- [D] Créer la commande console pour démarrer le serveur
- [ ] Implémenter le service d'écoute socket sur le port 25
- [ ] Gérer les connexions entrantes et les timeouts
- [ ] Implémenter le dialogue SMTP de base:
  - [ ] Commande HELO/EHLO
  - [ ] Commande MAIL FROM
  - [ ] Commande RCPT TO
  - [ ] Commande DATA
  - [ ] Commande QUIT
- [ ] Gérer les erreurs et les cas particuliers du protocole
- [ ] Mettre en place un système de redémarrage automatique en cas d'erreur

## Traitement des emails

- [ ] Intégrer une bibliothèque de parsing d'emails (zbateson/mail-mime-parser)
- [ ] Extraire les informations importantes des emails:
  - [ ] Expéditeur
  - [ ] Destinataires
  - [ ] Sujet
  - [ ] Corps du message
  - [ ] Pièces jointes
- [ ] Gérer les encodages et formats de contenu

## Stockage

- [ ] Concevoir la structure de stockage des emails
- [ ] Implémenter le service de stockage:
  - [ ] Stockage sous forme de fichiers .eml
  - [ ] Organisation par date/destinataire
- [ ] Créer une commande pour lister les emails stockés
- [ ] Ajouter une option de purge automatique des anciens emails

## Tests et débogage

- [ ] Mettre en place des tests unitaires pour les composants principaux
- [ ] Créer un environnement de test pour simuler des connexions SMTP
- [ ] Implémenter des outils de débogage et de diagnostic
- [ ] Tester avec différents clients SMTP:
  - [ ] Thunderbird
  - [ ] Outlook
  - [ ] Gmail (via SMTP)

## Déploiement

- [ ] Préparer un script de déploiement
- [ ] Documenter la configuration du serveur
- [ ] Configurer l'enregistrement MX pour le domaine
- [ ] Mettre en place un système de supervision

## Documentation

- [ ] Documenter l'API et les services
- [ ] Créer un guide d'utilisation
- [ ] Documenter la structure des emails stockés
- [ ] Ajouter des exemples d'utilisation et de configuration

## Améliorations futures (optionnel)

- [ ] Support TLS (STARTTLS)
- [ ] Interface web simple pour consulter les emails
- [ ] Filtrage de base pour le spam
- [ ] Règles de routage selon les destinataires
- [ ] Système de notification pour les nouveaux emails

## Notes et ressources

- Documentation RFC du protocole SMTP: [RFC 5321](https://tools.ietf.org/html/rfc5321)
- Documentation Symfony pour les commandes: [Symfony Console](https://symfony.com/doc/current/console.html)
- Documentation de parsing d'emails: [zbateson/mail-mime-parser](https://github.com/zbateson/mail-mime-parser)
