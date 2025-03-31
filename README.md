# GSC Indexing Tool

Un outil Streamlit pour gérer les demandes d'indexation via Google Search Console.

## Fonctionnalités

- **Authentification OAuth2** avec Google Search Console
- **Sélection de propriétés** parmi votre compte Google Search Console
- **Demandes d'indexation d'URLs** (une à la fois ou import en masse via CSV)
- **Vérification du statut d'indexation** d'URLs existantes
- **Suivi des demandes précédentes** avec historique complet
- **Génération de rapports** avec visualisations

## Installation

1. Clonez ce dépôt :
   ```bash
   git clone https://github.com/votre-utilisateur/gsc-indexing-tool.git
   cd gsc-indexing-tool
   ```

2. Installez les dépendances requises :
   ```bash
   pip install -r requirements.txt
   ```

3. Configurez les identifiants OAuth2 pour l'API Google Search Console :
   - Créez un projet dans [Google Cloud Console](https://console.cloud.google.com/)
   - Activez l'API Search Console
   - Configurez l'écran de consentement OAuth
   - Créez des identifiants OAuth2 (type: Desktop application)
   - Téléchargez le fichier JSON et renommez-le en `client_secrets.json`
   - Placez ce fichier dans le répertoire de l'application

## Utilisation

1. Lancez l'application Streamlit :
   ```bash
   streamlit run app.py
   ```

2. Accédez à l'application dans votre navigateur à l'adresse indiquée (généralement http://localhost:8501)

3. Connectez-vous à Google Search Console en utilisant les identifiants OAuth2

4. Utilisez les différentes fonctionnalités via le menu de navigation

## Structure des fichiers

- `app.py` : Code principal de l'application Streamlit
- `client_secrets.json` : Fichier d'identifiants OAuth2 (à configurer)
- `token.json` : Fichier de jeton d'authentification (généré automatiquement)
- `indexing_history.csv` : Historique des demandes d'indexation (généré automatiquement)
- `requirements.txt` : Liste des dépendances Python

## Déploiement

Pour déployer l'application sur Streamlit Cloud :

1. Poussez votre code vers un dépôt GitHub
2. Connectez-vous à [Streamlit Cloud](https://streamlit.io/cloud)
3. Déployez votre application en spécifiant le dépôt et le fichier principal (`app.py`)
4. Configurez les secrets pour les identifiants OAuth2 dans les paramètres de l'application

## Limites et considérations

- L'API Google Search Console a des limites de quota (environ
