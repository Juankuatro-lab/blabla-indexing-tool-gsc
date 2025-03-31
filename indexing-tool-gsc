import streamlit as st
import pandas as pd
import os
import json
import time
import datetime
from pathlib import Path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import plotly.express as px
import plotly.graph_objects as go
from io import StringIO

# Configuration des variables globales
SCOPES = ['https://www.googleapis.com/auth/webmasters']
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'client_secrets.json'
HISTORY_FILE = 'indexing_history.csv'

# Configuration de la page Streamlit
st.set_page_config(
    page_title="GSC Indexing Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Fonctions d'authentification et de gestion de l'API
def get_credentials():
    """Obtient et retourne les identifiants OAuth2 pour l'API Google Search Console."""
    creds = None
    
    # Vérifie si le fichier token.json existe
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_info(
            json.loads(open(TOKEN_FILE).read()), SCOPES)
    
    # Si les identifiants ne sont pas valides ou n'existent pas, les obtenir
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                st.error(f"Le fichier {CREDENTIALS_FILE} n'a pas été trouvé. Veuillez suivre les instructions pour le configurer.")
                return None
            
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=8501)
        
        # Sauvegarde les identifiants pour la prochaine exécution
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
    
    return creds

def get_service():
    """Crée et retourne un service API Search Console."""
    creds = get_credentials()
    if not creds:
        return None
    
    service = build('searchconsole', 'v1', credentials=creds)
    return service

def get_properties(service):
    """Récupère la liste des propriétés disponibles dans Search Console."""
    if not service:
        return []
    
    try:
        site_list = service.sites().list().execute()
        return site_list.get('siteEntry', [])
    except Exception as e:
        st.error(f"Erreur lors de la récupération des propriétés: {e}")
        return []

def request_indexing(service, site_url, page_url):
    """Demande l'indexation d'une URL spécifique."""
    if not service:
        return None
    
    try:
        result = service.urlNotifications().publish(
            body={
                'url': page_url,
                'type': 'URL_UPDATED'
            }
        ).execute()
        return result
    except Exception as e:
        return {"error": str(e)}

def check_index_status(service, site_url, page_url):
    """Vérifie le statut d'indexation d'une URL spécifique."""
    if not service:
        return None
    
    try:
        # Utilisation de l'API URL Inspection
        result = service.urlInspection().index().inspect(
            body={
                'inspectionUrl': page_url,
                'siteUrl': site_url
            }
        ).execute()
        return result
    except Exception as e:
        return {"error": str(e)}

def load_history():
    """Charge l'historique des demandes d'indexation."""
    if os.path.exists(HISTORY_FILE):
        return pd.read_csv(HISTORY_FILE)
    else:
        # Crée un DataFrame vide avec les colonnes nécessaires
        return pd.DataFrame(columns=[
            'date', 'site_url', 'page_url', 'action', 'status', 'details'
        ])

def save_to_history(site_url, page_url, action, status, details=None):
    """Ajoute une entrée à l'historique des demandes d'indexation."""
    history = load_history()
    
    new_entry = {
        'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'site_url': site_url,
        'page_url': page_url,
        'action': action,
        'status': status,
        'details': json.dumps(details) if details else ''
    }
    
    history = pd.concat([history, pd.DataFrame([new_entry])], ignore_index=True)
    history.to_csv(HISTORY_FILE, index=False)
    return history

# Interface utilisateur Streamlit
def sidebar_menu():
    """Affiche le menu latéral de navigation."""
    st.sidebar.title("GSC Indexing Tool")
    
    menu_options = [
        "Connexion & Configuration",
        "Demandes d'indexation",
        "Vérification de statut",
        "Historique et rapports"
    ]
    
    choice = st.sidebar.radio("Navigation", menu_options)
    
    # Informations sur l'application
    st.sidebar.markdown("---")
    st.sidebar.info(
        """
        **À propos**
        
        Cet outil vous permet de :
        - Demander l'indexation d'URLs dans Google
        - Vérifier le statut d'indexation
        - Suivre l'historique des demandes
        - Générer des rapports
        """
    )
    
    return choice

def auth_page():
    """Page de connexion et de configuration."""
    st.title("📝 Connexion & Configuration")
    
    st.markdown("""
    ### Configuration de l'authentification Google Search Console
    
    Pour utiliser cet outil, vous devez configurer l'authentification OAuth2 pour l'API Google Search Console.
    """)
    
    # Vérification du fichier d'identifiants
    if not os.path.exists(CREDENTIALS_FILE):
        st.warning(f"Le fichier {CREDENTIALS_FILE} n'a pas été trouvé.")
        
        st.markdown("""
        ### Instructions pour configurer les identifiants OAuth2 :
        
        1. Allez sur [Google Cloud Console](https://console.cloud.google.com/)
        2. Créez un projet ou sélectionnez un projet existant
        3. Activez l'API Search Console
        4. Configurez l'écran de consentement OAuth
        5. Créez des identifiants OAuth2 (type: Desktop application)
        6. Téléchargez le fichier JSON des identifiants
        7. Renommez-le en `client_secrets.json` et téléchargez-le ci-dessous
        """)
        
        uploaded_file = st.file_uploader("Télécharger le fichier client_secrets.json", type=["json"])
        if uploaded_file is not None:
            bytes_data = uploaded_file.getvalue()
            with open(CREDENTIALS_FILE, 'wb') as f:
                f.write(bytes_data)
            st.success(f"Fichier {CREDENTIALS_FILE} téléchargé avec succès!")
            st.info("Veuillez actualiser la page pour vous connecter.")
    
    # Si le fichier d'identifiants existe, essayez de se connecter
    if os.path.exists(CREDENTIALS_FILE):
        st.info("Fichier d'identifiants trouvé. Vous pouvez maintenant vous connecter à Google Search Console.")
        
        if st.button("Se connecter à Google Search Console"):
            with st.spinner("Connexion en cours..."):
                service = get_service()
                if service:
                    st.session_state['service'] = service
                    st.success("Connexion réussie!")
                    
                    # Récupérer les propriétés
                    properties = get_properties(service)
                    if properties:
                        st.session_state['properties'] = properties
                        st.success(f"{len(properties)} propriétés trouvées.")
                    else:
                        st.warning("Aucune propriété trouvée. Vérifiez vos accès à Search Console.")
                else:
                    st.error("Échec de la connexion. Veuillez vérifier vos identifiants.")
        
        # Si déjà connecté, afficher les informations
        if 'service' in st.session_state:
            st.success("Vous êtes connecté à Google Search Console!")
            
            if 'properties' in st.session_state and st.session_state['properties']:
                st.subheader("Propriétés disponibles :")
                
                for i, site in enumerate(st.session_state['properties']):
                    st.write(f"{i+1}. {site.get('siteUrl')}")
            
            if st.button("Se déconnecter"):
                # Supprimer le fichier token.json pour se déconnecter
                if os.path.exists(TOKEN_FILE):
                    os.remove(TOKEN_FILE)
                
                # Supprimer les variables de session
                if 'service' in st.session_state:
                    del st.session_state['service']
                if 'properties' in st.session_state:
                    del st.session_state['properties']
                
                st.success("Déconnexion réussie!")
                st.info("Actualisez la page pour vous reconnecter.")

def indexing_request_page():
    """Page pour les demandes d'indexation."""
    st.title("🚀 Demandes d'indexation")
    
    if 'service' not in st.session_state:
        st.warning("Veuillez vous connecter à Google Search Console d'abord.")
        if st.button("Aller à la page de connexion"):
            st.session_state['menu_choice'] = "Connexion & Configuration"
        return
    
    if 'properties' not in st.session_state or not st.session_state['properties']:
        st.warning("Aucune propriété disponible. Vérifiez vos accès à Search Console.")
        return
    
    # Sélection de la propriété
    property_options = [site.get('siteUrl') for site in st.session_state['properties']]
    selected_property = st.selectbox("Sélectionnez une propriété", property_options)
    
    # Options pour l'entrée des URLs
    st.subheader("Ajouter des URLs à indexer")
    input_method = st.radio("Méthode d'entrée", ["URL unique", "Import CSV"])
    
    urls_to_process = []
    
    if input_method == "URL unique":
        url_input = st.text_input("Entrez l'URL à indexer")
        if url_input:
            urls_to_process.append(url_input)
    else:  # Import CSV
        st.write("Téléchargez un fichier CSV avec une colonne 'url'")
        csv_file = st.file_uploader("Télécharger le fichier CSV", type=["csv"])
        
        if csv_file is not None:
            try:
                df = pd.read_csv(csv_file)
                if 'url' in df.columns:
                    urls_to_process = df['url'].tolist()
                    st.success(f"{len(urls_to_process)} URLs trouvées dans le fichier.")
                else:
                    st.error("Le fichier CSV doit contenir une colonne 'url'.")
            except Exception as e:
                st.error(f"Erreur lors de la lecture du fichier CSV: {e}")
    
    # Bouton pour soumettre les demandes d'indexation
    if urls_to_process and st.button("Soumettre les demandes d'indexation"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        results_container = st.container()
        
        results = []
        
        for i, url in enumerate(urls_to_process):
            status_text.text(f"Traitement de l'URL {i+1}/{len(urls_to_process)}: {url}")
            
            # Demande d'indexation
            result = request_indexing(st.session_state['service'], selected_property, url)
            
            # Enregistrement du résultat
            status = "success" if result and "error" not in result else "error"
            details = result if result else {"error": "Aucune réponse de l'API"}
            
            # Sauvegarde dans l'historique
            save_to_history(selected_property, url, "indexing_request", status, details)
            
            results.append({
                "url": url,
                "status": status,
                "details": details
            })
            
            # Mise à jour de la barre de progression
            progress_bar.progress((i + 1) / len(urls_to_process))
            
            # Petite pause pour éviter les limitations de l'API
            if len(urls_to_process) > 10:
                time.sleep(1)
        
        # Affichage des résultats
        with results_container:
            st.subheader("Résultats des demandes d'indexation")
            
            success_count = sum(1 for r in results if r["status"] == "success")
            error_count = len(results) - success_count
            
            col1, col2 = st.columns(2)
            col1.metric("Demandes réussies", success_count)
            col2.metric("Erreurs", error_count)
            
            if results:
                results_df = pd.DataFrame(results)
                st.dataframe(results_df[["url", "status"]])
                
                if error_count > 0:
                    st.error("Certaines demandes ont échoué. Consultez les détails pour plus d'informations.")

def status_check_page():
    """Page pour vérifier le statut d'indexation."""
    st.title("🔍 Vérification de statut")
    
    if 'service' not in st.session_state:
        st.warning("Veuillez vous connecter à Google Search Console d'abord.")
        if st.button("Aller à la page de connexion"):
            st.session_state['menu_choice'] = "Connexion & Configuration"
        return
    
    if 'properties' not in st.session_state or not st.session_state['properties']:
        st.warning("Aucune propriété disponible. Vérifiez vos accès à Search Console.")
        return
    
    # Sélection de la propriété
    property_options = [site.get('siteUrl') for site in st.session_state['properties']]
    selected_property = st.selectbox("Sélectionnez une propriété", property_options)
    
    # Options pour l'entrée des URLs
    st.subheader("URLs à vérifier")
    input_method = st.radio("Méthode d'entrée", ["URL unique", "Import CSV"])
    
    urls_to_check = []
    
    if input_method == "URL unique":
        url_input = st.text_input("Entrez l'URL à vérifier")
        if url_input:
            urls_to_check.append(url_input)
    else:  # Import CSV
        st.write("Téléchargez un fichier CSV avec une colonne 'url'")
        csv_file = st.file_uploader("Télécharger le fichier CSV", type=["csv"])
        
        if csv_file is not None:
            try:
                df = pd.read_csv(csv_file)
                if 'url' in df.columns:
                    urls_to_check = df['url'].tolist()
                    st.success(f"{len(urls_to_check)} URLs trouvées dans le fichier.")
                else:
                    st.error("Le fichier CSV doit contenir une colonne 'url'.")
            except Exception as e:
                st.error(f"Erreur lors de la lecture du fichier CSV: {e}")
    
    # Bouton pour vérifier le statut
    if urls_to_check and st.button("Vérifier le statut d'indexation"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        results_container = st.container()
        
        results = []
        
        for i, url in enumerate(urls_to_check):
            status_text.text(f"Vérification de l'URL {i+1}/{len(urls_to_check)}: {url}")
            
            # Vérification du statut
            result = check_index_status(st.session_state['service'], selected_property, url)
            
            # Extraction des informations pertinentes
            if result and "error" not in result:
                index_status = result.get('inspectionResult', {}).get('indexStatusResult', {}).get('indexingState', 'UNKNOWN')
                coverage_state = result.get('inspectionResult', {}).get('indexStatusResult', {}).get('coverageState', 'UNKNOWN')
                last_crawl = result.get('inspectionResult', {}).get('indexStatusResult', {}).get('lastCrawlTime', 'UNKNOWN')
                
                status_info = {
                    "indexingState": index_status,
                    "coverageState": coverage_state,
                    "lastCrawlTime": last_crawl
                }
                
                status = "indexed" if index_status == "INDEXED" else "not_indexed"
            else:
                status = "error"
                status_info = result if result else {"error": "Aucune réponse de l'API"}
            
            # Sauvegarde dans l'historique
            save_to_history(selected_property, url, "status_check", status, status_info)
            
            results.append({
                "url": url,
                "status": status,
                "indexingState": status_info.get("indexingState", "UNKNOWN"),
                "coverageState": status_info.get("coverageState", "UNKNOWN"),
                "lastCrawlTime": status_info.get("lastCrawlTime", "UNKNOWN"),
                "details": status_info
            })
            
            # Mise à jour de la barre de progression
            progress_bar.progress((i + 1) / len(urls_to_check))
            
            # Petite pause pour éviter les limitations de l'API
            if len(urls_to_check) > 5:
                time.sleep(2)
        
        # Affichage des résultats
        with results_container:
            st.subheader("Résultats de la vérification")
            
            indexed_count = sum(1 for r in results if r["status"] == "indexed")
            not_indexed_count = sum(1 for r in results if r["status"] == "not_indexed")
            error_count = sum(1 for r in results if r["status"] == "error")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Indexées", indexed_count)
            col2.metric("Non indexées", not_indexed_count)
            col3.metric("Erreurs", error_count)
            
            if results:
                results_df = pd.DataFrame(results)
                st.dataframe(results_df[["url", "indexingState", "coverageState", "lastCrawlTime"]])
                
                if error_count > 0:
                    st.error("Certaines vérifications ont échoué. Consultez les détails pour plus d'informations.")

def history_report_page():
    """Page pour l'historique et les rapports."""
    st.title("📊 Historique et rapports")
    
    # Chargement de l'historique
    history = load_history()
    
    if history.empty:
        st.info("Aucun historique disponible. Effectuez des demandes d'indexation ou des vérifications de statut pour créer un historique.")
        return
    
    # Affichage des statistiques
    st.subheader("Statistiques générales")
    
    col1, col2, col3 = st.columns(3)
    
    total_requests = len(history)
    indexing_requests = len(history[history['action'] == 'indexing_request'])
    status_checks = len(history[history['action'] == 'status_check'])
    
    col1.metric("Total des actions", total_requests)
    col2.metric("Demandes d'indexation", indexing_requests)
    col3.metric("Vérifications de statut", status_checks)
    
    # Graphiques
    st.subheader("Analyse des données")
    
    # Graphique 1: Actions par jour
    history['date'] = pd.to_datetime(history['date'])
    history['day'] = history['date'].dt.date
    
    actions_by_day = history.groupby(['day', 'action']).size().reset_index(name='count')
    
    fig1 = px.line(actions_by_day, x='day', y='count', color='action',
                 title="Actions par jour",
                 labels={'day': 'Date', 'count': 'Nombre d\'actions', 'action': 'Type d\'action'})
    
    st.plotly_chart(fig1, use_container_width=True)
    
    # Graphique 2: Statuts par type d'action
    status_by_action = history.groupby(['action', 'status']).size().reset_index(name='count')
    
    fig2 = px.bar(status_by_action, x='action', y='count', color='status',
                title="Statuts par type d'action",
                labels={'action': 'Type d\'action', 'count': 'Nombre', 'status': 'Statut'})
    
    st.plotly_chart(fig2, use_container_width=True)
    
    # Filtres pour l'historique détaillé
    st.subheader("Historique détaillé")
    
    col1, col2 = st.columns(2)
    
    with col1:
        filter_action = st.multiselect(
            "Filtrer par action",
            options=history['action'].unique(),
            default=history['action'].unique()
        )
    
    with col2:
        filter_status = st.multiselect(
            "Filtrer par statut",
            options=history['status'].unique(),
            default=history['status'].unique()
        )
    
    # Application des filtres
    filtered_history = history[
        history['action'].isin(filter_action) &
        history['status'].isin(filter_status)
    ]
    
    # Affichage de l'historique filtré
    if not filtered_history.empty:
        st.dataframe(filtered_history[['date', 'site_url', 'page_url', 'action', 'status']])
        
        # Option pour télécharger l'historique
        csv = filtered_history.to_csv(index=False)
        st.download_button(
            label="Télécharger l'historique filtré (CSV)",
            data=csv,
            file_name="gsc_indexing_history.csv",
            mime="text/csv"
        )
    else:
        st.info("Aucun résultat correspondant aux filtres sélectionnés.")

def main():
    """Fonction principale de l'application."""
    # Affichage du menu latéral
    if 'menu_choice' not in st.session_state:
        st.session_state['menu_choice'] = "Connexion & Configuration"
    
    menu_choice = sidebar_menu()
    
    # Si le choix du menu a changé, le mettre à jour dans la session
    if menu_choice != st.session_state['menu_choice']:
        st.session_state['menu_choice'] = menu_choice
    
    # Affichage de la page correspondante
    if st.session_state['menu_choice'] == "Connexion & Configuration":
        auth_page()
    elif st.session_state['menu_choice'] == "Demandes d'indexation":
        indexing_request_page()
    elif st.session_state['menu_choice'] == "Vérification de statut":
        status_check_page()
    elif st.session_state['menu_choice'] == "Historique et rapports":
        history_report_page()

if __name__ == "__main__":
    main()
