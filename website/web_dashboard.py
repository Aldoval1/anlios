from flask import Flask, render_template, request, redirect, url_for, session
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import TokenExpiredError
import os
import json
import logging
from dotenv import load_dotenv
import requests
from bs4 import BeautifulSoup
import PyPDF2
from youtube_transcript_api import YouTubeTranscriptApi

# --- CONFIGURACIÓN INICIAL ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
logging.basicConfig(level=logging.INFO)
env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(dotenv_path=env_path)

# --- CONSTANTES ---
CLIENT_ID, CLIENT_SECRET, BOT_TOKEN = os.getenv('DISCORD_CLIENT_ID'), os.getenv('DISCORD_CLIENT_SECRET'), os.getenv('DISCORD_BOT_TOKEN')

# URL de Redirección Dinámica
DOMAIN = os.getenv('DOMAIN_URL', 'http://127.0.0.1:5000')
REDIRECT_URI = f'{DOMAIN}/callback'

API_BASE_URL = 'https://discord.com/api'
AUTHORIZATION_BASE_URL, TOKEN_URL = f'{API_BASE_URL}/oauth2/authorize', f'{API_BASE_URL}/oauth2/token'
SCOPES = ['identify', 'guilds']
BOT_GUILDS_FILE = os.path.join(os.path.dirname(__file__), '..', 'bot_guilds.json')
COMMAND_QUEUE_FILE = os.path.join(os.path.dirname(__file__), '..', 'command_queue.json')
MODULE_CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', 'module_config.json')

# --- FUNCIONES AUXILIARES ---
def get_knowledge_path(guild_id: int) -> str: return os.path.join(os.path.dirname(__file__), '..', f"knowledge_{guild_id}.json")
def load_knowledge(guild_id: int) -> list:
    path = get_knowledge_path(guild_id)
    if not os.path.exists(path): return []
    with open(path, 'r', encoding='utf-8') as f: return json.load(f)
def save_knowledge(guild_id: int, data: list):
    path = get_knowledge_path(guild_id)
    with open(path, 'w', encoding='utf-8') as f: json.dump(data, f, indent=4, ensure_ascii=False)

def get_embed_config_path(guild_id: int) -> str: return os.path.join(os.path.dirname(__file__), '..', f"embed_config_{guild_id}.json")
def load_embed_config(guild_id: int) -> dict:
    path = get_embed_config_path(guild_id)
    default_config = {
        'panel': {'title': 'Sistema de Tickets', 'description': 'Haz clic para abrir un ticket.', 'color': '#ff4141', 'button_label': 'Crear Ticket', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'welcome': {'title': '¡Bienvenido, {user}!', 'description': 'Un asistente te atenderá pronto.', 'color': '#ff8282', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'ai_prompt': "Eres Anlios, un amigable y servicial asistente de IA para este servidor de Discord. Tu propósito es ayudar a los usuarios y responder sus preguntas. Para preguntas específicas sobre el servidor, consulta la siguiente 'Base de Conocimientos'. Si la respuesta no está ahí, indícalo amablemente sin inventar información. Para preguntas generales o conversacionales (como 'hola', 'cómo estás', o 'quién eres'), responde de forma natural y amigable.\n\n--- BASE DE CONOCIMIENTOS ---\n{knowledge}"
    }
    if not os.path.exists(path): return default_config
    with open(path, 'r', encoding='utf-8') as f:
        config = json.load(f)
        for embed_type in ['panel', 'welcome']:
            for key, value in default_config[embed_type].items():
                if key not in config.get(embed_type, {}):
                    if embed_type not in config: config[embed_type] = {}
                    config[embed_type][key] = value
        if 'ai_prompt' not in config: config['ai_prompt'] = default_config['ai_prompt']
        return config
def save_embed_config(guild_id: int, data: dict):
    path = get_embed_config_path(guild_id)
    with open(path, 'w', encoding='utf-8') as f: json.dump(data, f, indent=4, ensure_ascii=False)

def load_module_config() -> dict:
    if not os.path.exists(MODULE_CONFIG_FILE): return {}
    with open(MODULE_CONFIG_FILE, 'r') as f: return json.load(f)
def save_module_config(data: dict):
    with open(MODULE_CONFIG_FILE, 'w') as f: json.dump(data, f, indent=4)

def make_user_session(token=None):
    def token_updater(new_token): session['discord_token'] = new_token
    if token is None: token = session.get('discord_token')
    return OAuth2Session(CLIENT_ID, token=token, redirect_uri=REDIRECT_URI, scope=SCOPES,
                         auto_refresh_kwargs={'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET},
                         auto_refresh_url=TOKEN_URL, token_updater=token_updater)

# --- RUTAS DE LA APLICACIÓN WEB ---
@app.route("/")
def index():
    try:
        with open(BOT_GUILDS_FILE, 'r') as f: server_count = len(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError): server_count = 0
    stats = { "servers": server_count, "users": "1K+", "uptime": "99.9%" }
    return render_template("login.html", stats=stats)

@app.route("/login")
def login():
    discord = make_user_session()
    authorization_url, state = discord.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth2_state'] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    if request.values.get('error'): return request.values['error']
    discord = OAuth2Session(CLIENT_ID, state=session.get('oauth2_state'), redirect_uri=REDIRECT_URI)
    
    token_url_to_use = request.url
    if DOMAIN.startswith('http://'):
        token_url_to_use = request.url.replace('http://', 'https://', 1)

    token = discord.fetch_token(TOKEN_URL, client_secret=CLIENT_SECRET, authorization_response=token_url_to_use)
    session['discord_token'] = token
    return redirect(url_for('dashboard_home'))
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- RUTAS DEL PANEL DE CONTROL ---
@app.route("/dashboard")
def dashboard_home():
    if 'discord_token' not in session: return redirect(url_for('login'))
    discord = make_user_session()
    try:
        user_response = discord.get(f'{API_BASE_URL}/users/@me')
        if user_response.status_code != 200: return redirect(url_for('logout'))
        user_data = user_response.json()
        user_data['avatar_url'] = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"
        session['user'] = user_data
        guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
        if guilds_response.status_code != 200: return redirect(url_for('logout'))
        try:
            with open(BOT_GUILDS_FILE, 'r') as f: bot_guild_ids = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError): bot_guild_ids = []
        user_guilds = guilds_response.json()
        admin_guilds = [g for g in user_guilds if isinstance(g, dict) and (g.get('permissions', 0) & 0x8) == 0x8]
        guilds_with_bot = [g for g in admin_guilds if int(g['id']) in bot_guild_ids]
        guilds_without_bot = [g for g in admin_guilds if int(g['id']) not in bot_guild_ids]
        return render_template("select_server.html", user=session['user'], guilds_with_bot=guilds_with_bot, guilds_without_bot=guilds_without_bot, client_id=CLIENT_ID, active_guild_id=None)
    except TokenExpiredError:
        return redirect(url_for('logout'))

@app.route("/dashboard/<int:guild_id>/<page>", methods=['GET', 'POST'])
def select_page(guild_id, page):
    if 'discord_token' not in session: return redirect(url_for('login'))
    
    if request.method == 'POST':
        save_status = 'success'
        try:
            form_type = request.form.get('form_type')
            if form_type == 'toggle_module':
                module_name = request.form.get('module_name')
                is_enabled = 'enabled' in request.form
                config = load_module_config()
                if str(guild_id) not in config: config[str(guild_id)] = {}
                if 'modules' not in config[str(guild_id)]: config[str(guild_id)]['modules'] = {}
                config[str(guild_id)]['modules'][module_name] = is_enabled
                save_module_config(config)
            
            if page == 'modules':
                knowledge = load_knowledge(guild_id)
                if form_type == 'config':
                    current_config = load_embed_config(guild_id)
                    for embed_type in ['panel', 'welcome']:
                        for key in current_config[embed_type]:
                            current_config[embed_type][key] = request.form.get(f'{embed_type}_{key}')
                    current_config['ai_prompt'] = request.form.get('ai_prompt')
                    save_embed_config(guild_id, current_config)
                elif form_type == 'knowledge_add':
                    if text := request.form.get('new_knowledge'): knowledge.append(text)
                elif form_type == 'knowledge_delete':
                    if (index := request.form.get('item_index')) and 0 <= int(index) < len(knowledge): knowledge.pop(int(index))
                elif form_type == 'knowledge_web':
                    if url := request.form.get('web_url'):
                        page_req = requests.get(url, timeout=5)
                        soup = BeautifulSoup(page_req.content, 'html.parser')
                        knowledge.append(f"Contenido de {url}:\n{soup.get_text(separator=' ', strip=True)}")
                elif form_type == 'knowledge_youtube':
                    if url := request.form.get('youtube_url'):
                        video_id = url.split('v=')[1].split('&')[0]
                        transcript = YouTubeTranscriptApi.get_transcript(video_id, languages=['es', 'en'])
                        text = ' '.join([t['text'] for t in transcript])
                        knowledge.append(f"Transcripción de YouTube {url}:\n{text}")
                elif form_type == 'knowledge_pdf':
                    if 'pdf_file' in request.files and (file := request.files['pdf_file']).filename != '':
                        reader = PyPDF2.PdfReader(file.stream)
                        text = ''.join(page.extract_text() for page in reader.pages)
                        knowledge.append(f"Contenido del PDF {file.filename}:\n{text}")
                save_knowledge(guild_id, knowledge)
        except Exception as e:
            app.logger.error(f"Error saving form: {e}")
            save_status = 'error'
        return redirect(url_for('select_page', guild_id=guild_id, page=page, save=save_status))

    with open(BOT_GUILDS_FILE, 'r') as f: bot_guild_ids = json.load(f)
    discord = make_user_session()
    guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
    user_guilds = guilds_response.json()
    guilds_with_bot = [g for g in user_guilds if isinstance(g, dict) and int(g['id']) in bot_guild_ids and (g.get('permissions', 0) & 0x8) == 0x8]
    
    template_map = { "modules": "module_ticket_ia.html", "membership": "under_construction.html", "data": "under_construction.html", "customization": "under_construction.html", "settings": "under_construction.html" }
    template_to_render = template_map.get(page)

    render_data = {
        "user": session['user'], 
        "guilds_with_bot": guilds_with_bot, 
        "active_guild_id": guild_id, 
        "page": page
    }

    if page == 'modules':
        module_config = load_module_config()
        render_data['module_status'] = module_config.get(str(guild_id), {}).get('modules', {}).get('ticket_ia', False)
        
        bot_headers = {'Authorization': f'Bot {BOT_TOKEN}'}
        channels_response = requests.get(f'{API_BASE_URL}/guilds/{guild_id}/channels', headers=bot_headers)
        render_data['channels'] = [c for c in channels_response.json() if c['type'] == 0] if channels_response.status_code == 200 else []
        
        render_data['embed_config'] = load_embed_config(guild_id)
        render_data['knowledge_base'] = load_knowledge(guild_id)

    return render_template(template_to_render, **render_data)


@app.route("/dashboard/<int:guild_id>/send_panel", methods=['POST'])
def send_panel(guild_id):
    if 'discord_token' not in session: return redirect(url_for('login'))
    channel_id = int(request.form.get('channel_id'))
    command = {'command': 'send_panel', 'guild_id': guild_id, 'channel_id': channel_id}
    try:
        with open(COMMAND_QUEUE_FILE, 'r+') as f:
            queue = json.load(f); queue.append(command); f.seek(0); json.dump(queue, f, indent=4)
    except (FileNotFoundError, json.JSONDecodeError):
        with open(COMMAND_QUEUE_FILE, 'w') as f: json.dump([command], f, indent=4)
    return redirect(url_for('select_page', guild_id=guild_id, page='modules'))

if __name__ == "__main__":
    app.run(debug=True, port=5000)