from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import TokenExpiredError
import os
import json
import logging
from dotenv import load_dotenv
import requests
from bs4 import BeautifulSoup
import PyPDF2
from youtube_transcript_api import YouTubeTranscriptApi, NoTranscriptFound, TranscriptsDisabled
import redis
import time
import uuid
from datetime import datetime
import google.generativeai as genai

# --- CONFIGURACIÓN INICIAL ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
logging.basicConfig(level=logging.INFO)
env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(dotenv_path=env_path)

# --- CONFIGURACIÓN DE IA DE GEMINI ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    app.logger.warning("No se encontró la clave de API de Gemini. La demo de chat no funcionará.")

# --- CONFIGURACIÓN DE REDIS ---
try:
    redis_client = redis.from_url(os.getenv('REDIS_URL'), decode_responses=True)
    app.logger.info("Conexión con Redis establecida.")
except Exception as e:
    app.logger.error(f"No se pudo conectar a Redis: {e}")
    redis_client = None

# --- CONSTANTES ---
CLIENT_ID, CLIENT_SECRET, BOT_TOKEN = os.getenv('DISCORD_CLIENT_ID'), os.getenv('DISCORD_CLIENT_SECRET'), os.getenv('DISCORD_BOT_TOKEN')
DOMAIN = os.getenv('DOMAIN_URL', 'http://127.0.0.1:5000')
REDIRECT_URI = f'{DOMAIN}/callback'
API_BASE_URL = 'https://discord.com/api'
AUTHORIZATION_BASE_URL, TOKEN_URL = f'{API_BASE_URL}/oauth2/authorize', f'{API_BASE_URL}/oauth2/token'
SCOPES = ['identify', 'guilds']
REDIS_GUILDS_KEY = "bot_guilds_list"
REDIS_COMMAND_QUEUE_KEY = "command_queue"
REDIS_CODES_KEY = "premium_codes"
REDIS_SUBSCRIPTIONS_KEY = "subscriptions"

# --- FILTRO DE PLANTILLA PARA FECHAS ---
@app.template_filter('timestamp_to_date')
def timestamp_to_date(s):
    if not s: return "N/A"
    return datetime.fromtimestamp(s).strftime('%Y-%m-%d %H:%M:%S UTC')

# --- FUNCIONES AUXILIARES CON REDIS ---
def load_data_from_redis(key: str, default_value):
    if not redis_client: return default_value
    try:
        data = redis_client.get(key)
        return json.loads(data) if data else default_value
    except Exception as e:
        app.logger.error(f"Error cargando datos de Redis para la clave {key}: {e}")
        return default_value

def save_data_to_redis(key: str, data):
    if not redis_client: return
    try:
        redis_client.set(key, json.dumps(data))
    except Exception as e:
        app.logger.error(f"Error guardando datos en Redis para la clave {key}: {e}")

def load_ticket_config(guild_id: int) -> dict:
    default_config = {'admin_roles': []}
    return load_data_from_redis(f"ticket_config:{guild_id}", default_config)
def save_ticket_config(guild_id: int, data: dict): save_data_to_redis(f"ticket_config:{guild_id}", data)

def load_knowledge(guild_id: int) -> list: return load_data_from_redis(f"knowledge:{guild_id}", [])
def save_knowledge(guild_id: int, data: list): save_data_to_redis(f"knowledge:{guild_id}", data)

def load_embed_config(guild_id: int) -> dict:
    default_config = {
        'panel': {'title': 'Sistema de Tickets', 'description': 'Haz clic para abrir un ticket.', 'color': '#ff4141', 'button_label': 'Crear Ticket', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'welcome': {'title': '¡Bienvenido, {user}!', 'description': 'Un asistente te atenderá pronto.', 'color': '#ff8282', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'ai_prompt': "Eres Anlios, un amigable y servicial asistente de IA..."
    }
    config = load_data_from_redis(f"embed_config:{guild_id}", {})
    for key, value in default_config.items():
        if key not in config:
            config[key] = value
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_key not in config[key]:
                    config[key][sub_key] = sub_value
    return config
def save_embed_config(guild_id: int, data: dict): save_data_to_redis(f"embed_config:{guild_id}", data)

def load_module_config() -> dict: return load_data_from_redis("module_config", {})
def save_module_config(data: dict): save_data_to_redis("module_config", data)

def make_user_session(token=None):
    def token_updater(new_token): session['discord_token'] = new_token
    if token is None: token = session.get('discord_token')
    return OAuth2Session(CLIENT_ID, token=token, redirect_uri=REDIRECT_URI, scope=SCOPES,
                         auto_refresh_kwargs={'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET},
                         auto_refresh_url=TOKEN_URL, token_updater=token_updater)

# --- RUTAS DE LA APLICACIÓN WEB ---
@app.route("/")
def index():
    bot_guild_ids = load_data_from_redis(REDIS_GUILDS_KEY, [])
    stats = { "servers": len(bot_guild_ids), "users": "1K+", "uptime": "99.9%" }
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
    if DOMAIN.startswith('http://'): token_url_to_use = request.url.replace('http://', 'https://', 1)
    token = discord.fetch_token(TOKEN_URL, client_secret=CLIENT_SECRET, authorization_response=token_url_to_use)
    session['discord_token'] = token
    return redirect(url_for('dashboard_home'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route("/dashboard")
def dashboard_home():
    if 'discord_token' not in session: return redirect(url_for('login'))
    discord = make_user_session()
    try:
        user_response = discord.get(f'{API_BASE_URL}/users/@me')
        if user_response.status_code != 200: return redirect(url_for('logout'))
        user_data = user_response.json()
        user_data['avatar_url'] = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png" if user_data.get('avatar') else "https://cdn.discordapp.com/embed/avatars/0.png"
        session['user'] = user_data
        
        guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
        if guilds_response.status_code != 200: return redirect(url_for('logout'))
        
        bot_guild_ids_str = load_data_from_redis(REDIS_GUILDS_KEY, [])
        bot_guild_ids = {str(gid) for gid in bot_guild_ids_str}

        user_guilds = guilds_response.json()
        admin_guilds = [g for g in user_guilds if isinstance(g, dict) and (int(g.get('permissions', 0)) & 0x8) == 0x8]
        
        guilds_with_bot = [g for g in admin_guilds if g['id'] in bot_guild_ids]
        guilds_without_bot = [g for g in admin_guilds if g['id'] not in bot_guild_ids]
        
        return render_template("select_server.html", user=session['user'], guilds_with_bot=guilds_with_bot, guilds_without_bot=guilds_without_bot, client_id=CLIENT_ID, active_guild_id=None, page=None)
    except TokenExpiredError:
        return redirect(url_for('logout'))

@app.route("/dashboard/<guild_id>/<page>", methods=['GET', 'POST'])
def select_page(guild_id, page):
    if 'discord_token' not in session: return redirect(url_for('login'))
    guild_id_str = str(guild_id)

    if request.method == 'POST':
        save_status = 'success'
        try:
            form_type = request.form.get('form_type')
            if form_type == 'toggle_module':
                module_name = request.form.get('module_name')
                is_enabled = 'enabled' in request.form
                config = load_module_config()
                if guild_id_str not in config: config[guild_id_str] = {}
                if 'modules' not in config[guild_id_str]: config[guild_id_str]['modules'] = {}
                config[guild_id_str]['modules'][module_name] = is_enabled
                save_module_config(config)
            
            elif form_type == 'config':
                current_config = load_embed_config(int(guild_id_str))
                for embed_type in ['panel', 'welcome']:
                    for key in current_config[embed_type]:
                        current_config[embed_type][key] = request.form.get(f'{embed_type}_{key}')
                current_config['ai_prompt'] = request.form.get('ai_prompt')
                save_embed_config(int(guild_id_str), current_config)
                
                admin_roles = request.form.getlist('admin_roles')
                ticket_config = load_ticket_config(int(guild_id_str))
                ticket_config['admin_roles'] = [int(role_id) for role_id in admin_roles]
                save_ticket_config(int(guild_id_str), ticket_config)

            elif form_type == 'knowledge_add':
                knowledge = load_knowledge(int(guild_id_str))
                if text := request.form.get('new_knowledge'): knowledge.append(text)
                save_knowledge(int(guild_id_str), knowledge)
            elif form_type == 'knowledge_delete':
                knowledge = load_knowledge(int(guild_id_str))
                if (index := request.form.get('item_index')) and 0 <= int(index) < len(knowledge): knowledge.pop(int(index))
                save_knowledge(int(guild_id_str), knowledge)
        except Exception as e:
            app.logger.error(f"Error saving form: {e}")
            save_status = 'error'
        return redirect(url_for('select_page', guild_id=guild_id_str, page=page, save=save_status))

    discord = make_user_session()
    guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
    user_guilds = guilds_response.json()
    
    bot_guild_ids_str = load_data_from_redis(REDIS_GUILDS_KEY, [])
    bot_guild_ids = {str(gid) for gid in bot_guild_ids_str}
    
    admin_guilds = [g for g in user_guilds if isinstance(g, dict) and (int(g.get('permissions', 0)) & 0x8) == 0x8]
    guilds_with_bot = [g for g in admin_guilds if g['id'] in bot_guild_ids]
    guilds_without_bot = [g for g in admin_guilds if g['id'] not in bot_guild_ids]

    template_map = { "modules": "module_ticket_ia.html", "membership": "membership.html", "data": "under_construction.html", "customization": "under_construction.html", "settings": "under_construction.html" }
    template_to_render = template_map.get(page)
    
    render_data = { "user": session['user'], "guilds_with_bot": guilds_with_bot, "guilds_without_bot": guilds_without_bot, "client_id": CLIENT_ID, "active_guild_id": guild_id_str, "page": page }
    
    if page == 'modules':
        module_config = load_module_config()
        render_data['module_status'] = module_config.get(guild_id_str, {}).get('modules', {}).get('ticket_ia', False)
        bot_headers = {'Authorization': f'Bot {BOT_TOKEN}'}
        channels_response = requests.get(f'{API_BASE_URL}/guilds/{guild_id_str}/channels', headers=bot_headers)
        render_data['channels'] = [c for c in channels_response.json() if c['type'] == 0] if channels_response.status_code == 200 else []
        roles_response = requests.get(f'{API_BASE_URL}/guilds/{guild_id_str}/roles', headers=bot_headers)
        if roles_response.status_code == 200:
            all_roles = roles_response.json()
            render_data['roles'] = [r for r in all_roles if r['name'] != '@everyone' and not r.get('tags', {}).get('bot_id')]
        else:
            render_data['roles'] = []
        render_data['embed_config'] = load_embed_config(int(guild_id_str))
        render_data['knowledge_base'] = load_knowledge(int(guild_id_str))
        render_data['ticket_config'] = load_ticket_config(int(guild_id_str))
        
    return render_template(template_to_render, **render_data)

@app.route("/dashboard/<guild_id>/send_panel", methods=['POST'])
def send_panel(guild_id):
    if 'discord_token' not in session: return redirect(url_for('login'))
    if not redis_client: return redirect(url_for('select_page', guild_id=guild_id, page='modules'))
    channel_id = int(request.form.get('channel_id'))
    command = {'command': 'send_panel', 'guild_id': int(guild_id), 'channel_id': channel_id}
    redis_client.lpush(REDIS_COMMAND_QUEUE_KEY, json.dumps(command))
    return redirect(url_for('select_page', guild_id=guild_id, page='modules'))

# --- RUTAS PARA LA DEMO ---
@app.route("/demo_chat", methods=['POST'])
def demo_chat():
    if not GEMINI_API_KEY: return jsonify({'reply': 'Error: La API de IA no está configurada en el servidor.'}), 500
    data = request.json
    try:
        knowledge_text = "\n".join(f"- {item}" for item in data['knowledge'].splitlines() if item) if data.get('knowledge') else "No hay información."
        final_prompt = f"{data['prompt'].replace('{knowledge}', knowledge_text)}\n\n--- CONVERSACIÓN ---\nUsuario: {data['message']}\nAnlios:"
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(final_prompt)
        return jsonify({'reply': response.text})
    except Exception as e:
        app.logger.error(f"Error en la API de Gemini durante la demo: {e}")
        return jsonify({'reply': 'Ocurrió un error al procesar la respuesta de la IA.'}), 500

@app.route("/demo_extract_knowledge", methods=['POST'])
def demo_extract_knowledge():
    source_type = request.form.get('source_type')
    text = ""
    try:
        if source_type == 'web':
            url = request.form.get('url')
            page_req = requests.get(url, timeout=10)
            page_req.raise_for_status()
            soup = BeautifulSoup(page_req.content, 'html.parser')
            text = f"Contenido de {url}:\n{soup.get_text(separator=' ', strip=True)}"
        elif source_type == 'youtube':
            url = request.form.get('url')
            if 'v=' not in url: raise ValueError("URL de YouTube no válida.")
            video_id = url.split('v=')[1].split('&')[0]
            transcript = YouTubeTranscriptApi.get_transcript(video_id, languages=['es', 'en'])
            text = f"Transcripción de YouTube {url}:\n{' '.join([t['text'] for t in transcript])}"
        elif source_type == 'pdf':
            if 'file' not in request.files: raise ValueError("No se encontró el archivo PDF.")
            file = request.files['file']
            if file.filename == '': raise ValueError("No se seleccionó ningún archivo.")
            reader = PyPDF2.PdfReader(file.stream)
            pdf_text = ''.join(page.extract_text() for page in reader.pages)
            text = f"Contenido del PDF {file.filename}:\n{pdf_text}"
        else:
            return jsonify({'success': False, 'error': 'Tipo de fuente no válido.'}), 400
        return jsonify({'success': True, 'text': text})
    except (NoTranscriptFound, TranscriptsDisabled):
        return jsonify({'success': False, 'error': 'No se encontraron transcripciones o están desactivadas para este video.'}), 400
    except Exception as e:
        app.logger.error(f"Error en la extracción de conocimiento para demo: {e}")
        return jsonify({'success': False, 'error': f'Error al procesar la fuente: {e}'}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)