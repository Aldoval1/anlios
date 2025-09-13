from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
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
from datetime import datetime, timedelta
import google.generativeai as genai
import re
from functools import wraps

# --- CONFIGURACIÓN INICIAL ---
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'super-secret-key-for-dev')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
logging.basicConfig(level=logging.INFO)
env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(dotenv_path=env_path)

# --- Lógica de Traducción ---
translations = {}
try:
    with open(os.path.join(os.path.dirname(__file__), 'translations.json'), 'r', encoding='utf-8') as f:
        translations = json.load(f)
except Exception as e:
    app.logger.error(f"No se pudo cargar el archivo de traducciones: {e}")

def get_translation(text_key):
    """Obtiene una traducción para ser usada dentro de las rutas de Flask."""
    lang = g.get('lang', 'en')
    return translations.get(lang, {}).get(text_key, text_key)

@app.before_request
def before_request_lang():
    if 'lang' not in session:
        browser_lang = request.headers.get('Accept-Language', 'en')
        if browser_lang.lower().startswith('es'):
            session['lang'] = 'es'
        else:
            session['lang'] = 'en'

    g.lang = session.get('lang', 'en')

@app.context_processor
def inject_translations():
    def _(text_key):
        return translations.get(g.lang, {}).get(text_key, text_key)
    return dict(_=_)

# --- CONFIGURACIÓN DE IA DE GEMINI ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    app.logger.warning("No se encontró la clave de API de Gemini. La demo de chat no funcionará.")

# --- CONFIGURACIÓN DE REDIS ---
try:
    r = redis.from_url(os.getenv('REDIS_URL'), decode_responses=True)
    app.logger.info("Conexión con Redis establecida.")
except Exception as e:
    app.logger.error(f"No se pudo conectar a Redis: {e}")
    r = None

# --- CONSTANTES ---
CLIENT_ID, CLIENT_SECRET, BOT_TOKEN = os.getenv('DISCORD_CLIENT_ID'), os.getenv('DISCORD_CLIENT_SECRET'), os.getenv('DISCORD_BOT_TOKEN')
DOMAIN = os.getenv('DOMAIN_URL', 'http://127.0.0.1:5000')

def get_redirect_uri():
    protocol = 'https' if request.headers.get('X-Forwarded-Proto') == 'https' or request.is_secure else 'http'
    return f"{protocol}://{request.host}/callback"

API_BASE_URL = 'https://discord.com/api'
AUTHORIZATION_BASE_URL, TOKEN_URL = f'{API_BASE_URL}/oauth2/authorize', f'{API_BASE_URL}/oauth2/token'
SCOPES = ['identify', 'guilds']
REDIS_GUILDS_KEY = "bot_guilds_list"
REDIS_COMMAND_QUEUE_KEY = "command_queue"
REDIS_TRAINING_QUEUE_KEY = "training_queue"
REDIS_LOG_KEY = "dashboard_audit_log"


# Middleware para el Modo Mantenimiento
@app.before_request
def check_for_maintenance():
    if request.path.startswith('/static'):
        return

    if not r:
        return

    maintenance_config = r.hgetall('maintenance_status')
    maintenance_mode = maintenance_config.get('status', 'disabled')

    if maintenance_mode != 'enabled':
        return

    if session.get('is_tester'):
        return

    allowed_paths = [
        url_for('maintenance'),
        url_for('login'),
        url_for('logout'),
        url_for('callback')
    ]
    if request.path in allowed_paths or '/language/' in request.path:
        return

    return redirect(url_for('maintenance'))

# --- DECORADOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'discord_token' not in session:
            flash("Tu sesión ha caducado. Por favor, inicia sesión de nuevo.", "warning")
            return redirect(url_for('login'))

        if 'user' not in session:
            discord = make_user_session()
            try:
                user_response = discord.get(f'{API_BASE_URL}/users/@me')
                user_response.raise_for_status()
                user_data = user_response.json()
                user_data['avatar_url'] = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png" if user_data.get('avatar') else "https://cdn.discordapp.com/embed/avatars/0.png"
                session['user'] = user_data

            except TokenExpiredError:
                session.clear()
                flash("Tu sesión ha caducado. Por favor, inicia sesión de nuevo.", "warning")
                return redirect(url_for('login'))

            except requests.exceptions.RequestException as e:
                session.clear()
                app.logger.error(f"Error al obtener datos del usuario durante la comprobación de login_required: {e}")
                flash("No se pudo conectar con Discord. Por favor, inténtalo de nuevo más tarde.", "danger")
                return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

# --- FILTRO DE PLANTILLA ---
@app.template_filter('timestamp_to_date')
def timestamp_to_date(s):
    if not s: return "N/A"
    try:
        if isinstance(s, str):
            dt_object = datetime.fromisoformat(s)
        else:
            dt_object = datetime.fromtimestamp(float(s))
        return dt_object.strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, TypeError):
        return "Fecha inválida"


# --- FUNCIONES AUXILIARES ---
def log_action(user, action, details):
    if not r: return
    log_entry = {
        "timestamp": time.time(),
        "user": user,
        "action": action,
        "details": details
    }
    r.lpush(REDIS_LOG_KEY, json.dumps(log_entry))
    r.ltrim(REDIS_LOG_KEY, 0, 999)

def load_data_from_redis(key: str, default_value):
    if not r: return default_value
    try:
        data = r.get(key)
        return json.loads(data) if data else default_value
    except Exception as e:
        app.logger.error(f"Error al cargar datos de Redis para la clave {key}: {e}")
        return default_value

def save_data_to_redis(key: str, data):
    if not r: return
    try:
        r.set(key, json.dumps(data))
    except Exception as e:
        app.logger.error(f"Error al guardar datos en Redis para la clave {key}: {e}")

def get_guild_data_bot(guild_id):
    headers = {'Authorization': f'Bot {BOT_TOKEN}'}
    response = requests.get(f'{API_BASE_URL}/guilds/{guild_id}', headers=headers)
    return response.json() if response.status_code == 200 else None

def get_guild_channels_bot(guild_id):
    headers = {'Authorization': f'Bot {BOT_TOKEN}'}
    response = requests.get(f'{API_BASE_URL}/guilds/{guild_id}/channels', headers=headers)
    if response.status_code == 200:
        return sorted(response.json(), key=lambda x: x.get('position', 0))
    return []

def get_guild_roles_bot(guild_id):
    headers = {'Authorization': f'Bot {BOT_TOKEN}'}
    response = requests.get(f'{API_BASE_URL}/guilds/{guild_id}/roles', headers=headers)
    if response.status_code == 200:
        return sorted(response.json(), key=lambda x: x.get('position', 0), reverse=True)
    return []

def load_ticket_config(guild_id: int) -> dict:
    default_config = {'admin_roles': [], 'log_enabled': False, 'log_channel_id': None, 'language': 'es'}
    config = load_data_from_redis(f"ticket_config:{guild_id}", default_config)
    config.setdefault('log_enabled', False)
    config.setdefault('log_channel_id', None)
    config.setdefault('language', 'es')
    return config

def save_ticket_config(guild_id: int, data: dict): save_data_to_redis(f"ticket_config:{guild_id}", data)
def load_knowledge(guild_id: int) -> list: return load_data_from_redis(f"knowledge:{guild_id}", [])
def save_knowledge(guild_id: int, data: list): save_data_to_redis(f"knowledge:{guild_id}", data)

def load_embed_config(guild_id: int) -> dict:
    default_personality = "Eres Anlios, un amigable y servicial asistente de IA."
    default_prompt_template = (
        "{personality}\n\n"
        "Tu propósito es ayudar a los usuarios y responder sus preguntas. "
        "Para preguntas específicas sobre el servidor, consulta la siguiente 'Base de Conocimientos'. "
        "Si la respuesta no está ahí, DEBES empezar tu respuesta única y exclusivamente con la etiqueta [NO_KNOWLEDGE] y nada más. "
        "Para preguntas generales o conversacionales (como 'hola', 'cómo estás', 'quién eres'), responde de forma natural y amigable.\n\n"
        "--- BASE DE CONOCIMIENTOS ---\n{knowledge}"
    )

    default_config = {
        'panel': {'title': 'Sistema de Tickets', 'description': 'Haz clic para abrir un ticket.', 'color': '#ff4141', 'button_label': 'Crear Ticket', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'welcome': {'title': '¡Bienvenido, {user}!', 'description': 'Un asistente te atenderá pronto.', 'color': '#ff8282', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'ai_prompt': default_prompt_template.format(personality=default_personality, knowledge="{knowledge}"),
        'ai_personality': default_personality
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

def load_moderation_config(guild_id: int) -> dict:
    default_config = {
        "automod": {
            "enabled": False, "forbidden_words": [], "forbidden_words_action": "delete",
            "block_links": False, "block_links_action": "delete",
            "block_nsfw": False, "block_nsfw_action": "delete"
        },
        "warnings": {"enabled": False, "limit": 3, "dm_user": True},
        "commands": {"enabled": False, "cleanc": False, "lock": False},
        "vault": {"enabled": False}
    }
    config = load_data_from_redis(f"moderation_config:{guild_id}", {})
    for section, defaults in default_config.items():
        if section not in config:
            config[section] = defaults
        else:
            for key, value in defaults.items():
                config[section].setdefault(key, value)
    return config

def save_moderation_config(guild_id: int, data: dict):
    save_data_to_redis(f"moderation_config:{guild_id}", data)

def load_warnings_log(guild_id: int) -> dict:
    return load_data_from_redis(f"warnings_log:{guild_id}", {})

def save_warnings_log(guild_id: int, data: dict):
    save_data_to_redis(f"warnings_log:{guild_id}", data)

def load_backups(guild_id: int) -> list:
    return load_data_from_redis(f"backups:{guild_id}", [])

def save_backups(guild_id: int, data: list):
    save_data_to_redis(f"backups:{guild_id}", data)

def make_user_session(token=None):
    def token_updater(new_token): session['discord_token'] = new_token
    if token is None: token = session.get('discord_token')
    return OAuth2Session(CLIENT_ID, token=token, redirect_uri=get_redirect_uri(), scope=SCOPES,
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
    if 'discord_token' in session:
        return redirect(url_for('dashboard_home'))
    discord = make_user_session()
    authorization_url, state = discord.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth2_state'] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    if request.values.get('error'):
        return request.values['error']

    redirect_uri = get_redirect_uri()
    state = session.get('oauth2_state')

    if state is None:
        app.logger.warning("oauth2_state no encontrado en la sesión durante el callback. El usuario podría tener las cookies desactivadas o la sesión expiró.")
        flash("Tu sesión de autenticación ha expirado o es inválida. Por favor, intenta iniciar sesión de nuevo.", "warning")
        return redirect(url_for('login'))

    discord = OAuth2Session(CLIENT_ID, state=state, redirect_uri=redirect_uri)

    try:
        token = discord.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url
        )
        session['discord_token'] = token
        session.pop('oauth2_state', None)  # Limpiar el estado de la sesión
    except Exception as e:
        app.logger.error(f"Error al obtener token de Discord: {e}")
        flash("Error de autenticación. Por favor, inténtalo de nuevo.", "danger")
        return redirect(url_for('login'))

    return redirect(url_for('dashboard_home'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/language/<lang>')
def set_language(lang):
    if lang in ['es', 'en']:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

@app.route('/maintenance', methods=['GET', 'POST'])
def maintenance():
    if not r:
        return "Error: No se puede conectar a la base de datos.", 500

    maintenance_config = r.hgetall('maintenance_status')
    if maintenance_config.get('status', 'disabled') == 'disabled' and not session.get('is_tester'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        tester_password = maintenance_config.get('tester_password', 'NO_PASSWORD_SET_XYZ')
        if tester_password and request.form.get('password') == tester_password:
            session['is_tester'] = True
            return redirect(url_for('dashboard_home'))
        else:
            flash("Contraseña de Tester incorrecta.", "error")
            return render_template('maintenance.html', error="Contraseña incorrecta")

    return render_template('maintenance.html')


@app.route("/dashboard")
@login_required
def dashboard_home():
    discord = make_user_session()
    try:
        guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
        if guilds_response.status_code in [401, 403]:
            return redirect(url_for('logout'))
        guilds_response.raise_for_status()

        bot_guild_ids = {str(gid) for gid in load_data_from_redis(REDIS_GUILDS_KEY, [])}
        user_guilds = guilds_response.json()
        admin_guilds = [g for g in user_guilds if isinstance(g, dict) and (int(g.get('permissions', 0)) & 0x8) == 0x8]

        guilds_with_bot = [g for g in admin_guilds if g['id'] in bot_guild_ids]

        last_guild_id = session.get('active_guild_id')
        if last_guild_id and any(g['id'] == last_guild_id for g in guilds_with_bot):
            return redirect(url_for('select_page', guild_id=last_guild_id, page='modules'))
        elif guilds_with_bot:
            return redirect(url_for('select_page', guild_id=guilds_with_bot[0]['id'], page='modules'))

        guilds_without_bot = [g for g in admin_guilds if g['id'] not in bot_guild_ids]
        return render_template("select_server.html", user=session['user'], guilds_with_bot=guilds_with_bot, guilds_without_bot=guilds_without_bot, client_id=CLIENT_ID, active_guild_id=None, page=None)

    except TokenExpiredError:
        return redirect(url_for('logout'))
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error al obtener los servidores de Discord: {e}")
        flash("No se pudieron obtener tus servidores de Discord. Por favor, inténtalo de nuevo más tarde.", "warning")
        return render_template("select_server.html", user=session['user'], guilds_with_bot=[], guilds_without_bot=[], client_id=CLIENT_ID, active_guild_id=None, page=None)

@app.route("/dashboard/profile")
@login_required
def profile_page():
    discord = make_user_session()
    guilds_with_bot = []
    guilds_without_bot = []

    try:
        guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
        if guilds_response.status_code in [401, 403]:
            return redirect(url_for('logout'))
        guilds_response.raise_for_status()

        bot_guild_ids = {str(gid) for gid in load_data_from_redis(REDIS_GUILDS_KEY, [])}
        user_guilds = guilds_response.json()
        admin_guilds = [g for g in user_guilds if isinstance(g, dict) and (int(g.get('permissions', 0)) & 0x8) == 0x8]

        guilds_with_bot = [g for g in admin_guilds if g['id'] in bot_guild_ids]
        guilds_without_bot = [g for g in admin_guilds if g['id'] not in bot_guild_ids]

    except TokenExpiredError:
        return redirect(url_for('logout'))
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error al obtener los servidores de Discord en la página de perfil: {e}")
        flash("No se pudieron obtener tus servidores de Discord. Por favor, inténtalo de nuevo más tarde.", "warning")

    module_config = load_module_config()
    module_statuses = {
        'ticket_ia': module_config.get(session.get('active_guild_id', ''), {}).get('modules', {}).get('ticket_ia', False),
        'moderation': module_config.get(session.get('active_guild_id', ''), {}).get('modules', {}).get('moderation', False),
        'designer': module_config.get(session.get('active_guild_id', ''), {}).get('modules', {}).get('designer', False)
    }

    return render_template("profile.html",
                           user=session['user'],
                           guilds_with_bot=guilds_with_bot,
                           guilds_without_bot=guilds_without_bot,
                           client_id=CLIENT_ID,
                           active_guild_id=None,
                           page='profile',
                           module_statuses=module_statuses)

@app.route("/dashboard/<int:guild_id>/membership", methods=['GET', 'POST'])
@login_required
def membership(guild_id):
    if not r:
        flash("Error de conexión con la base de datos.", "danger")
        return redirect(url_for('dashboard_home'))

    discord = make_user_session()
    try:
        guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
        if guilds_response.status_code != 200:
            flash("No se pudo obtener la lista de servidores de Discord.", "danger")
            return redirect(url_for('dashboard_home'))

        user_guilds = guilds_response.json()
        bot_guild_ids = {str(gid) for gid in load_data_from_redis(REDIS_GUILDS_KEY, [])}
        admin_guilds = [g for g in user_guilds if isinstance(g, dict) and (int(g.get('permissions', 0)) & 0x8) == 0x8]
        guilds_with_bot = [g for g in admin_guilds if g['id'] in bot_guild_ids]
        guilds_without_bot = [g for g in admin_guilds if g['id'] not in bot_guild_ids]

        current_guild = next((g for g in user_guilds if g['id'] == str(guild_id)), None)

        if not current_guild:
            flash("Servidor no encontrado o no tienes permisos.", "danger")
            return redirect(url_for('dashboard_home'))

        if request.method == 'POST':
            code = request.form.get('premium_code', '').strip()
            if not code:
                flash('Debes introducir un código para canjear.', 'warning')
            else:
                code_key = f"premium_code:{code}"
                if not r.exists(code_key):
                    flash('El código premium introducido no es válido o no existe.', 'danger')
                else:
                    code_data = r.hgetall(code_key)
                    if code_data.get('is_used') == 'True':
                        flash(f"Este código ya fue canjeado en el servidor ID: {code_data.get('used_by_guild', 'N/A')}", 'danger')
                    else:
                        duration_days = int(code_data.get('duration_days', 0))

                        r.hset(code_key, mapping={'is_used': 'True', 'used_by_guild': str(guild_id)})

                        sub_key = f"subscription:{guild_id}"
                        current_sub = r.hgetall(sub_key)
                        start_date = datetime.utcnow()

                        if current_sub and 'expires_at' in current_sub:
                            current_expiry = datetime.fromisoformat(current_sub['expires_at'])
                            if current_expiry > start_date:
                                start_date = current_expiry

                        expires_at = start_date + timedelta(days=duration_days)

                        r.hset(sub_key, mapping={
                            'status': 'active', 'expires_at': expires_at.isoformat(),
                            'redeemed_at': datetime.utcnow().isoformat(), 'last_code_used': code
                        })

                        flash(f'¡Felicidades! La membresía premium ha sido activada o extendida por {duration_days} días.', 'success')
                        return redirect(url_for('membership', guild_id=guild_id))

        sub_info = r.hgetall(f"subscription:{guild_id}")
        time_left, is_active = None, False
        if sub_info and sub_info.get('status') == 'active':
            expires_at_str = sub_info.get('expires_at')
            if expires_at_str:
                expires_at = datetime.fromisoformat(expires_at_str)
                if expires_at > datetime.utcnow():
                    time_left = expires_at - datetime.utcnow()
                    is_active = True
                else:
                    r.hset(f"subscription:{guild_id}", 'status', 'expired')
                    sub_info['status'] = 'expired'

        module_config = load_module_config()
        module_statuses = {
            'ticket_ia': module_config.get(str(guild_id), {}).get('modules', {}).get('ticket_ia', False),
            'moderation': module_config.get(str(guild_id), {}).get('modules', {}).get('moderation', False),
            'designer': module_config.get(str(guild_id), {}).get('modules', {}).get('designer', False)
        }

        return render_template('membership.html',
                               user=session.get('user'),
                               guilds_with_bot=guilds_with_bot,
                               guilds_without_bot=guilds_without_bot,
                               client_id=CLIENT_ID,
                               active_guild_id=str(guild_id),
                               guild=current_guild,
                               sub_info=sub_info,
                               time_left=time_left,
                               is_active=is_active,
                               page='membership',
                               module_statuses=module_statuses)

    except TokenExpiredError:
        return redirect(url_for('logout'))
    except Exception as e:
        app.logger.error(f"Error en la página de membresía: {e}")
        flash("Ocurrió un error inesperado.", "danger")
        return redirect(url_for('dashboard_home'))


@app.route("/dashboard/<guild_id>/<page>", methods=['GET', 'POST'])
@login_required
def select_page(guild_id, page):
    session['active_guild_id'] = guild_id
    guild_id_int = int(guild_id)

    if request.method == 'POST':
        try:
            user_info = session.get('user', {'username': 'Desconocido', 'id': 'Desconocido'})

            if 'action_remove_warning' in request.form:
                user_id_to_clear = request.form.get('action_remove_warning')
                warnings_log = load_warnings_log(guild_id_int)
                if user_id_to_clear in warnings_log and warnings_log[user_id_to_clear]['warnings']:
                    warnings_log[user_id_to_clear]['warnings'].pop()
                    if not warnings_log[user_id_to_clear]['warnings']:
                        del warnings_log[user_id_to_clear]
                    save_warnings_log(guild_id_int, warnings_log)
                    flash("Última advertencia eliminada.", "success")
                else:
                    flash("El usuario no tiene advertencias para eliminar.", "warning")
                return redirect(url_for('select_page', guild_id=guild_id, page='moderation'))

            elif 'action_delete_backup' in request.form:
                backup_id_to_delete = request.form.get('action_delete_backup')
                backups = load_backups(guild_id_int)
                new_backups = [b for b in backups if b['id'] != backup_id_to_delete]
                if len(new_backups) < len(backups):
                    save_backups(guild_id_int, new_backups)
                    flash("Backup eliminado.", "success")
                else:
                    flash("No se encontró el backup a eliminar.", "danger")
                return redirect(url_for('select_page', guild_id=guild_id, page='moderation'))

            action = request.form.get('action')
            if action == 'toggle_module':
                config = load_module_config()
                if guild_id not in config: config[guild_id] = {'modules': {}}
                is_enabled = 'enabled' in request.form
                config[guild_id]['modules']['ticket_ia'] = is_enabled
                save_module_config(config)
                log_action(user_info, "Módulo Activado/Desactivado", {"guild_id": guild_id, "module": "ticket_ia", "enabled": is_enabled})
                flash("Módulo Ticket I.A actualizado.", "success")
                return redirect(url_for('select_page', guild_id=guild_id, page='modules'))

            elif action == 'toggle_moderation_module':
                config = load_module_config()
                if guild_id not in config: config[guild_id] = {'modules': {}}
                is_enabled = 'enabled' in request.form
                config[guild_id]['modules']['moderation'] = is_enabled
                save_module_config(config)
                log_action(user_info, "Módulo Activado/Desactivado", {"guild_id": guild_id, "module": "moderation", "enabled": is_enabled})
                flash("Módulo de Moderación actualizado.", "success")
                return redirect(url_for('select_page', guild_id=guild_id, page='moderation'))

            elif action == 'toggle_designer_module':
                config = load_module_config()
                if guild_id not in config: config[guild_id] = {'modules': {}}
                is_enabled = 'enabled' in request.form
                config[guild_id]['modules']['designer'] = is_enabled
                save_module_config(config)
                log_action(user_info, "Módulo Activado/Desactivado", {"guild_id": guild_id, "module": "designer", "enabled": is_enabled})
                flash("Módulo Diseñador actualizado.", "success")
                return redirect(url_for('select_page', guild_id=guild_id, page='designer'))

            elif action == 'save_moderation':
                config = load_moderation_config(guild_id_int)
                config['automod']['enabled'] = 'automod_enabled' in request.form
                config['automod']['forbidden_words'] = [word.strip() for word in request.form.get('forbidden_words', '').splitlines() if word.strip()]
                config['automod']['forbidden_words_action'] = request.form.get('forbidden_words_action')
                config['automod']['block_links'] = 'block_links' in request.form
                config['automod']['block_links_action'] = request.form.get('block_links_action')
                config['automod']['block_nsfw'] = 'block_nsfw' in request.form
                config['automod']['block_nsfw_action'] = request.form.get('block_nsfw_action')
                config['warnings']['enabled'] = 'warnings_enabled' in request.form
                config['warnings']['limit'] = int(request.form.get('warning_limit', 3))
                config['warnings']['dm_user'] = 'warn_dm_user' in request.form
                config['commands']['enabled'] = 'commands_enabled' in request.form
                config['commands']['cleanc'] = 'command_cleanc_enabled' in request.form
                config['commands']['lock'] = 'command_lock_enabled' in request.form
                config['vault']['enabled'] = 'vault_enabled' in request.form
                save_moderation_config(guild_id_int, config)
                log_action(user_info, "Guardada Configuración de Moderación", {"guild_id": guild_id})
                flash("Configuración de moderación guardada con éxito.", "success")
                return redirect(url_for('select_page', guild_id=guild_id, page='moderation'))

            elif action == 'create_backup':
                command = {'command': 'create_backup', 'guild_id': guild_id_int, 'user_id': user_info['id']}
                r.lpush(REDIS_COMMAND_QUEUE_KEY, json.dumps(command))
                flash("La creación del backup se ha puesto en cola. Aparecerá en la lista en breve.", "info")
                return redirect(url_for('select_page', guild_id=guild_id, page='moderation'))

            elif action == 'save_all':
                log_action(user_info, "Guardada Configuración Completa", {"guild_id": guild_id, "form_data": request.form.to_dict()})
                ticket_config = load_ticket_config(guild_id_int)
                log_enabled = 'log_enabled' in request.form
                log_channel_id = request.form.get('log_channel_id')

                if log_enabled and not log_channel_id:
                    flash("Debes seleccionar un canal de logs si la opción está activada.", "log_error")
                else:
                    current_config = load_embed_config(guild_id_int)
                    for embed_type in ['panel', 'welcome']:
                        for key in current_config[embed_type]:
                            current_config[embed_type][key] = request.form.get(f'{embed_type}_{key}', current_config[embed_type][key])

                    personality = request.form.get('ai_personality', "Eres Anlios, un amigable y servicial asistente de IA.")
                    prompt_template = (
                        "{personality}\n\n"
                        "Tu propósito es ayudar a los usuarios y responder sus preguntas. "
                        "Para preguntas específicas sobre el servidor, consulta la siguiente 'Base de Conocimientos'. "
                        "Si la respuesta no está ahí, DEBES empezar tu respuesta única y exclusivamente con la etiqueta [NO_KNOWLEDGE] y nada más. "
                        "Para preguntas generales o conversacionales (como 'hola', 'cómo estás', o 'quién eres'), responde de forma natural y amigable.\n\n"
                        "--- BASE DE CONOCIMIENTOS ---\n{knowledge}"
                    )
                    full_prompt = prompt_template.format(personality=personality, knowledge="{knowledge}")

                    current_config['ai_personality'] = personality
                    current_config['ai_prompt'] = full_prompt

                    save_embed_config(guild_id_int, current_config)

                    admin_roles = json.loads(request.form.get('admin_roles_json', '[]'))
                    ticket_config['admin_roles'] = [str(role_id) for role_id in admin_roles]
                    ticket_config['log_enabled'] = log_enabled
                    ticket_config['log_channel_id'] = log_channel_id
                    ticket_config['language'] = request.form.get('bot_language', 'es')
                    save_ticket_config(guild_id_int, ticket_config)

                    flash("Configuración guardada con éxito.", "success")

            elif action in ['knowledge_web', 'knowledge_youtube', 'knowledge_pdf']:
                try:
                    knowledge_item = {}
                    if action == 'knowledge_web':
                        url = request.form.get('web_url')
                        if not url: raise ValueError("La URL no puede estar vacía.")
                        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
                        page_req = requests.get(url, timeout=30, headers=headers)
                        page_req.raise_for_status()
                        soup = BeautifulSoup(page_req.content, 'html.parser')
                        knowledge_item = {"type": "web", "source": url, "content": soup.get_text(separator=' ', strip=True)}
                    elif action == 'knowledge_youtube':
                        url = request.form.get('youtube_url')
                        if not url: raise ValueError("La URL no puede estar vacía.")
                        video_id_match = re.search(r'(?:v=|\/|youtu\.be\/|embed\/)([a-zA-Z0-9_-]{11})', url)
                        if not video_id_match: raise ValueError("URL de YouTube no válida o ID no encontrado.")
                        video_id = video_id_match.group(1)
                        try:
                            transcript_list = YouTubeTranscriptApi.list_transcripts(video_id)
                            transcript = transcript_list.find_transcript(['es', 'en'])
                            transcript_data = transcript.fetch()
                            transcript_text = ' '.join([t['text'] for t in transcript_data])
                            knowledge_item = {"type": "youtube", "source": url, "content": transcript_text}
                        except (NoTranscriptFound, TranscriptsDisabled):
                            raise ValueError("No se pudieron obtener los subtítulos para este video.")
                    elif action == 'knowledge_pdf':
                        if 'pdf_file' not in request.files: raise ValueError("No se encontró el archivo PDF.")
                        file = request.files['file']
                        if file.filename == '': raise ValueError("No se seleccionó ningún archivo.")
                        reader = PyPDF2.PdfReader(file.stream)
                        pdf_text = ''.join(page.extract_text() for page in reader.pages)
                        knowledge_item = {"type": "pdf", "filename": file.filename, "content": pdf_text}

                    if knowledge_item:
                        knowledge = load_knowledge(guild_id_int)
                        knowledge.append(knowledge_item)
                        save_knowledge(guild_id_int, knowledge)
                        flash("Conocimiento añadido con éxito desde la fuente externa.", "success")
                except Exception as e:
                    flash(f"Error al procesar la fuente: {e}", "danger")
                return redirect(url_for('select_page', guild_id=guild_id, page='modules'))
        except Exception as e:
            app.logger.error(f"Error al procesar formulario: {e}")
            flash(f"Error al guardar: {e}", "danger")

    discord = make_user_session()
    guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
    if guilds_response.status_code != 200: return redirect(url_for('logout'))

    user_guilds = guilds_response.json()
    bot_guild_ids = {str(gid) for gid in load_data_from_redis(REDIS_GUILDS_KEY, [])}
    admin_guilds = [g for g in user_guilds if isinstance(g, dict) and (int(g.get('permissions', 0)) & 0x8) == 0x8]

    guilds_with_bot = [g for g in admin_guilds if g['id'] in bot_guild_ids]
    guilds_without_bot = [g for g in admin_guilds if g['id'] not in bot_guild_ids]

    module_config = load_module_config()

    module_statuses = {
        'ticket_ia': module_config.get(guild_id, {}).get('modules', {}).get('ticket_ia', False),
        'moderation': module_config.get(guild_id, {}).get('modules', {}).get('moderation', False),
        'designer': module_config.get(guild_id, {}).get('modules', {}).get('designer', False)
    }

    module_status = module_statuses.get('designer' if page == 'designer' else 'moderation' if page == 'moderation' else 'ticket_ia', False)

    current_guild = next((g for g in user_guilds if g['id'] == guild_id), None)

    render_data = {
        "user": session['user'], "guilds_with_bot": guilds_with_bot, "guilds_without_bot": guilds_without_bot,
        "client_id": CLIENT_ID, "active_guild_id": guild_id, "page": page,
        "module_status": module_status, "module_statuses": module_statuses, "guild": current_guild
    }

    template_map = {"modules": "module_ticket_ia.html", "profile": "profile.html", "training": "training.html", "moderation": "module_moderation.html", "membership": "membership.html", "designer": "module_designer.html"}
    template_to_render = template_map.get(page, "under_construction.html")

    if page in ['modules', 'training', 'membership']:
        bot_headers = {'Authorization': f'Bot {BOT_TOKEN}'}
        channels_response = requests.get(f'{API_BASE_URL}/guilds/{guild_id}/channels', headers=bot_headers)
        render_data['channels'] = [c for c in channels_response.json() if c['type'] == 0] if channels_response.status_code == 200 else []

        if page == 'modules':
            roles_response = requests.get(f'{API_BASE_URL}/guilds/{guild_id}/roles', headers=bot_headers)
            all_roles = roles_response.json() if roles_response.status_code == 200 else []
            render_data['roles'] = [r for r in all_roles if r['name'] != '@everyone' and not r.get('tags', {}).get('bot_id')]
            render_data['embed_config'] = load_embed_config(guild_id_int)
            render_data['knowledge_base'] = load_knowledge(guild_id_int)
            render_data['ticket_config'] = load_ticket_config(guild_id_int)

        elif page == 'training':
            render_data['pending_questions'] = load_data_from_redis(f"{REDIS_TRAINING_QUEUE_KEY}:{guild_id_int}", [])

        elif page == 'membership':
            sub_info = r.hgetall(f"subscription:{guild_id}")
            time_left, is_active = None, False
            if sub_info and sub_info.get('status') == 'active':
                expires_at_str = sub_info.get('expires_at')
                if expires_at_str:
                    expires_at = datetime.fromisoformat(expires_at_str)
                    if expires_at > datetime.utcnow():
                        time_left = expires_at - datetime.utcnow()
                        is_active = True
                    else:
                        r.hset(f"subscription:{guild_id}", 'status', 'expired')
                        sub_info['status'] = 'expired'

            module_config = load_module_config()
            module_statuses = {
                'ticket_ia': module_config.get(str(guild_id), {}).get('modules', {}).get('ticket_ia', False),
                'moderation': module_config.get(str(guild_id), {}).get('modules', {}).get('moderation', False),
                'designer': module_config.get(str(guild_id), {}).get('modules', {}).get('designer', False)
            }

            render_data['sub_info'] = sub_info
            render_data['time_left'] = time_left
            render_data['is_active'] = is_active
            render_data['module_statuses'] = module_statuses

    elif page == 'moderation':
        render_data['moderation_config'] = load_moderation_config(guild_id_int)
        render_data['warnings_log'] = load_warnings_log(guild_id_int)
        render_data['backups'] = load_backups(guild_id_int)

    return render_template(template_to_render, **render_data)

# --- RUTAS DE CONOCIMIENTO ASÍNCRONO ---
@app.route("/dashboard/<guild_id>/knowledge/add", methods=['POST'])
@login_required
def add_knowledge_ajax(guild_id):
    try:
        data = request.json
        text = data.get('text')
        if not text: return jsonify({'success': False, 'error': 'El texto no puede estar vacío'}), 400

        knowledge = load_knowledge(int(guild_id))
        new_item = {"type": "text", "content": text}
        knowledge.append(new_item)
        save_knowledge(int(guild_id), knowledge)

        log_action(session.get('user'), "Añadido Conocimiento", {"guild_id": guild_id, "text": text})

        new_item_response = {'type': 'text', 'content': text, 'index': len(knowledge) - 1}
        return jsonify({'success': True, 'newItem': new_item_response})
    except Exception as e:
        app.logger.error(f"Error al añadir conocimiento: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/dashboard/<guild_id>/knowledge/delete", methods=['POST'])
@login_required
def delete_knowledge_ajax(guild_id):
    try:
        data = request.json
        index = int(data.get('index'))
        knowledge = load_knowledge(int(guild_id))
        if 0 <= index < len(knowledge):
            deleted_item = knowledge.pop(index)
            save_knowledge(int(guild_id), knowledge)

            log_action(session.get('user'), "Eliminado Conocimiento", {"guild_id": guild_id, "deleted_text": deleted_item, "index": index})

            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Índice inválido'}), 400
    except Exception as e:
        app.logger.error(f"Error al eliminar conocimiento: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# --- RUTA DE ACCIÓN DE ENTRENAMIENTO ---
@app.route("/dashboard/<guild_id>/training_action", methods=['POST'])
@login_required
def training_action(guild_id):
    guild_id_int = int(guild_id)
    action = request.form.get('action')
    question_id = request.form.get('question_id')
    training_queue_key = f"{REDIS_TRAINING_QUEUE_KEY}:{guild_id_int}"
    pending_questions = load_data_from_redis(training_queue_key, [])
    question_to_process = next((q for q in pending_questions if q['id'] == question_id), None)

    if not question_to_process:
        flash("La pregunta ya no existe o fue procesada.", "warning")
        return redirect(url_for('select_page', guild_id=guild_id, page='training'))

    user_info = session.get('user', {'username': 'Desconocido', 'id': 'Desconocido'})
    if action == 'train':
        answer = request.form.get('answer_text')
        if not answer:
            flash("La respuesta no puede estar vacía.", "danger")
        else:
            knowledge = load_knowledge(guild_id_int)
            new_knowledge_entry = {"type": "text", "content": answer}
            knowledge.append(new_knowledge_entry)
            save_knowledge(guild_id_int, knowledge)
            log_action(user_info, "IA Entrenada", {"guild_id": guild_id, "question": question_to_process['question'], "answer": answer})
            pending_questions = [q for q in pending_questions if q['id'] != question_id]
            save_data_to_redis(training_queue_key, pending_questions)
            flash("¡IA entrenada con éxito!", "success")

    elif action == 'discard':
        log_action(user_info, "Pregunta Descartada", {"guild_id": guild_id, "question": question_to_process})
        pending_questions = [q for q in pending_questions if q['id'] != question_id]
        save_data_to_redis(training_queue_key, pending_questions)
        flash("Pregunta descartada.", "info")

    return redirect(url_for('select_page', guild_id=guild_id, page='training'))

@app.route("/dashboard/<guild_id>/send_panel", methods=['POST'])
@login_required
def send_panel(guild_id):
    if not r: return redirect(url_for('select_page', guild_id=guild_id, page='modules'))
    channel_id = int(request.form.get('channel_id'))
    command = {'command': 'send_panel', 'guild_id': int(guild_id), 'channel_id': channel_id}
    r.lpush(REDIS_COMMAND_QUEUE_KEY, json.dumps(command))
    flash("El panel de tickets se está enviando...", "info")
    return redirect(url_for('select_page', guild_id=guild_id, page='modules'))

# --- NUEVAS RUTAS PARA EL MÓDULO DISEÑADOR ---
@app.route('/designer/<guild_id>')
@login_required
def designer_page(guild_id):
    return redirect(url_for('select_page', guild_id=guild_id, page='designer'))

@app.route('/api/designer/<guild_id>/structure')
@login_required
def get_server_structure(guild_id):
    discord = make_user_session()
    guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
    if guilds_response.status_code != 200:
        return jsonify({"error": "No se pudieron obtener los servidores del usuario"}), guilds_response.status_code
    user_guilds = guilds_response.json()
    current_guild = next((g for g in user_guilds if g['id'] == guild_id), None)
    if not current_guild or (int(current_guild.get('permissions', 0)) & 0x8) != 0x8:
        return jsonify({"error": "No tienes permiso para administrar este servidor."}), 403

    channels = get_guild_channels_bot(guild_id)
    roles = get_guild_roles_bot(guild_id)
    guild_info = get_guild_data_bot(guild_id)

    if guild_info is None:
        return jsonify({"error": "No se pudo obtener la información del servidor."}), 500

    server_structure = {
        "id": guild_info.get('id'),
        "name": guild_info.get('name'),
        "icon_url": f"https://cdn.discordapp.com/icons/{guild_id}/{guild_info.get('icon')}.png" if guild_info.get('icon') else "https://cdn.discordapp.com/embed/avatars/0.png",
        "roles": [],
        "categories": {},
        "channels_no_category": []
    }

    for role in roles:
        server_structure["roles"].append({
            "id": role.get('id'),
            "name": role.get('name'),
            "color": f"#{role.get('color'):06x}" if role.get('color') else "#99aab5",
            "position": role.get('position'),
            "permissions": role.get('permissions')
        })

    for channel in channels:
        channel_type = channel.get('type')
        if channel_type == 4:
            if channel['id'] not in server_structure["categories"]:
                server_structure["categories"][channel['id']] = {
                    "id": channel.get('id'), "name": channel.get('name'),
                    "position": channel.get('position'), "channels": []
                }
        elif channel.get('parent_id'):
            parent_id = channel['parent_id']
            if parent_id not in server_structure["categories"]:
                 server_structure["categories"][parent_id] = {"id": parent_id, "name": "Categoría Desconocida", "channels": []}

            server_structure["categories"][parent_id]['channels'].append({
                "id": channel.get('id'), "name": channel.get('name'),
                "type": "text" if channel_type == 0 else "voice",
                "position": channel.get('position')
            })
        else:
            server_structure["channels_no_category"].append({
                "id": channel.get('id'), "name": channel.get('name'),
                "type": "text" if channel_type == 0 else "voice",
                "position": channel.get('position')
            })

    server_structure["categories"] = sorted(server_structure["categories"].values(), key=lambda x: x.get('position', 0))

    return jsonify(server_structure)


@app.route('/api/designer/<guild_id>/process_prompt', methods=['POST'])
@login_required
def process_designer_prompt(guild_id):
    discord = make_user_session()
    guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
    if guilds_response.status_code != 200:
        return jsonify({"error": "No se pudieron obtener los servidores del usuario"}), guilds_response.status_code
    user_guilds = guilds_response.json()
    current_guild = next((g for g in user_guilds if g['id'] == guild_id), None)
    if not current_guild or (int(current_guild.get('permissions', 0)) & 0x8) != 0x8:
        return jsonify({"error": "No tienes permiso para administrar este servidor."}), 403

    data = request.json
    user_prompt = data.get('prompt')
    current_structure = data.get('structure')

    if not user_prompt or not current_structure:
        return jsonify({"error": "Faltan datos en la petición."}), 400

    # Placeholder
    return jsonify(current_structure)


@app.route('/api/designer/<guild_id>/apply_changes', methods=['POST'])
@login_required
def apply_designer_changes(guild_id):
    discord = make_user_session()
    guilds_response = discord.get(f'{API_BASE_URL}/users/@me/guilds')
    if guilds_response.status_code != 200:
        return jsonify({"error": "No se pudieron obtener los servidores del usuario"}), guilds_response.status_code
    user_guilds = guilds_response.json()
    current_guild = next((g for g in user_guilds if g['id'] == guild_id), None)
    if not current_guild or (int(current_guild.get('permissions', 0)) & 0x8) != 0x8:
        return jsonify({"error": "No tienes permiso para administrar este servidor."}), 403

    final_structure = request.json

    # Placeholder

    return jsonify({"status": "success", "message": "Los cambios se están aplicando. Puede tardar unos momentos."})

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
            url = request.form.get('web_url')
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
