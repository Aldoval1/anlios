# ----------------------------------------
# Importaciones de bibliotecas necesarias
# ----------------------------------------
from flask import (
    Flask, render_template, redirect, url_for, session, request,
    make_response, jsonify, g, send_from_directory, abort
)
from flask_babel import Babel, gettext
from authlib.integrations.flask_client import OAuth
from functools import wraps
from dotenv import load_dotenv
from urllib.parse import urlencode, quote_plus
from http.cookies import SimpleCookie
import redis
import requests
import json
import os
import uuid
import logging
import base64
import re
import aiohttp
import asyncio
from io import BytesIO

# Importaciones de Google Generative AI
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# ----------------------------------------
# Carga de variables de entorno
# ----------------------------------------
load_dotenv()

# ----------------------------------------
# Configuración de logging
# ----------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ----------------------------------------
# Configuración de la aplicación Flask
# ----------------------------------------
app = Flask(__name__)
app.config.from_mapping({
    'SECRET_KEY': os.getenv("FLASK_SECRET_KEY"),
    'SESSION_COOKIE_NAME': 'anlios_session',
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'SESSION_COOKIE_SECURE': os.getenv('FLASK_ENV') == 'production',
})

# ----------------------------------------
# Configuración de Babel para i18n
# ----------------------------------------
babel = Babel(app)

# Cargar traducciones
def load_translations():
    try:
        with open('website/translations.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando translations.json: {e}")
        return {}

translations = load_translations()

@babel.localeselector
def get_locale():
    # 1. Obtener de la sesión del usuario
    if 'lang' in session:
        return session['lang']
    # 2. Obtener del encabezado Accept-Language
    lang = request.accept_languages.best_match(['en', 'es'])
    if lang:
        session['lang'] = lang
        return lang
    # 3. Valor por defecto
    session['lang'] = 'es'
    return 'es'

@app.before_request
def before_request():
    # Cargar traducciones en 'g' para que estén disponibles en todas las plantillas
    g.translations = translations
    g.locale = get_locale()
    # Definir una función de traducción 'gettext' en 'g'
    g._ = lambda text: translations.get(g.locale, {}).get(text, text)
    # Hacer que la función _ esté disponible en el contexto de la plantilla
    app.jinja_env.globals['_'] = g._

@app.route('/change_lang/<lang_code>')
def change_lang(lang_code):
    if lang_code in ['en', 'es']:
        session['lang'] = lang_code
    # Redirigir a la página anterior o al dashboard
    referrer = request.referrer or url_for('dashboard')
    return redirect(referrer)

# ----------------------------------------
# Configuración de OAuth para Discord
# ----------------------------------------
oauth = OAuth(app)
oauth.register(
    name='discord',
    client_id=os.getenv("DISCORD_CLIENT_ID"),
    client_secret=os.getenv("DISCORD_CLIENT_SECRET"),
    access_token_url='https://discord.com/api/oauth2/token',
    authorize_url='https://discord.com/api/oauth2/authorize',
    api_base_url='https://discord.com/api/v10/',
    client_kwargs={
        'scope': 'identify guilds guilds.join',
        'token_endpoint_auth_method': 'client_secret_post',
    },
    authorize_params={
        'prompt': 'consent'
    }
)

# ----------------------------------------
# Configuración de Redis
# ----------------------------------------
try:
    redis_client = redis.StrictRedis.from_url(os.getenv("REDIS_URL"), decode_responses=True)
    redis_client.ping()
    logger.info("Conexión a Redis establecida con éxito.")
except Exception as e:
    logger.critical(f"No se pudo conectar a Redis: {e}", exc_info=True)
    # Si no podemos conectar a Redis, la aplicación no puede funcionar.
    # En un escenario real, podríamos querer reintentar o fallar de forma elegante.
    # Por ahora, saldremos si Redis no está disponible al inicio.
    raise ConnectionError(f"No se pudo conectar a Redis: {e}") from e

# ----------------------------------------
# Configuración de Google Generative AI
# ----------------------------------------
try:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    if not GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY no está configurada. Las funciones de IA no funcionarán.")
    else:
        genai.configure(api_key=GEMINI_API_KEY)
except Exception as e:
    logger.error(f"Error al configurar la API de Gemini: {e}")

# Modelos de IA
try:
    # Modelo para chat y texto
    chat_model = genai.GenerativeModel('gemini-1.5-flash')
    # Modelo para embeddings (procesamiento de archivos)
    embedding_model = genai.GenerativeModel('models/text-embedding-004')
    logger.info("Modelos de Google Generative AI cargados.")
except Exception as e:
    logger.error(f"No se pudieron cargar los modelos de IA: {e}")

# ----------------------------------------
# Constantes y Configuraciones
# ----------------------------------------
MAINTENANCE_MODE = os.getenv('MAINTENANCE_MODE', 'false').lower() == 'true'
ANLIOS_GUILD_ID = os.getenv('ANLIOS_GUILD_ID')
PREMIUM_ROLE_ID = os.getenv('PREMIUM_ROLE_ID')

# ----------------------------------------
# Funciones de Utilidad
# ----------------------------------------

def get_user_data_from_redis(user_id):
    """Obtiene los datos del usuario de Redis."""
    user_data = redis_client.get(f"user:{user_id}")
    return json.loads(user_data) if user_data else None

def get_server_config(server_id, module):
    """Obtiene la configuración de un módulo para un servidor."""
    config_key = f"config:{server_id}:{module}"
    config_data = redis_client.get(config_key)
    return json.loads(config_data) if config_data else {}

def save_server_config(server_id, module, config):
    """Guarda la configuración de un módulo para un servidor."""
    config_key = f"config:{server_id}:{module}"
    redis_client.set(config_key, json.dumps(config))

def get_all_server_configs(server_id):
    """Obtiene todas las configuraciones de un servidor."""
    keys = redis_client.keys(f"config:{server_id}:*")
    pipeline = redis_client.pipeline()
    for key in keys:
        pipeline.get(key)
    results = pipeline.execute()
    
    configs = {}
    for key, data in zip(keys, results):
        if data:
            module_name = key.split(':')[-1]
            configs[module_name] = json.loads(data)
    return configs

def is_user_premium(user_id):
    """Verifica si un usuario es premium (Nivel 1)."""
    if not ANLIOS_GUILD_ID or not PREMIUM_ROLE_ID:
        logger.warning("ANLIOS_GUILD_ID o PREMIUM_ROLE_ID no están configurados. La verificación de premium no funcionará.")
        return False
        
    try:
        # 1. Obtener el token de acceso del bot (almacenado en Redis por bot.py)
        bot_token = redis_client.get("discord_bot_token")
        if not bot_token:
            logger.error("No se encontró el token del bot en Redis.")
            return False

        # 2. Llamar a la API de Discord para verificar los roles del usuario en el servidor de Anlios
        headers = {"Authorization": f"Bot {bot_token}"}
        url = f"https://discord.com/api/v10/guilds/{ANLIOS_GUILD_ID}/members/{user_id}"
        
        # Esta es una solicitud síncrona. Considerar mover a asíncrono si causa bloqueos.
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            member_data = response.json()
            user_roles = member_data.get("roles", [])
            return PREMIUM_ROLE_ID in user_roles
        elif response.status_code == 404:
            logger.info(f"Usuario {user_id} no encontrado en el servidor de Anlios.")
            return False
        else:
            logger.error(f"Error al verificar membresía de Anlios Guild. Status: {response.status_code}, Response: {response.text}")
            return False

    except Exception as e:
        logger.error(f"Excepción al verificar premium: {e}", exc_info=True)
        return False

def check_server_premium(server_id):
    """Verifica si un servidor tiene premium (Nivel 2)."""
    premium_data = redis_client.get(f"premium:server:{server_id}")
    if premium_data:
        data = json.loads(premium_data)
        # Comprobar si 'expires_at' es 'permanent' o una fecha futura
        if data.get("status") == "active":
            return True
    return False

def get_user_id():
    """Obtiene el user_id de la sesión de forma segura."""
    encrypted_user_id = session.get('user_id')
    if not encrypted_user_id:
        return None
    
    # Simple "desencriptación" (en este caso, es solo decodificación)
    try:
        return base64.b64decode(encrypted_user_id).decode('utf-8')
    except Exception as e:
        logger.warning(f"Error al decodificar user_id de la sesión: {e}")
        session.clear() # Limpiar sesión corrupta
        return None

def store_user_id(user_id):
    """Almacena el user_id en la sesión de forma "ofuscada"."""
    # Esto no es encriptación real, solo ofuscación.
    # Para encriptación real, usar una biblioteca como 'cryptography'.
    session['user_id'] = base64.b64encode(user_id.encode('utf-8')).decode('utf-8')

def publish_command_to_bot(command, data):
    """Publica un comando en el canal de Redis para que el bot lo escuche."""
    try:
        payload = json.dumps({"command": command, "data": data})
        redis_client.publish("bot_commands", payload)
        logger.info(f"Comando '{command}' publicado en Redis.")
        return True
    except Exception as e:
        logger.error(f"Error al publicar comando en Redis: {e}")
        return False

# ----------------------------------------
# Decoradores de autenticación y permisos
# ----------------------------------------

def login_required(f):
    """Decorador para rutas que requieren que el usuario esté logueado."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'token' not in session:
            logger.info("Intento de acceso sin token. Redirigiendo a login.")
            return redirect(url_for('login', next=request.url))
        
        if MAINTENANCE_MODE:
            # Si el modo mantenimiento está activo, solo el admin puede pasar
            user_id = get_user_id()
            admin_user_id = os.getenv('ADMIN_USER_ID')
            if not user_id or user_id != admin_user_id:
                logger.warning(f"Modo mantenimiento activado. Usuario {user_id} redirigido.")
                return redirect(url_for('maintenance'))
        
        # Verificar si el token ha expirado (aunque OAuth suele manejar esto)
        # ... (lógica de verificación de expiración si es necesaria) ...
        
        return f(*args, **kwargs)
    return decorated_function

def check_premium_and_permissions(module_name):
    """
    Decorador para verificar:
    1. Si el servidor es premium (si el módulo lo requiere).
    2. Si el usuario tiene permisos (Admin o Manage Guild) en ese servidor.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(server_id, *args, **kwargs):
            
            # --- Verificación de Permisos ---
            try:
                guild_id = int(server_id)
                user_id = get_user_id()
                
                if not user_id:
                    logger.warning("No se pudo obtener user_id de la sesión.")
                    return redirect(url_for('login'))

                # Obtener gremios del usuario de la sesión de Discord
                user_guilds = session.get('user_guilds')
                if not user_guilds:
                    logger.warning(f"No se encontraron gremios en la sesión para {user_id}. Refrescando...")
                    # Forzar recarga de gremios
                    return redirect(url_for('select_server', force_refresh=True))

                # Buscar el gremio específico
                guild_obj = next((g for g in user_guilds if g['id'] == str(guild_id)), None)

                if not guild_obj:
                    logger.warning(f"Usuario {user_id} intentó acceder a {guild_id} pero no está en ese gremio (según la sesión).")
                    response = make_response(render_template('error.html', title=g._('error_403_titulo'), message=g._('error_403_no_en_servidor_msg')), 403)
                    return response

                # Verificar permisos (Admin: 0x8, Manage Guild: 0x20)
                permissions = int(guild_obj['permissions'])
                is_admin = (permissions & 0x8) == 0x8
                is_manage_guild = (permissions & 0x20) == 0x20

                if not is_admin and not is_manage_guild:
                    logger.warning(f"Usuario {user_id} intentó acceder a {guild_id} sin permisos (Perms: {permissions}).")
                    response = make_response(render_template('error.html', title=g._('error_403_titulo'), message=g._('error_403_no_permisos_msg')), 403)
                    return response
                
                # Almacenar permisos en 'g' para uso en la plantilla
                g.user_permissions = {'is_admin': is_admin, 'is_manage_guild': is_manage_guild}

            except Exception as e:
                app.logger.error(f"Error in permission check: {e}", exc_info=True)
                # FIX: Asignar una 'response' genérica de error aquí
                response = make_response(render_template('error.html', title=g._('error_500_titulo'), message=g._('error_500_permisos_msg')), 500)
                return response # <- El error estaba aquí

            # --- Verificación de Premium ---
            # Cargar la configuración de módulos (que dice qué módulo es premium)
            try:
                with open('module_config.json', 'r', encoding='utf-8') as f:
                    module_config = json.load(f)
            except Exception as e:
                logger.error(f"Error crítico: no se pudo cargar module_config.json: {e}")
                return make_response(render_template('error.html', title=g._('error_500_titulo'), message=g._('error_500_config_modulo_msg')), 500)

            module_info = module_config.get(module_name)
            
            # Si el módulo no existe en la config, es un error 404
            if not module_info:
                logger.error(f"Se intentó acceder a un módulo inexistente: {module_name}")
                abort(404)

            # Verificar si el módulo requiere premium
            if module_info.get("requires_premium", False):
                is_server_premium = check_server_premium(server_id)
                if not is_server_premium:
                    logger.info(f"Servidor {server_id} intentó acceder al módulo premium '{module_name}' sin ser premium.")
                    # Redirigir a la página de membresía de ese servidor
                    return redirect(url_for('membership', server_id=server_id, error='premium_required'))

            # Si pasa ambas verificaciones, continuar a la ruta
            return f(server_id, *args, **kwargs)

        return decorated_function
    return decorator

# ----------------------------------------
# Rutas de la aplicación web
# ----------------------------------------

@app.route('/static/css/colors/<path:filename>')
def custom_color_theme(filename):
    """Sirve las paletas de colores dinámicas."""
    return send_from_directory('static/css/colors', filename)

@app.route('/static/css/designs/<path:filename>')
def custom_design_theme(filename):
    """Sirve los diseños de layout dinámicos."""
    return send_from_directory('static/css/designs', filename)

@app.route('/favicon.ico')
def favicon():
    """Sirve el favicon."""
    return send_from_directory(os.path.join(app.root_path, 'static', 'images'),
                               'favicon.png', mimetype='image/png')

@app.errorhandler(404)
def not_found_error(error):
    """Manejador de error 404."""
    return render_template('error.html', title=g._('error_404_titulo'), message=g._('error_404_msg')), 404

@app.errorhandler(500)
def internal_error(error):
    """Manejador de error 500."""
    logger.error(f"Error interno 500: {error}", exc_info=True)
    return render_template('error.html', title=g._('error_500_titulo'), message=g._('error_500_msg')), 500

@app.route('/')
@login_required
def dashboard():
    """Página principal del dashboard (redirige a selección de servidor)."""
    return redirect(url_for('select_server'))

@app.route('/maintenance')
def maintenance():
    """Página de mantenimiento."""
    if not MAINTENANCE_MODE:
        return redirect(url_for('dashboard'))
    return render_template('maintenance.html', title=g._('mantenimiento_titulo'))

# --- Autenticación ---

@app.route('/login')
def login():
    """Página de inicio de sesión."""
    if MAINTENANCE_MODE:
        return redirect(url_for('maintenance'))
    
    if 'token' in session:
        return redirect(url_for('dashboard'))
    
    # Guardar la URL a la que el usuario quería ir
    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url
        
    return render_template('login.html', title=g._('login_titulo'))

@app.route('/auth/discord')
def auth_discord():
    """Redirige al usuario a Discord para autenticación."""
    redirect_uri = url_for('callback', _external=True)
    
    # Asegurarse de que la URL de callback sea HTTPS si estamos en producción
    if app.config['SESSION_COOKIE_SECURE']:
        redirect_uri = redirect_uri.replace('http://', 'https://')
        
    logger.info(f"Generando URI de redirección: {redirect_uri}")
    return oauth.discord.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    """Maneja la respuesta de callback de Discord."""
    if MAINTENANCE_MODE:
        return redirect(url_for('maintenance'))
        
    try:
        # Intercambiar el código por un token
        token = oauth.discord.authorize_access_token()
        session['token'] = token
        logger.info(f"Token obtenido: {token.get('access_token')[:10]}...") # No loguear token completo

        # Obtener información del usuario
        resp = oauth.discord.get('users/@me')
        user_info = resp.json()
        
        if not user_info:
            logger.warning("No se pudo obtener user_info de Discord.")
            return redirect(url_for('login', error='auth_failed'))

        session['user_info'] = user_info
        store_user_id(user_info['id']) # Guardar ID de forma ofuscada
        logger.info(f"Usuario {user_info['username']} ({user_info['id']}) ha iniciado sesión.")

        # Obtener gremios del usuario
        resp_guilds = oauth.discord.get('users/@me/guilds')
        user_guilds = resp_guilds.json()
        session['user_guilds'] = user_guilds

        # (Opcional) Unir al bot al servidor de Anlios si aún no está
        # ... (código para auto-unir al servidor de soporte) ...

        # Redirigir a la URL original o al dashboard
        next_url = session.pop('next_url', None)
        return redirect(next_url or url_for('select_server'))

    except Exception as e:
        logger.error(f"Error durante el callback de OAuth: {e}", exc_info=True)
        session.clear() # Limpiar sesión en caso de error
        return redirect(url_for('login', error='auth_failed'))

@app.route('/logout')
def logout():
    """Cierra la sesión del usuario."""
    session.clear()
    logger.info("Usuario ha cerrado sesión.")
    return redirect(url_for('login'))

# --- Selección de Servidor ---

@app.route('/select-server')
@login_required
def select_server():
    """Muestra la lista de servidores donde el usuario puede gestionar el bot."""
    
    force_refresh = request.args.get('force_refresh', 'false').lower() == 'true'

    if 'user_guilds' not in session or force_refresh:
        try:
            logger.info(f"Refrescando gremios para el usuario {session.get('user_info', {}).get('username')}")
            resp_guilds = oauth.discord.get('users/@me/guilds')
            if resp_guilds.status_code == 401:
                logger.warning("Token expirado o inválido. Redirigiendo a login.")
                return redirect(url_for('logout'))
            resp_guilds.raise_for_status() # Lanza error para otros códigos HTTP malos
            user_guilds = resp_guilds.json()
            session['user_guilds'] = user_guilds
        except Exception as e:
            logger.error(f"Error al refrescar gremios: {e}", exc_info=True)
            return redirect(url_for('logout'))
    else:
        user_guilds = session['user_guilds']

    # Obtener la lista de IDs de gremios donde el bot está (de Redis)
    try:
        bot_guild_ids = redis_client.smembers("bot_guilds")
    except Exception as e:
        logger.error(f"Error obteniendo bot_guilds de Redis: {e}")
        bot_guild_ids = set()

    # Filtrar gremios: el usuario debe tener permisos (Admin o Manage Guild)
    manageable_guilds = []
    for guild in user_guilds:
        permissions = int(guild['permissions'])
        if (permissions & 0x8) or (permissions & 0x20): # Admin o Manage Guild
            guild['bot_is_in'] = guild['id'] in bot_guild_ids
            manageable_guilds.append(guild)

    # Ordenar: primero los servidores donde está el bot
    manageable_guilds.sort(key=lambda g: g['bot_is_in'], reverse=True)

    # Obtener el ID del bot para el enlace de invitación
    bot_id = os.getenv("DISCORD_CLIENT_ID")
    invite_link = f"https://discord.com/api/oauth2/authorize?client_id={bot_id}&permissions=8&scope=bot%20applications.commands"

    return render_template(
        'select_server.html',
        title=g._('select_server_titulo'),
        user_info=session['user_info'],
        guilds=manageable_guilds,
        invite_link=invite_link
    )

# --- Dashboard del Servidor ---

@app.route('/dashboard/<server_id>')
@login_required
@check_premium_and_permissions('dashboard') # El decorador maneja los permisos
def manage_server(server_id):
    """Página principal de gestión de un servidor."""
    
    # El decorador ya ha verificado los permisos y el gremio.
    guild = next((g for g in session['user_guilds'] if g['id'] == server_id), None)
    if not guild:
        # Esto no debería pasar si el decorador funciona, pero por si acaso.
        abort(404)

    # Cargar la configuración de módulos
    try:
        with open('module_config.json', 'r', encoding='utf-8') as f:
            all_modules = json.load(f)
    except Exception as e:
        logger.error(f"Error crítico: no se pudo cargar module_config.json: {e}")
        return make_response(render_template('error.html', title=g._('error_500_titulo'), message=g._('error_500_config_modulo_msg')), 500)

    # Obtener el estado (activado/desactivado) de los módulos desde Redis
    module_states = redis_client.get(f"config:{server_id}:modules")
    enabled_modules = json.loads(module_states) if module_states else {}

    # Combinar la info
    modules_list = []
    for key, module_info in all_modules.items():
        if key == "dashboard": continue # No mostrar el propio dashboard
        
        module_info['id'] = key
        module_info['enabled'] = enabled_modules.get(key, False)
        # (Opcional) Verificar premium aquí también para mostrar un candado
        if module_info.get("requires_premium", False) and not check_server_premium(server_id):
             module_info['locked'] = True
        else:
             module_info['locked'] = False
             
        modules_list.append(module_info)
        
    # Ordenar módulos
    modules_list.sort(key=lambda m: m.get('order', 99))

    return render_template(
        'manage_server.html',
        title=f"Dashboard: {guild['name']}",
        server=guild,
        modules=modules_list,
        user_info=session['user_info']
    )

@app.route('/dashboard/<server_id>/save_modules', methods=['POST'])
@login_required
@check_premium_and_permissions('dashboard')
def save_modules(server_id):
    """Guarda el estado (activado/desactivado) de los módulos."""
    try:
        data = request.json
        if 'modules' not in data:
            return jsonify({"success": False, "error": "Datos inválidos."}), 400
        
        # 'data['modules']' es un diccionario como {'ia_ticket': true, 'moderation': false}
        enabled_modules = data['modules']
        
        # Validar contra module_config.json
        with open('module_config.json', 'r', encoding='utf-8') as f:
            all_modules = json.load(f)
            
        validated_modules = {}
        for key, is_enabled in enabled_modules.items():
            if key in all_modules:
                # Si el módulo requiere premium, verificarlo ANTES de activarlo
                if is_enabled and all_modules[key].get("requires_premium", False):
                    if not check_server_premium(server_id):
                        logger.warning(f"Intento de activar módulo premium '{key}' sin premium en {server_id}.")
                        # No activar y no guardar
                        continue
                
                validated_modules[key] = bool(is_enabled)
            else:
                logger.warning(f"Intento de guardar estado para módulo desconocido: {key}")

        # Guardar en Redis
        save_server_config(server_id, 'modules', validated_modules)
        
        # Publicar comando al bot para que recargue los cogs (módulos)
        publish_command_to_bot(
            command="RELOAD_MODULES",
            data={"server_id": server_id, "modules": validated_modules}
        )

        return jsonify({"success": True, "message": g._('guardado_exito_msg')})

    except Exception as e:
        logger.error(f"Error al guardar módulos para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

# --- Módulo: Ticket I.A. ---

@app.route('/dashboard/<server_id>/module/ia_ticket')
@login_required
@check_premium_and_permissions('ia_ticket')
def module_ticket_ia(server_id):
    """Página de configuración del módulo de Ticket I.A."""
    guild = next((g for g in session['user_guilds'] if g['id'] == server_id), None)
    
    # Obtener configuración actual
    config = get_server_config(server_id, 'ia_ticket')
    knowledge = get_server_config(server_id, 'knowledge_base')

    return render_template(
        'module_ticket_ia.html',
        title=g._('ia_ticket_titulo'),
        server=guild,
        config=config,
        knowledge=knowledge,
        user_info=session['user_info']
    )

@app.route('/dashboard/<server_id>/save/ia_ticket', methods=['POST'])
@login_required
@check_premium_and_permissions('ia_ticket')
def save_ia_ticket(server_id):
    """Guarda la configuración general del módulo Ticket I.A."""
    try:
        data = request.json
        
        # Validar datos (ej. longitud, tipo)
        config = {
            "ai_personality": data.get("ai_personality", "Eres un asistente amigable y servicial."),
            "ticket_welcome_message": data.get("ticket_welcome_message", "¡Hola! ¿En qué puedo ayudarte?"),
            "ai_language": data.get("ai_language", "es"),
            "embed_config": data.get("embed_config", {}),
            # ... otros campos ...
        }
        
        # Validar el embed (campos requeridos, etc.)
        if not config["embed_config"].get("title") or not config["embed_config"].get("description"):
             return jsonify({"success": False, "error": g._('ia_ticket_error_embed_incompleto')}), 400

        save_server_config(server_id, 'ia_ticket', config)
        return jsonify({"success": True, "message": g._('guardado_exito_msg')})

    except Exception as e:
        logger.error(f"Error al guardar config ia_ticket para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

@app.route('/dashboard/<server_id>/send_ticket_panel', methods=['POST'])
@login_required
@check_premium_and_permissions('ia_ticket')
def send_ticket_panel(server_id):
    """Envía un comando al bot para que publique el panel de tickets."""
    try:
        data = request.json
        channel_id = data.get('channel_id')
        
        if not channel_id or not channel_id.isdigit():
            return jsonify({"success": False, "error": g._('ia_ticket_error_canal_invalido')}), 400

        # Obtener la config del embed guardada
        config = get_server_config(server_id, 'ia_ticket')
        embed_config = config.get("embed_config")
        
        if not embed_config:
            return jsonify({"success": False, "error": g._('ia_ticket_error_primero_guarda_embed')}), 400

        success = publish_command_to_bot(
            command="SEND_TICKET_PANEL",
            data={
                "server_id": server_id,
                "channel_id": channel_id,
                "embed_config": embed_config
            }
        )
        
        if success:
            return jsonify({"success": True, "message": g._('ia_ticket_enviando_panel_msg')})
        else:
            return jsonify({"success": False, "error": g._('error_500_comando_bot_msg')}), 500

    except Exception as e:
        logger.error(f"Error al enviar comando send_ticket_panel para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

# --- Módulo: Knowledge Base (Parte de Ticket I.A.) ---

async def aiohttp_get(url):
    """Función asíncrona para hacer requests con aiohttp."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                response.raise_for_status() # Lanza error si no es 2xx
                return await response.text()
    except Exception as e:
        logger.error(f"Error en aiohttp_get (url: {url}): {e}")
        return None

async def process_knowledge_source(source_type, content):
    """Procesa una fuente de conocimiento y genera embeddings."""
    if not embedding_model:
        raise Exception("Embedding model no está inicializado.")

    text_content = ""
    if source_type == "text":
        text_content = content
    
    elif source_type == "url" or source_type == "youtube":
        # Para URLs y YouTube, necesitamos el contenido de la página/transcripción
        # Esto es complejo y requiere herramientas como BeautifulSoup, youtube_transcript_api, etc.
        # Simplificación: Asumimos que 'content' ya es el texto extraído
        # En un caso real, aquí llamaríamos a las APIs/librerías de scraping/transcripción
        #
        # Ejemplo (requeriría instalar 'beautifulsoup4' y 'requests'):
        # if source_type == "url":
        #     import requests
        #     from bs4 import BeautifulSoup
        #     try:
        #         page = requests.get(content)
        #         soup = BeautifulSoup(page.content, 'html.parser')
        #         text_content = soup.get_text()
        #     except Exception as e:
        #         logger.error(f"Error scraping URL {content}: {e}")
        #         raise Exception(f"No se pudo procesar la URL: {e}")
        #
        # Esta implementación asume que el BOT (bot.py) manejará la extracción real
        # y que aquí solo almacenamos la URL.
        #
        # *** REVISIÓN DE LÓGICA ***
        # El bot es el que usa la knowledge base, así que el bot debe hacer el procesamiento.
        # El dashboard solo debe *guardar* las fuentes.
        # PERO, para la búsqueda semántica (IA), necesitamos embeddings.
        # ¿Quién genera los embeddings? ¿El bot o el dashboard?
        #
        # Si el dashboard los genera, necesita el contenido.
        # Si el bot los genera, el dashboard solo guarda la URL/texto.
        #
        # Vamos a asumir que el BOT es responsable de procesar las fuentes
        # y generar los embeddings cuando se actualiza la config.
        # Por lo tanto, el dashboard *no* genera embeddings aquí.
        
        # Simplemente guardamos la fuente tal cual.
        return {"type": source_type, "content": content}

    elif source_type == "file":
        # El contenido es el nombre del archivo.
        # El dashboard debe leer el archivo, extraer texto y generar embeddings.
        # Esto es un trabajo pesado para un request web.
        #
        # *** NUEVO PLAN ***
        # El dashboard SÍ procesará texto, pero archivos y URLs complejas
        # se las pasará al bot para procesamiento en segundo plano.
        
        if source_type == "text":
            # Generar embedding para texto simple
            # result = genai.embed_content(model=embedding_model, content=content, task_type="RETRIEVAL_DOCUMENT")
            # return {"type": "text", "content": content, "embedding": result['embedding']}
            #
            # *** NUEVO PLAN (v3) - Simplificación ***
            # El bot (bot.py) se encargará de TODO el procesamiento de la knowledge base
            # cuando detecte un cambio. El dashboard solo gestiona la lista de fuentes.
            # Esto evita timeouts en el dashboard y mantiene la lógica de IA en el bot.
            
            return {"type": "text", "content": content}

        else:
            # Para 'url', 'youtube', 'file', solo guardamos el identificador
            return {"type": source_type, "content": content}

    else:
        raise ValueError(f"Tipo de fuente desconocido: {source_type}")

@app.route('/dashboard/<server_id>/upload_knowledge', methods=['POST'])
@login_required
@check_premium_and_permissions('ia_ticket')
async def upload_knowledge(server_id):
    """Sube un archivo (PDF, TXT) a la Knowledge Base."""
    
    # Verificar si es un archivo
    if 'file' not in request.files:
        return jsonify({"success": False, "error": g._('error_no_archivo')}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"success": False, "error": g._('error_no_archivo_seleccionado')}), 400

    # Validar extensión
    allowed_extensions = {'pdf', 'txt', 'md'}
    filename = file.filename
    if '.' not in filename or filename.split('.')[-1].lower() not in allowed_extensions:
        return jsonify({"success": False, "error": g._('ia_ticket_error_archivo_invalido')}), 400

    # --- Lógica de almacenamiento ---
    # No podemos guardar archivos en el sistema de archivos de Heroku/Railway (es efímero).
    # Opciones:
    # 1. Almacenar en un S3 (AWS, Google Cloud Storage, etc.)
    # 2. Almacenar en Redis (mala idea para archivos grandes)
    # 3. Almacenar en una base de datos (ej. MongoDB GridFS)
    #
    # Por simplicidad, este proyecto parece estar guardando el *contenido*
    # o una referencia en la config de Redis.
    #
    # Si guardamos en Redis, leamos el archivo y guardemos su contenido
    # (Esto puede fallar si el archivo es más grande que el límite de Redis)
    
    # Límite de tamaño (ej. 5MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024
    file_content = file.read()
    if len(file_content) > MAX_FILE_SIZE:
         return jsonify({"success": False, "error": g._('ia_ticket_error_archivo_grande')}), 400

    # Guardar el contenido en Redis (usar un hash separado para archivos)
    # Usaremos un identificador único para este archivo
    file_id = f"kb_file:{server_id}:{filename}"
    
    try:
        # Almacenar el contenido del archivo
        redis_client.set(file_id, file_content)
        
        # Ahora, agregar la referencia a la Knowledge Base
        kb_config = get_server_config(server_id, 'knowledge_base')
        if "files" not in kb_config:
            kb_config["files"] = []
            
        # Evitar duplicados
        if filename not in kb_config["files"]:
            kb_config["files"].append(filename)
        
        save_server_config(server_id, 'knowledge_base', kb_config)
        
        # Notificar al bot que debe reprocesar la KB
        publish_command_to_bot("REPROCESS_KNOWLEDGE", {"server_id": server_id})

        return jsonify({"success": True, "filename": filename})

    except Exception as e:
        logger.error(f"Error al guardar archivo en Redis: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_guardar_archivo_msg')}), 500

@app.route('/dashboard/<server_id>/save_knowledge', methods=['POST'])
@login_required
@check_premium_and_permissions('ia_ticket')
def save_knowledge(server_id):
    """Guarda las fuentes de conocimiento (Texto, URL, YouTube)."""
    try:
        data = request.json
        source_type = data.get('type')
        content = data.get('content')
        
        if not source_type or not content:
            return jsonify({"success": False, "error": g._('error_datos_invalidos')}), 400
        
        # Validar tipos
        valid_types = {"text", "url", "youtube"}
        if source_type not in valid_types:
            return jsonify({"success": False, "error": g._('ia_ticket_error_fuente_invalida')}), 400
            
        # Validar URL (simple)
        if source_type == "url" and not re.match(r'^https?://', content):
            return jsonify({"success": False, "error": g._('ia_ticket_error_url_invalida')}), 400
            
        # Validar YouTube (simple)
        if source_type == "youtube" and "youtube.com" not in content and "youtu.be" not in content:
            return jsonify({"success": False, "error": g._('ia_ticket_error_youtube_invalida')}), 400

        # Obtener config actual
        kb_config = get_server_config(server_id, 'knowledge_base')
        
        # Inicializar listas si no existen
        if source_type == "text":
            if "texts" not in kb_config: kb_config["texts"] = []
            kb_list = kb_config["texts"]
        elif source_type == "url":
            if "urls" not in kb_config: kb_config["urls"] = []
            kb_list = kb_config["urls"]
        elif source_type == "youtube":
            if "youtubes" not in kb_config: kb_config["youtubes"] = []
            kb_list = kb_config["youtubes"]

        # Evitar duplicados
        if content not in kb_list:
            kb_list.append(content)
        
        # Guardar
        save_server_config(server_id, 'knowledge_base', kb_config)
        
        # Notificar al bot
        publish_command_to_bot("REPROCESS_KNOWLEDGE", {"server_id": server_id})
        
        return jsonify({"success": True, "message": g._('ia_ticket_fuente_agregada_msg')})

    except Exception as e:
        logger.error(f"Error en save_knowledge para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

@app.route('/dashboard/<server_id>/delete_knowledge', methods=['POST'])
@login_required
@check_premium_and_permissions('ia_ticket')
def delete_knowledge(server_id):
    """Elimina una fuente de conocimiento."""
    try:
        data = request.json
        source_type = data.get('type')
        content = data.get('content') # El contenido o nombre del archivo a borrar

        if not source_type or not content:
            return jsonify({"success": False, "error": g._('error_datos_invalidos')}), 400

        kb_config = get_server_config(server_id, 'knowledge_base')
        found = False

        if source_type == "text" and "texts" in kb_config:
            if content in kb_config["texts"]:
                kb_config["texts"].remove(content)
                found = True
        elif source_type == "url" and "urls" in kb_config:
            if content in kb_config["urls"]:
                kb_config["urls"].remove(content)
                found = True
        elif source_type == "youtube" and "youtubes" in kb_config:
            if content in kb_config["youtubes"]:
                kb_config["youtubes"].remove(content)
                found = True
        elif source_type == "file" and "files" in kb_config:
            if content in kb_config["files"]:
                kb_config["files"].remove(content)
                found = True
                # Eliminar también el archivo de Redis
                file_id = f"kb_file:{server_id}:{content}"
                redis_client.delete(file_id)

        if not found:
            return jsonify({"success": False, "error": g._('ia_ticket_error_fuente_no_encontrada')}), 404
            
        # Guardar la config actualizada
        save_server_config(server_id, 'knowledge_base', kb_config)
        
        # Notificar al bot
        publish_command_to_bot("REPROCESS_KNOWLEDGE", {"server_id": server_id})

        return jsonify({"success": True, "message": g._('ia_ticket_fuente_eliminada_msg')})

    except Exception as e:
        logger.error(f"Error en delete_knowledge para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

# --- Módulo: Moderación ---

@app.route('/dashboard/<server_id>/module/moderation')
@login_required
@check_premium_and_permissions('moderation')
def module_moderation(server_id):
    """Página de configuración del módulo de Moderación."""
    guild = next((g for g in session['user_guilds'] if g['id'] == server_id), None)
    config = get_server_config(server_id, 'moderation')
    
    # Cargar backups (Anlios Vault)
    backups_raw = redis_client.hgetall(f"backups:{server_id}")
    backups = []
    if backups_raw:
        for backup_id, backup_json in backups_raw.items():
            try:
                backup_data = json.loads(backup_json)
                backups.append({
                    "id": backup_id,
                    "name": backup_data.get("name", "Backup"),
                    "created_at": backup_data.get("created_at", "N/A"),
                    "description": backup_data.get("description", "N/A")
                })
            except Exception:
                continue # Ignorar backup corrupto
        backups.sort(key=lambda b: b['created_at'], reverse=True) # Mostrar más recientes primero

    return render_template(
        'module_moderation.html',
        title=g._('moderacion_titulo'),
        server=guild,
        config=config,
        backups=backups,
        user_info=session['user_info']
    )

@app.route('/dashboard/<server_id>/save/moderation', methods=['POST'])
@login_required
@check_premium_and_permissions('moderation')
def save_moderation(server_id):
    """Guarda la configuración de Moderación."""
    try:
        data = request.json
        
        # Sanitizar y validar datos
        config = {
            "automod": data.get("automod", {}),
            "warn_system": data.get("warn_system", {}),
            "log_channel": data.get("log_channel")
        }
        
        # Ejemplo de validación
        if config["log_channel"] and not config["log_channel"].isdigit():
            return jsonify({"success": False, "error": g._('moderacion_error_canal_logs_invalido')}), 400
            
        if "links" not in config["automod"]:
             config["automod"]["links"] = {"enabled": False, "allowed_roles": [], "allowed_channels": []}

        save_server_config(server_id, 'moderation', config)
        
        # Publicar comando al bot para que actualice su config de moderación
        publish_command_to_bot(
            command="UPDATE_MOD_CONFIG",
            data={"server_id": server_id, "config": config}
        )
        
        return jsonify({"success": True, "message": g._('guardado_exito_msg')})

    except Exception as e:
        logger.error(f"Error en save_moderation para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

# --- Anlios Vault (Backups) ---

@app.route('/dashboard/<server_id>/vault/create', methods=['POST'])
@login_required
@check_premium_and_permissions('moderation') # Asumimos que es parte de moderación
def create_backup(server_id):
    """Envía un comando al bot para crear un backup del servidor."""
    try:
        # (Opcional) Verificar límite de backups
        current_backups = redis_client.hlen(f"backups:{server_id}")
        if current_backups >= 5: # Límite de 5 backups
            return jsonify({"success": False, "error": g._('moderacion_error_limite_backups')}), 400

        data = request.json
        name = data.get("name", "Backup")
        description = data.get("description", "")
        
        if not name:
             return jsonify({"success": False, "error": g._('moderacion_error_nombre_backup_vacio')}), 400

        success = publish_command_to_bot(
            command="CREATE_BACKUP",
            data={
                "server_id": server_id,
                "user_id": get_user_id(),
                "name": name,
                "description": description
            }
        )
        
        if success:
            return jsonify({"success": True, "message": g._('moderacion_backup_creando_msg')})
        else:
            return jsonify({"success": False, "error": g._('error_500_comando_bot_msg')}), 500

    except Exception as e:
        logger.error(f"Error en create_backup para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

@app.route('/dashboard/<server_id>/vault/load', methods=['POST'])
@login_required
@check_premium_and_permissions('moderation')
def load_backup(server_id):
    """Envía un comando al bot para cargar un backup."""
    try:
        data = request.json
        backup_id = data.get("backup_id")
        
        if not backup_id:
            return jsonify({"success": False, "error": g._('moderacion_error_id_backup_invalido')}), 400
            
        # Verificar que el backup existe antes de enviar el comando
        if not redis_client.hexists(f"backups:{server_id}", backup_id):
            return jsonify({"success": False, "error": g._('moderacion_error_backup_no_encontrado')}), 404

        success = publish_command_to_bot(
            command="LOAD_BACKUP",
            data={
                "server_id": server_id,
                "user_id": get_user_id(),
                "backup_id": backup_id
            }
        )
        
        if success:
            return jsonify({"success": True, "message": g._('moderacion_backup_cargando_msg')})
        else:
            return jsonify({"success": False, "error": g._('error_500_comando_bot_msg')}), 500

    except Exception as e:
        logger.error(f"Error en load_backup para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

@app.route('/dashboard/<server_id>/vault/delete', methods=['POST'])
@login_required
@check_premium_and_permissions('moderation')
def delete_backup(server_id):
    """Elimina un backup de Redis."""
    try:
        data = request.json
        backup_id = data.get("backup_id")
        
        if not backup_id:
            return jsonify({"success": False, "error": g._('moderacion_error_id_backup_invalido')}), 400
            
        # Eliminar de Redis
        deleted_count = redis_client.hdel(f"backups:{server_id}", backup_id)
        
        if deleted_count > 0:
            return jsonify({"success": True, "message": g._('moderacion_backup_eliminado_msg')})
        else:
            return jsonify({"success": False, "error": g._('moderacion_error_backup_no_encontrado')}), 404

    except Exception as e:
        logger.error(f"Error en delete_backup para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

# --- Módulo: Designer ---

@app.route('/dashboard/<server_id>/module/designer')
@login_required
@check_premium_and_permissions('designer')
def module_designer(server_id):
    """Página de configuración del módulo de Designer."""
    guild = next((g for g in session['user_guilds'] if g['id'] == server_id), None)
    
    # Obtener historial de chat (si existe)
    chat_history = []
    try:
        chat_history_raw = redis_client.lrange(f"designer_chat:{server_id}", 0, -1)
        for msg in chat_history_raw:
            chat_history.append(json.loads(msg))
    except Exception as e:
        logger.error(f"Error al cargar historial de chat de Designer para {server_id}: {e}")
        # No es crítico, solo empezar con historial vacío

    return render_template(
        'module_designer.html',
        title=g._('designer_titulo'),
        server=guild,
        chat_history=chat_history,
        user_info=session['user_info']
    )

@app.route('/dashboard/<server_id>/designer_chat', methods=['POST'])
@login_required
@check_premium_and_permissions('designer')
async def designer_chat(server_id):
    """Maneja los mensajes del chat del Designer."""
    try:
        data = request.json
        prompt = data.get('prompt')
        if not prompt:
            return jsonify({"error": "Prompt vacío."}), 400

        user_id = get_user_id()
        guild = next((g for g in session['user_guilds'] if g['id'] == server_id), None)
        
        # 1. Guardar mensaje del usuario
        user_msg = {"role": "user", "content": prompt}
        redis_client.rpush(f"designer_chat:{server_id}", json.dumps(user_msg))

        # 2. Obtener el token del bot
        bot_token = redis_client.get("discord_bot_token")
        if not bot_token:
            logger.error("No se encontró el token del bot en Redis.")
            return jsonify({"error": "Error interno: Bot no conectado."}), 500

        # 3. Obtener estructura actual del servidor (roles y canales)
        headers = {"Authorization": f"Bot {bot_token}"}
        
        async with aiohttp.ClientSession(headers=headers) as session_async:
            # Usar asyncio.gather para hacer requests concurrentes
            tasks = [
                session_async.get(f"https://discord.com/api/v10/guilds/{server_id}/roles"),
                session_async.get(f"https://discord.com/api/v10/guilds/{server_id}/channels")
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            roles_resp, channels_resp = responses

            # Manejar errores de API
            if isinstance(roles_resp, Exception) or not roles_resp.ok:
                logger.error(f"Error al obtener roles de {server_id}: {roles_resp}")
                return jsonify({"error": "Error al obtener roles del servidor."}), 500
            if isinstance(channels_resp, Exception) or not channels_resp.ok:
                logger.error(f"Error al obtener canales de {server_id}: {channels_resp}")
                return jsonify({"error": "Error al obtener canales del servidor."}), 500

            roles = await roles_resp.json()
            channels = await channels_resp.json()

        # 4. Formatear la estructura para la IA
        server_structure = {
            "roles": [{"id": r['id'], "name": r['name'], "position": r['position']} for r in roles],
            "channels": [{"id": c['id'], "name": c['name'], "type": c['type'], "parent_id": c.get('parent_id')} for c in channels]
        }
        
        # 5. Crear el prompt para la IA
        system_prompt = f"""
        Eres "Anlios Designer", un experto en diseño de servidores de Discord.
        Tu tarea es generar un plan JSON para modificar la estructura de un servidor basado en la petición del usuario.
        El usuario es un administrador del servidor: {guild['name']}.

        ESTRUCTURA ACTUAL DEL SERVIDOR:
        {json.dumps(server_structure, indent=2)}

        PETICIÓN DEL USUARIO:
        "{prompt}"

        REGLAS DE RESPUESTA:
        1.  Solo puedes responder con un objeto JSON.
        2.  El JSON debe contener dos claves: "explanation" (string) y "actions" (array).
        3.  "explanation": Explica brevemente (en el idioma del usuario, detecta si es 'es' o 'en') el plan que vas a ejecutar.
        4.  "actions": Es una lista de objetos. Cada objeto representa una acción atómica.
        5.  Acciones permitidas (el 'action_type'):
            * {"action_type": "CREATE_ROLE", "name": "Nombre Rol", "color": "#FFFFFF", "permissions": "0"}
            * {"action_type": "CREATE_CATEGORY", "name": "Nombre Categoría", "permissions": [...]}
            * {"action_type": "CREATE_CHANNEL", "name": "nombre-canal", "type": 0, "parent_name": "Nombre Categoría"} (type 0=TEXT, 2=VOICE)
            * {"action_type": "MODIFY_ROLE", "name": "Nombre Rol Existente", "new_name": "Nuevo Nombre", "color": "#000000"}
            * {"action_type": "MODIFY_CHANNEL", "name": "nombre-canal-existente", "new_name": "nuevo-nombre", "topic": "Nuevo topic"}
            * {"action_type": "DELETE_ROLE", "name": "Nombre Rol a Borrar"}
            * {"action_type": "DELETE_CHANNEL", "name": "nombre-canal-a-borrar"}
        6.  'permissions' para CREATE_CATEGORY: es una lista de objetos {"role_name": "Nombre Rol", "allow": "0", "deny": "0"}. Usa "@everyone" para el rol base.
        7.  Piensa paso a paso. Si el usuario pide "una categoría de staff", debes crear la categoría Y los canales (ej. #staff-chat, #staff-comandos).
        8.  Si la petición no es clara o es peligrosa (ej. "borra todo"), responde con una explicación amigable y un array 'actions' vacío.
        
        Responde solo con el JSON.
        """
        
        # 6. Llamar a la IA
        logger.info(f"Enviando prompt a Gemini para Designer (Servidor: {server_id})...")
        ia_response = chat_model.generate_content(system_prompt)
        
        # 7. Procesar y validar la respuesta JSON
        ia_json_text = ia_response.text.strip().replace("```json", "").replace("```", "")
        logger.info(f"Respuesta de IA (raw): {ia_json_text[:200]}...")
        
        try:
            ia_data = json.loads(ia_json_text)
            if "explanation" not in ia_data or "actions" not in ia_data:
                raise ValueError("JSON de IA no contiene 'explanation' o 'actions'.")
        except Exception as e:
            logger.error(f"Error al parsear JSON de la IA: {e}\nRespuesta recibida: {ia_json_text}")
            ia_data = {
                "explanation": "Hubo un error al procesar tu solicitud. La IA devolvió una respuesta inesperada. Revisa los logs.",
                "actions": []
            }
            
        # 8. Guardar respuesta de la IA
        ia_msg = {"role": "model", "content": ia_data.get("explanation", "Error"), "actions": ia_data.get("actions", [])}
        redis_client.rpush(f"designer_chat:{server_id}", json.dumps(ia_msg))
        
        # 9. Enviar comando al bot para EJECUTAR las acciones
        if ia_data.get("actions"):
            publish_command_to_bot(
                command="EXECUTE_DESIGN",
                data={
                    "server_id": server_id,
                    "user_id": user_id,
                    "actions": ia_data["actions"]
                }
            )

        # 10. Devolver la explicación al frontend
        return jsonify(ia_msg)

    except Exception as e:
        logger.error(f"Error en designer_chat para {server_id}: {e}", exc_info=True)
        return jsonify({"error": g._('error_500_msg')}), 500


# --- Membresía y Perfil ---

@app.route('/dashboard/<server_id>/membership')
@login_required
@check_premium_and_permissions('dashboard') # Cualquiera puede ver la página de membresía
def membership(server_id):
    """Página para gestionar la membresía premium del servidor."""
    guild = next((g for g in session['user_guilds'] if g['id'] == server_id), None)
    
    is_premium = False
    premium_info = {}
    premium_data = redis_client.get(f"premium:server:{server_id}")
    
    if premium_data:
        premium_info = json.loads(premium_data)
        if premium_info.get("status") == "active":
            is_premium = True
            
    # Mensaje de error si se redirigió aquí
    error_msg = None
    if request.args.get('error') == 'premium_required':
        error_msg = g._('membresia_error_premium_requerido')
    
    return render_template(
        'membership.html',
        title=g._('membresia_titulo'),
        server=guild,
        is_premium=is_premium,
        premium_info=premium_info,
        user_info=session['user_info'],
        error_msg=error_msg
    )

@app.route('/dashboard/<server_id>/redeem_code', methods=['POST'])
@login_required
@check_premium_and_permissions('dashboard')
def redeem_code(server_id):
    """Canjea un código premium."""
    try:
        data = request.json
        code = data.get('code')
        
        if not code:
            return jsonify({"success": False, "error": g._('membresia_error_codigo_vacio')}), 400
            
        code = code.strip().upper()
        
        # 1. Verificar si el código existe en Redis
        code_key = f"premium_code:{code}"
        code_data_raw = redis_client.get(code_key)
        
        if not code_data_raw:
            return jsonify({"success": False, "error": g._('membresia_error_codigo_invalido')}), 404
            
        code_data = json.loads(code_data_raw)
        
        # 2. Verificar si ya fue usado
        if code_data.get("used", False):
            return jsonify({"success": False, "error": g._('membresia_error_codigo_usado')}), 400
            
        # 3. Activar premium para el servidor
        duration_days = code_data.get("duration", 30)
        
        # (Lógica para extender el premium si ya tiene)
        # ...
        
        premium_record = {
            "status": "active",
            "activated_by": get_user_id(),
            "activated_at": (datetime.utcnow().isoformat() + "Z"),
            "duration_days": duration_days,
            "code_used": code
            # "expires_at": ... (calcular fecha de expiración)
        }
        
        redis_client.set(f"premium:server:{server_id}", json.dumps(premium_record))
        
        # 4. Marcar el código como usado
        code_data["used"] = True
        code_data["used_by_user"] = get_user_id()
        code_data["used_on_server"] = server_id
        code_data["used_at"] = premium_record["activated_at"]
        redis_client.set(code_key, json.dumps(code_data))
        
        logger.info(f"Código '{code}' canjeado en servidor {server_id} por {get_user_id()}.")
        
        return jsonify({"success": True, "message": g._('membresia_exito_codigo_canjeado').format(days=duration_days)})

    except Exception as e:
        logger.error(f"Error en redeem_code para {server_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

@app.route('/profile')
@login_required
def profile():
    """Página de perfil de usuario (para cambiar tema, etc.)."""
    
    # Obtener config de perfil (tema, color)
    user_id = get_user_id()
    profile_config = redis_client.get(f"user_profile:{user_id}")
    config = json.loads(profile_config) if profile_config else {}
    
    return render_template(
        'profile.html',
        title=g._('perfil_titulo'),
        user_info=session['user_info'],
        config=config
    )

@app.route('/save_profile', methods=['POST'])
@login_required
def save_profile():
    """Guarda la configuración de perfil del usuario (tema, color)."""
    try:
        data = request.json
        user_id = get_user_id()
        
        config = {
            "design": data.get("design", "design-anlios"),
            "color": data.get("color", "color-oceano-neon")
        }
        
        # Validar (opcional, pero buena idea)
        
        redis_client.set(f"user_profile:{user_id}", json.dumps(config))
        
        # Actualizar la sesión para que el layout.html lo detecte
        session['profile_config'] = config
        
        return jsonify({"success": True, "message": g._('guardado_exito_msg')})

    except Exception as e:
        logger.error(f"Error en save_profile para {user_id}: {e}", exc_info=True)
        return jsonify({"success": False, "error": g._('error_500_msg')}), 500

# ----------------------------------------
# Context Processors (Variables Globales)
# ----------------------------------------
@app.context_processor
def inject_global_vars():
    """Inyecta variables en todas las plantillas."""
    
    # Cargar config de perfil del usuario (tema/color)
    profile_config = {}
    if 'token' in session: # Solo si está logueado
        # 1. Intentar desde la sesión (más rápido)
        if 'profile_config' in session:
            profile_config = session['profile_config']
        else:
            # 2. Si no, cargar de Redis y guardar en sesión
            user_id = get_user_id()
            if user_id:
                profile_config_raw = redis_client.get(f"user_profile:{user_id}")
                if profile_config_raw:
                    profile_config = json.loads(profile_config_raw)
                session['profile_config'] = profile_config # Cachear en sesión

    # Valores por defecto si no hay config
    design = profile_config.get("design", "design-anlios")
    color = profile_config.get("color", "color-oceano-neon")

    return {
        'current_locale': g.locale,
        'user_info': session.get('user_info'),
        'g': g, # Hacer 'g' accesible (para g._)
        'current_design_css': f"css/designs/{design}.css",
        'current_color_css': f"css/colors/{color}.css"
    }

# ----------------------------------------
# Ejecución de la aplicación
# ----------------------------------------
if __name__ == '__main__':
    # Usar 'waitress' o 'gunicorn' en producción, no 'app.run()'
    # El puerto se obtiene de la variable de entorno PORT (para Heroku/Railway)
    port = int(os.environ.get("PORT", 5000))
    
    # ¡Importante! En producción, el host debe ser '0.0.0.0'
    # 'debug=True' NUNCA debe usarse en producción.
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV') != 'production')
