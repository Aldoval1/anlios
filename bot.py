import discord
from discord.ext import commands, tasks
from discord import app_commands
import os
import json
import google.generativeai as genai
from dotenv import load_dotenv
import asyncio
import redis
import time
import uuid
from datetime import datetime, timedelta
import io
import aiohttp

# --- CONFIGURACIÓN INICIAL ---
load_dotenv()
intents = discord.Intents.default()
intents.guilds = True
intents.message_content = True
intents.members = True 
bot = commands.Bot(command_prefix="!", intents=intents)

# --- Cargar traducciones del bot ---
bot_translations = {}
try:
    with open('bot_translations.json', 'r', encoding='utf-8') as f:
        bot_translations = json.load(f)
except Exception as e:
    print(f"ERROR: No se pudo cargar el archivo de traducciones del bot: {e}")

# --- CONFIGURACIÓN DE REDIS ---
try:
    redis_client = redis.from_url(os.getenv('REDIS_URL'), decode_responses=True)
    print("Conexión con Redis establecida.")
except Exception as e:
    print(f"ERROR: No se pudo conectar a Redis. Error: {e}")
    redis_client = None

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("⚠️ ADVERTENCIA: No se encontró la clave de API de Gemini.")

# --- Nombres de Claves de Redis y Constantes ---
CLAIMED_TAG = "-reclamado"
NO_KNOWLEDGE_TAG = "[NO_KNOWLEDGE]"
REDIS_GUILDS_KEY = "bot_guilds_list"
REDIS_GUILD_NAMES_KEY = "guild_names_map"
REDIS_COMMAND_QUEUE_KEY = "command_queue"
REDIS_TRAINING_QUEUE_KEY = "training_queue"
REDIS_SUBSCRIPTIONS_KEY = "subscriptions"
REDIS_CODES_KEY = "premium_codes"
REDIS_MODERATION_CONFIG_KEY = "moderation_config:{}"
REDIS_WARNINGS_LOG_KEY = "warnings_log:{}"
REDIS_BACKUPS_KEY = "backups:{}"

# --- FUNCIONES AUXILIARES CON REDIS ---
def load_data_from_redis(key: str, default_value):
    if not redis_client: return default_value
    try:
        data = redis_client.get(key)
        return json.loads(data) if data else default_value
    except Exception as e:
        print(f"Error cargando datos de Redis para la clave {key}: {e}")
        return default_value

def save_data_to_redis(key: str, data):
    if not redis_client: return
    try:
        redis_client.set(key, json.dumps(data))
    except Exception as e:
        print(f"Error guardando datos en Redis para la clave {key}: {e}")

def load_ticket_config(guild_id: int) -> dict:
    default_config = {
        'admin_roles': [],
        'log_enabled': False,
        'log_channel_id': None,
        'language': 'es'
    }
    config = load_data_from_redis(f"ticket_config:{guild_id}", default_config)
    config.setdefault('log_enabled', False)
    config.setdefault('log_channel_id', None)
    config.setdefault('language', 'es')
    return config

def load_moderation_config(guild_id: int) -> dict:
    default_config = {
        "automod": {"enabled": False, "forbidden_words": [], "forbidden_words_action": "delete", "block_links": False, "block_links_action": "delete", "block_nsfw": False, "block_nsfw_action": "delete"},
        "warnings": {"enabled": False, "limit": 3, "dm_user": True},
        "commands": {"enabled": False, "cleanc": False, "lock": False},
        "vault": {"enabled": False}
    }
    key = REDIS_MODERATION_CONFIG_KEY.format(guild_id)
    config = load_data_from_redis(key, {})
    for section, defaults in default_config.items():
        if section not in config: config[section] = defaults
        else:
            for sub_key, value in defaults.items(): config[section].setdefault(sub_key, value)
    return config

def load_warnings_log(guild_id: int) -> dict: return load_data_from_redis(REDIS_WARNINGS_LOG_KEY.format(guild_id), {})
def save_warnings_log(guild_id: int, data: dict): save_data_to_redis(REDIS_WARNINGS_LOG_KEY.format(guild_id), data)
def load_backups(guild_id: int) -> list: return load_data_from_redis(REDIS_BACKUPS_KEY.format(guild_id), [])
def save_backups(guild_id: int, data: list): save_data_to_redis(REDIS_BACKUPS_KEY.format(guild_id), data)

def _(guild_id: int, key: str, **kwargs):
    config = load_ticket_config(guild_id)
    lang = config.get('language', 'es')
    text = bot_translations.get(lang, {}).get(key, key)
    return text.format(**kwargs) if kwargs else text

def load_knowledge(guild_id: int) -> list: return load_data_from_redis(f"knowledge:{guild_id}", [])
def save_knowledge(guild_id: int, data: list): save_data_to_redis(f"knowledge:{guild_id}", data)
def load_embed_config(guild_id: int) -> dict:
    default_config = {
        'panel': {'title': 'Sistema de Tickets', 'description': 'Haz clic para abrir un ticket.', 'color': '#ff4141', 'button_label': 'Crear Ticket', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'welcome': {'title': '¡Bienvenido, {user}!', 'description': 'Un asistente te atenderá pronto.', 'color': '#ff8282', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'ai_prompt': "Eres Anlios, un amigable y servicial asistente de IA. Tu propósito es ayudar a los usuarios con su conocimiento base. Si no encuentras la respuesta en tu base de conocimientos, DEBES empezar tu respuesta única y exclusivamente con la etiqueta [NO_KNOWLEDGE] y nada más."
    }
    config = load_data_from_redis(f"embed_config:{guild_id}", {})
    for key, value in default_config.items():
        if key not in config: config[key] = value
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_key not in config[key]: config[key][sub_key] = sub_value
    return config
def load_module_config() -> dict: return load_data_from_redis("module_config", {})

async def send_ticket_log(guild: discord.Guild, title: str, description: str, color: discord.Color, author: discord.Member, file: discord.File = None):
    config = load_ticket_config(guild.id)
    if not config.get('log_enabled') or not config.get('log_channel_id'): return
    log_channel = guild.get_channel(int(config['log_channel_id']))
    if not log_channel:
        print(f"Error de Log: Canal {config['log_channel_id']} no encontrado en el servidor {guild.name}.")
        return
    embed = discord.Embed(title=title, description=description, color=color, timestamp=datetime.utcnow())
    embed.set_author(name=str(author), icon_url=author.display_avatar.url)
    embed.set_footer(text=f"ID de Usuario: {author.id}")
    await log_channel.send(embed=embed, file=file)

def update_guilds_in_redis():
    if not redis_client: return
    print("Actualizando la lista y nombres de servidores en Redis...")
    guilds = bot.guilds
    guild_ids = [guild.id for guild in guilds]
    guild_names = {str(guild.id): guild.name for guild in guilds}
    save_data_to_redis(REDIS_GUILDS_KEY, guild_ids)
    save_data_to_redis(REDIS_GUILD_NAMES_KEY, guild_names)
    print(f"El bot está ahora en {len(guild_ids)} servidores. Lista y nombres actualizados en Redis.")

def build_embed_from_config(config: dict, user: discord.Member = None) -> discord.Embed:
    color_str = config.get('color', '#000000').lstrip('#')
    color = int(color_str, 16) if color_str else 0
    title = config.get('title', '')
    if user: title = title.replace('{user}', user.display_name)
    embed = discord.Embed(title=title, description=config.get('description', ''), color=color)
    if name := config.get('author_name'): embed.set_author(name=name, icon_url=config.get('author_icon') or None)
    if url := config.get('image'): embed.set_image(url=url)
    if url := config.get('thumbnail'): embed.set_thumbnail(url=url)
    if text := config.get('footer_text'): embed.set_footer(text=text, icon_url=config.get('footer_icon') or None)
    return embed

# --- VISTAS DE BOTONES ---
class TicketActionsView(discord.ui.View):
    def __init__(self, guild_id: int): 
        super().__init__(timeout=None)
        self.guild_id = guild_id
        self.claim_button.label = _(guild_id, "Reclamar Ticket")
        self.close_button.label = _(guild_id, "Cerrar Ticket")

    async def check_permissions(self, interaction: discord.Interaction) -> bool:
        if interaction.user.guild_permissions.manage_channels: return True
        ticket_config = load_ticket_config(interaction.guild.id)
        admin_role_ids = set(ticket_config.get('admin_roles', []))
        user_role_ids = {str(role.id) for role in interaction.user.roles}
        return not admin_role_ids.isdisjoint(user_role_ids)

    @discord.ui.button(label="Reclamar Ticket", style=discord.ButtonStyle.primary, custom_id="ticket_actions:claim")
    async def claim_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await self.check_permissions(interaction):
            return await interaction.response.send_message(_(interaction.guild.id, "NO_PERMISSION"), ephemeral=True)
        
        channel_name = interaction.channel.name
        if CLAIMED_TAG not in channel_name:
            new_name = f"{channel_name}{CLAIMED_TAG}"
            await interaction.channel.edit(name=new_name)
            button.disabled = True
            await interaction.response.edit_message(view=self)
            await interaction.channel.send(_(interaction.guild.id, "TICKET_CLAIMED", user_display_name=interaction.user.display_name))
        else:
            await interaction.response.send_message(_(interaction.guild.id, "TICKET_ALREADY_CLAIMED"), ephemeral=True)

    @discord.ui.button(label="Cerrar Ticket", style=discord.ButtonStyle.danger, custom_id="ticket_actions:close")
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await self.check_permissions(interaction):
            return await interaction.response.send_message(_(interaction.guild.id, "NO_PERMISSION"), ephemeral=True)
        
        await interaction.response.send_message(_(interaction.guild.id, "TICKET_CLOSED_TRANSCRIPT"))
        
        transcript_content = ""
        async for message in interaction.channel.history(limit=None, oldest_first=True):
            timestamp = message.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            transcript_content += f"[{timestamp}] {message.author.name}: {message.content}\n"
            for attachment in message.attachments:
                transcript_content += f"  [Archivo Adjunto: {attachment.url}]\n"

        transcript_file = None
        if transcript_content:
            buffer = io.StringIO(transcript_content)
            transcript_file = discord.File(buffer, filename=f"transcript-{interaction.channel.name}.txt")

        log_description = _(interaction.guild.id, "LOG_TICKET_CLOSED_DESC", channel_name=interaction.channel.name, user_mention=interaction.user.mention)
        await send_ticket_log(interaction.guild, _(interaction.guild.id, "LOG_TICKET_CLOSED_TITLE"), log_description, discord.Color.red(), interaction.user, file=transcript_file)
        
        await asyncio.sleep(5)
        await interaction.channel.delete(reason=f"Ticket cerrado por {interaction.user}")

class TicketCreateView(discord.ui.View):
    def __init__(self, button_label: str):
        super().__init__(timeout=None)
        create_button = discord.ui.Button(label=button_label, style=discord.ButtonStyle.primary, custom_id="persistent_view:create_ticket")
        create_button.callback = self.create_ticket_button_callback
        self.add_item(create_button)

    async def create_ticket_button_callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        ticket_channel_name = f"ticket-{interaction.user.name}"
        for channel in interaction.guild.text_channels:
            if channel.name.startswith(ticket_channel_name.lower()):
                return await interaction.followup.send(_(interaction.guild.id, "ALREADY_HAS_TICKET"), ephemeral=True)
        
        category = discord.utils.get(interaction.guild.categories, name="Tickets")
        if category is None: category = await interaction.guild.create_category("Tickets")
        
        overwrites = {
            interaction.guild.default_role: discord.PermissionOverwrite(read_messages=False),
            interaction.user: discord.PermissionOverwrite(read_messages=True, send_messages=True),
            interaction.guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True)
        }
        ticket_config = load_ticket_config(interaction.guild.id)
        for role_id in ticket_config.get('admin_roles', []):
            role = interaction.guild.get_role(int(role_id))
            if role: overwrites[role] = discord.PermissionOverwrite(read_messages=True, send_messages=True)
        
        ticket_channel = await interaction.guild.create_text_channel(name=ticket_channel_name, category=category, overwrites=overwrites)
        
        welcome_config = load_embed_config(interaction.guild.id).get('welcome', {})
        welcome_embed = build_embed_from_config(welcome_config, user=interaction.user)
        
        await ticket_channel.send(embed=welcome_embed, view=TicketActionsView(guild_id=interaction.guild.id))
        await interaction.followup.send(_(interaction.guild.id, "TICKET_CREATED_SUCCESS", channel_mention=ticket_channel.mention), ephemeral=True)
        
        log_description = _(interaction.guild.id, "LOG_TICKET_CREATED_DESC", channel_name=ticket_channel.name, user_mention=interaction.user.mention)
        await send_ticket_log(interaction.guild, _(interaction.guild.id, "LOG_TICKET_CREATED_TITLE"), log_description, discord.Color.green(), interaction.user)

# --- TAREAS EN SEGUNDO PLANO ---
@tasks.loop(seconds=5.0)
async def check_command_queue():
    await bot.wait_until_ready()
    if not redis_client: return
    try:
        command_json = redis_client.rpop(REDIS_COMMAND_QUEUE_KEY)
        if not command_json: return
        command_data = json.loads(command_json)
        command = command_data.get('command')
        
        if command == 'send_panel':
            guild_id, channel_id = command_data.get('guild_id'), command_data.get('channel_id')
            guild, channel = bot.get_guild(guild_id), bot.get_channel(channel_id)
            if guild and isinstance(channel, discord.TextChannel):
                panel_config = load_embed_config(guild_id).get('panel', {})
                panel_embed = build_embed_from_config(panel_config)
                view = TicketCreateView(button_label=panel_config.get('button_label', 'Crear Ticket'))
                await channel.send(embed=panel_embed, view=view)
        
        elif command == 'create_backup':
            guild_id = command_data.get('guild_id')
            guild = bot.get_guild(guild_id)
            if not guild: return

            icon_url = str(guild.icon.url) if guild.icon else None
            
            roles_data = []
            for role in sorted(guild.roles, key=lambda r: r.position, reverse=True):
                if role.is_default(): continue
                roles_data.append({
                    "name": role.name, "permissions": role.permissions.value,
                    "color": role.color.value, "hoist": role.hoist,
                    "mentionable": role.mentionable
                })

            channels_data = []
            for category, channels in guild.by_category():
                category_data = None
                if category:
                    # --- INICIO DE LA MODIFICACIÓN: Corrección del guardado de permisos ---
                    category_overwrites = []
                    for role, perms in category.overwrites.items():
                        if isinstance(role, discord.Role):
                            category_overwrites.append({
                                "role_name": role.name,
                                "allow": perms.allow.value,
                                "deny": perms.deny.value
                            })
                    category_data = {
                        "name": category.name, "type": "category",
                        "overwrites": category_overwrites
                    }
                    # --- FIN DE LA MODIFICACIÓN ---
                
                channel_list = []
                for channel in channels:
                    # --- INICIO DE LA MODIFICACIÓN: Corrección del guardado de permisos ---
                    channel_overwrites = []
                    for role, perms in channel.overwrites.items():
                         if isinstance(role, discord.Role):
                            channel_overwrites.append({
                                "role_name": role.name,
                                "allow": perms.allow.value,
                                "deny": perms.deny.value
                            })
                    channel_list.append({
                        "name": channel.name, "type": str(channel.type),
                        "topic": getattr(channel, 'topic', None),
                        "overwrites": channel_overwrites
                    })
                    # --- FIN DE LA MODIFICACIÓN ---
                
                channels_data.append({"category": category_data, "channels": channel_list})

            backup = {
                "id": str(uuid.uuid4()), "timestamp": time.time(),
                "name": guild.name, "icon_url": icon_url,
                "roles": roles_data, "channels": channels_data
            }
            
            backups = load_backups(guild_id)
            backups.append(backup)
            save_backups(guild_id, backups)
            print(f"Backup creado para el servidor {guild.name} (ID: {backup['id']})")

    except Exception as e: print(f"[TAREA] ERROR: {e}")

# --- EVENTOS DEL BOT ---
@bot.event
async def on_ready():
    print(f'✅ ¡Bot conectado como {bot.user}!')
    guild_ids = load_data_from_redis(REDIS_GUILDS_KEY, [])
    for guild_id in guild_ids:
        config = load_embed_config(guild_id)
        button_label = config.get('panel', {}).get('button_label', 'Crear Ticket')
        bot.add_view(TicketCreateView(button_label=button_label))
        bot.add_view(TicketActionsView(guild_id=guild_id))
    update_guilds_in_redis()
    check_command_queue.start()
    try:
        synced = await bot.tree.sync()
        print(f"Sincronizados {len(synced)} comandos slash.")
    except Exception as e:
        print(f"Error al sincronizar comandos: {e}")

@bot.event
async def on_guild_join(guild: discord.Guild):
    print(f"Bot añadido al servidor: {guild.name}")
    update_guilds_in_redis()

@bot.event
async def on_guild_remove(guild: discord.Guild):
    print(f"Bot eliminado del servidor: {guild.name}")
    update_guilds_in_redis()

@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        await bot.process_commands(message)
        return

    module_config = load_module_config()
    moderation_enabled = module_config.get(str(message.guild.id), {}).get('modules', {}).get('moderation', False)
    
    if moderation_enabled and not message.author.guild_permissions.manage_messages:
        mod_config = load_moderation_config(message.guild.id)
        automod_config = mod_config.get('automod', {})
        
        if automod_config.get('enabled'):
            forbidden_words = automod_config.get('forbidden_words', [])
            if any(word in message.content.lower() for word in forbidden_words):
                action = automod_config.get('forbidden_words_action')
                await message.delete()
                if action == 'warn':
                    await warn_user(message.author, message.guild, _(message.guild.id, "AUTO_WARN_REASON_WORD"))
                elif action == 'timeout':
                    await message.author.timeout(timedelta(minutes=10), reason=_(message.guild.id, "AUTO_TIMEOUT_REASON_WORD"))
                return

            if automod_config.get('block_links') and ('http://' in message.content or 'https://' in message.content):
                action = automod_config.get('block_links_action')
                await message.delete()
                reason = _(message.guild.id, "AUTO_REASON_LINK")
                if action == 'warn': await warn_user(message.author, message.guild, reason)
                elif action == 'kick': await message.author.kick(reason=reason)
                elif action == 'ban': await message.author.ban(reason=reason)
                return
            
            if automod_config.get('block_nsfw') and message.attachments:
                pass

    await bot.process_commands(message)
    if not message.channel.name.startswith('ticket-'): return
    
    if not module_config.get(str(message.guild.id), {}).get('modules', {}).get('ticket_ia', False): return
    if CLAIMED_TAG in message.channel.name: return
    if not GEMINI_API_KEY: return
    
    async with message.channel.typing():
        config = load_embed_config(message.guild.id)
        knowledge = load_knowledge(message.guild.id)
        
        knowledge_parts = []
        for item in knowledge:
            if isinstance(item, dict):
                content, item_type = item.get('content', ''), item.get('type')
                if item_type == 'pdf': knowledge_parts.append(f"Contenido del PDF '{item.get('filename', 'N/A')}':\n{content}")
                elif item_type == 'web': knowledge_parts.append(f"Contenido de la web {item.get('source', 'N/A')}:\n{content}")
                elif item_type == 'youtube': knowledge_parts.append(f"Transcripción de YouTube {item.get('source', 'N/A')}:\n{content}")
                else: knowledge_parts.append(content)
            else: knowledge_parts.append(str(item)) 

        knowledge_text = "\n\n".join(f"- {part}" for part in knowledge_parts) if knowledge_parts else "No hay información específica proporcionada."

        history_log = ""
        async for msg in message.channel.history(limit=10, oldest_first=False):
            if msg.embeds and msg.author == bot.user: continue
            speaker = "Usuario" if msg.author != bot.user else "Anlios"
            history_log = f"{speaker}: {msg.content}\n" + history_log
        
        system_prompt = config.get('ai_prompt').replace('{knowledge}', knowledge_text)
        final_prompt = f"{system_prompt}\n\n--- CONVERSACIÓN RECIENTE ---\n{history_log}--- FIN ---\n\nResponde al último mensaje del usuario."
        
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = await model.generate_content_async(final_prompt)
            response_text = response.text

            if response_text.strip().startswith(NO_KNOWLEDGE_TAG):
                training_queue_key = f"{REDIS_TRAINING_QUEUE_KEY}:{message.guild.id}"
                pending_questions = load_data_from_redis(training_queue_key, [])
                new_question = {"id": str(uuid.uuid4()), "question": message.content, "user": message.author.name}
                pending_questions.append(new_question)
                save_data_to_redis(training_queue_key, pending_questions)
                await message.reply(_(message.guild.id, "AI_NO_KNOWLEDGE"))
            else:
                await message.reply(response_text)
        except Exception as e:
            print(f"Error en Gemini: {e}")
            await message.reply(_(message.guild.id, "AI_ERROR"))

# --- COMANDOS SLASH DE MODERACIÓN ---
async def warn_user(member: discord.Member, guild: discord.Guild, reason: str):
    mod_config = load_moderation_config(guild.id)
    if not mod_config['warnings']['enabled']: return

    warnings_log = load_warnings_log(guild.id)
    user_id = str(member.id)
    
    if user_id not in warnings_log:
        warnings_log[user_id] = {"username": member.name, "warnings": []}
    
    warnings_log[user_id]['warnings'].append({"reason": reason, "timestamp": time.time()})
    
    limit = mod_config['warnings']['limit']
    current_warnings = len(warnings_log[user_id]['warnings'])

    if mod_config['warnings']['dm_user']:
        try:
            await member.send(_(guild.id, "WARN_DM", guild_name=guild.name, reason=reason, current_warnings=current_warnings, limit=limit))
        except discord.Forbidden:
            pass

    if current_warnings >= limit:
        await member.ban(reason=_(guild.id, "BAN_REASON_WARN_LIMIT", limit=limit))
        del warnings_log[user_id]
    
    save_warnings_log(guild.id, warnings_log)
    return current_warnings, limit

@bot.tree.command(name="warn", description="Advierte a un usuario.")
@app_commands.describe(member="El miembro a advertir", reason="La razón de la advertencia")
@app_commands.checks.has_permissions(kick_members=True)
async def warn(interaction: discord.Interaction, member: discord.Member, reason: str):
    current_warnings, limit = await warn_user(member, interaction.guild, reason)
    await interaction.response.send_message(_(interaction.guild.id, "WARN_SUCCESS", member_name=member.name, reason=reason, current_warnings=current_warnings, limit=limit), ephemeral=True)

@bot.tree.command(name="cleanc", description="Borra y recrea el canal actual.")
@app_commands.checks.has_permissions(manage_channels=True)
async def cleanc(interaction: discord.Interaction):
    class ConfirmationView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=30)
            self.value = None
        
        @discord.ui.button(label="Confirmar", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
            self.value = True
            self.stop()
        
        @discord.ui.button(label="Cancelar", style=discord.ButtonStyle.grey)
        async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
            self.value = False
            self.stop()

    view = ConfirmationView()
    await interaction.response.send_message(_(interaction.guild.id, "CLEANC_CONFIRM"), view=view, ephemeral=True)
    await view.wait()

    if view.value is True:
        channel = interaction.channel
        try:
            new_channel = await channel.clone(reason=f"Clonado por {interaction.user}")
            await channel.delete(reason=f"Canal limpiado por {interaction.user}")
            await new_channel.send(_(interaction.guild.id, "CLEANC_SUCCESS"))
        except discord.HTTPException as e:
            await interaction.followup.send(f"Error: {e}", ephemeral=True)

@bot.tree.command(name="lock", description="Bloquea el canal actual.")
@app_commands.checks.has_permissions(manage_channels=True)
async def lock(interaction: discord.Interaction):
    await interaction.channel.set_permissions(interaction.guild.default_role, send_messages=False)
    await interaction.response.send_message(_(interaction.guild.id, "LOCK_SUCCESS"))

@bot.tree.command(name="unlock", description="Desbloquea el canal actual.")
@app_commands.checks.has_permissions(manage_channels=True)
async def unlock(interaction: discord.Interaction):
    await interaction.channel.set_permissions(interaction.guild.default_role, send_messages=None)
    await interaction.response.send_message(_(interaction.guild.id, "UNLOCK_SUCCESS"))

# --- Comandos de Backup ---
backup_commands = app_commands.Group(name="backup", description="Comandos para gestionar backups del servidor.")

@backup_commands.command(name="load", description="Carga un backup en el servidor actual. ¡Esto borrará toda la configuración!")
@app_commands.describe(backup_id="El ID del backup a cargar.")
async def load_backup(interaction: discord.Interaction, backup_id: str):
    if interaction.user.id != interaction.guild.owner_id:
        await interaction.response.send_message(_(interaction.guild.id, "BACKUP_LOAD_NO_PERMISSION"), ephemeral=True)
        return

    class ConfirmationView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=30)
            self.value = None
        @discord.ui.button(label="Confirmar Carga", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
            self.value = True
            self.stop()
        @discord.ui.button(label="Cancelar", style=discord.ButtonStyle.grey)
        async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
            self.value = False
            self.stop()

    view = ConfirmationView()
    await interaction.response.send_message(_(interaction.guild.id, "BACKUP_LOAD_CONFIRM"), view=view, ephemeral=True)
    await view.wait()

    if view.value is not True:
        await interaction.followup.send(_(interaction.guild.id, "BACKUP_LOAD_ABORTED"), ephemeral=True)
        return

    await interaction.edit_original_response(content="⏳ " + _(interaction.guild.id, "BACKUP_LOAD_STARTING"), view=None)
    
    backups = load_backups(interaction.guild.id)
    backup_data = next((b for b in backups if b['id'] == backup_id), None)

    if not backup_data:
        await interaction.followup.send("❌ " + _(interaction.guild.id, "BACKUP_LOAD_NOT_FOUND"), ephemeral=True)
        return

    guild = interaction.guild
    try:
        for channel in guild.channels: await channel.delete(reason="Cargando backup")
        for role in guild.roles:
            if role.is_default() or role.is_bot_managed(): continue
            try:
                await role.delete(reason="Cargando backup")
            except discord.HTTPException:
                pass 

        if backup_data.get("icon_url"):
            async with aiohttp.ClientSession() as session:
                async with session.get(backup_data["icon_url"]) as resp:
                    if resp.status == 200:
                        icon_bytes = await resp.read()
                        await guild.edit(icon=icon_bytes)

        await interaction.followup.send("⏳ " + _(interaction.guild.id, "BACKUP_LOAD_PROGRESS_ROLES"), ephemeral=True)
        role_map = {}
        for role_data in reversed(backup_data["roles"]):
            permissions = discord.Permissions(role_data["permissions"])
            color = discord.Color(role_data["color"])
            new_role = await guild.create_role(
                name=role_data["name"], permissions=permissions, color=color,
                hoist=role_data["hoist"], mentionable=role_data["mentionable"],
                reason="Cargando backup"
            )
            role_map[role_data["name"]] = new_role

        await interaction.followup.send("⏳ " + _(interaction.guild.id, "BACKUP_LOAD_PROGRESS_CHANNELS"), ephemeral=True)
        for category_info in backup_data["channels"]:
            category_data = category_info.get("category")
            new_category = None
            if category_data:
                # --- INICIO DE LA MODIFICACIÓN: Corrección de la carga de permisos ---
                overwrites = {}
                for ow_data in category_data.get("overwrites", []):
                    role = role_map.get(ow_data["role_name"])
                    if role:
                        allow_perms = discord.Permissions(ow_data["allow"])
                        deny_perms = discord.Permissions(ow_data["deny"])
                        overwrites[role] = discord.PermissionOverwrite.from_pair(allow_perms, deny_perms)
                new_category = await guild.create_category(name=category_data["name"], overwrites=overwrites)
                # --- FIN DE LA MODIFICACIÓN ---

            for channel_data in category_info["channels"]:
                # --- INICIO DE LA MODIFICACIÓN: Corrección de la carga de permisos ---
                overwrites = {}
                for ow_data in channel_data.get("overwrites", []):
                    role = role_map.get(ow_data["role_name"])
                    if role:
                        allow_perms = discord.Permissions(ow_data["allow"])
                        deny_perms = discord.Permissions(ow_data["deny"])
                        overwrites[role] = discord.PermissionOverwrite.from_pair(allow_perms, deny_perms)
                # --- FIN DE LA MODIFICACIÓN ---
                
                channel_type = channel_data.get("type")
                if channel_type == "text":
                    await guild.create_text_channel(name=channel_data["name"], topic=channel_data.get("topic"), category=new_category, overwrites=overwrites)
                elif channel_type == "voice":
                    await guild.create_voice_channel(name=channel_data["name"], category=new_category, overwrites=overwrites)

        await interaction.followup.send("✅ " + _(interaction.guild.id, "BACKUP_LOAD_SUCCESS"), ephemeral=True)

    except Exception as e:
        await interaction.followup.send(f"❌ {_ (interaction.guild.id, 'BACKUP_LOAD_ERROR')}: {e}", ephemeral=True)

bot.tree.add_command(backup_commands)

# --- EJECUCIÓN DEL BOT ---
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
if not BOT_TOKEN: 
    print("❌ ERROR: No se encontró el token del bot.")
else: 
    bot.run(BOT_TOKEN)