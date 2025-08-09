import discord
from discord.ext import commands, tasks
import os
import json
import google.generativeai as genai
from dotenv import load_dotenv
import asyncio
import redis
import time
import uuid
from datetime import datetime

# --- CONFIGURACIÓN INICIAL ---
load_dotenv()
intents = discord.Intents.default()
intents.guilds = True
intents.message_content = True
intents.members = True 
bot = commands.Bot(command_prefix="!", intents=intents)

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
CLAIMED_TAG = "[RECLAMADO]"
NO_KNOWLEDGE_TAG = "[NO_KNOWLEDGE]"
REDIS_GUILDS_KEY = "bot_guilds_list"
REDIS_COMMAND_QUEUE_KEY = "command_queue"
REDIS_TRAINING_QUEUE_KEY = "training_queue"
REDIS_SUBSCRIPTIONS_KEY = "subscriptions"
REDIS_CODES_KEY = "premium_codes"
PREMIUM_ROLE_ID = 1401935354575065158

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
        'log_channel_id': None
    }
    config = load_data_from_redis(f"ticket_config:{guild_id}", default_config)
    config.setdefault('log_enabled', False)
    config.setdefault('log_channel_id', None)
    return config

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
        if key not in config:
            config[key] = value
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_key not in config[key]:
                    config[key][sub_key] = sub_value
    return config
def load_module_config() -> dict: return load_data_from_redis("module_config", {})

# --- NUEVA FUNCIÓN PARA ENVIAR LOGS ---
async def send_ticket_log(guild: discord.Guild, title: str, description: str, color: discord.Color, author: discord.Member):
    config = load_ticket_config(guild.id)
    if not config.get('log_enabled') or not config.get('log_channel_id'):
        return

    log_channel = guild.get_channel(int(config['log_channel_id']))
    if not log_channel:
        print(f"Error de Log: Canal {config['log_channel_id']} no encontrado en el servidor {guild.name}.")
        return

    embed = discord.Embed(title=title, description=description, color=color, timestamp=datetime.utcnow())
    embed.set_author(name=str(author), icon_url=author.display_avatar.url)
    embed.set_footer(text=f"ID de Usuario: {author.id}")
    
    await log_channel.send(embed=embed)

def update_guilds_in_redis():
    if not redis_client: return
    print("Actualizando la lista de servidores en Redis...")
    guild_ids = [guild.id for guild in bot.guilds]
    save_data_to_redis(REDIS_GUILDS_KEY, guild_ids)
    print(f"El bot está ahora en {len(guild_ids)} servidores. Lista actualizada en Redis.")

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
    def __init__(self): super().__init__(timeout=None)
    
    async def check_permissions(self, interaction: discord.Interaction) -> bool:
        if interaction.user.guild_permissions.manage_channels: return True
        ticket_config = load_ticket_config(interaction.guild.id)
        admin_role_ids = set(ticket_config.get('admin_roles', []))
        user_role_ids = {str(role.id) for role in interaction.user.roles}
        return not admin_role_ids.isdisjoint(user_role_ids)

    @discord.ui.button(label="Reclamar Ticket", style=discord.ButtonStyle.primary, custom_id="ticket_actions:claim")
    async def claim_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await self.check_permissions(interaction):
            return await interaction.response.send_message("❌ No tienes permisos para reclamar este ticket.", ephemeral=True)
        
        # CORREGIDO: Manejo de canales y hilos
        channel_name = interaction.channel.name
        if CLAIMED_TAG not in channel_name:
            new_name = f"{channel_name} {CLAIMED_TAG}"
            await interaction.channel.edit(name=new_name)
            button.disabled = True
            await interaction.response.edit_message(view=self)
            await interaction.channel.send(f"✅ Ticket reclamado por **{interaction.user.display_name}**. El asistente de IA ha sido desactivado.")
        else:
            await interaction.response.send_message("Este ticket ya ha sido reclamado.", ephemeral=True)


    @discord.ui.button(label="Cerrar Ticket", style=discord.ButtonStyle.danger, custom_id="ticket_actions:close")
    async def close_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not await self.check_permissions(interaction):
            return await interaction.response.send_message("❌ No tienes permisos para cerrar este ticket.", ephemeral=True)
        
        await interaction.response.send_message("✅ **Ticket cerrado.** Este canal se eliminará en 5 segundos.")
        
        # --- MODIFICADO: Enviar log al cerrar ---
        log_description = f"Ticket `{interaction.channel.name}` cerrado por {interaction.user.mention}."
        await send_ticket_log(interaction.guild, "Ticket Cerrado", log_description, discord.Color.red(), interaction.user)
        
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
                return await interaction.followup.send("⚠️ ¡Ya tienes un ticket abierto!", ephemeral=True)
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
        await ticket_channel.send(embed=welcome_embed, view=TicketActionsView())
        await interaction.followup.send(f"✅ ¡Ticket creado! Ve a {ticket_channel.mention} para continuar.", ephemeral=True)
        
        # --- MODIFICADO: Enviar log al crear ---
        log_description = f"Ticket `{ticket_channel.name}` creado por {interaction.user.mention}."
        await send_ticket_log(interaction.guild, "Ticket Creado", log_description, discord.Color.green(), interaction.user)


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

    except Exception as e: print(f"[TAREA] ERROR: {e}")

# --- EVENTOS DEL BOT ---
@bot.event
async def on_ready():
    print(f'✅ ¡Bot conectado como {bot.user}!')
    bot.add_view(TicketActionsView())
    guild_ids = load_data_from_redis(REDIS_GUILDS_KEY, [])
    for guild_id in guild_ids:
        config = load_embed_config(guild_id)
        button_label = config.get('panel', {}).get('button_label', 'Crear Ticket')
        bot.add_view(TicketCreateView(button_label=button_label))
    update_guilds_in_redis()
    check_command_queue.start()

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
    await bot.process_commands(message)
    if message.author.bot or not message.channel.name.startswith('ticket-'): return
    
    module_config = load_module_config()
    if not module_config.get(str(message.guild.id), {}).get('modules', {}).get('ticket_ia', False): return
    
    # --- CORREGIDO: Manejo de error para hilos (Threads) ---
    # Los hilos no tienen 'topic', así que verificamos el nombre del canal/hilo
    if CLAIMED_TAG in message.channel.name:
        return

    if not GEMINI_API_KEY: return
    
    async with message.channel.typing():
        config = load_embed_config(message.guild.id)
        knowledge = load_knowledge(message.guild.id)
        knowledge_text = "\n".join(f"- {item}" for item in knowledge) if knowledge else "No hay información específica proporcionada."
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
                
                new_question = {
                    "id": str(uuid.uuid4()),
                    "question": message.content,
                    "user": message.author.name
                }
                pending_questions.append(new_question)
                save_data_to_redis(training_queue_key, pending_questions)
                
                await message.reply("🤔 No estoy seguro de la respuesta. He enviado tu pregunta a un administrador para que me ayude a aprender.")
            else:
                await message.reply(response_text)

        except Exception as e:
            print(f"Error en Gemini: {e}")
            await message.reply("🤖 Ocurrió un error al contactar con la IA.")

# --- COMANDOS DEL BOT ---
@bot.command()
@commands.guild_only()
@commands.is_owner()
async def sync(ctx: commands.Context):
    synced = await bot.tree.sync()
    await ctx.send(f"Sincronizados {len(synced)} comandos.")

# --- EJECUCIÓN DEL BOT ---
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
if not BOT_TOKEN: 
    print("❌ ERROR: No se encontró el token del bot.")
else: 
    bot.run(BOT_TOKEN)