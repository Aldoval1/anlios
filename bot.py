import discord
from discord.ext import commands, tasks
import os
import json
import google.generativeai as genai
from dotenv import load_dotenv
import asyncio
import redis
import time

# --- CONFIGURACIÓN INICIAL ---
load_dotenv()
intents = discord.Intents.default()
intents.guilds = True
intents.message_content = True
intents.members = True # Requerido para buscar miembros y asignar/quitar roles
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
REDIS_GUILDS_KEY = "bot_guilds_list"
REDIS_COMMAND_QUEUE_KEY = "command_queue"
REDIS_SUBSCRIPTIONS_KEY = "subscriptions"
REDIS_CODES_KEY = "premium_codes"

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

def load_knowledge(guild_id: int) -> list: return load_data_from_redis(f"knowledge:{guild_id}", [])
def load_embed_config(guild_id: int) -> dict:
    default_config = {
        'panel': {'title': 'Sistema de Tickets', 'description': 'Haz clic para abrir un ticket.', 'color': '#ff4141', 'button_label': 'Crear Ticket', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'welcome': {'title': '¡Bienvenido, {user}!', 'description': 'Un asistente te atenderá pronto.', 'color': '#ff8282', 'author_name': '', 'author_icon': '', 'image': '', 'thumbnail': '', 'footer_text': '', 'footer_icon': ''},
        'ai_prompt': "Eres Anlios, un amigable y servicial asistente de IA..."
    }
    return load_data_from_redis(f"embed_config:{guild_id}", default_config)
def load_module_config() -> dict: return load_data_from_redis("module_config", {})

def update_guilds_in_redis():
    if not redis_client: return
    print("Actualizando la lista de servidores en Redis...")
    guild_ids = [guild.id for guild in bot.guilds]
    save_data_to_redis(REDIS_GUILDS_KEY, guild_ids)
    print(f"El bot está ahora en {len(guild_ids)} servidores. Lista actualizada en Redis.")

def build_embed_from_config(config: dict, user: discord.Member = None) -> discord.Embed:
    color = int(config.get('color', '#000000').lstrip('#'), 16)
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
    @discord.ui.button(label="Reclamar Ticket", style=discord.ButtonStyle.primary, custom_id="ticket_actions:claim")
    async def claim_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.user.guild_permissions.manage_channels:
            return await interaction.response.send_message("❌ No tienes permisos para reclamar este ticket.", ephemeral=True)
        button.disabled = True
        await interaction.response.edit_message(view=self)
        await interaction.channel.edit(topic=f"{interaction.channel.topic} {CLAIMED_TAG}")
        await interaction.channel.send(f"✅ Ticket reclamado por **{interaction.user.display_name}**. El asistente de IA ha sido desactivado.")
    @discord.ui.button(label="Cerrar Ticket", style=discord.ButtonStyle.danger, custom_id="ticket_actions:close")
    async def close_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("✅ **Ticket cerrado.** Este canal se eliminará en 5 segundos.")
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
        overwrites = { interaction.guild.default_role: discord.PermissionOverwrite(read_messages=False), interaction.user: discord.PermissionOverwrite(read_messages=True, send_messages=True), interaction.guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True) }
        ticket_channel = await interaction.guild.create_text_channel(name=ticket_channel_name, category=category, overwrites=overwrites, topic=f"Ticket de {interaction.user.id}")
        welcome_config = load_embed_config(interaction.guild.id).get('welcome', {})
        welcome_embed = build_embed_from_config(welcome_config, user=interaction.user)
        await ticket_channel.send(embed=welcome_embed, view=TicketActionsView())
        await interaction.followup.send(f"✅ ¡Ticket creado! Ve a {ticket_channel.mention} para continuar.", ephemeral=True)

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
        module_config = load_module_config()
        
        if command == 'send_panel':
            guild_id, channel_id = command_data.get('guild_id'), command_data.get('channel_id')
            if not module_config.get(str(guild_id), {}).get('modules', {}).get('ticket_ia', False): return
            guild, channel = bot.get_guild(guild_id), bot.get_channel(channel_id)
            if guild and isinstance(channel, discord.TextChannel):
                panel_config = load_embed_config(guild_id).get('panel', {})
                panel_embed = build_embed_from_config(panel_config)
                view = TicketCreateView(button_label=panel_config.get('button_label', 'Crear Ticket'))
                await channel.send(embed=panel_embed, view=view)
        
        elif command == 'assign_premium_role':
            guild_id, user_id, role_id = command_data.get('guild_id'), command_data.get('user_id'), command_data.get('role_id')
            guild = bot.get_guild(guild_id)
            if not guild: return
            member = await guild.fetch_member(user_id)
            role = guild.get_role(role_id)
            if member and role:
                await member.add_roles(role, reason="Código premium canjeado")
                print(f"Rol premium asignado a {member.name} en {guild.name}.")

    except Exception as e: print(f"[TAREA] ERROR: {e}")

@tasks.loop(hours=1)
async def check_expired_subscriptions():
    await bot.wait_until_ready()
    if not redis_client: return
    print("[TAREA DE SUSCRIPCIÓN] Verificando suscripciones expiradas...")
    all_subscriptions = load_data_from_redis(REDIS_SUBSCRIPTIONS_KEY, {})
    current_time = time.time()
    for guild_id_str, sub_data in list(all_subscriptions.items()):
        if sub_data.get('expires_at', 0) < current_time:
            print(f"Suscripción expirada para el servidor {guild_id_str}.")
            guild_id, user_id, role_id = int(guild_id_str), sub_data.get('user_id'), 1401935354575065158
            guild = bot.get_guild(guild_id)
            if not guild:
                del all_subscriptions[guild_id_str]
                continue
            try:
                member = await guild.fetch_member(user_id)
                role = guild.get_role(role_id)
                if member and role and role in member.roles:
                    await member.remove_roles(role, reason="Suscripción premium expirada")
                    print(f"  -> Rol premium eliminado de {member.name} en {guild.name}.")
            except Exception as e:
                print(f"  -> ERROR al quitar rol: {e}")
            del all_subscriptions[guild_id_str]
    save_data_to_redis(REDIS_SUBSCRIPTIONS_KEY, all_subscriptions)
    print("[TAREA DE SUSCRIPCIÓN] Verificación completada.")

# --- EVENTOS DEL BOT ---
@bot.event
async def on_ready():
    print(f'✅ ¡Bot conectado como {bot.user}!')
    bot.add_view(TicketActionsView())
    update_guilds_in_redis()
    check_command_queue.start()
    check_expired_subscriptions.start()

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
    if message.channel.topic and CLAIMED_TAG in message.channel.topic: return
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
            await message.reply(response.text)
        except Exception as e:
            print(f"Error en Gemini: {e}")
            await message.reply("🤖 Ocurrió un error al contactar con la IA.")

# --- COMANDOS DEL BOT ---
@bot.command(name="añadir")
@commands.has_permissions(administrator=True)
async def add_knowledge(ctx: commands.Context, *, texto: str):
    knowledge = load_knowledge(ctx.guild.id); knowledge.append(texto); save_knowledge(ctx.guild.id, knowledge)
    await ctx.send(f"✅ Conocimiento añadido: '{texto}'")

@bot.command()
@commands.guild_only()
@commands.is_owner()
async def clear_commands(ctx: commands.Context):
    await ctx.send("Limpiando todos los comandos globales...")
    bot.tree.clear_commands(guild=None)
    await bot.tree.sync(guild=None)
    await ctx.send("✅ Comandos de barra (slash commands) globales limpiados.")

# --- EJECUCIÓN DEL BOT ---
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
if not BOT_TOKEN: print("❌ ERROR: No se encontró el token del bot.")
else: bot.run(BOT_TOKEN)