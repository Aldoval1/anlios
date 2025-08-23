# admin_dashboard.py

import os
import redis
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__, template_folder='website/templates')

# --- Configuración ---
# Se recomienda encarecidamente usar variables de entorno para estos valores en producción.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'una-clave-secreta-muy-fuerte-para-admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123') # ¡Cambia esto en producción!
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

# Conexión a Redis (asegúrate que coincida con la configuración de tus otros archivos)
try:
    redis_url = os.environ.get('REDIS_URL')
    if not redis_url:
        raise ValueError("La variable de entorno REDIS_URL no está configurada.")
    r = redis.from_url(redis_url, decode_responses=True)
    r.ping()
    print("Conexión a Redis en el panel de administración exitosa.")
except (redis.exceptions.ConnectionError, ValueError) as e:
    print(f"Error crítico al conectar con Redis: {e}")
    # En un entorno real, podrías querer manejar esto de forma más robusta.
    exit()

# --- Decorador de Autenticación ---
def login_required(f):
    """
    Asegura que un administrador haya iniciado sesión antes de acceder a una ruta.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Rutas de Autenticación ---
@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    """
    Página de inicio de sesión para el panel de administración.
    """
    if 'admin_logged_in' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        password = request.form.get('password')
        if password and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            session.permanent = True  # La sesión persistirá
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('home'))
        else:
            flash('La contraseña proporcionada es incorrecta.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def logout():
    """
    Cierra la sesión del administrador.
    """
    session.pop('admin_logged_in', None)
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('login'))

# --- Rutas del Panel ---
@app.route('/admin')
@login_required
def home():
    """
    Página principal del panel de administración.
    """
    return render_template('admin_layout.html', active_page='home')

@app.route('/admin/codes', methods=['GET', 'POST'])
@login_required
def manage_codes():
    """
    Gestiona la creación y visualización de códigos premium.
    """
    if request.method == 'POST':
        try:
            duration = int(request.form.get('duration'))
            if duration <= 0:
                flash('La duración debe ser un número positivo de días.', 'danger')
            else:
                # Genera un código único y más legible
                code = f"ANLIOS-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
                # Almacena el código en un hash de Redis
                r.hset(f"premium_code:{code}", mapping={
                    'duration_days': duration,
                    'is_used': 'False',
                    'used_by_guild': '',
                    'created_at': datetime.utcnow().isoformat()
                })
                flash(f'Código "{code}" generado exitosamente para {duration} días.', 'success')
        except (ValueError, TypeError):
            flash('Por favor, introduce una duración válida en días.', 'danger')

    # Obtiene todos los códigos para mostrarlos en la tabla
    codes_keys = r.keys('premium_code:*')
    codes_list = []
    for key in codes_keys:
        code_data = r.hgetall(key)
        codes_list.append({
            'code': key.split(':', 1)[1],
            'duration_days': code_data.get('duration_days', 'N/A'),
            'is_used': 'Sí' if code_data.get('is_used') == 'True' else 'No',
            'used_by_guild': code_data.get('used_by_guild', 'N/A')
        })
    # Ordena los códigos para una mejor visualización si es necesario
    codes_list.sort(key=lambda x: x['code'])
    return render_template('manage_premium.html', codes=codes_list, active_page='codes')

@app.route('/admin/servers')
@login_required
def view_servers():
    """
    Muestra una lista de todos los servidores donde el bot está activo.
    """
    # Escanea por claves que almacenan nombres de servidores
    guild_ids = {key.split(':', 1)[1] for key in r.keys('guild_name:*')}
    servers = []
    for guild_id in guild_ids:
        servers.append({
            'id': guild_id,
            'name': r.get(f"guild_name:{guild_id}") or "Nombre no disponible"
        })
    servers.sort(key=lambda x: x['name'])
    return render_template('server_viewer.html', servers=servers, active_page='servers')

@app.route('/admin/servers/<guild_id>')
@login_required
def view_server_config(guild_id):
    """
    Muestra la configuración detallada de un servidor específico.
    """
    config_data = {
        'Configuración de Tickets': r.hgetall(f"ticket_config:{guild_id}"),
        'Configuración de Moderación': r.hgetall(f"moderation_config:{guild_id}"),
        'Base de Conocimiento (Info)': r.hgetall(f"knowledge:{guild_id}"),
        'Suscripción Premium': r.hgetall(f"subscription:{guild_id}")
    }
    server_name = r.get(f"guild_name:{guild_id}") or f"Servidor {guild_id}"
    return render_template('view_server_config.html', config=config_data, server_name=server_name, guild_id=guild_id, active_page='servers')

@app.route('/admin/audit')
@login_required
def audit_log():
    """
    Muestra el registro de auditoría de las acciones realizadas en el dashboard de usuario.
    """
    # Obtiene los últimos 1000 registros para no sobrecargar
    logs = r.lrange('dashboard_audit_log', 0, 999)
    # Aquí podrías procesar los logs si estuvieran en formato JSON
    return render_template('audit_log.html', logs=logs, active_page='audit')

@app.route('/admin/maintenance', methods=['GET', 'POST'])
@login_required
def maintenance():
    """
    Controla el modo de mantenimiento del sitio principal.
    """
    if request.method == 'POST':
        # Actualiza el estado del modo mantenimiento
        status = 'enabled' if 'maintenance_mode' in request.form else 'disabled'
        r.hset('maintenance_status', 'status', status)

        # Actualiza la contraseña de tester
        tester_password = request.form.get('tester_password', '').strip()
        r.hset('maintenance_status', 'tester_password', tester_password)

        flash('La configuración de mantenimiento ha sido actualizada.', 'success')
        return redirect(url_for('maintenance'))

    m_status = r.hgetall('maintenance_status')
    status = m_status.get('status', 'disabled')
    tester_pass = m_status.get('tester_password', '')

    return render_template('admin_maintenance.html', status=status, tester_password=tester_pass, active_page='maintenance')

if __name__ == '__main__':
    # El host '0.0.0.0' permite el acceso desde la red local.
    # Para desarrollo local estricto, usa '127.0.0.1'.
    # El puerto 5001 es para evitar conflictos con el dashboard principal.
    app.run(host='0.0.0.0', port=5001, debug=True)