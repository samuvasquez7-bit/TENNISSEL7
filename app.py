import os
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, Response, send_from_directory
from database import connect as connect_sqlite
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from decimal import Decimal
from flask import current_app
from werkzeug.utils import secure_filename
import json
import requests
import re
import unicodedata
import folium
from geopy.geocoders import ArcGIS
from geopy.distance import geodesic


from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'tennissel_secret_key'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 86400

# Configuración de Sesión
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Servidor y puerto oficial de Gmail para envíos seguros
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Servidor SMTP de Google
app.config['MAIL_PORT'] = 587                 # Puerto estándar con cifrado TLS
app.config['MAIL_USE_TLS'] = True             # Activa la seguridad TLS (Transport Layer Security)

# Credenciales de autenticación
app.config['MAIL_USERNAME'] = 'tennisselnuestrosaber@gmail.com'  # Tu dirección de correo real
app.config['MAIL_PASSWORD'] = 'gqwm vkjx ziod mfqp'  # Contraseña de aplicación de Google
app.config['MAIL_DEFAULT_SENDER'] = ('TENNISSEL', 'tennisselnuestrosaber@gmail.com') # Nombre e email que verá el usuario

# Inicializamos el envío de correos asociándolo a tu app de Flask
mail = Mail(app)

# Inicializamos el generador de tokens usando la clave secreta de tu proyecto
serializer = URLSafeTimedSerializer(app.secret_key)

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'db', 'tennissel20.sqlite3')
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'db', 'tennissel2.0.sql')

UPLOAD_FOLDER = os.path.join('static', 'uploads', 'perfiles')
PRODUCT_UPLOAD_FOLDER = os.path.join('static', 'uploads', 'productos')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(PRODUCT_UPLOAD_FOLDER):
    os.makedirs(PRODUCT_UPLOAD_FOLDER)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/proxy-imagen')
def proxy_imagen():
    """Entrega imágenes remotas para evitar bloqueos de hotlink del navegador."""
    image_url = request.args.get('url', '')
    if image_url.startswith('IMG/'):
        return send_from_directory(app.static_folder, image_url)
    if not image_url.startswith(('https://', 'http://')):
        return '', 400

    try:
        response = requests.get(
            image_url,
            headers={'User-Agent': 'TENNISSEL/1.0'},
            timeout=8,
            stream=True
        )
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '')
        if not content_type.startswith('image/'):
            return '', 415
        return Response(
            response.content,
            content_type=content_type,
            headers={'Cache-Control': 'public, max-age=3600'}
        )
    except requests.RequestException:
        return '', 404


def get_db_connection():
    try:
        return connect_sqlite(DATABASE_PATH, SCHEMA_PATH)
    except sqlite3.Error as err:
        print(f"Error de conexion SQLite: {err}")
        return None


def asegurar_columna_hora_fin(conn):
    cursor = conn.cursor()
    try:
        cursor.execute('PRAGMA table_info(reservas)')
        if not any(row[1] == 'hora_fin' for row in cursor.fetchall()):
            cursor.execute('ALTER TABLE reservas ADD COLUMN hora_fin TIME DEFAULT NULL')
            conn.commit()
    finally:
        cursor.close()


def asegurar_columna_usuario_reserva(conn):
    cursor = conn.cursor()
    try:
        cursor.execute('PRAGMA table_info(reservas)')
        if not any(row[1] == 'user_id' for row in cursor.fetchall()):
            cursor.execute('ALTER TABLE reservas ADD COLUMN user_id INT NULL')
            conn.commit()
        cursor.execute('''
            UPDATE reservas
            SET user_id = (
                SELECT u.id FROM usuarios u
                WHERE reservas.nombre_usuario = u.username COLLATE NOCASE
                   OR reservas.nombre_usuario = u.nombre_completo COLLATE NOCASE
                LIMIT 1
            )
            WHERE user_id IS NULL AND EXISTS (
                SELECT 1 FROM usuarios u
                WHERE reservas.nombre_usuario = u.username COLLATE NOCASE
                   OR reservas.nombre_usuario = u.nombre_completo COLLATE NOCASE
            )
        ''')
        conn.commit()
    finally:
        cursor.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Para acceder a esta seccion necesitas registrarte primero.', 'warning')
            return redirect(url_for('registro'))
        return f(*args, **kwargs)
    return decorated_function


def not_banned_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        usuario_id = session.get('user_id')
        if usuario_id:
            baneado, _ = usuario_baneado(usuario_id)
            if baneado:
                flash('Tu cuenta esta bloqueada. Debes solicitar una revision antes de continuar.', 'error')
                return redirect(url_for('apelar_baneo'))
        return f(*args, **kwargs)
    return decorated_function


def tienda_premium_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Debes iniciar sesión para administrar productos.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'tienda' or not verificar_premium(session['user_id']):
            flash('Solo las cuentas Tienda con Premium pueden publicar productos.', 'warning')
            return redirect(url_for('premium'))
        baneado, _ = usuario_baneado(session['user_id'])
        if baneado:
            return redirect(url_for('apelar_baneo'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Debes iniciar sesion primero.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Acceso denegado.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def verificar_premium(user_id):
    """Verifica si un usuario tiene suscripcion activa en la tabla premium."""
    conn = get_db_connection()
    if not conn:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM premium WHERE user_id = %s", (user_id,))
        resultado = cursor.fetchone()
        return resultado and resultado[0] > 0
    except sqlite3.Error as err:
        print(f"Error verificando premium: {err}")
        return False
    finally:
        if cursor:
            cursor.close()
        conn.close()


PALABRAS_PROHIBIDAS = {
    # Lista inicial multilingue; se puede ampliar sin cambiar el flujo de moderacion.
    'puta', 'puto', 'putas', 'putos', 'mierda', 'marica', 'maricon',
    'hijueputa', 'hijoputa', 'cojones', 'cabron', 'pendejo', 'idiota',
    'fuck', 'fucking', 'shit', 'bitch', 'asshole', 'bastard', 'motherfucker',
    'dick', 'cunt', 'slut', 'whore', 'bullshit', 'kurwa', 'dupa', 'putain',
    'merde', 'con', 'cul', 'scheisse', 'arschloch', 'mierda', 'zorra'
}


def texto_moderacion(texto):
    """Normaliza texto para detectar insultos con acentos, simbolos o leetspeak."""
    texto = unicodedata.normalize('NFKD', texto.lower())
    texto = ''.join(char for char in texto if not unicodedata.combining(char))
    reemplazos = str.maketrans({'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
                                '7': 't', '@': 'a', '$': 's'})
    texto = texto.translate(reemplazos)
    return re.sub(r'[^a-z0-9]+', ' ', texto)


def contiene_lenguaje_ofensivo(texto):
    normalizado = texto_moderacion(texto)
    compacto = normalizado.replace(' ', '')
    tokens = set(normalizado.split())
    return any(palabra in tokens or palabra in compacto or re.search(rf'(?<![a-z]){re.escape(palabra)}(?![a-z])', normalizado)
               for palabra in PALABRAS_PROHIBIDAS)


def asegurar_columna_propietario_producto(conn):
    cursor = conn.cursor()
    try:
        cursor.execute('PRAGMA table_info(productos)')
        if not any(row[1] == 'owner_user_id' for row in cursor.fetchall()):
            cursor.execute('ALTER TABLE productos ADD COLUMN owner_user_id INT NULL')
            conn.commit()
    finally:
        cursor.close()


def asegurar_tabla_valoraciones_producto(conn):
    cursor = conn.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS producto_valoraciones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                producto_id INT NOT NULL,
                usuario_id INT NOT NULL,
                calificacion TINYINT NOT NULL,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (producto_id, usuario_id),
                FOREIGN KEY (producto_id) REFERENCES productos(id) ON DELETE CASCADE,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
            )
        ''')
        conn.commit()
    finally:
        cursor.close()


def imagen_producto_valida(file_storage):
    extension = os.path.splitext(secure_filename(file_storage.filename or ''))[1].lower()
    if extension not in {'.png', '.jpg', '.jpeg', '.gif', '.webp'}:
        return False
    cabecera = file_storage.stream.read(12)
    file_storage.stream.seek(0)
    firmas = (
        cabecera.startswith(b'\x89PNG'),
        cabecera.startswith(b'\xff\xd8\xff'),
        cabecera.startswith((b'GIF87a', b'GIF89a')),
        cabecera.startswith(b'RIFF') and cabecera[8:12] == b'WEBP',
    )
    return any(firmas)


def usuario_baneado(usuario_id):
    conn = get_db_connection()
    if not conn:
        return False, None
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT baneado, motivo_baneo FROM usuarios WHERE id = %s", (usuario_id,))
        usuario = cursor.fetchone() or {}
        return bool(usuario.get('baneado')), usuario.get('motivo_baneo')
    except sqlite3.Error:
        return False, None
    finally:
        if cursor:
            cursor.close()
        conn.close()


def banear_usuario_por_moderacion(usuario_id, motivo, evidencia, locacion_id):
    conn = get_db_connection()
    if not conn:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE usuarios
            SET baneado = 1, motivo_baneo = %s, evidencia_baneo = %s,
                locacion_baneo = %s, fecha_baneo = NOW()
            WHERE id = %s
        """, (motivo, evidencia, locacion_id, usuario_id))
        conn.commit()
        return True
    except sqlite3.Error as err:
        conn.rollback()
        print(f"Error aplicando baneo automatico: {err}")
        return False
    finally:
        if cursor:
            cursor.close()
        conn.close()


def contar_notificaciones(user_id):
    """Cuenta todas las notificaciones disponibles para un usuario."""
    conn = get_db_connection()
    if not conn:
        return 0

    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*)
            FROM (
                SELECT id FROM soporte_tecnico
                WHERE usuario_id = %s AND respuesta IS NOT NULL
                UNION ALL
                SELECT id FROM solicitudes_contacto
                WHERE usuario_id = %s AND respuesta IS NOT NULL
                UNION ALL
                SELECT id FROM notificaciones_moderacion
                WHERE usuario_id = %s
            ) AS notificaciones
        """, (user_id, user_id, user_id))
        resultado = cursor.fetchone()
        return resultado[0] if resultado else 0
    except sqlite3.Error as err:
        print(f"Error contando notificaciones: {err}")
        return 0
    finally:
        if cursor:
            cursor.close()
        conn.close()


@app.context_processor
def contexto_usuario():
    """Expone el estado de autenticación y Premium a todas las plantillas."""
    autenticado = 'user_id' in session
    esta_baneado = bool(usuario_baneado(session['user_id'])[0]) if autenticado else False
    es_premium = autenticado and (
        session.get('role') in ('admin', 'premium')
        or verificar_premium(session['user_id'])
    )
    return {
        'usuario_autenticado': autenticado,
        'is_premium': es_premium,
        'is_banned': esta_baneado,
        'notification_count': contar_notificaciones(session['user_id']) if autenticado else 0,
    }


# ═══════════════════════════════════════════════════════════════════════════
# RUTAS PUBLICAS
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/robots.txt')
def robots_txt():
    contenido = f"User-agent: *\nAllow: /\nDisallow: /admin/\nDisallow: /tienda/\nSitemap: {url_for('sitemap_xml', _external=True)}\n"
    return Response(contenido, mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap_xml():
    urls = [url_for('index', _external=True), url_for('productos', _external=True)]
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute('SELECT slug FROM productos WHERE activo = 1 ORDER BY id DESC')
            urls.extend(url_for('producto_detalle', slug=row['slug'], _external=True) for row in cursor.fetchall())
        finally:
            cursor.close()
            conn.close()
    xml = '<?xml version="1.0" encoding="UTF-8"?>' + '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    xml += ''.join(f'<url><loc>{url}</loc></url>' for url in urls)
    xml += '</urlset>'
    return Response(xml, mimetype='application/xml')


@app.route('/juegos')
def juegos():
    """Centro de minijuegos de TENNISSEL."""
    return render_template('juegos.html')


@app.route('/juego')
def juego():
    """Partido interactivo Tennis Arena."""
    return render_template('juego.html')


SECCIONES_INFORMATIVAS = {
    'jugadores': ('Jugadores', 'Conoce cómo analizar el estilo, la evolución y los resultados de los tenistas del circuito.'),
    'partidos_recientes': ('Partidos recientes', 'Aprende a leer resultados, estadísticas y decisiones que definen cada encuentro.'),
    'datos_y_tips': ('Datos y tips', 'Convierte estadísticas y hábitos de entrenamiento en mejoras concretas para tu juego.'),
    'noticias_semanales': ('Noticias semanales', 'Sigue los resultados, el ranking y el calendario con el contexto de cada semana.'),
    'noticias_new': ('Noticias de último momento', 'Consulta novedades del circuito y aprende a diferenciar información confirmada de rumores.'),
    'marcas_y_utiles': ('Marcas y útiles', 'Elige raquetas, calzado y accesorios según tu nivel, superficie y forma de jugar.'),
    'sitios_tennis': ('Sitios para ver tenis', 'Encuentra recursos para seguir marcadores, calendarios, estadísticas y transmisiones.'),
}


def mostrar_seccion_informativa(seccion):
    """Carga el contenido editable y conserva la guía completa si la tabla está vacía."""
    titulo, descripcion = SECCIONES_INFORMATIVAS[seccion]
    bloques = []
    conn = get_db_connection()
    if conn:
        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            # El nombre procede exclusivamente del diccionario anterior, no de la petición.
            cursor.execute(
                f'SELECT tipo, titulo, texto, orden FROM contenido_{seccion} '
                'WHERE activo = TRUE ORDER BY orden, id'
            )
            bloques = cursor.fetchall()
        except sqlite3.Error as err:
            print(f'Error cargando contenido de {seccion}: {err}')
        finally:
            if cursor:
                cursor.close()
            conn.close()
    return render_template('informacion/info_generica.html', titulo=titulo, descripcion=descripcion, bloques=bloques)


@app.route('/informacion/jugadores')
def informacion_jugadores():
    return mostrar_seccion_informativa('jugadores')


@app.route('/informacion/atp_wta')
def informacion_atp_wta():
    return render_template('informacion/atp_wta.html')


@app.route('/informacion/datos_y_tips')
def informacion_datos_y_tips():
    return mostrar_seccion_informativa('datos_y_tips')


@app.route('/informacion/noticias_new')
def informacion_noticias_new():
    return mostrar_seccion_informativa('noticias_new')


@app.route('/informacion/noticias_semanales')
def informacion_noticias_semanales():
    return mostrar_seccion_informativa('noticias_semanales')


@app.route('/informacion/partidos_recientes')
def informacion_partidos_recientes():
    return mostrar_seccion_informativa('partidos_recientes')


@app.route('/informacion/sitios_tennis')
def informacion_sitios_tennis():
    return mostrar_seccion_informativa('sitios_tennis')


@app.route('/informacion/torneos')
def informacion_torneos():
    """Muestra los bloques y eventos que administra el panel de torneos."""
    contenidos, torneos = [], []
    conn = get_db_connection()
    if conn:
        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('''
                SELECT tipo, titulo, texto, orden
                FROM contenido_torneos
                WHERE activo = TRUE
                ORDER BY orden, id
            ''')
            contenidos = cursor.fetchall()
            cursor.execute('''
                SELECT id, nombre, categoria, fecha, lugar, nivel, descripcion
                FROM torneos
                WHERE activo = TRUE
                ORDER BY orden, id
            ''')
            torneos = cursor.fetchall()
        except sqlite3.Error as err:
            # La página sigue disponible aunque todavía no se haya aplicado la migración.
            print(f'Error cargando torneos: {err}')
        finally:
            if cursor:
                cursor.close()
            conn.close()
    return render_template('informacion/torneos.html', contenidos=contenidos, torneos=torneos)


@app.route('/informacion/marcas_y_utiles')
def informacion_marcas_y_utiles():
    return mostrar_seccion_informativa('marcas_y_utiles')





@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if 'user_id' in session:
        flash('Ya tienes una sesión iniciada.', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        telefono = request.form.get('telefono', '').strip()
        email = request.form.get('email', '').strip()
        ciudad = request.form.get('ciudad', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        nivel = request.form.get('nivel', 'principiante')
        rol = request.form.get('rol', 'cliente')

        if not username or not email or not password:
            flash('Por favor, completa todos los campos obligatorios.', 'error')
            return redirect(url_for('registro'))

        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'error')
            return redirect(url_for('registro'))

        if len(password) < 6:
            flash('La contraseña debe tener al menos 6 caracteres.', 'error')
            return redirect(url_for('registro'))

        if nivel not in {'principiante', 'intermedio', 'avanzado'} or rol not in {'cliente', 'profesor', 'tienda'}:
            flash('Selecciona un nivel y tipo de cuenta válidos.', 'error')
            return redirect(url_for('registro'))

        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        if conn is None:
            flash('Error al conectar con la base de datos.', 'error')
            return redirect(url_for('registro'))

        try:
            cursor = conn.cursor()
            query_usuario = """
                INSERT INTO usuarios (username, nombre_completo, email, telefono, ciudad, password, rol)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query_usuario, (username, username, email, telefono, ciudad or None, hashed_password, rol))
            usuario_id = cursor.lastrowid

            query_perfil_defecto = """
                INSERT INTO perfil_usuario (usuario_id, foto, nivel, mano, reves)
                VALUES (%s, 'default.png', %s, 'diestro', 'dos_manos')
            """
            cursor.execute(query_perfil_defecto, (usuario_id, nivel))
            conn.commit()
            flash('Registro exitoso! Por favor inicia sesion.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as err:
            conn.rollback()
            print(f"Error al registrar: {err}")
            flash('No fue posible registrar el usuario. El correo o usuario ya existen.', 'error')
            return redirect(url_for('registro'))
        finally:
            cursor.close()
            conn.close()

    return render_template('registro.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session:
        flash('Ya tienes una sesión iniciada.', 'info')
        return redirect(url_for('index'))

    if request.method == "POST":
        email = request.form.get("email", '').strip()
        password = request.form.get("password", '')
        conn = get_db_connection()
        if conn is None:
            flash("Error de conexion.", "error")
            return redirect(url_for("login"))

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
            usuario = cursor.fetchone()
        except sqlite3.Error as err:
            print(f"Error: {err}")
            flash("Error al consultar la base de datos.", "error")
            return redirect(url_for("login"))
        finally:
            cursor.close()
            conn.close()

        if usuario and check_password_hash(usuario["password"], password):
            session['user_id'] = usuario['id']
            session['username'] = usuario['username']
            session['role'] = usuario['rol']
            if usuario.get('baneado'):
                flash('Tu cuenta esta bloqueada. Puedes consultar o enviar una apelación.', 'error')
                return redirect(url_for('apelar_baneo'))
            flash(f"Bienvenido de vuelta, {usuario['username']}!", "success")
            return redirect(url_for("index"))
        flash("Correo o contrasena incorrectos.", "error")

    return render_template("login.html")


@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesion correctamente.', 'info')
    return redirect(url_for('index'))


@app.route('/productos')
def productos():
    subcat = request.args.get('subcategoria') or request.args.get('categoria')
    marca = request.args.get('marca')
    color = request.args.get('color')
    talla = request.args.get('talla')
    precio_min = request.args.get('precio_min')
    precio_max = request.args.get('precio_max')
    orden = request.args.get('orden')

    query = "SELECT * FROM productos WHERE 1=1"
    params = []

    if subcat and subcat != 'Todas':
        query += " AND subcategoria = %s"
        params.append(subcat)
    if marca:
        query += " AND marca LIKE %s"
        params.append(f"%{marca}%")
    if color:
        query += " AND color LIKE %s"
        params.append(f"%{color}%")
    if talla:
        query += " AND talla = %s"
        params.append(talla)
    if precio_min:
        query += " AND precio >= %s"
        params.append(precio_min)
    if precio_max:
        query += " AND precio <= %s"
        params.append(precio_max)
    if orden == 'precio_asc':
        query += " ORDER BY precio ASC"
    elif orden == 'precio_desc':
        query += " ORDER BY precio DESC"
    elif orden == 'nombre_asc':
        query += " ORDER BY nombre ASC"
    elif orden == 'nombre_desc':
        query += " ORDER BY nombre DESC"

    conn = get_db_connection()
    if not conn:
        flash("Error de conexion a la base de datos", "error")
        return render_template('productos.html', productos=[])

    try:
        cursor = conn.cursor(dictionary=True)
        asegurar_columna_propietario_producto(conn)
        cursor.execute(query, tuple(params))
        lista_productos = cursor.fetchall()
    except sqlite3.Error as err:
        print(f"Error al filtrar productos: {err}")
        lista_productos = []
    finally:
        cursor.close()
        conn.close()

    return render_template('productos.html', productos=lista_productos)


@app.route('/tienda/productos', methods=['GET', 'POST'])
@tienda_premium_required
def tienda_productos():
    conn = get_db_connection()
    if not conn:
        flash('No fue posible conectar con la base de datos.', 'error')
        return render_template('tienda_productos.html', productos=[])

    cursor = conn.cursor(dictionary=True)
    asegurar_columna_propietario_producto(conn)
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        descripcion = request.form.get('descripcion', '').strip()
        precio_raw = request.form.get('precio', '').strip()
        imagen = request.files.get('imagen')
        nombre_archivo = (imagen.filename if imagen else '').strip()

        if contiene_lenguaje_ofensivo(f'{nombre} {descripcion}') or contiene_lenguaje_ofensivo(nombre_archivo):
            cursor.close()
            conn.close()
            banear_usuario_por_moderacion(session['user_id'], 'Contenido ofensivo en un producto.', f'{nombre} {descripcion} {nombre_archivo}', None)
            flash('Tu cuenta fue bloqueada por publicar contenido ofensivo. Puedes apelar la decisión.', 'error')
            return redirect(url_for('apelar_baneo'))

        try:
            precio = float(precio_raw)
        except (TypeError, ValueError):
            precio = 0
        if not nombre or not descripcion or precio <= 0 or not imagen or not imagen.filename:
            flash('Completa nombre, descripción, precio e imagen.', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('tienda_productos'))
        if not imagen_producto_valida(imagen):
            flash('La imagen debe ser PNG, JPG, GIF o WEBP válida.', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('tienda_productos'))

        nombre_seguro = secure_filename(imagen.filename)
        nombre_archivo = f"tienda_{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{nombre_seguro}"
        ruta_imagen = os.path.join(PRODUCT_UPLOAD_FOLDER, nombre_archivo)
        imagen.save(ruta_imagen)
        slug_base = re.sub(r'[^a-z0-9]+', '-', texto_moderacion(nombre)).strip('-') or 'producto'
        slug = f'{slug_base}-{session["user_id"]}-{datetime.now().strftime("%H%M%S%f")}'
        try:
            cursor.execute('SELECT id FROM categorias ORDER BY id LIMIT 1')
            categoria = cursor.fetchone()
            if not categoria:
                raise sqlite3.Error('No hay categorías disponibles')
            cursor.execute('''
                INSERT INTO productos
                    (owner_user_id, nombre, slug, descripcion_corta, descripcion_larga,
                     categoria_id, subcategoria, precio, stock, imagen_principal, activo)
                VALUES (%s, %s, %s, %s, %s, %s, 'Tienda', %s, 1, %s, 1)
            ''', (session['user_id'], nombre, slug, descripcion[:255], descripcion,
                  categoria['id'], precio, f'uploads/productos/{nombre_archivo}'))
            conn.commit()
            flash('Producto publicado correctamente.', 'success')
        except sqlite3.Error as err:
            conn.rollback()
            if os.path.exists(ruta_imagen):
                os.remove(ruta_imagen)
            print(f'Error creando producto de tienda: {err}')
            flash('No se pudo publicar el producto.', 'error')
        finally:
            cursor.close()
            conn.close()
        return redirect(url_for('tienda_productos'))

    cursor.execute('''
        SELECT id, nombre, descripcion_corta, precio, imagen_principal
        FROM productos WHERE owner_user_id = %s ORDER BY created_at DESC, id DESC
    ''', (session['user_id'],))
    productos_tienda = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('tienda_productos.html', productos=productos_tienda)


@app.route('/tienda/productos/<int:id>/eliminar', methods=['POST'])
@tienda_premium_required
def eliminar_producto_tienda(id):
    conn = get_db_connection()
    if not conn:
        flash('No fue posible conectar con la base de datos.', 'error')
        return redirect(url_for('tienda_productos'))
    cursor = conn.cursor(dictionary=True)
    asegurar_columna_propietario_producto(conn)
    cursor.execute('''
        SELECT imagen_principal FROM productos
        WHERE id = %s AND owner_user_id = %s
    ''', (id, session['user_id']))
    producto = cursor.fetchone()
    if not producto:
        cursor.close()
        conn.close()
        flash('No puedes eliminar productos de otra tienda.', 'error')
        return redirect(url_for('tienda_productos'))
    cursor.execute('DELETE FROM productos WHERE id = %s AND owner_user_id = %s', (id, session['user_id']))
    conn.commit()
    cursor.close()
    conn.close()
    imagen = producto.get('imagen_principal', '')
    if imagen.startswith('uploads/productos/'):
        ruta_imagen = os.path.join('static', imagen.replace('/', os.sep))
        if os.path.exists(ruta_imagen):
            os.remove(ruta_imagen)
    flash('Producto eliminado correctamente.', 'success')
    return redirect(url_for('tienda_productos'))


@app.route('/producto/<int:id>')
def producto_detalle_legacy(id):
    conn = get_db_connection()
    if not conn:
        return "Error de conexion", 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT slug FROM productos WHERE id = %s", (id,))
    producto = cursor.fetchone()
    cursor.close()
    conn.close()
    if not producto:
        return "Producto no encontrado", 404
    return redirect(url_for('producto_detalle', slug=producto['slug']), code=301)


@app.route('/productos/<string:slug>')
def producto_detalle(slug):
    conn = get_db_connection()
    if not conn:
        return "Error de conexion", 500

    cursor = conn.cursor(dictionary=True)
    asegurar_tabla_valoraciones_producto(conn)
    cursor.execute("SELECT * FROM productos WHERE slug = %s", (slug,))
    producto = cursor.fetchone()

    if not producto:
        cursor.close()
        conn.close()
        return "Producto no encontrado", 404

    try:
        cursor.execute('''
            SELECT COALESCE(AVG(calificacion), 0) AS promedio, COUNT(*) AS total
            FROM producto_valoraciones WHERE producto_id = %s
        ''', (producto['id'],))
        valoracion = cursor.fetchone() or {'promedio': 0, 'total': 0}
        cursor.execute("SELECT * FROM productos WHERE id != %s LIMIT 4", (producto['id'],))
        similares = cursor.fetchall()
    except sqlite3.Error:
        similares = []

    try:
        cursor.execute("""
            SELECT pf.*, u.username AS usuario_nombre,
                   COALESCE(AVG(pv.calificacion), 0) AS valoracion_promedio,
                   COUNT(pv.id) AS total_valoraciones
            FROM preguntas_frecuentes pf
            LEFT JOIN usuarios u ON u.id = pf.usuario_id
            LEFT JOIN preguntas_frecuentes_valoraciones pv ON pv.pregunta_id = pf.id
            WHERE pf.producto_id = %s AND pf.aprobada = 1
            GROUP BY pf.id
            ORDER BY valoracion_promedio DESC, total_valoraciones DESC, pf.created_at DESC
        """, (producto['id'],))
        preguntas = cursor.fetchall()
    except sqlite3.Error:
        preguntas = []

    cursor.close()
    conn.close()
    return render_template('producto_detalle.html', producto=producto, similares=similares,
                           preguntas=preguntas, valoracion=valoracion)


@app.route('/productos/<string:slug>/preguntas', methods=['POST'])
@login_required
@not_banned_required
def preguntar_producto(slug):
    pregunta = request.form.get('pregunta', '').strip()
    if not pregunta or len(pregunta) > 1000:
        flash('Escribe una pregunta válida de máximo 1000 caracteres.', 'error')
        return redirect(url_for('producto_detalle', slug=slug))
    if contiene_lenguaje_ofensivo(pregunta):
        banear_usuario_por_moderacion(session['user_id'], 'Lenguaje ofensivo en una pregunta de producto.', pregunta, None)
        flash('Tu cuenta fue bloqueada por publicar contenido ofensivo.', 'error')
        return redirect(url_for('apelar_baneo'))
    conn = get_db_connection()
    if not conn:
        flash('No fue posible guardar la pregunta.', 'error')
        return redirect(url_for('producto_detalle', slug=slug))
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT id FROM productos WHERE slug = %s AND activo = 1', (slug,))
        producto = cursor.fetchone()
        if not producto:
            return 'Producto no encontrado', 404
        cursor.execute('''
            INSERT INTO preguntas_frecuentes (producto_id, usuario_id, pregunta, aprobada)
            VALUES (%s, %s, %s, 1)
        ''', (producto['id'], session['user_id'], pregunta))
        conn.commit()
        flash('Pregunta enviada. Aparecerá cuando sea aprobada.', 'success')
    except sqlite3.Error:
        conn.rollback()
        flash('No fue posible guardar la pregunta.', 'error')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('producto_detalle', slug=slug))


@app.route('/preguntas/<int:pregunta_id>/calificar', methods=['POST'])
@login_required
@not_banned_required
def calificar_pregunta_producto(pregunta_id):
    try:
        calificacion = int(request.form.get('calificacion', 0))
    except (TypeError, ValueError):
        calificacion = 0
    if calificacion not in range(1, 6):
        flash('La calificación debe estar entre 1 y 5 estrellas.', 'error')
        return redirect(request.referrer or url_for('productos'))
    conn = get_db_connection()
    if not conn:
        flash('No fue posible guardar la calificación.', 'error')
        return redirect(request.referrer or url_for('productos'))
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO preguntas_frecuentes_valoraciones (pregunta_id, usuario_id, calificacion)
            SELECT id, %s, %s FROM preguntas_frecuentes WHERE id = %s AND aprobada = 1
            ON CONFLICT (pregunta_id, usuario_id) DO UPDATE
            SET calificacion = excluded.calificacion, fecha = CURRENT_TIMESTAMP
        ''', (session['user_id'], calificacion, pregunta_id))
        if cursor.rowcount == 0:
            flash('La pregunta no está disponible para calificar.', 'error')
        else:
            conn.commit()
            flash('Tu calificación de la pregunta fue guardada.', 'success')
    except sqlite3.Error:
        conn.rollback()
        flash('No fue posible guardar la calificación.', 'error')
    finally:
        cursor.close()
        conn.close()
    return redirect(request.referrer or url_for('productos'))


@app.route('/productos/<string:slug>/calificar', methods=['POST'])
@login_required
@not_banned_required
def calificar_producto(slug):
    try:
        calificacion = int(request.form.get('calificacion', 0))
    except (TypeError, ValueError):
        calificacion = 0
    if calificacion not in range(1, 6):
        flash('La calificación debe estar entre 1 y 5 estrellas.', 'error')
        return redirect(url_for('producto_detalle', slug=slug))
    conn = get_db_connection()
    if not conn:
        flash('No fue posible guardar la calificación.', 'error')
        return redirect(url_for('producto_detalle', slug=slug))
    cursor = conn.cursor(dictionary=True)
    try:
        asegurar_tabla_valoraciones_producto(conn)
        cursor.execute('SELECT id FROM productos WHERE slug = %s AND activo = 1', (slug,))
        producto = cursor.fetchone()
        if not producto:
            return 'Producto no encontrado', 404
        cursor.execute('''
            INSERT INTO producto_valoraciones (producto_id, usuario_id, calificacion)
            VALUES (%s, %s, %s)
            ON CONFLICT (producto_id, usuario_id) DO UPDATE
            SET calificacion = excluded.calificacion, fecha = CURRENT_TIMESTAMP
        ''', (producto['id'], session['user_id'], calificacion))
        conn.commit()
        flash('Tu calificación fue guardada.', 'success')
    except sqlite3.Error:
        conn.rollback()
        flash('No fue posible guardar la calificación.', 'error')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('producto_detalle', slug=slug))


@app.route('/catalogo')
def catalogo():
    categoria = request.args.get('categoria')
    subcategoria = request.args.get('subcategoria')
    marca = request.args.get('marca')
    color = request.args.get('color')
    talla = request.args.get('talla')
    precio_max = request.args.get('precio_max')

    conn = get_db_connection()
    if not conn:
        return render_template('productos.html', productos=[])

    query = "SELECT * FROM productos WHERE 1=1"
    parametros = []

    if categoria:
        query += " AND categoria = %s"
        parametros.append(categoria)
    if subcategoria:
        query += " AND subcategoria = %s"
        parametros.append(subcategoria)
    if marca:
        query += " AND marca = %s"
        parametros.append(marca)
    if color:
        query += " AND color = %s"
        parametros.append(color)
    if talla:
        query += " AND talla = %s"
        parametros.append(talla)
    if precio_max:
        query += " AND precio <= %s"
        parametros.append(precio_max)

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, tuple(parametros))
        productos_lista = cursor.fetchall()
    except sqlite3.Error as err:
        print(f"Error en catalogo: {err}")
        productos_lista = []
    finally:
        cursor.close()
        conn.close()

    return render_template('productos.html', productos=productos_lista)


@app.route('/contacto', methods=['GET', 'POST'])
def contacto():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip()
        motivo = request.form.get('motivo', '').strip()
        mensaje = request.form.get('mensaje', '').strip()
        usuario_id = session.get('user_id')

        conn = get_db_connection()
        if conn is None:
            flash("Error de conexion a la base de datos.", "error")
            return redirect(url_for('contacto'))

        try:
            cursor = conn.cursor()
            query = """
                INSERT INTO solicitudes_contacto (usuario_id, nombre, correo, motivo, mensaje)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (usuario_id, nombre, correo, motivo, mensaje))
            conn.commit()
            flash('Mensaje enviado con exito!', 'success')
            return redirect(url_for('contacto_exito'))
        except sqlite3.Error as err:
            print(f"Error: {err}")
            flash('Hubo un error interno.', 'error')
            return redirect(url_for('contacto'))
        finally:
            cursor.close()
            conn.close()

    usuario_datos = None
    if 'user_id' in session:
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT username, email FROM usuarios WHERE id = %s", (session['user_id'],))
                usuario_datos = cursor.fetchone()
            except sqlite3.Error as err:
                print(f"Error: {err}")
            finally:
                cursor.close()
                conn.close()

    return render_template('contacto.html', usuario=usuario_datos)


@app.route('/contacto-exito')
def contacto_exito():
    return render_template('contacto_exito.html')


# ═══════════════════════════════════════════════════════════════════════════
# RUTAS PROTEGIDAS (LOGIN REQUIRED)
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/carrito/agregar/<int:producto_id>', methods=['POST'])
@login_required
def agregar_al_carrito(producto_id):
    usuario_id = session.get('user_id')
    try:
        cantidad = int(request.form.get('cantidad', 1))
    except ValueError:
        cantidad = 1

    conn = get_db_connection()
    if not conn:
        flash("Error de conexion", "error")
        return redirect(url_for('productos'))

    try:
        cursor = conn.cursor()
        query = """
            INSERT INTO carrito (usuario_id, producto_id, cantidad) 
            VALUES (%s, %s, %s)
            ON CONFLICT (usuario_id, producto_id) DO UPDATE
            SET cantidad = carrito.cantidad + excluded.cantidad
        """
        cursor.execute(query, (usuario_id, producto_id, cantidad))
        conn.commit()
        flash("Producto agregado al carrito", "success")
    except sqlite3.Error as err:
        conn.rollback()
        print(f"Error al agregar al carrito: {err}")
        flash("No se pudo agregar el producto", "error")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('ver_carrito'))


@app.route('/api/compras', methods=['POST'])
@login_required
def crear_compra():
    """Crea una factura a partir del carrito enviado por el cliente."""
    datos = request.get_json(silent=True) or {}
    productos_solicitados = datos.get('productos', [])
    metodo_pago = (datos.get('metodo_pago') or 'Tarjeta').strip()[:50]
    if not isinstance(productos_solicitados, list) or not productos_solicitados:
        return jsonify(error='El carrito está vacío.'), 400

    cantidades = {}
    try:
        for producto in productos_solicitados:
            producto_id = int(producto['id'])
            cantidad = int(producto.get('cantidad', 1))
            if producto_id <= 0 or cantidad <= 0:
                raise ValueError
            cantidades[producto_id] = cantidades.get(producto_id, 0) + cantidad
    except (KeyError, TypeError, ValueError):
        return jsonify(error='Los datos del carrito no son válidos.'), 400

    conn = get_db_connection()
    if not conn:
        return jsonify(error='No fue posible conectar con la base de datos.'), 500

    cursor = None
    try:
        conn.start_transaction()
        cursor = conn.cursor(dictionary=True)
        productos_confirmados = []
        total = Decimal('0.00')
        for producto_id, cantidad in cantidades.items():
            cursor.execute("""
                SELECT id, nombre, precio, stock FROM productos
                WHERE id = %s AND activo = 1 FOR UPDATE
            """, (producto_id,))
            producto = cursor.fetchone()
            if not producto:
                raise ValueError('Uno de los productos ya no está disponible.')
            if producto['stock'] < cantidad:
                raise ValueError(f"No hay suficientes unidades de {producto['nombre']}.")
            subtotal = producto['precio'] * cantidad
            total += subtotal
            productos_confirmados.append((producto, cantidad, subtotal))

        costo_envio = Decimal('0.00') if total >= Decimal('300000.00') else Decimal('10000.00')
        total += costo_envio

        cursor.execute("""
            INSERT INTO facturas (usuario_id, total, estado, metodo_pago)
            VALUES (%s, %s, 'pagado', %s)
        """, (session['user_id'], total, metodo_pago))
        factura_id = cursor.lastrowid
        for producto, cantidad, subtotal in productos_confirmados:
            cursor.execute("""
                INSERT INTO detalle_factura (factura_id, producto_id, cantidad, precio_unitario, subtotal)
                VALUES (%s, %s, %s, %s, %s)
            """, (factura_id, producto['id'], cantidad, producto['precio'], subtotal))
            cursor.execute("UPDATE productos SET stock = stock - %s WHERE id = %s", (cantidad, producto['id']))

        cursor.execute("DELETE FROM carrito WHERE usuario_id = %s", (session['user_id'],))
        conn.commit()
        fecha_entrega = (datetime.now() + timedelta(days=5)).date().isoformat()
        return jsonify(factura_id=factura_id, fecha_entrega_estimada=fecha_entrega,
                       redirect_url=url_for('mis_compras')), 201
    except ValueError as err:
        conn.rollback()
        return jsonify(error=str(err)), 400
    except sqlite3.Error as err:
        conn.rollback()
        print(f"Error al crear compra: {err}")
        return jsonify(error='No fue posible registrar la compra.'), 500
    finally:
        if cursor:
            cursor.close()
        conn.close()


@app.route('/carrito')
@login_required
def ver_carrito():
    usuario_id = session.get('user_id')
    conn = get_db_connection()
    if not conn:
        flash("Error de conexion", "error")
        return redirect(url_for('index'))

    carrito_items = []
    total = 0
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT c.id AS carrito_id, p.id AS producto_id, p.nombre, p.precio, c.cantidad, 
                   (p.precio * c.cantidad) AS subtotal
            FROM carrito c
            JOIN productos p ON c.producto_id = p.id
            WHERE c.usuario_id = %s
        """
        cursor.execute(query, (usuario_id,))
        carrito_items = cursor.fetchall()
        total = sum(item['subtotal'] for item in carrito_items)
    except sqlite3.Error as err:
        print(f"Error al cargar carrito: {err}")
    finally:
        cursor.close()
        conn.close()

    return render_template('carrito.html', carrito=carrito_items, total=total)


@app.route('/carrito/eliminar/<int:carrito_id>', methods=['POST'])
@login_required
def eliminar_item_carrito(carrito_id):
    usuario_id = session.get('user_id')
    conn = get_db_connection()
    if not conn:
        flash("Error de conexion", "error")
        return redirect(url_for('ver_carrito'))

    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM carrito WHERE id = %s AND usuario_id = %s", (carrito_id, usuario_id))
        conn.commit()
        flash("Producto eliminado del carrito", "success")
    except sqlite3.Error as err:
        conn.rollback()
        print(f"Error al eliminar item: {err}")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('ver_carrito'))


@app.route('/premium', methods=['GET', 'POST'])
@login_required
def premium():
    if request.method == 'POST':
        plan = request.form.get('plan', '').strip()
        if not plan:
            flash('Faltan datos para procesar la suscripcion.', 'error')
            return redirect(url_for('premium'))

        conn = get_db_connection()
        if conn is None:
            flash('Error al conectar con la base de datos.', 'error')
            return redirect(url_for('premium'))

        try:
            cursor = conn.cursor()
            query = "INSERT INTO premium (user_id, plan) VALUES (%s, %s)"
            cursor.execute(query, (session['user_id'], plan))
            conn.commit()
            flash('Suscripcion Premium activada!', 'success')
            return redirect(url_for('index'))
        except sqlite3.Error as err:
            print(f"Error en Premium: {err}")
            flash('Error al procesar la suscripcion.', 'error')
            return redirect(url_for('premium'))
        finally:
            cursor.close()
            conn.close()

    return render_template('premium.html')


@app.route('/exito')
def exito():
    return render_template('exito.html')


@app.route('/notificaciones')
@login_required
def notificaciones():
    usuario_id = session.get('user_id')
    conn = get_db_connection()
    if conn is None:
        flash("Error de conexion.", "error")
        return redirect(url_for('index'))

    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT id, motivo, mensaje, respuesta, fecha_respuesta, NULL AS evidencia, 'soporte' AS origen
            FROM soporte_tecnico WHERE usuario_id = %s AND respuesta IS NOT NULL
            UNION
            SELECT id, motivo, mensaje, respuesta, fecha_respuesta, NULL AS evidencia, 'contacto' AS origen
            FROM solicitudes_contacto WHERE usuario_id = %s AND respuesta IS NOT NULL
            UNION
            SELECT id, titulo AS motivo, apelacion AS mensaje, respuesta,
                   fecha_respuesta, evidencia, 'moderacion' AS origen
            FROM notificaciones_moderacion WHERE usuario_id = %s
            ORDER BY fecha_respuesta DESC
        """
        cursor.execute(query, (usuario_id, usuario_id, usuario_id))
        notificaciones_list = cursor.fetchall()
    except sqlite3.Error as err:
        print(f"Error al cargar notificaciones: {err}")
        notificaciones_list = []
    finally:
        cursor.close()
        conn.close()

    return render_template('notificaciones.html', notificaciones=notificaciones_list)


@app.route('/api/notificaciones/count')
@login_required
def api_notificaciones_count():
    return jsonify(count=contar_notificaciones(session['user_id']))


@app.route('/soporte_tecnico', methods=['GET', 'POST'])
@login_required
def soporte_tecnico():
    if request.method == 'POST':
        motivo = request.form.get('motivo', '').strip()
        mensaje = request.form.get('mensaje', '').strip()
        usuario_id = session.get('user_id')

        if not motivo or not mensaje:
            flash("Por favor, completa todos los campos.", "error")
            return redirect(url_for('soporte_tecnico'))

        conn = get_db_connection()
        if conn is None:
            flash("Error de conexion.", "error")
            return redirect(url_for('soporte_tecnico'))

        try:
            cursor = conn.cursor()
            query = """
                INSERT INTO soporte_tecnico (usuario_id, motivo, mensaje, fecha_envio)
                VALUES (%s, %s, %s, NOW())
            """
            cursor.execute(query, (usuario_id, motivo, mensaje))
            conn.commit()
            flash('Solicitud de soporte enviada con exito!', 'success')
            return redirect(url_for('contacto_exito'))
        except sqlite3.Error as err:
            conn.rollback()
            print(f"Error al guardar soporte: {err}")
            flash('Hubo un error al procesar tu solicitud.', 'error')
            return redirect(url_for('soporte_tecnico'))
        finally:
            cursor.close()
            conn.close()

    return render_template('soporte_tecnico.html')


# ═══════════════════════════════════════════════════════════════════════════
# RUTA DE EDITAR PERFIL
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/editarperfil', methods=['GET', 'POST'])
@login_required
def editarperfil():
    conn = get_db_connection()
    if conn is None:
        flash("Error de conexión con la base de datos.", "error")
        return redirect(url_for("index"))

    if request.method == 'POST':
        username        = request.form.get('username', '').strip()
        nombre_completo = request.form.get('nombre_completo', '').strip()
        email           = request.form.get('email', '').strip()
        telefono        = request.form.get('telefono', '').strip()
        ciudad          = request.form.get('ciudad', '').strip()
        nivel           = request.form.get('nivel', 'principiante')
        mano_dominante  = request.form.get('mano_dominante', 'diestro')
        reves           = request.form.get('reves', 'dos_manos')

        if not username or not email or not nombre_completo:
            flash("El nombre de usuario, nombre completo y correo son obligatorios.", "error")
            conn.close()
            return redirect(url_for("editarperfil"))

        try:
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE usuarios 
                SET username = %s, nombre_completo = %s, email = %s, 
                    telefono = %s, ciudad = %s
                WHERE id = %s
            """, (username, nombre_completo, email, telefono, ciudad, session['user_id']))

            cursor.execute("SELECT COUNT(*) FROM perfil_usuario WHERE usuario_id = %s", (session['user_id'],))
            existe = cursor.fetchone()[0]

            foto_filename = None
            if 'foto_perfil' in request.files:
                file = request.files['foto_perfil']
                if file and file.filename != '' and allowed_file(file.filename):
                    if existe:
                        cursor.execute("SELECT foto FROM perfil_usuario WHERE usuario_id = %s", (session['user_id'],))
                        row = cursor.fetchone()
                        if row and row[0] and row[0] != 'default.png':
                            old_path = os.path.join(app.config['UPLOAD_FOLDER'], row[0])
                            if os.path.exists(old_path):
                                os.remove(old_path)

                    ext = file.filename.rsplit('.', 1)[1].lower()
                    foto_filename = f"user_{session['user_id']}_{int(datetime.now().timestamp())}.{ext}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))

            if existe:
                if foto_filename:
                    cursor.execute("""
                        UPDATE perfil_usuario 
                        SET nivel = %s, mano = %s, reves = %s, foto = %s
                        WHERE usuario_id = %s
                    """, (nivel, mano_dominante, reves, foto_filename, session['user_id']))
                else:
                    cursor.execute("""
                        UPDATE perfil_usuario 
                        SET nivel = %s, mano = %s, reves = %s
                        WHERE usuario_id = %s
                    """, (nivel, mano_dominante, reves, session['user_id']))
            else:
                foto_def = foto_filename or 'default.png'
                cursor.execute("""
                    INSERT INTO perfil_usuario (usuario_id, foto, nivel, mano, reves)
                    VALUES (%s, %s, %s, %s, %s)
                """, (session['user_id'], foto_def, nivel, mano_dominante, reves))

            nueva_password = request.form.get('password', '').strip()
            if nueva_password:
                if len(nueva_password) < 6:
                    flash("La nueva contraseña debe tener al menos 6 caracteres.", "warning")
                else:
                    cursor.execute("""
                        UPDATE usuarios SET password = %s WHERE id = %s
                    """, (generate_password_hash(nueva_password), session['user_id']))

            conn.commit()
            session['username'] = username
            flash("Perfil actualizado con éxito!", "success")
            return redirect(url_for("editarperfil"))

        except sqlite3.Error as err:
            conn.rollback()
            print(f"Error al actualizar el perfil: {err}")
            flash("Error al actualizar los datos.", "error")
            return redirect(url_for("editarperfil"))
        finally:
            cursor.close()
            conn.close()

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                u.id, u.username, u.nombre_completo, u.email, 
                u.telefono, u.ciudad,
                p.foto, p.nivel, p.mano AS mano_dominante, p.reves
            FROM usuarios u
            LEFT JOIN perfil_usuario p ON u.id = p.usuario_id
            WHERE u.id = %s
        """, (session['user_id'],))
        usuario = cursor.fetchone()
    except sqlite3.Error as err:
        print(err)
        flash("No fue posible obtener el usuario.", "error")
        return redirect(url_for("index"))
    finally:
        cursor.close()
        conn.close()

    if usuario is None:
        flash("Usuario no encontrado.", "error")
        return redirect(url_for("index"))

    if not usuario.get('foto') or usuario['foto'] == 'default.png':
        usuario['foto'] = None
    elif not usuario['foto'].startswith('http'):
        usuario['foto'] = url_for('static', filename=f'uploads/perfiles/{usuario["foto"]}')

    return render_template("editarperfil.html", usuario=usuario)


DIAS_ESPANOL = {
    0: 'Lunes', 1: 'Martes', 2: 'Miercoles', 
    3: 'Jueves', 4: 'Viernes', 5: 'Sabado', 6: 'Domingo'
}


@app.route('/terminos-servicio')
def terminos_servicio():
    return render_template('terminos_servicio.html')

@app.route('/politica-privacidad')
def politica_privacidad():
    return render_template('politica_privacidad.html')


# --- RUTAS DE POLÍTICAS Y LEGALES ---

@app.route('/politica-devoluciones')
def politica_devoluciones():
    return render_template('politica_devoluciones.html')

@app.route('/politica-garantias')
def politica_garantias():
    return render_template('politica_garantias.html')

@app.route('/tratamiento-datos')
def tratamiento_datos():
    return render_template('tratamiento_datos.html')

@app.route('/politica-cookies')
def politica_cookies():
    return render_template('politica_cookies.html')

@app.route('/entreno')
@login_required
def entreno():
    dias_semana = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo']
    dia_seleccionado = request.args.get('dia', dias_semana[datetime.today().weekday()])
    
    rol_usuario = session.get('role', 'cliente')
    tiene_premium_db = verificar_premium(session['user_id'])

    ve_contenido_premium = (rol_usuario == 'admin' or tiene_premium_db)
    tipo_cuenta = 'admin' if rol_usuario == 'admin' else ('premium' if tiene_premium_db else 'free')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if ve_contenido_premium:
        query = """
            SELECT r.*, e.nombre, e.descripcion, e.categoria, e.dificultad
            FROM rutinas_entrenamiento r
            JOIN ejercicios e ON r.ejercicio_id = e.id
            WHERE r.dia_semana = %s
        """
        cursor.execute(query, (dia_seleccionado,))
    else:
        query = """
            SELECT r.*, e.nombre, e.descripcion, e.categoria, e.dificultad
            FROM rutinas_entrenamiento r
            JOIN ejercicios e ON r.ejercicio_id = e.id
            WHERE r.dia_semana = %s AND r.tipo_usuario = 'free'
        """
        cursor.execute(query, (dia_seleccionado,))

    rutinas = cursor.fetchall()
    cursor.close()
    conn.close()

    tiempo_total = sum(r['duracion_minutos'] for r in rutinas) if rutinas else 0
    calorias_totales = sum(r['calorias_estimadas'] for r in rutinas) if rutinas else 0

    return render_template(
        'entreno.html',
        dia=dia_seleccionado,
        tipo_cuenta=tipo_cuenta,
        rutinas=rutinas,
        tiempo_total=tiempo_total,
        calorias_totales=calorias_totales
    )

@app.route('/matchmaking')
@login_required
@not_banned_required
def matchmaking():
    if session.get('role') == 'admin' or session.get('role') == 'profesor' or verificar_premium(session['user_id']):
        canchas = []
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT id, nombre FROM locaciones WHERE LOWER(TRIM(tipo)) = 'cancha' ORDER BY nombre")
                canchas = cursor.fetchall()
            finally:
                cursor.close()
                conn.close()
        return render_template('matchmaking.html', canchas=canchas)
    flash("Para acceder a Matchmaking necesitas una cuenta Premium.", "warning")
    return redirect(url_for('premium'))

@app.route('/chatbot')
@login_required
def chatbot_page():
    return render_template('chatbot.html')

@app.route('/api/reservas/disponibilidad')
@login_required
@not_banned_required
def disponibilidad_reservas():
    fecha = request.args.get('fecha')
    if not fecha:
        return jsonify({'error': 'Selecciona una fecha.'}), 400
    horarios = [f'{hour:02d}:00' for hour in range(6, 22)]
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        asegurar_columna_hora_fin(conn)
        asegurar_columna_usuario_reserva(conn)
        cursor.execute("SELECT id, nombre, direccion FROM locaciones WHERE tipo = 'cancha' ORDER BY nombre")
        canchas = cursor.fetchall()
        cursor.execute('''
                 SELECT locacion_id,
                     MIN(id) AS id,
                     strftime('%H:%M', hora_reserva) AS hora_reserva,
                     strftime('%H:%M', COALESCE(hora_fin, time(hora_reserva, '+1 hour'))) AS hora_fin
            FROM reservas WHERE fecha_reserva = %s
            GROUP BY locacion_id, fecha_reserva, hora_reserva, hora_fin
        ''', (fecha,))
        reservas_por_cancha = {}
        for reserva in cursor.fetchall():
            reservas_por_cancha.setdefault(reserva['locacion_id'], []).append(reserva)
        for cancha in canchas:
            cancha['reservas'] = reservas_por_cancha.get(cancha['id'], [])
        cursor.execute('SELECT nombre_completo, username FROM usuarios WHERE id = %s', (session['user_id'],))
        usuario = cursor.fetchone() or {}
        mis_reservas = []
        cursor.execute('''
                SELECT r.id, r.nombre_usuario, r.fecha_reserva, r.hora_reserva, r.hora_fin,
                       l.nombre AS nombre_cancha, l.direccion
                FROM reservas r JOIN locaciones l ON l.id = r.locacion_id
                WHERE r.user_id = %s AND r.fecha_reserva >= CURDATE()
                ORDER BY r.fecha_reserva, r.hora_reserva
            ''', (session['user_id'],))
        mis_reservas = cursor.fetchall()
        for reserva in mis_reservas:
            for campo in ('hora_reserva', 'hora_fin'):
                valor = reserva.get(campo)
                if hasattr(valor, 'total_seconds'):
                    total_seconds = int(valor.total_seconds())
                    horas, resto = divmod(total_seconds, 3600)
                    minutos = resto // 60
                    reserva[campo] = f'{horas:02d}:{minutos:02d}'
                elif valor is not None:
                    reserva[campo] = str(valor)[:5]
        return jsonify({'fecha': fecha, 'horarios': horarios, 'canchas': canchas, 'mis_reservas': mis_reservas})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/reservas', methods=['POST'])
@login_required
@not_banned_required
def crear_reserva_api():
    data = request.json or {}
    locacion_id = data.get('locacion_id')
    fecha = data.get('fecha_reserva')
    hora = data.get('hora_reserva')
    hora_fin = data.get('hora_fin')
    if not locacion_id or not fecha or not hora or not hora_fin:
        return jsonify({'error': 'Faltan datos de la reserva.'}), 400
    try:
        locacion_id = int(locacion_id)
        datetime.strptime(fecha, '%Y-%m-%d')
        inicio = datetime.strptime(hora, '%H:%M') if len(hora) == 5 else datetime.strptime(hora, '%H:%M:%S')
        final = datetime.strptime(hora_fin, '%H:%M') if len(hora_fin) == 5 else datetime.strptime(hora_fin, '%H:%M:%S')
    except (TypeError, ValueError):
        return jsonify({'error': 'La fecha o el horario no tienen un formato valido.'}), 400
    duracion = (final - inicio).total_seconds() / 3600
    if duracion not in (1, 2):
        return jsonify({'error': 'La reserva debe durar exactamente 1 o 2 horas.'}), 400
    if inicio.hour < 6 or final.hour > 22:
        return jsonify({'error': 'Las reservas solo están disponibles entre las 06:00 y las 22:00.'}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        asegurar_columna_hora_fin(conn)
        asegurar_columna_usuario_reserva(conn)
        cursor.execute('SELECT nombre_completo, username FROM usuarios WHERE id = %s', (session['user_id'],))
        usuario = cursor.fetchone()
        cursor.execute('SELECT COUNT(*) AS total FROM reservas WHERE user_id = %s AND fecha_reserva >= CURDATE()', (session['user_id'],))
        if cursor.fetchone()['total'] >= 2:
            return jsonify({'error': 'Cada usuario puede tener como máximo 2 reservas activas.'}), 409
        cursor.execute('''
            SELECT id FROM reservas
            WHERE locacion_id = %s AND fecha_reserva = %s
              AND hora_reserva < %s AND COALESCE(hora_fin, time(hora_reserva, '+1 hour')) > %s
        ''', (locacion_id, fecha, hora_fin, hora))
        if cursor.fetchone():
            return jsonify({'error': 'Ese horario ya está reservado.'}), 409
        nombre_usuario = (usuario.get('nombre_completo') or usuario.get('username')) if usuario else session.get('username', 'Usuario')
        cursor.execute('INSERT INTO reservas (locacion_id, user_id, nombre_usuario, fecha_reserva, hora_reserva, hora_fin) VALUES (%s, %s, %s, %s, %s, %s)', (locacion_id, session['user_id'], nombre_usuario or 'Usuario', fecha, hora, hora_fin))
        conn.commit()
        return jsonify({'status': 'success', 'reserva_id': cursor.lastrowid})
    except sqlite3.Error as err:
        conn.rollback()
        print(f'Error guardando reserva: {err}')
        return jsonify({'error': 'No se pudo guardar la reserva. Verifica que la tabla reservas tenga la columna hora_fin.'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/reservas/<int:reserva_id>', methods=['DELETE'])
@login_required
@not_banned_required
def eliminar_reserva(reserva_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor()
    try:
        asegurar_columna_usuario_reserva(conn)
        cursor.execute('DELETE FROM reservas WHERE id = %s AND user_id = %s', (reserva_id, session['user_id']))
        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({'error': 'La reserva no existe o no pertenece a tu cuenta.'}), 404
        conn.commit()
        return jsonify({'status': 'success'})
    except sqlite3.Error as err:
        conn.rollback()
        print(f'Error eliminando reserva: {err}')
        return jsonify({'error': 'No se pudo eliminar la reserva.'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/reservas')
@login_required
@not_banned_required
def reservas():
    if session.get('role') == 'admin' or verificar_premium(session['user_id']):
        return render_template('reservas.html')
    flash("Para acceder a Reservas necesitas una cuenta Premium.", "warning")
    return redirect(url_for('premium'))


# ═══════════════════════════════════════════════════════════════════════════
# RUTAS ADMIN
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/admin/torneos', methods=['GET', 'POST'])
@admin_required
def admin_torneos():
    """CRUD de los bloques informativos y del calendario de torneos."""
    conn = get_db_connection()
    if not conn:
        flash('No fue posible conectar con la base de datos.', 'error')
        return redirect(url_for('index'))

    cursor = conn.cursor(dictionary=True)
    try:
        if request.method == 'POST':
            accion = request.form.get('accion')
            registro_id = request.form.get('id', type=int)

            if accion == 'guardar_bloque':
                datos = (request.form.get('tipo', '').strip(), request.form.get('titulo', '').strip(),
                         request.form.get('texto', '').strip(), request.form.get('orden', type=int) or 0)
                if not all(datos[:3]):
                    flash('Completa todos los campos del bloque.', 'error')
                elif registro_id:
                    cursor.execute('UPDATE contenido_torneos SET tipo = %s, titulo = %s, texto = %s, orden = %s WHERE id = %s', (*datos, registro_id))
                    conn.commit()
                    flash('Bloque actualizado correctamente.', 'success')
                else:
                    cursor.execute('INSERT INTO contenido_torneos (tipo, titulo, texto, orden) VALUES (%s, %s, %s, %s)', datos)
                    conn.commit()
                    flash('Bloque creado correctamente.', 'success')
            elif accion == 'eliminar_bloque' and registro_id:
                cursor.execute('DELETE FROM contenido_torneos WHERE id = %s', (registro_id,))
                conn.commit()
                flash('Bloque eliminado.', 'success')
            elif accion == 'guardar_torneo':
                datos = (request.form.get('nombre', '').strip(), request.form.get('categoria', '').strip(),
                         request.form.get('fecha', '').strip(), request.form.get('lugar', '').strip(),
                         request.form.get('nivel', '').strip(), request.form.get('descripcion', '').strip())
                if not all(datos):
                    flash('Completa todos los datos del torneo.', 'error')
                elif registro_id:
                    cursor.execute('''UPDATE torneos SET nombre = %s, categoria = %s, fecha = %s,
                                      lugar = %s, nivel = %s, descripcion = %s WHERE id = %s''', (*datos, registro_id))
                    conn.commit()
                    flash('Torneo actualizado correctamente.', 'success')
                else:
                    cursor.execute('''INSERT INTO torneos (nombre, categoria, fecha, lugar, nivel, descripcion)
                                      VALUES (%s, %s, %s, %s, %s, %s)''', datos)
                    conn.commit()
                    flash('Torneo creado correctamente.', 'success')
            elif accion == 'eliminar_torneo' and registro_id:
                cursor.execute('DELETE FROM torneos WHERE id = %s', (registro_id,))
                conn.commit()
                flash('Torneo eliminado.', 'success')

            return redirect(url_for('admin_torneos'))

        cursor.execute('SELECT id, tipo, titulo, texto, orden FROM contenido_torneos ORDER BY orden, id')
        contenidos = cursor.fetchall()
        cursor.execute('SELECT id, nombre, categoria, fecha, lugar, nivel, descripcion FROM torneos ORDER BY orden, id')
        torneos = cursor.fetchall()
        return render_template('admin/torneos.html', contenidos=contenidos, torneos=torneos)
    except sqlite3.Error as err:
        conn.rollback()
        print(f'Error administrando torneos: {err}')
        flash('No fue posible guardar los cambios. Verifica que ejecutaste informacion_extra.sql.', 'error')
        return redirect(url_for('admin_torneos'))
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/denuncias', methods=['GET', 'POST'])
@admin_required
def admin_denuncias():
    conn = get_db_connection()
    if not conn:
        flash('No fue posible cargar las denuncias.', 'error')
        return redirect(url_for('index'))
    cursor = conn.cursor(dictionary=True)
    try:
        if request.method == 'POST':
            denuncia_id = request.form.get('denuncia_id')
            accion = request.form.get('accion')
            cursor.execute('SELECT denunciado_id FROM denuncias_mensajes WHERE id = %s', (denuncia_id,))
            denuncia = cursor.fetchone()
            if denuncia and accion == 'banear':
                cursor.execute('''
                    UPDATE usuarios SET baneado = 1, motivo_baneo = %s, evidencia_baneo = %s, fecha_baneo = NOW()
                    WHERE id = %s
                ''', ('Denuncia de mensaje revisada por administración.', f'Denuncia #{denuncia_id}', denuncia['denunciado_id']))
                cursor.execute("UPDATE denuncias_mensajes SET estado = 'revisada' WHERE id = %s", (denuncia_id,))
                flash('El usuario fue bloqueado.', 'success')
            elif denuncia and accion == 'descartar':
                cursor.execute("UPDATE denuncias_mensajes SET estado = 'descartada' WHERE id = %s", (denuncia_id,))
                flash('La denuncia fue descartada.', 'info')
            conn.commit()
        cursor.execute('''
            SELECT d.*, m.texto, u1.username AS denunciante, u2.username AS denunciado
            FROM denuncias_mensajes d
            JOIN messages m ON m.id = d.mensaje_id
            JOIN usuarios u1 ON u1.id = d.denunciante_id
            JOIN usuarios u2 ON u2.id = d.denunciado_id
            ORDER BY d.fecha_denuncia DESC
        ''')
        return render_template('admin/denuncias.html', denuncias=cursor.fetchall())
    except sqlite3.Error as err:
        conn.rollback()
        print(f'Error cargando denuncias: {err}')
        flash('No fue posible cargar las denuncias.', 'error')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

ADMIN_CRUDS = {
    'categorias': {
        'title': 'Categorías de tienda', 'table': 'categorias',
        'fields': [
            ('nombre', 'Nombre', 'text', True), ('slug', 'Slug', 'text', True),
            ('descripcion', 'Descripción', 'textarea', False), ('icono', 'Icono', 'text', False),
            ('orden', 'Orden', 'number', False), ('activo', 'Activo', 'checkbox', False),
        ],
        'columns': ['id', 'nombre', 'slug', 'orden', 'activo'],
    },
    'ejercicios': {
        'title': 'Ejercicios', 'table': 'ejercicios',
        'fields': [
            ('nombre', 'Nombre', 'text', True), ('descripcion', 'Descripción', 'textarea', False),
            ('categoria', 'Categoría', 'text', False),
            ('dificultad', 'Dificultad', 'select:Principiante|Intermedio|Avanzado|Élite', False),
        ],
        'columns': ['id', 'nombre', 'categoria', 'dificultad'],
    },
    'rutinas': {
        'title': 'Rutinas de entrenamiento', 'table': 'rutinas_entrenamiento',
        'fields': [
            ('dia_semana', 'Día', 'select:Lunes|Martes|Miércoles|Jueves|Viernes|Sábado|Domingo', True),
            ('tipo_usuario', 'Tipo de usuario', 'select:free|premium', True),
            ('titulo_rutina', 'Título', 'text', True), ('objetivo', 'Objetivo', 'textarea', True),
            ('consejo_entrenador', 'Consejo', 'textarea', False), ('ejercicio_id', 'ID ejercicio', 'number', False),
            ('series_repeticiones', 'Series / repeticiones', 'text', False),
            ('duracion_minutos', 'Duración (minutos)', 'number', False),
            ('calorias_estimadas', 'Calorías', 'number', False), ('imagen_url', 'Imagen', 'text', False),
        ],
        'columns': ['id', 'dia_semana', 'tipo_usuario', 'titulo_rutina', 'duracion_minutos'],
    },
    'locaciones': {
        'title': 'Ubicaciones del mapa', 'table': 'locaciones',
        'fields': [
            ('nombre', 'Nombre', 'text', True), ('tipo', 'Tipo', 'select:cancha|tienda|bar', True),
            ('lat', 'Latitud', 'number', True), ('lng', 'Longitud', 'number', True),
            ('estrellas', 'Estrellas', 'text', False), ('direccion', 'Dirección', 'text', True),
            ('horario', 'Horario', 'text', True), ('telefono', 'Teléfono', 'text', True),
            ('precio_aprox', 'Precio aproximado', 'text', True), ('info_adicional', 'Información', 'textarea', True),
            ('imagen_url', 'Imagen', 'text', False),
        ],
        'columns': ['id', 'nombre', 'tipo', 'direccion', 'telefono', 'imagen_url'],
    },
    'reservas': {
        'title': 'Reservas de canchas', 'table': 'reservas',
        'fields': [
            ('locacion_id', 'ID ubicación', 'number', True), ('nombre_usuario', 'Usuario', 'text', True),
            ('fecha_reserva', 'Fecha', 'date', True), ('hora_reserva', 'Hora', 'time', True),
        ],
        'columns': ['id', 'locacion_id', 'nombre_usuario', 'fecha_reserva', 'hora_reserva'],
    },
    'premium': {
        'title': 'Suscripciones Premium', 'table': 'premium',
        'fields': [('user_id', 'ID usuario', 'number', True), ('plan', 'Plan', 'text', True)],
        'columns': ['id', 'user_id', 'plan', 'fecha_inicio'],
    },
    'resenas': {
        'title': 'Reseñas de productos', 'table': 'resenas',
        'fields': [
            ('producto_id', 'ID producto', 'number', True), ('usuario_id', 'ID usuario', 'number', True),
            ('calificacion', 'Calificación (1-5)', 'number', True), ('comentario', 'Comentario', 'textarea', False),
            ('aprobada', 'Aprobada', 'checkbox', False),
        ],
        'columns': ['id', 'producto_id', 'usuario_id', 'calificacion', 'aprobada'],
    },
    'favoritos': {
        'title': 'Favoritos', 'table': 'favoritos',
        'fields': [('usuario_id', 'ID usuario', 'number', True), ('producto_id', 'ID producto', 'number', True)],
        'columns': ['id', 'usuario_id', 'producto_id', 'created_at'],
    },
    'pagos': {
        'title': 'Pagos', 'table': 'pagos',
        'fields': [
            ('orden_id', 'ID orden', 'number', False), ('usuario_id', 'ID usuario', 'number', True),
            ('monto', 'Monto', 'number', True),
            ('metodo', 'Método', 'select:tarjeta|transferencia|efecty|nequi|daviplata|paypal', True),
            ('estado', 'Estado', 'select:pendiente|completado|fallido|reembolsado', True),
            ('referencia_pago', 'Referencia', 'text', False),
        ],
        'columns': ['id', 'orden_id', 'usuario_id', 'monto', 'metodo', 'estado', 'created_at'],
    },
    'comentarios': {
        'title': 'Comentarios del mapa', 'table': 'comentarios',
        'fields': [
            ('locacion_id', 'ID ubicación', 'number', True), ('usuario_id', 'ID usuario', 'number', False),
            ('nombre_usuario', 'Nombre visible', 'text', True), ('comentario', 'Comentario', 'textarea', True),
            ('estrellas', 'Estrellas (1-5)', 'number', True),
        ],
        'columns': ['id', 'locacion_id', 'usuario_id', 'nombre_usuario', 'comentario', 'estrellas', 'acuerdo_promedio', 'total_acuerdos'],
        'order_by': 'acuerdo_promedio DESC, total_acuerdos DESC, id DESC',
    },
    'ordenes': {
        'title': 'Órdenes y envíos', 'table': 'ordenes',
        'fields': [
            ('usuario_id', 'ID usuario', 'number', True), ('numero_orden', 'Número de orden', 'text', True),
            ('estado', 'Estado', 'select:pendiente|pagado|en_proceso|enviado|entregado|cancelado', True),
            ('subtotal', 'Subtotal', 'number', True), ('envio', 'Envío', 'number', False),
            ('descuento', 'Descuento', 'number', False), ('total', 'Total', 'number', True),
            ('direccion_envio', 'Dirección', 'textarea', False), ('ciudad_envio', 'Ciudad', 'text', False),
            ('telefono_envio', 'Teléfono', 'text', False),
        ],
        'columns': ['id', 'numero_orden', 'usuario_id', 'estado', 'total', 'created_at'],
    },
}


def _crud_config(resource):
    return ADMIN_CRUDS.get(resource)


@app.route('/admin/crud/<resource>', methods=['GET', 'POST'])
@admin_required
def admin_crud(resource):
    config = _crud_config(resource)
    if not config:
        flash('Módulo administrativo no encontrado.', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    if not conn:
        flash('Error de conexión con la base de datos.', 'error')
        return redirect(url_for('index'))
    cursor = conn.cursor(dictionary=True)
    try:
        if request.method == 'POST':
            record_id = request.form.get('record_id')
            values = []
            columns = []
            for field, _, field_type, required in config['fields']:
                value = request.form.get(field)
                if field_type == 'checkbox':
                    value = 1 if request.form.get(field) else 0
                elif value == '' and not required:
                    value = None
                elif value not in (None, '') and field_type == 'number':
                    value = float(value) if '.' in value else int(value)
                if required and value in (None, ''):
                    flash('Completa todos los campos obligatorios.', 'error')
                    return redirect(url_for('admin_crud', resource=resource))
                columns.append(field)
                values.append(value)

            if record_id:
                assignments = ', '.join(f'{column} = %s' for column in columns)
                cursor.execute(f"UPDATE {config['table']} SET {assignments} WHERE id = %s", (*values, record_id))
                flash('Registro actualizado correctamente.', 'success')
            else:
                placeholders = ', '.join(['%s'] * len(columns))
                cursor.execute(f"INSERT INTO {config['table']} ({', '.join(columns)}) VALUES ({placeholders})", values)
                flash('Registro creado correctamente.', 'success')
            conn.commit()
            return redirect(url_for('admin_crud', resource=resource))

        search = request.args.get('q', '').strip()
        query = ("SELECT c.*, COALESCE(AVG(cv.calificacion), 0) AS acuerdo_promedio, "
             "COUNT(cv.id) AS total_acuerdos "
             "FROM comentarios c LEFT JOIN comentarios_valoraciones cv "
             "ON cv.comentario_id = c.id"
             if resource == 'comentarios' else f"SELECT * FROM {config['table']}")
        params = []
        if search:
            searchable = [field[0] for field in config['fields'] if field[2] not in ('checkbox',)]
            prefix = 'c.' if resource == 'comentarios' else ''
            query += ' WHERE ' + ' OR '.join(f'CAST({prefix}{field} AS CHAR) LIKE %s' for field in searchable)
            params = [f'%{search}%'] * len(searchable)
        if resource == 'comentarios':
            query += ' GROUP BY c.id ORDER BY acuerdo_promedio DESC, total_acuerdos DESC, c.id DESC'
        else:
            query += ' ORDER BY ' + config.get('order_by', 'id DESC')
        cursor.execute(query, params)
        records = cursor.fetchall()
        edit_id = request.args.get('edit', type=int)
        record = None
        if edit_id:
            cursor.execute(f"SELECT * FROM {config['table']} WHERE id = %s", (edit_id,))
            record = cursor.fetchone()
        return render_template('admin/crud.html', config=config, records=records, record=record, search=search, resource=resource)
    except sqlite3.Error as err:
        conn.rollback()
        print(f'Error CRUD {resource}: {err}')
        flash('No se pudo completar la operación. Revisa las relaciones del registro.', 'error')
        return redirect(url_for('admin_crud', resource=resource))
    finally:
        cursor.close()
        conn.close()


@app.post('/admin/crud/<resource>/eliminar/<int:record_id>')
@admin_required
def admin_crud_eliminar(resource, record_id):
    config = _crud_config(resource)
    if not config:
        return redirect(url_for('index'))
    conn = get_db_connection()
    if not conn:
        flash('Error de conexión con la base de datos.', 'error')
        return redirect(url_for('index'))
    cursor = conn.cursor()
    try:
        cursor.execute(f"DELETE FROM {config['table']} WHERE id = %s", (record_id,))
        conn.commit()
        flash('Registro eliminado correctamente.', 'success')
    except sqlite3.Error as err:
        conn.rollback()
        print(f'Error eliminando {resource}: {err}')
        flash('No se puede eliminar este registro porque está relacionado con otros datos.', 'error')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('admin_crud', resource=resource))

@app.route('/apelar-baneo', methods=['GET', 'POST'])
def apelar_baneo():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        motivo = request.form.get('motivo', '').strip()
        if not email or not motivo:
            flash('Completa tu correo y explica el motivo de la apelación.', 'error')
            return redirect(url_for('apelar_baneo'))

        conn = get_db_connection()
        if conn is None:
            flash('No fue posible enviar la apelación.', 'error')
            return redirect(url_for('apelar_baneo'))
        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT id, baneado, evidencia_baneo, locacion_baneo
                FROM usuarios WHERE email = %s
            """, (email,))
            usuario = cursor.fetchone()
            if not usuario or not usuario['baneado']:
                flash('No encontramos un bloqueo activo para ese correo.', 'warning')
                return redirect(url_for('apelar_baneo'))
            cursor.execute("""
                INSERT INTO apelaciones_baneo
                    (usuario_id, correo, motivo, evidencia_comentario, locacion_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (usuario['id'], email, motivo, usuario.get('evidencia_baneo'), usuario.get('locacion_baneo')))
            conn.commit()
            flash('Tu apelación fue enviada para revisión administrativa.', 'success')
            return redirect(url_for('apelar_baneo'))
        except sqlite3.Error as err:
            conn.rollback()
            print(f"Error guardando apelación: {err}")
            flash('No fue posible enviar la apelación.', 'error')
        finally:
            if cursor:
                cursor.close()
            conn.close()
    return render_template('apelar_baneo.html')


@app.route('/admin/apelaciones', methods=['GET', 'POST'])
@admin_required
def admin_apelaciones():
    conn = get_db_connection()
    if conn is None:
        flash('Error de conexión con la base de datos.', 'error')
        return redirect(url_for('index'))
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        if request.method == 'POST':
            apelacion_id = request.form.get('apelacion_id')
            decision = request.form.get('decision')
            cursor.execute("SELECT usuario_id FROM apelaciones_baneo WHERE id = %s", (apelacion_id,))
            apelacion = cursor.fetchone()
            if apelacion and decision in ('aprobar', 'rechazar'):
                estado = 'aprobada' if decision == 'aprobar' else 'rechazada'
                if decision == 'aprobar':
                    cursor.execute("UPDATE usuarios SET baneado = 0, motivo_baneo = NULL, fecha_baneo = NULL WHERE id = %s", (apelacion['usuario_id'],))
                decision_texto = (
                    'Tu apelación fue aprobada. Tu cuenta ha sido desbloqueada y puedes volver a utilizar los servicios.'
                    if decision == 'aprobar' else
                    'Tu apelación fue rechazada. El bloqueo se mantiene porque la evidencia fue considerada suficiente.'
                )
                cursor.execute("""
                    INSERT INTO notificaciones_moderacion
                        (usuario_id, apelacion_id, titulo, apelacion, respuesta, evidencia)
                    SELECT usuario_id, id, %s, motivo, %s, evidencia_comentario
                    FROM apelaciones_baneo WHERE id = %s
                """, ('Resultado de apelación', decision_texto, apelacion_id))
                cursor.execute("""
                    UPDATE apelaciones_baneo
                    SET estado = %s, revisado_por = %s, fecha_revision = NOW()
                    WHERE id = %s
                """, (estado, session['user_id'], apelacion_id))
                conn.commit()
                flash('Apelación procesada correctamente.', 'success')
            return redirect(url_for('admin_apelaciones'))

        cursor.execute("""
            SELECT a.*, u.username, u.email AS usuario_email, u.motivo_baneo
            FROM apelaciones_baneo a
            JOIN usuarios u ON u.id = a.usuario_id
            WHERE a.estado = 'pendiente'
            ORDER BY a.fecha_envio ASC
        """)
        apelaciones = cursor.fetchall()
        return render_template('admin/apelaciones.html', apelaciones=apelaciones)
    except sqlite3.Error as err:
        conn.rollback()
        print(f'Error cargando apelaciones: {err}')
        flash('No fue posible cargar las apelaciones.', 'error')
        return redirect(url_for('index'))
    finally:
        if cursor:
            cursor.close()
        conn.close()

@app.route('/admin/perfiles', methods=['GET', 'POST'])
@admin_required
def admin_perfiles():
    conn = get_db_connection()
    if conn is None:
        flash("Error de conexión con la base de datos.", "error")
        return redirect(url_for('index'))

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":
            action = request.form.get("action")

            if action == "eliminar":
                usuario_id = request.form.get("usuario_id")
                try:
                    if int(usuario_id) == session['user_id']:
                        flash("No puedes eliminar tu propia cuenta.", "error")
                    else:
                        # ON DELETE CASCADE elimina automáticamente el registro en perfil_usuario
                        cursor.execute("DELETE FROM usuarios WHERE id=%s", (usuario_id,))
                        conn.commit()
                        flash("Usuario eliminado correctamente.", "success")
                except (ValueError, TypeError):
                    flash("ID de usuario inválido.", "error")

            return redirect(url_for('admin_perfiles'))

        # Consulta con LEFT JOIN para traer los datos de ambas tablas
        cursor.execute("""
            SELECT 
                u.id, u.username, u.email, u.telefono, u.rol, u.fecha_creacion,
                p.apellido, p.foto, p.nivel, p.club
            FROM usuarios u
            LEFT JOIN perfil_usuario p ON u.id = p.usuario_id
            ORDER BY u.id DESC
        """)
        usuarios = cursor.fetchall()
        return render_template('admin/perfiles.html', usuarios=usuarios)

    except sqlite3.Error as err:
        if conn:
            conn.rollback()
        print(f"Error SQLite: {err}")
        flash("Error al cargar los perfiles.", "error")
        return redirect(url_for('index'))
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


@app.route('/admin/actualizar_eliminar_perfil/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_actualizar_usuario(id):
    conn = get_db_connection()
    if conn is None:
        flash("Error de conexión con la base de datos.", "error")
        return redirect(url_for('admin_perfiles'))

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":
            # 1. Recibir datos de la tabla 'usuarios'
            username = request.form.get("username", '').strip()
            email = request.form.get("email", '').strip()
            telefono = request.form.get("telefono", '').strip()
            rol = request.form.get("rol")
            password = request.form.get("password", '')

            # 2. Recibir datos de la tabla 'perfil_usuario'
            apellido = request.form.get("apellido", '').strip() or None
            fecha_nacimiento = request.form.get("fecha_nacimiento") or None
            nivel = request.form.get("nivel", 'principiante')
            mano = request.form.get("mano", 'diestro')
            reves = request.form.get("reves", 'dos_manos')
            club = request.form.get("club", '').strip() or None
            biografia = request.form.get("biografia", '').strip() or None

            # 3. Procesar la subida de la nueva foto de perfil
            foto_nombre = None
            if 'foto_perfil' in request.files:
                file = request.files['foto_perfil']
                if file and file.filename != '' and allowed_file(file.filename):
                    ext = file.filename.rsplit('.', 1)[1].lower()
                    foto_nombre = f"user_{id}_{secure_filename(file.filename)}"
                    
                    # Definir carpeta de destino (static/uploads/perfiles)
                    folder = os.path.join(current_app.root_path, 'static', 'uploads', 'perfiles')
                    os.makedirs(folder, exist_ok=True)
                    
                    ruta_guardado = os.path.join(folder, foto_nombre)
                    file.save(ruta_guardado)

            # 4. Actualizar la tabla 'usuarios' (con o sin cambio de contraseña)
            if password:
                password_hash = generate_password_hash(password)
                cursor.execute("""
                    UPDATE usuarios 
                    SET username=%s, email=%s, telefono=%s, password=%s, rol=%s
                    WHERE id=%s
                """, (username, email, telefono, password_hash, rol, id))
            else:
                cursor.execute("""
                    UPDATE usuarios 
                    SET username=%s, email=%s, telefono=%s, rol=%s
                    WHERE id=%s
                """, (username, email, telefono, rol, id))

            # 5. Insertar o Actualizar la tabla 'perfil_usuario'
            if foto_nombre:
                # Si subió nueva foto, se actualiza la columna 'foto'
                cursor.execute("""
                    INSERT INTO perfil_usuario 
                        (usuario_id, apellido, foto, fecha_nacimiento, nivel, mano, reves, club, biografia)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (usuario_id) DO UPDATE SET
                        apellido = excluded.apellido,
                        foto = excluded.foto,
                        fecha_nacimiento = excluded.fecha_nacimiento,
                        nivel = excluded.nivel,
                        mano = excluded.mano,
                        reves = excluded.reves,
                        club = excluded.club,
                        biografia = excluded.biografia
                """, (id, apellido, foto_nombre, fecha_nacimiento, nivel, mano, reves, club, biografia))
            else:
                # Si no subió foto, mantenemos la foto actual en la base de datos
                cursor.execute("""
                    INSERT INTO perfil_usuario 
                        (usuario_id, apellido, fecha_nacimiento, nivel, mano, reves, club, biografia)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (usuario_id) DO UPDATE SET
                        apellido = excluded.apellido,
                        fecha_nacimiento = excluded.fecha_nacimiento,
                        nivel = excluded.nivel,
                        mano = excluded.mano,
                        reves = excluded.reves,
                        club = excluded.club,
                        biografia = excluded.biografia
                """, (id, apellido, fecha_nacimiento, nivel, mano, reves, club, biografia))

            conn.commit()
            flash("Perfil actualizado correctamente.", "success")
            return redirect(url_for('admin_perfiles'))

        # GET: Consultar datos del usuario unificando ambas tablas
        cursor.execute("""
            SELECT 
                u.id, u.username, u.email, u.telefono, u.rol,
                p.apellido, p.foto, p.fecha_nacimiento, p.nivel, p.mano, p.reves, p.club, p.biografia
            FROM usuarios u
            LEFT JOIN perfil_usuario p ON u.id = p.usuario_id
            WHERE u.id = %s
        """, (id,))
        usuario = cursor.fetchone()

        if not usuario:
            flash("Usuario no encontrado.", "error")
            return redirect(url_for('admin_perfiles'))

        return render_template('admin/actualizar_eliminar_perfil.html', usuario=usuario)

    except sqlite3.Error as err:
        if conn:
            conn.rollback()
        print(f"Error SQLite: {err}")
        flash("Error al actualizar datos del perfil.", "error")
        return redirect(url_for('admin_perfiles'))
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()

@app.route('/admin/facturas')
@admin_required
def facturas():
    conn = get_db_connection()
    if not conn:
        flash("Error de conexión a la base de datos.", "error")
        return redirect(url_for('index'))

    busqueda = request.args.get('busqueda', '').strip()
    
    try:
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT
                f.id,
                printf('FAC-%04d', f.id) AS id_formateado,
                f.fecha,
                f.total,
                f.estado,
                f.metodo_pago,
                f.usuario_id,
                u.username AS cliente,
                u.email AS cliente_email
            FROM facturas f
            JOIN usuarios u ON f.usuario_id = u.id
        """
        params = []

        if busqueda:
            query += """ WHERE f.id LIKE %s 
                        OR printf('FAC-%04d', f.id) LIKE %s
                        OR u.username LIKE %s 
                        OR u.email LIKE %s 
                        OR f.estado LIKE %s"""
            pattern = f"%{busqueda}%"
            params = [pattern, pattern, pattern, pattern, pattern]

        query += " ORDER BY f.fecha DESC"
        cursor.execute(query, params)
        facturas_raw = cursor.fetchall()

        facturas = []
        for fac in facturas_raw:
            cursor.execute("""
                SELECT
                    df.id AS detalle_id,
                    df.producto_id,
                    df.cantidad,
                    df.precio_unitario,
                    df.subtotal,
                    p.nombre AS producto_nombre
                FROM detalle_factura df
                JOIN productos p ON df.producto_id = p.id
                WHERE df.factura_id = %s
            """, (fac['id'],))
            productos = cursor.fetchall()

            fac['productos'] = productos
            fac['fecha_iso'] = fac['fecha'].strftime('%Y-%m-%dT%H:%M:%S') if fac['fecha'] else ''
            fac['fecha_entrega_estimada'] = (fac['fecha'] + timedelta(days=5)).date().isoformat() if fac['fecha'] else ''
            fac['num_productos'] = sum(p['cantidad'] for p in productos)
            facturas.append(fac)

    except sqlite3.Error as err:
        print(f"Error al cargar facturas: {err}")
        flash("Error al cargar las facturas.", "error")
        facturas = []
    finally:
        cursor.close()
        conn.close()

    return render_template('admin/facturas.html', facturas=facturas, busqueda=busqueda, facturas_json=preparar_facturas(facturas))


# RUTA 2: Editar Factura + Datos de Entrega (Acepta GET para mostrar y POST para guardar o eliminar)
@app.route('/admin/factura/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_factura(id):
    conn = get_db_connection()
    if not conn:
        flash("Error de conexión a la base de datos.", "error")
        return redirect(url_for('facturas'))

    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        # Opción 1: Procesar Eliminación directa desde el formulario
        if request.form.get('accion') == 'eliminar':
            try:
                cursor.execute("DELETE FROM facturas WHERE id = %s", (id,))
                conn.commit()
                flash("Factura eliminada correctamente.", "success")
            except sqlite3.Error as err:
                conn.rollback()
                flash("Error al eliminar la factura.", "error")
            finally:
                cursor.close()
                conn.close()
            return redirect(url_for('facturas'))

        # Opción 2: Guardar Cambios y Datos de Entrega
        try:
            usuario_id = request.form.get('usuario_id')
            estado = request.form.get('estado')
            metodo_pago = request.form.get('metodo_pago')

            # Datos de Entrega
            direccion_entrega = request.form.get('direccion_entrega', '')
            ciudad_entrega = request.form.get('ciudad_entrega', '')
            telefono_contacto = request.form.get('telefono_contacto', '')
            notas_entrega = request.form.get('notas_entrega', '')
            
            productos_ids = request.form.getlist('producto_id[]')
            cantidades = request.form.getlist('cantidad[]')
            precios = request.form.getlist('precio[]')

            nuevo_total = 0
            for i in range(len(productos_ids)):
                nuevo_total += int(cantidades[i]) * float(precios[i])

            # Actualizar datos principales
            cursor.execute("""
                UPDATE facturas 
                SET usuario_id = %s, estado = %s, metodo_pago = %s, total = %s 
                WHERE id = %s
            """, (usuario_id, estado, metodo_pago, nuevo_total, id))

            # Reemplazar detalles de los productos
            cursor.execute("DELETE FROM detalle_factura WHERE factura_id = %s", (id,))
            for i in range(len(productos_ids)):
                cant = int(cantidades[i])
                precio = float(precios[i])
                sub = cant * precio
                cursor.execute("""
                    INSERT INTO detalle_factura (factura_id, producto_id, cantidad, precio_unitario, subtotal)
                    VALUES (%s, %s, %s, %s, %s)
                """, (id, productos_ids[i], cant, precio, sub))

            conn.commit()
            flash("Factura y datos de entrega actualizados con éxito.", "success")
            return redirect(url_for('facturas'))

        except sqlite3.Error as err:
            conn.rollback()
            print(f"Error al actualizar factura: {err}")
            flash("Error al actualizar la factura.", "error")
        finally:
            cursor.close()
            conn.close()

    # GET: Cargar datos actuales de la factura
    cursor.execute("""
        SELECT f.*, printf('FAC-%04d', f.id) AS id_formateado, u.username, u.email
        FROM facturas f
        JOIN usuarios u ON f.usuario_id = u.id
        WHERE f.id = %s
    """, (id,))
    factura = cursor.fetchone()

    cursor.execute("""
        SELECT df.*, p.nombre AS producto_nombre
        FROM detalle_factura df
        JOIN productos p ON df.producto_id = p.id
        WHERE df.factura_id = %s
    """, (id,))
    detalles = cursor.fetchall()

    cursor.execute("SELECT id, username, email FROM usuarios ORDER BY username ASC")
    usuarios = cursor.fetchall()

    cursor.execute("SELECT id, nombre, precio FROM productos WHERE activo = 1 ORDER BY nombre ASC")
    productos = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin/editar_factura.html', factura=factura, detalles=detalles, usuarios=usuarios, productos=productos)


def preparar_facturas(facturas):
    for factura in facturas:
        factura['fecha'] = factura.get('fecha_iso', '')
        factura['total'] = float(factura['total']) if isinstance(factura.get('total'), Decimal) else factura.get('total', 0)
        for producto in factura.get('productos', []):
            for campo in ('precio_unitario', 'subtotal'):
                if isinstance(producto.get(campo), Decimal):
                    producto[campo] = float(producto[campo])
    return facturas


@app.route('/mis-compras')
@login_required
def mis_compras():
    """Muestra únicamente las facturas del usuario que inició sesión."""
    conn = get_db_connection()
    if not conn:
        flash("Error de conexión a la base de datos.", "error")
        return redirect(url_for('index'))

    facturas_usuario = []
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT f.id, printf('FAC-%04d', f.id) AS id_formateado,
                   f.fecha, f.total, f.estado, f.metodo_pago, u.username AS cliente
            FROM facturas f
            JOIN usuarios u ON u.id = f.usuario_id
            WHERE f.usuario_id = %s
            ORDER BY f.fecha DESC
        """, (session['user_id'],))
        facturas_usuario = cursor.fetchall()

        for factura in facturas_usuario:
            cursor.execute("""
                SELECT df.cantidad, df.precio_unitario, df.subtotal,
                       p.nombre AS producto_nombre
                FROM detalle_factura df
                JOIN productos p ON p.id = df.producto_id
                WHERE df.factura_id = %s
            """, (factura['id'],))
            factura['productos'] = cursor.fetchall()
            factura['fecha_iso'] = factura['fecha'].isoformat() if factura['fecha'] else ''
            factura['fecha_entrega_estimada'] = (factura['fecha'] + timedelta(days=5)).date().isoformat() if factura['fecha'] else ''
    except sqlite3.Error as err:
        print(f"Error al cargar compras: {err}")
        flash("No fue posible cargar tus compras.", "error")
    finally:
        if cursor:
            cursor.close()
        conn.close()

    return render_template('facturas.html', facturas_json=preparar_facturas(facturas_usuario))





# ═══════════════════════════════════════════════════════════════════════════
# CRUD DE PRODUCTOS (ADMIN)
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# CRUD DE PRODUCTOS (ADMIN)
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# CRUD DE PRODUCTOS (ADMIN)
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/admin/productos')
@admin_required
def admin_productos():
    conn = get_db_connection()
    if not conn:
        flash("Error de conexión con la base de datos.", "error")
        return redirect(url_for("index"))
    
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, nombre, sku, marca, precio, stock, imagen_principal, destacado, activo 
        FROM productos 
        ORDER BY id DESC
    """)
    productos = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('admin/productos.html', productos=productos)

@app.route('/admin/productos/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_producto(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        slug = request.form.get('slug', '').strip()
        descripcion_corta = request.form.get('descripcion_corta', '').strip()
        descripcion_larga = request.form.get('descripcion_larga', '').strip()
        categoria_id = request.form.get('categoria_id', 1)
        subcategoria = request.form.get('subcategoria', '').strip()
        marca = request.form.get('marca', '').strip()
        color = request.form.get('color', '').strip()
        talla = request.form.get('talla', '').strip()
        precio = request.form.get('precio', 0.0)
        precio_anterior = request.form.get('precio_anterior') or None
        stock = request.form.get('stock', 0)
        sku = request.form.get('sku', '').strip()
        imagen_principal = request.form.get('imagen_principal', 'default-product.jpg').strip()
        video_url = request.form.get('video_url', '').strip()
        peso = request.form.get('peso') or None
        badge = request.form.get('badge', '').strip()
        destacado = 1 if request.form.get('destacado') == 'on' else 0
        activo = 1 if request.form.get('activo') == 'on' else 0

        # Manejo de campos JSON opcionales
        imagenes_raw = request.form.get('imagenes', '').strip()
        especificaciones_raw = request.form.get('especificaciones', '').strip()
        preguntas_raw = request.form.get('preguntas_frecuentes', '').strip()

        try:
            imagenes = json.dumps(json.loads(imagenes_raw)) if imagenes_raw else None
        except Exception:
            imagenes = None

        try:
            especificaciones = json.dumps(json.loads(especificaciones_raw)) if especificaciones_raw else None
        except Exception:
            especificaciones = None

        try:
            preguntas = json.loads(preguntas_raw) if preguntas_raw else []
            if not isinstance(preguntas, list):
                raise ValueError
            preguntas = [item for item in preguntas if isinstance(item, dict) and item.get('pregunta') and item.get('respuesta')]
        except (ValueError, TypeError, json.JSONDecodeError):
            conn.close()
            flash('Las preguntas frecuentes deben ser una lista JSON válida.', 'error')
            return redirect(url_for('editar_producto', id=id))

        cursor.execute("""
            UPDATE productos SET 
                nombre=%s, slug=%s, descripcion_corta=%s, descripcion_larga=%s,
                categoria_id=%s, subcategoria=%s, marca=%s, color=%s, talla=%s,
                precio=%s, precio_anterior=%s, stock=%s, sku=%s, imagen_principal=%s,
                imagenes=%s, video_url=%s, especificaciones=%s, peso=%s,
                destacado=%s, badge=%s, activo=%s
            WHERE id=%s
        """, (
            nombre, slug, descripcion_corta, descripcion_larga,
            categoria_id, subcategoria, marca, color, talla,
            precio, precio_anterior, stock, sku, imagen_principal,
            imagenes, video_url, especificaciones, peso,
            destacado, badge, activo, id
        ))

        cursor.execute("DELETE FROM preguntas_frecuentes WHERE producto_id = %s", (id,))
        for item in preguntas:
            cursor.execute("""
                INSERT INTO preguntas_frecuentes (producto_id, pregunta, respuesta, aprobada)
                VALUES (%s, %s, %s, 1)
            """, (id, item['pregunta'].strip(), item['respuesta'].strip()))

        conn.commit()
        cursor.close()
        conn.close()
        flash("Producto actualizado correctamente.", "success")
        return redirect(url_for('admin_productos'))

    cursor.execute("SELECT * FROM productos WHERE id = %s", (id,))
    producto = cursor.fetchone()
    cursor.execute("SELECT pregunta, respuesta FROM preguntas_frecuentes WHERE producto_id = %s ORDER BY id", (id,))
    producto['preguntas_frecuentes'] = json.dumps(cursor.fetchall(), ensure_ascii=False, indent=2)
    cursor.close()
    conn.close()

    # Convertir JSON a String legible para los textareas
    if producto:
        if isinstance(producto.get('imagenes'), (dict, list)):
            producto['imagenes'] = json.dumps(producto['imagenes'], ensure_ascii=False)
        if isinstance(producto.get('especificaciones'), (dict, list)):
            producto['especificaciones'] = json.dumps(producto['especificaciones'], ensure_ascii=False)

    return render_template('admin/editar_producto.html', producto=producto)

@app.route('/admin/productos/eliminar/<int:id>', methods=['POST'])
@admin_required
def eliminar_producto(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM productos WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Producto eliminado correctamente.", "success")
    return redirect(url_for('admin_productos'))



@app.route('/admin/pedidos')
@admin_required
def admin_pedidos_envios():
    return redirect(url_for('admin_crud', resource='ordenes'))


@app.route('/admin/pedidos/detalle/<int:id>')
@admin_required
def detalle_pedido(id):
    conn = get_db_connection()
    if not conn:
        flash("Error de conexión a la base de datos.", "error")
        return redirect(url_for('admin_pedidos_envios'))

    try:
        cursor = conn.cursor(dictionary=True)
        
        # 1. Obtener la orden y los datos del cliente
        cursor.execute("""
            SELECT o.*, u.nombre_completo AS cliente_nombre, u.email AS cliente_email
            FROM ordenes o
            JOIN usuarios u ON o.usuario_id = u.id
            WHERE o.id = %s
        """, (id,))
        pedido = cursor.fetchone()

        if not pedido:
            flash("La orden solicitada no existe.", "error")
            return redirect(url_for('admin_pedidos_envios'))

        # 2. Obtener los ítems de la orden
        cursor.execute("""
            SELECT * FROM orden_items WHERE orden_id = %s
        """, (id,))
        items = cursor.fetchall()

        # 3. Obtener el estado del pago asociado
        cursor.execute("""
            SELECT * FROM pagos WHERE orden_id = %s
        """, (id,))
        pago = cursor.fetchone()

    except sqlite3.Error as err:
        print(f"Error al cargar detalle de orden: {err}")
        flash("Error al cargar los detalles de la orden.", "error")
        return redirect(url_for('admin_pedidos_envios'))
    finally:
        cursor.close()
        conn.close()

    return render_template('admin/detalle_pedido.html', pedido=pedido, items=items, pago=pago)

@app.route('/admin/facturas')
@admin_required
def admin_facturas():
    return redirect(url_for('facturas'))

@app.route('/admin/pagos')
@admin_required
def admin_pagos():
    return redirect(url_for('admin_crud', resource='pagos'))

@app.route('/admin/inventario')
@admin_required
def admin_inventario():
    conn = get_db_connection()
    if not conn:
        flash("Error de conexión a la base de datos.", "error")
        return redirect(url_for('index'))

    busqueda = request.args.get('busqueda', '').strip()
    orden = request.args.get('orden', 'id_asc')

    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT p.id, p.nombre, p.sku, p.precio, p.stock, p.activo, p.categoria_id, c.nombre AS categoria_nombre
            FROM productos p
            LEFT JOIN categorias c ON p.categoria_id = c.id
        """
        params = []

        if busqueda:
            query += " WHERE p.nombre LIKE %s OR p.sku LIKE %s OR p.id LIKE %s"
            pattern = f"%{busqueda}%"
            params = [pattern, pattern, pattern]

        # Diccionario seguro de cláusulas de ordenamiento SQL
        ordenes_sql = {
            'id_asc': " ORDER BY p.id ASC",
            'id_desc': " ORDER BY p.id DESC",
            'precio_asc': " ORDER BY p.precio ASC",
            'precio_desc': " ORDER BY p.precio DESC",
            'stock_asc': " ORDER BY p.stock ASC",
            'stock_desc': " ORDER BY p.stock DESC",
            'nombre_asc': " ORDER BY p.nombre ASC",
            'nombre_desc': " ORDER BY p.nombre DESC"
        }

        # Aplica el orden seleccionado o usa id_asc por defecto
        query += ordenes_sql.get(orden, " ORDER BY p.id ASC")

        cursor.execute(query, params)
        productos = cursor.fetchall()

    except sqlite3.Error as err:
        print(f"Error al cargar inventario: {err}")
        flash("Error al cargar el inventario.", "error")
        productos = []
    finally:
        cursor.close()
        conn.close()

    return render_template('admin/inventario.html', productos=productos, busqueda=busqueda, orden=orden)



def crear_slug(texto):
    texto = texto.lower().strip()
    texto = re.sub(r'[^\w\s-]', '', texto)
    return re.sub(r'[\s_-]+', '-', texto)

# RUTA 2: Crear / Editar Producto y Control de Stock
@app.route('/admin/inventario/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def editar_inventario(id):
    conn = get_db_connection()
    if not conn:
        flash("Error de conexión a la base de datos.", "error")
        return redirect(url_for('admin_inventario'))

    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        # Procesar eliminación rápida
        if request.form.get('accion') == 'eliminar':
            try:
                cursor.execute("DELETE FROM productos WHERE id = %s", (id,))
                conn.commit()
                flash("Producto eliminado del inventario.", "success")
            except sqlite3.Error:
                conn.rollback()
                flash("No se puede eliminar el producto porque tiene facturas o ventas asociadas.", "error")
            finally:
                cursor.close()
                conn.close()
            return redirect(url_for('admin_inventario'))

        # Capturar campos del formulario
        nombre = request.form.get('nombre', '').strip()
        slug = crear_slug(nombre)
        descripcion_corta = request.form.get('descripcion_corta', '')
        categoria_id = int(request.form.get('categoria_id', 1))
        marca = request.form.get('marca', '')
        precio = float(request.form.get('precio', 0))
        stock = int(request.form.get('stock', 0))
        sku = request.form.get('sku', '').strip() or None
        activo = 1 if request.form.get('activo') else 0
        destacado = 1 if request.form.get('destacado') else 0

        try:
            if id == 0:
                cursor.execute("""
                    INSERT INTO productos (nombre, slug, descripcion_corta, categoria_id, marca, precio, stock, sku, activo, destacado)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (nombre, slug, descripcion_corta, categoria_id, marca, precio, stock, sku, activo, destacado))
                flash("Producto creado e ingresado al inventario con éxito.", "success")
            else:
                cursor.execute("""
                    UPDATE productos 
                    SET nombre = %s, slug = %s, descripcion_corta = %s, categoria_id = %s, marca = %s, 
                        precio = %s, stock = %s, sku = %s, activo = %s, destacado = %s
                    WHERE id = %s
                """, (nombre, slug, descripcion_corta, categoria_id, marca, precio, stock, sku, activo, destacado, id))
                flash("Inventario y producto actualizados correctamente.", "success")

            conn.commit()
            return redirect(url_for('admin_inventario'))

        except sqlite3.Error as err:
            conn.rollback()
            print(f"Error en BD: {err}")
            flash(f"Error en la operación: {err.msg}", "error")
        finally:
            cursor.close()
            conn.close()

    # GET: Cargar datos actualizados
    producto = None
    if id > 0:
        cursor.execute("SELECT * FROM productos WHERE id = %s", (id,))
        producto = cursor.fetchone()

    cursor.execute("SELECT id, nombre FROM categorias ORDER BY nombre ASC")
    categorias = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin/editar_inventario.html', producto=producto, producto_id=id, categorias=categorias)


@app.route('/admin/contacto')
@admin_required
def admin_contacto():
    conn = get_db_connection()
    if conn is None:
        flash("Error de conexion.", "error")
        return redirect(url_for('index'))

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM solicitudes_contacto WHERE respuesta IS NULL ORDER BY fecha_envio DESC")
        mensajes = cursor.fetchall()
    except sqlite3.Error as err:
        print(f"Error cargando mensajes: {err}")
        mensajes = []
    finally:
        cursor.close()
        conn.close()

    return render_template('admin/contacto.html', mensajes=mensajes)


@app.route('/admin/responder_contacto/<int:msg_id>', methods=['POST'])
@admin_required
def responder_contacto(msg_id):
    respuesta = request.form.get('respuesta', '').strip()
    if not respuesta:
        flash('La respuesta no puede estar vacia.', 'error')
        return redirect(url_for('admin_contacto'))

    conn = get_db_connection()
    if conn is None:
        flash("Error de conexion.", "error")
        return redirect(url_for('admin_contacto'))

    try:
        cursor = conn.cursor()
        query = """
            UPDATE solicitudes_contacto 
            SET respuesta = %s, fecha_respuesta = NOW() WHERE id = %s
        """
        cursor.execute(query, (respuesta, msg_id))
        conn.commit()
        flash('Respuesta enviada con exito!', 'success')
    except sqlite3.Error as err:
        conn.rollback()
        print(f"Error al responder contacto: {err}")
        flash('Hubo un error al enviar la respuesta.', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_contacto'))


@app.route('/admin/soporte')
@admin_required
def admin_soporte():
    conn = get_db_connection()
    if conn is None:
        flash("Error de conexion.", "error")
        return redirect(url_for('index'))

    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT s.id, s.motivo, s.mensaje, s.fecha_envio, s.respuesta, u.username 
            FROM soporte_tecnico s
            JOIN usuarios u ON s.usuario_id = u.id
            ORDER BY s.fecha_envio DESC
        """
        cursor.execute(query)
        tickets = cursor.fetchall()
    except sqlite3.Error as err:
        print(f"Error cargando soporte: {err}")
        tickets = []
    finally:
        cursor.close()
        conn.close()

    return render_template('admin/soporte.html', tickets=tickets)


@app.route('/admin/soporte/responder/<int:ticket_id>', methods=['POST'])
@admin_required
def responder_soporte(ticket_id):
    respuesta = request.form.get('respuesta', '').strip()
    if not respuesta:
        flash('La respuesta no puede estar vacia.', 'error')
        return redirect(url_for('admin_soporte'))

    conn = get_db_connection()
    if conn is None:
        flash("Error de conexion.", "error")
        return redirect(url_for('admin_soporte'))

    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE soporte_tecnico SET respuesta = %s, fecha_respuesta = NOW() WHERE id = %s
        """, (respuesta, ticket_id))
        conn.commit()
        flash('Respuesta enviada correctamente.', 'success')
    except sqlite3.Error as err:
        conn.rollback()
        print(f"Error al responder soporte: {err}")
        flash('Hubo un error al enviar la respuesta.', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_soporte'))


@app.route('/admin/eliminar_mensaje/<string:origen>/<int:id_msg>', methods=['POST'])
@admin_required
def eliminar_mensaje(origen, id_msg):
    tabla = "soporte_tecnico" if origen == "soporte" else "solicitudes_contacto"
    redirect_url = 'admin_soporte' if origen == "soporte" else 'admin_contacto'

    conn = get_db_connection()
    if conn is None:
        flash("Error de conexion.", "error")
        return redirect(url_for(redirect_url))

    try:
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {tabla} WHERE id = %s", (id_msg,))
        conn.commit()
        flash("Registro eliminado correctamente.", "success")
    except sqlite3.Error as err:
        conn.rollback()
        print(f"Error al eliminar registro: {err}")
        flash("No se pudo eliminar el registro.", "error")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for(redirect_url))


@app.route('/usuario/eliminar_notificacion/<string:origen>/<int:id_notif>', methods=['POST'])
@login_required
def eliminar_notificacion(origen, id_notif):
    usuario_id = session.get('user_id')
    tablas = {
        'soporte': 'soporte_tecnico',
        'contacto': 'solicitudes_contacto',
        'moderacion': 'notificaciones_moderacion',
    }
    tabla = tablas.get(origen)
    if not tabla:
        flash("Origen de notificación no válido.", "error")
        return redirect(url_for('notificaciones'))

    conn = get_db_connection()
    if conn is None:
        flash("Error de conexion.", "error")
        return redirect(url_for('notificaciones'))

    try:
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {tabla} WHERE id = %s AND usuario_id = %s", (id_notif, usuario_id))
        conn.commit()
        flash("Notificacion eliminada correctamente.", "success")
    except sqlite3.Error as err:
        conn.rollback()
        print(f"Error al eliminar notificacion: {err}")
        flash("No se pudo eliminar la notificacion.", "error")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('notificaciones'))



# 1. Ruta para solicitar la recuperación
# ==========================================
# RUTAS DE RECUPERACIÓN DE CONTRASEÑA
# ==========================================

@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
            usuario = cursor.fetchone()
            cursor.close()
            conn.close()
        except Exception as e:
            print(">>> ERROR BD AL BUSCAR USUARIO:", str(e))
            usuario = None

        if usuario:
            token = serializer.dumps(email, salt='recuperar-password-salt')
            link = url_for('reset_password', token=token, _external=True)

            msg = Message('Restablecimiento de Contraseña - TENNISSEL', recipients=[email])
            
            msg.html = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
            </head>
            <body style="margin: 0; padding: 0; background-color: #0d1117; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #ffffff;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin: 30px auto; background-color: #161b22; border: 1px solid #21262d; border-radius: 12px; overflow: hidden;">
                    <tr>
                        <td align="center" style="padding: 30px 20px 10px 20px; background-color: #161b22;">
                            <h1 style="color: #ffffff; font-size: 28px; font-weight: 800; letter-spacing: 2px; margin: 0;">
                                TENNIS<span style="color: #00ff66;">SEL.</span>
                            </h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 40px 30px 40px; text-align: center;">
                            <h2 style="color: #ffffff; font-size: 20px; font-weight: 600; margin-bottom: 15px;">¿Olvidaste tu contraseña?</h2>
                            <p style="color: #8b949e; font-size: 14px; line-height: 1.6; margin-bottom: 25px;">
                                Recibimos una solicitud para restablecer la contraseña de tu cuenta en <strong>TENNISSEL</strong>. Haz clic en el siguiente botón para continuar:
                            </p>
                            <div style="margin: 30px 0;">
                                <a href="{link}" target="_blank" style="background-color: #00ff66; color: #000000; text-decoration: none; padding: 14px 28px; border-radius: 8px; font-weight: bold; font-size: 15px; display: inline-block; box-shadow: 0 4px 12px rgba(0,255,102,0.2);">
                                    Restablecer Contraseña
                                </a>
                            </div>
                            <p style="color: #8b949e; font-size: 12px; line-height: 1.5; margin-top: 25px;">
                                Si el botón no funciona, copia y pega el siguiente enlace en tu navegador:<br>
                                <a href="{link}" style="color: #00ff66; word-break: break-all;">{link}</a>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 0 40px;">
                            <hr style="border: 0; border-top: 1px solid #21262d; margin: 0;">
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 40px; text-align: center; background-color: #0d1117;">
                            <p style="color: #484f58; font-size: 12px; margin: 0; line-height: 1.4;">
                                Este enlace expira en <strong>1 hora</strong>.<br>
                                Si no solicitaste este cambio, puedes ignorar este mensaje de forma segura.
                            </p>
                            <p style="color: #30363d; font-size: 11px; margin-top: 15px;">
                                &copy; TENNISSEL. Todos los derechos reservados.
                            </p>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            '''
            
            try:
                mail.send(msg)
                flash('Hemos enviado un enlace de recuperación a tu correo electrónico.', 'info')
                return redirect(url_for('login'))
            except Exception as e:
                print(">>> ERROR AL ENVIAR CORREO:", str(e))
                flash('Error al enviar el correo. Inténtalo de nuevo.', 'danger')
        else:
            flash('No existe ninguna cuenta asociada a este correo electrónico.', 'warning')

    return render_template('recuperar_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='recuperar-password-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        session.pop('recovery_token', None)
        flash('El enlace es inválido o ha expirado. Por favor solicita uno nuevo.', 'danger')
        return redirect(url_for('recuperar_password'))

    session['recovery_token'] = token

    if request.method == 'POST':
        nueva_password = request.form.get('password')
        password_hashed = generate_password_hash(nueva_password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            query = "UPDATE usuarios SET password = %s WHERE email = %s"
            cursor.execute(query, (password_hashed, email))
            conn.commit()

            cursor.close()
            conn.close()

            session.pop('recovery_token', None)

            flash('¡Tu contraseña se ha actualizado correctamente! Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            print(">>> ERROR BD AL ACTUALIZAR CONTRASEÑA:", str(e))
            flash('Ocurrió un error al actualizar la contraseña en la base de datos.', 'danger')

    return render_template('reset_password.html', token=token)

    #MAPAS PERRAS 

@app.post('/comentario/<int:comentario_id>/calificar')
@login_required
@not_banned_required
def calificar_comentario_mapa(comentario_id):
    try:
        calificacion = int(request.form.get('calificacion', 0))
    except (TypeError, ValueError):
        calificacion = 0
    if calificacion not in range(1, 6):
        flash('La valoración debe estar entre 1 y 5.', 'error')
        return redirect(request.referrer or url_for('mapas'))
    conn = get_db_connection()
    if not conn:
        flash('No fue posible guardar la valoración.', 'error')
        return redirect(request.referrer or url_for('mapas'))
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO comentarios_valoraciones (comentario_id, usuario_id, calificacion)
            VALUES (%s, %s, %s)
            ON CONFLICT (comentario_id, usuario_id) DO UPDATE
            SET calificacion = excluded.calificacion, fecha = CURRENT_TIMESTAMP
        """, (comentario_id, session['user_id'], calificacion))
        conn.commit()
        flash('Valoración guardada.', 'success')
    except sqlite3.Error:
        conn.rollback()
        flash('No fue posible guardar la valoración.', 'error')
    finally:
        cursor.close()
        conn.close()
    return redirect(request.referrer or url_for('mapas'))


@app.route('/mapas', methods=['GET', 'POST'])
@login_required
@not_banned_required
def mapas():
    baneado, motivo_baneo = usuario_baneado(session['user_id'])
    if baneado:
        flash('Tu cuenta esta bloqueada por incumplir las normas de la comunidad.', 'error')
        return redirect(url_for('apelar_baneo'))

    es_usuario_gratuito = session.get('role') not in ('admin', 'premium') and not verificar_premium(session['user_id'])
    if request.method == 'GET' and es_usuario_gratuito and session.get('mapas_uso_gratuito'):
        flash('Si quieres tener acceso nuevamente, únete a Premium.', 'warning')
        return redirect(url_for('premium'))

    direccion = request.form.get('direccion', '')
    categoria = request.form.get('categoria', 'todos')
    
    mensaje_error = None
    mensaje_exito = None
    
    # Manejar POST requests
    if request.method == 'POST':
        action = request.form.get('action')
        
        # 1. Manejar Comentarios
        if action == 'comentar':
            loc_id = request.form.get('locacion_id')
            usuario_id = session['user_id']
            usuario = session.get('username', 'Usuario')
            comentario = request.form.get('comentario')
            estrellas = request.form.get('estrellas')
            if loc_id and comentario and estrellas and contiene_lenguaje_ofensivo(comentario):
                motivo = 'Lenguaje ofensivo detectado en una reseña.'
                banear_usuario_por_moderacion(usuario_id, motivo, comentario, loc_id)
                flash('Tu reseña fue eliminada y tu cuenta fue bloqueada automáticamente. Puedes apelar la decisión.', 'error')
                return redirect(url_for('apelar_baneo'))

            if loc_id and comentario and estrellas:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("INSERT INTO comentarios (locacion_id, usuario_id, nombre_usuario, comentario, estrellas) VALUES (%s, %s, %s, %s, %s)",
                            (loc_id, usuario_id, usuario, comentario, int(estrellas)))
                conn.commit()
                cur.close(); conn.close()
                mensaje_exito = f"✅ Comentario publicado correctamente por {usuario}."
                
        # 2. Manejar Reservas
        elif action == 'reservar':
            loc_id = request.form.get('locacion_id')
            usuario = request.form.get('usuario_reserva')
            fecha = request.form.get('fecha_reserva')
            hora = request.form.get('hora_reserva')
            hora_fin = request.form.get('hora_fin') or '23:59:59'
            
            if loc_id and usuario and fecha and hora:
                conn = get_db_connection()
                cur = conn.cursor(dictionary=True)
                asegurar_columna_hora_fin(conn)
                asegurar_columna_usuario_reserva(conn)
                cur.execute('SELECT COUNT(*) AS total FROM reservas WHERE user_id = %s AND fecha_reserva >= CURDATE()', (session['user_id'],))
                if cur.fetchone()['total'] >= 2:
                    mensaje_error = 'Cada usuario puede tener como máximo 2 reservas activas.'
                    cur.close(); conn.close()
                else:
                    # Revisar si ya existe reserva
                    cur.execute("""
                    SELECT * FROM reservas
                    WHERE locacion_id = %s AND fecha_reserva = %s
                      AND hora_reserva < %s
                      AND COALESCE(hora_fin, time(hora_reserva, '+1 hour')) > %s
                    """, (loc_id, fecha, hora_fin, hora))
                    existe = cur.fetchone()
                
                if mensaje_error:
                    pass
                elif existe:
                    mensaje_error = f"⚠️ La cancha ya está reservada el {fecha} a las {hora}. Por favor, elige otro horario."
                elif hora_fin <= hora:
                    mensaje_error = "La hora final debe ser posterior a la hora inicial."
                else:
                    try:
                        cur.execute("INSERT INTO reservas (locacion_id, user_id, nombre_usuario, fecha_reserva, hora_reserva, hora_fin) VALUES (%s, %s, %s, %s, %s, %s)",
                                    (loc_id, session['user_id'], usuario, fecha, hora, hora_fin))
                        conn.commit()
                        mensaje_exito = f"🎾 ¡Reserva confirmada exitosamente para {usuario} el {fecha} a las {hora}!"
                    except Exception as err:
                        mensaje_error = f"Error al reservar: La cancha podría estar ocupada."
                
                cur.close(); conn.close()

    # Cargar todas las ubicaciones para que el filtro de reseñas sea independiente
    # del filtro de categoría utilizado para los marcadores del mapa.
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    asegurar_columna_hora_fin(conn)
    cur.execute("SELECT * FROM locaciones")
    locaciones = cur.fetchall()
    locaciones_mapa = (
        locaciones if categoria == 'todos'
        else [loc for loc in locaciones if loc['tipo'] == categoria]
    )
    
    # Obtener comentarios
    cur.execute("SELECT * FROM comentarios ORDER BY id DESC")
    todos_comentarios = cur.fetchall()
    cur.execute("""
        SELECT comentario_id, AVG(calificacion) AS promedio, COUNT(*) AS total
        FROM comentarios_valoraciones GROUP BY comentario_id
    """)
    valoraciones = {row['comentario_id']: row for row in cur.fetchall()}
    
    comentarios_por_locacion = {}
    for c in todos_comentarios:
        l_id = c['locacion_id']
        c['acuerdo_promedio'] = float(valoraciones.get(c['id'], {}).get('promedio') or 0)
        c['total_acuerdos'] = int(valoraciones.get(c['id'], {}).get('total') or 0)
        if l_id not in comentarios_por_locacion:
            comentarios_por_locacion[l_id] = []
        comentarios_por_locacion[l_id].append(c)

    for comentarios in comentarios_por_locacion.values():
        comentarios.sort(key=lambda comentario: (comentario['total_acuerdos'], comentario['acuerdo_promedio']), reverse=True)
    
    # Obtener promedio de estrellas
    cur.execute("SELECT locacion_id, AVG(estrellas) as prom FROM comentarios GROUP BY locacion_id")
    promedios = {row['locacion_id']: round(row['prom'], 1) for row in cur.fetchall()}
    
    # Consultar todas las reservas para el panel lateral
    cur.execute("""
        SELECT r.id, r.nombre_usuario, r.fecha_reserva, r.hora_reserva, r.hora_fin, l.nombre AS nombre_cancha
        FROM reservas r
        JOIN locaciones l ON r.locacion_id = l.id
        ORDER BY r.fecha_reserva, r.hora_reserva
    """)
    reservas_lista = cur.fetchall()
    
    cur.close(); conn.close()

    # Resolver la ubicación antes de crear el mapa para que el centro inicial sea correcto.
    posicion_usuario = None

    if direccion:
        try:
            coordenadas = [parte.strip() for parte in direccion.split(',')]
            if len(coordenadas) == 2:
                latitud = float(coordenadas[0])
                longitud = float(coordenadas[1])
                if -90 <= latitud <= 90 and -180 <= longitud <= 180:
                    posicion_usuario = (latitud, longitud)
            else:
                geolocator = ArcGIS(user_agent="tennisel_app")
                ubicacion = geolocator.geocode(f"{direccion}, Bogotá, Colombia")
                if ubicacion:
                    posicion_usuario = (ubicacion.latitude, ubicacion.longitude)
        except Exception as e:
            print("Error geocoder:", e)

    mapa = folium.Map(
        location=list(posicion_usuario or (4.6650, -74.0850)),
        zoom_start=14 if posicion_usuario else 12
    )

    if posicion_usuario:
        folium.Marker(
            posicion_usuario,
            popup="Tu ubicación",
            tooltip="Tu ubicación",
            icon=folium.Icon(color="red", icon="user")
        ).add_to(mapa)

    colores = {'cancha': 'green', 'tienda': 'gray', 'bar': 'orange'}
    iconos = {'cancha': '🎾', 'tienda': '🛍️', 'bar': '🍻'}

    locaciones_mapa_ids = {loc['id'] for loc in locaciones_mapa}

    for loc in locaciones:
        loc['comentarios_lista'] = comentarios_por_locacion.get(loc['id'], [])
        lat, lng = float(loc['lat']), float(loc['lng'])
        distancia_km = geodesic(posicion_usuario, (lat, lng)).kilometers if posicion_usuario else None
        promedio = promedios.get(loc['id'])
        calidad = float(promedio) if promedio is not None else float(str(loc.get('estrellas', '')).count('⭐'))
        loc['distancia_km'] = distancia_km
        loc['calidad'] = calidad
        dist = f"<br><b>Distancia:</b> {distancia_km:.1f} km" if distancia_km is not None else ""
        prom_estrellas = f"{calidad:.1f}/5" if promedio is not None else f"{int(calidad)}/5"
        
        # Formulario inyectado en el mapa
        if loc['tipo'] == 'cancha':
            form_reserva = f"""
            <form action="/mapas" method="POST" target="_parent" style="margin-top:10px; display:flex; flex-direction:column; gap:5px;">
                <input type="hidden" name="action" value="reservar">
                <input type="hidden" name="locacion_id" value="{loc['id']}">
                <input type="hidden" name="direccion" value="{direccion}">
                <input type="hidden" name="categoria" value="{categoria}">
                <input type="text" name="usuario_reserva" placeholder="Tu nombre" required style="padding:6px; border-radius:4px; border:none; color:#333; font-size:12px; font-family:sans-serif;">
                <div style="display:flex; gap:5px;">
                    <input type="date" name="fecha_reserva" required style="width:55%; padding:6px; border-radius:4px; border:none; color:#333; font-size:12px;">
                    <input type="time" name="hora_reserva" step="3600" required style="width:45%; padding:6px; border-radius:4px; border:none; color:#333; font-size:12px;">
                    <input type="time" name="hora_fin" step="3600" required style="width:45%; padding:6px; border-radius:4px; border:none; color:#333; font-size:12px;">
                </div>
                <button type="submit" style="background:#2ecc71; color:white; border:none; padding:8px; border-radius:4px; cursor:pointer; font-weight:bold; width:100%; margin-top:3px;">Reservar Cancha</button>
            </form>
            """
        else:
            form_reserva = ""
        
        html = f"""
        <div style="font-family:Courier; width:220px; background:#111; color:#fff; padding:10px; border:1px solid #39ff14; border-radius:8px;">
            <img src="{url_for('proxy_imagen', url=loc.get('imagen_url', ''))}" onerror="this.onerror=null; this.src='https://images.unsplash.com/photo-1595435934249-5df7ed86e1c0?auto=format&fit=crop&w=500&q=70';" style="width:100%; height:110px; object-fit:cover; border-radius:4px; margin-bottom:8px;">
            <h4 style="color:#39ff14; margin:0; font-size:14px;">{iconos.get(loc['tipo'], '📍')} {loc['nombre']}</h4>
            <hr style="border-color:#39ff14; margin: 8px 0;">
            <small style="font-size:12px;"><b>Dir:</b> {loc['direccion']}<br>
            <b>Precio:</b> {loc['precio_aprox']}<br>
            <b>Rating:</b> ⭐ {prom_estrellas}</small>
            {dist}
            {form_reserva}
        </div>
        """
        if loc['id'] in locaciones_mapa_ids:
            folium.Marker([lat, lng], popup=folium.Popup(html, max_width=250),
                          icon=folium.Icon(color=colores.get(loc['tipo'], 'blue'))).add_to(mapa)

    if es_usuario_gratuito and request.method == 'GET':
        session['mapas_uso_gratuito'] = True

    return render_template('mapas.html', 
                           mapa_widget=mapa._repr_html_(), 
                           locaciones=locaciones,
                           reservas=reservas_lista,
                           mensaje_error=mensaje_error,
                           mensaje_exito=mensaje_exito)


import math

def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Debes iniciar sesion.'}), 401
        baneado, motivo = usuario_baneado(session['user_id'])
        if baneado:
            return jsonify({'error': 'Tu cuenta esta bloqueada.', 'motivo': motivo}), 403
        if session.get('role') not in ('admin', 'profesor', 'premium') and not verificar_premium(session['user_id']):
            return jsonify({'error': 'El chat y el matchmaking requieren Premium.'}), 403
        return f(*args, **kwargs)
    return decorated_function

def haversine(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2): return 9999.0
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return round(R * c, 2)

@app.route('/api/radar', methods=['GET'])
@api_login_required
def obtener_radar():
    user_id = session['user_id']
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
            SELECT p.lat, p.lng FROM perfil_usuario p WHERE p.usuario_id = %s
        ''', (user_id,))
        mi_ubi = cursor.fetchone() or {}
        cursor.execute('''
            SELECT u.id, COALESCE(u.nombre_completo, u.username) AS nombre, p.foto, u.ciudad AS barrio, p.ubicacion_texto, p.lat, p.lng, p.nivel, u.rol
            FROM usuarios u
            LEFT JOIN perfil_usuario p ON p.usuario_id = u.id
            WHERE u.id <> %s AND (p.compartir = 1 OR p.id IS NULL) AND u.rol IN ('cliente', 'premium', 'jugador') AND u.baneado = 0
        ''', (user_id,))
        otros = cursor.fetchall()
        resultados = []
        for usuario in otros:
            distancia = haversine(mi_ubi.get('lat'), mi_ubi.get('lng'), usuario['lat'], usuario['lng'])
            cursor.execute('''
                SELECT id, emisor_id, receptor_id, estado FROM contacts
                WHERE (emisor_id = %s AND receptor_id = %s) OR (emisor_id = %s AND receptor_id = %s)
                ORDER BY id DESC LIMIT 1
            ''', (user_id, usuario['id'], usuario['id'], user_id))
            contacto = cursor.fetchone()
            estado = 'ninguno'
            if contacto:
                estado = 'aceptado' if contacto['estado'] == 'aceptada' else ('enviado' if contacto['emisor_id'] == user_id else 'recibido')
            resultados.append({
                'id': usuario['id'], 'nombre': usuario['nombre'],
                'foto': usuario['foto'],
                'ubicacion_texto': usuario['barrio'] or 'Zona no indicada',
                'distancia_km': distancia, 'nivel': usuario['nivel'],
                'estado_chat': estado, 'contacto_id': contacto['id'] if contacto else None
            })
        resultados.sort(key=lambda item: item['distancia_km'])
        return jsonify(resultados)
    finally:
        cursor.close()
        conn.close()

@app.route('/api/matchmaking/usuarios', methods=['GET'])
@api_login_required
def matchmaking_usuarios():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
            SELECT u.id, COALESCE(u.nombre_completo, u.username) AS nombre, u.ciudad AS barrio, p.foto, p.nivel, p.mano, p.reves
            FROM usuarios u LEFT JOIN perfil_usuario p ON p.usuario_id = u.id
                        WHERE u.id <> %s AND u.baneado = 0
                            AND u.rol IN ('cliente', 'premium', 'jugador', 'visita')
            ORDER BY u.username
        ''', (session['user_id'],))
        usuarios = cursor.fetchall()
        for usuario in usuarios:
            cursor.execute('''
                SELECT id, emisor_id, estado FROM contacts
                WHERE (emisor_id = %s AND receptor_id = %s) OR (emisor_id = %s AND receptor_id = %s)
                ORDER BY id DESC LIMIT 1
            ''', (session['user_id'], usuario['id'], usuario['id'], session['user_id']))
            contacto = cursor.fetchone()
            usuario['contacto_id'] = contacto['id'] if contacto else None
            usuario['estado_chat'] = 'ninguno' if not contacto else ('aceptado' if contacto['estado'] == 'aceptada' else ('enviado' if contacto['emisor_id'] == session['user_id'] else 'recibido'))
        return jsonify(usuarios)
    finally:
        cursor.close()
        conn.close()

@app.route('/api/profesores', methods=['GET'])
@api_login_required
def obtener_profesores():
    user_id = session['user_id']
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
                 SELECT u.id, COALESCE(u.nombre_completo, u.username) AS nombre,
                     p.foto, u.ciudad AS barrio, p.ubicacion_texto, p.nivel
                 FROM usuarios u LEFT JOIN perfil_usuario p ON p.usuario_id = u.id
                 WHERE u.id <> %s AND u.rol = 'profesor' AND u.baneado = 0
        ''', (user_id,))
        profesores = cursor.fetchall()
        for profesor in profesores:
            cursor.execute('''
                SELECT id, emisor_id, receptor_id, estado FROM contacts
                WHERE (emisor_id = %s AND receptor_id = %s) OR (emisor_id = %s AND receptor_id = %s)
                ORDER BY id DESC LIMIT 1
            ''', (user_id, profesor['id'], profesor['id'], user_id))
            contacto = cursor.fetchone()
            profesor['estado_chat'] = 'ninguno'
            profesor['contacto_id'] = None
            if contacto:
                profesor['contacto_id'] = contacto['id']
                profesor['estado_chat'] = 'aceptado' if contacto['estado'] == 'aceptada' else ('enviado' if contacto['emisor_id'] == user_id else 'recibido')
        return jsonify(profesores)
    except Exception as err:
        print(f'Error cargando profesores: {err}')
        return jsonify({'error': 'No se pudieron cargar los profesores.'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/solicitar_chat', methods=['POST'])
@api_login_required
def solicitar_chat():
    receptor_id = (request.json or {}).get('receptor_id')
    if not receptor_id or int(receptor_id) == session['user_id']:
        return jsonify({'error': 'Destinatario no valido.'}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
            SELECT id, emisor_id, estado FROM contacts
            WHERE (emisor_id = %s AND receptor_id = %s) OR (emisor_id = %s AND receptor_id = %s)
            ORDER BY id DESC LIMIT 1
        ''', (session['user_id'], receptor_id, receptor_id, session['user_id']))
        contacto = cursor.fetchone()
        if contacto:
            return jsonify({'status': 'exists', 'contacto_id': contacto['id'], 'estado': contacto['estado']})
        cursor.execute('INSERT INTO contacts (emisor_id, receptor_id) VALUES (%s, %s)', (session['user_id'], receptor_id))
        conn.commit()
        return jsonify({'status': 'success', 'contacto_id': cursor.lastrowid})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/contactos', methods=['GET'])
@api_login_required
def obtener_contactos():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
            SELECT u.id, u.username AS nombre, u.rol, p.foto, p.nivel,
                   c.id AS contacto_id, c.estado, c.emisor_id, c.receptor_id
            FROM contacts c
            JOIN usuarios u ON u.id = IF(c.emisor_id = %s, c.receptor_id, c.emisor_id)
            LEFT JOIN perfil_usuario p ON p.usuario_id = u.id
            WHERE c.emisor_id = %s OR c.receptor_id = %s
            ORDER BY u.username
        ''', (session['user_id'], session['user_id'], session['user_id']))
        contactos = cursor.fetchall()
        for contacto in contactos:
            contacto['estado_chat'] = 'aceptado' if contacto['estado'] == 'aceptada' else ('recibido' if contacto['receptor_id'] == session['user_id'] else 'enviado')
        return jsonify(contactos)
    finally:
        cursor.close()
        conn.close()

@app.route('/api/perfiles/<int:usuario_id>', methods=['GET'])
@api_login_required
def obtener_perfil_chat(usuario_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
                 SELECT u.id, u.username AS nombre, u.rol, u.ciudad AS barrio, p.foto, p.nivel,
                     p.mano, p.reves
            FROM usuarios u LEFT JOIN perfil_usuario p ON p.usuario_id = u.id
            WHERE u.id = %s
        ''', (usuario_id,))
        perfil = cursor.fetchone()
        if not perfil:
            return jsonify({'error': 'Perfil no encontrado.'}), 404
        return jsonify(perfil)
    finally:
        cursor.close()
        conn.close()

@app.route('/api/locaciones/canchas', methods=['GET'])
@api_login_required
def obtener_canchas_chat():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, nombre FROM locaciones WHERE LOWER(TRIM(tipo)) = 'cancha' ORDER BY nombre")
        return jsonify(cursor.fetchall())
    finally:
        cursor.close()
        conn.close()

@app.route('/api/responder_solicitud', methods=['POST'])
@api_login_required
def responder_solicitud():
    data = request.json or {}
    estado = data.get('estado')
    if estado not in ('aceptada', 'rechazada'):
        return jsonify({'error': 'Estado no valido.'}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE contacts SET estado = %s WHERE id = %s AND receptor_id = %s', (estado, data.get('contacto_id'), session['user_id']))
        conn.commit()
        return jsonify({'status': 'success'})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/mensajes/<int:otro_usuario_id>', methods=['GET'])
@api_login_required
def obtener_mensajes(otro_usuario_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
            SELECT m.* FROM messages m
            WHERE (m.emisor_id = %s AND m.receptor_id = %s) OR (m.emisor_id = %s AND m.receptor_id = %s)
            ORDER BY m.enviado ASC
        ''', (session['user_id'], otro_usuario_id, otro_usuario_id, session['user_id']))
        return jsonify(cursor.fetchall())
    finally:
        cursor.close()
        conn.close()

@app.route('/api/enviar_mensaje', methods=['POST'])
@api_login_required
def enviar_mensaje():
    data = request.json or {}
    receptor_id = data.get('receptor_id')
    texto = (data.get('texto') or '').strip()
    if not receptor_id or not texto:
        return jsonify({'error': 'Mensaje incompleto.'}), 400
    try:
        receptor_id = int(receptor_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'El destinatario no es valido.'}), 400
    if receptor_id == session['user_id']:
        return jsonify({'error': 'No puedes enviarte un mensaje a ti mismo.'}), 400
    tipo = data.get('tipo', 'texto')
    if tipo not in ('texto', 'propuesta'):
        tipo = 'texto'
    if tipo == 'propuesta' and session.get('role') != 'profesor':
        return jsonify({'error': 'Solo los profesores pueden enviar propuestas de clase.'}), 403
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT id, estado FROM contacts
            WHERE ((emisor_id = %s AND receptor_id = %s) OR (emisor_id = %s AND receptor_id = %s))
              AND estado = 'aceptada'
            LIMIT 1
        ''', (session['user_id'], receptor_id, receptor_id, session['user_id']))
        if not cursor.fetchone():
            return jsonify({'error': 'Primero debes aceptar la conexión para enviar mensajes.'}), 403
        datos_extra = json.dumps(data.get('datos_extra', {})) if tipo == 'propuesta' else None
        cursor.execute('''
            INSERT INTO messages (emisor_id, receptor_id, texto, tipo, datos_extra, estado_propuesta)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (session['user_id'], receptor_id, texto, tipo, datos_extra, 'pendiente' if tipo == 'propuesta' else None))
        conn.commit()
        return jsonify({'status': 'success', 'mensaje_id': cursor.lastrowid})
    except sqlite3.Error as err:
        conn.rollback()
        print(f'Error enviando mensaje: {err}')
        return jsonify({'error': 'No se pudo guardar el mensaje. Revisa la tabla messages en la base de datos.'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/denunciar_mensaje', methods=['POST'])
@api_login_required
def denunciar_mensaje():
    data = request.json or {}
    mensaje_id = data.get('mensaje_id')
    motivo = (data.get('motivo') or 'Lenguaje ofensivo o conducta inapropiada.').strip()
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('''
            SELECT emisor_id, receptor_id FROM messages
            WHERE id = %s AND (emisor_id = %s OR receptor_id = %s)
        ''', (mensaje_id, session['user_id'], session['user_id']))
        mensaje = cursor.fetchone()
        if not mensaje or mensaje['emisor_id'] == session['user_id']:
            return jsonify({'error': 'No puedes denunciar este mensaje.'}), 400
        cursor.execute('''
            INSERT INTO denuncias_mensajes (mensaje_id, denunciante_id, denunciado_id, motivo)
            VALUES (%s, %s, %s, %s)
        ''', (mensaje_id, session['user_id'], mensaje['emisor_id'], motivo))
        conn.commit()
        return jsonify({'status': 'success'})
    except sqlite3.Error:
        conn.rollback()
        return jsonify({'error': 'La denuncia no pudo guardarse.'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/responder_propuesta', methods=['POST'])
@api_login_required
def responder_propuesta():
    data = request.json or {}
    accion = data.get('accion')
    if accion not in ('aceptada', 'rechazada'):
        return jsonify({'error': 'Accion no valida.'}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'No se pudo conectar a la base de datos.'}), 503
    cursor = conn.cursor(dictionary=True)
    try:
        asegurar_columna_hora_fin(conn)
        asegurar_columna_usuario_reserva(conn)
        cursor.execute('''
            SELECT emisor_id, receptor_id, datos_extra FROM messages
            WHERE id = %s AND receptor_id = %s AND tipo = 'propuesta' AND estado_propuesta = 'pendiente'
        ''', (data.get('mensaje_id'), session['user_id']))
        mensaje = cursor.fetchone()
        if not mensaje:
            return jsonify({'error': 'Propuesta no encontrada.'}), 404
        if accion == 'aceptada':
            propuesta = json.loads(mensaje['datos_extra'] or '{}')
            locacion_id = propuesta.get('locacion_id')
            fecha = propuesta.get('fecha_reserva')
            hora = propuesta.get('hora_reserva')
            try:
                duracion = int(propuesta.get('duracion', 1))
                hora_inicio = datetime.strptime(hora, '%H:%M')
            except (TypeError, ValueError):
                return jsonify({'error': 'La fecha, hora o duración de la propuesta no son válidas.'}), 400
            if not locacion_id or not fecha or not hora:
                return jsonify({'error': 'La propuesta no tiene datos de reserva completos.'}), 400
            if duracion not in (1, 2):
                return jsonify({'error': 'La propuesta debe durar 1 o 2 horas.'}), 400
            hora_fin = (hora_inicio + timedelta(hours=duracion)).strftime('%H:%M:%S')
            cursor.execute('''
                                SELECT id FROM reservas
                                WHERE locacion_id = %s AND fecha_reserva = %s
                                    AND hora_reserva < %s
                                    AND COALESCE(hora_fin, time(hora_reserva, '+1 hour')) > %s
                        ''', (locacion_id, fecha, hora_fin, hora))
            if cursor.fetchone():
                return jsonify({'error': 'La cancha ya esta reservada en ese horario.'}), 409
            participantes = (session['user_id'], mensaje['emisor_id'])
            cursor.execute('''
                SELECT user_id, COUNT(*) AS total FROM reservas
                WHERE user_id IN (%s, %s) AND fecha_reserva >= CURDATE()
                GROUP BY user_id
            ''', participantes)
            reservas_por_usuario = {row['user_id']: row['total'] for row in cursor.fetchall()}
            if any(reservas_por_usuario.get(usuario_id, 0) >= 2 for usuario_id in participantes):
                return jsonify({'error': 'Uno de los participantes ya tiene el máximo de 2 reservas activas.'}), 409
            cursor.execute('SELECT id, username, nombre_completo FROM usuarios WHERE id IN (%s, %s)', participantes)
            nombres = {row['id']: (row['nombre_completo'] or row['username'] or 'Usuario') for row in cursor.fetchall()}
            cursor.execute('''
                INSERT INTO reservas (locacion_id, user_id, nombre_usuario, fecha_reserva, hora_reserva, hora_fin)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (locacion_id, session['user_id'], nombres.get(session['user_id'], session.get('username', 'Usuario')), fecha, hora, hora_fin))
            cursor.execute('''
                INSERT INTO reservas (locacion_id, user_id, nombre_usuario, fecha_reserva, hora_reserva, hora_fin)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (locacion_id, mensaje['emisor_id'], nombres.get(mensaje['emisor_id'], 'Profesor'), fecha, hora, hora_fin))
        cursor.execute('UPDATE messages SET estado_propuesta = %s WHERE id = %s', (accion, data.get('mensaje_id')))
        texto = 'La propuesta de clase fue aceptada.' if accion == 'aceptada' else 'La propuesta de clase fue rechazada.'
        cursor.execute('INSERT INTO messages (emisor_id, receptor_id, texto, tipo) VALUES (%s, %s, %s, "sistema")', (session['user_id'], mensaje['emisor_id'], texto))
        conn.commit()
        return jsonify({'status': 'success'})
    finally:
        cursor.close()
        conn.close()

# ==========================================
# RUTA CHATBOT (NUEVO)
# ==========================================
@app.route('/api/chatbot', methods=['POST'])
def chatbot():
    data = request.get_json(silent=True) or {}
    mensaje = str(data.get('mensaje', '')).strip().lower()
    pagina = str(data.get('pagina', '')).lower()
    if not mensaje:
        return jsonify({'respuesta': 'Escribe una pregunta y te ayudo con reservas, jugadores, entrenamientos, productos o tu cuenta.'})

    intenciones = [
        (('hola', 'buenas', 'saludos'), 'Hola. Soy TennisBot, la asistente virtual de TENNISSEL. Puedo orientarte paso a paso sobre reservas, jugadores, profesores, entrenamientos, productos, torneos, Premium y tu cuenta.', None, None),
        (('mis reservas', 'mis reserva', 'agenda'), 'En Reservas puedes desplegar “Mis reservas” para revisar tus canchas, fechas y horarios. Desde cada tarjeta también puedes eliminar una reserva que ya no necesites.', 'reservas', 'Abrir Mis reservas'),
        (('reserva', 'reservar', 'cancha', 'horario'), 'Para reservar, selecciona una fecha, elige una cancha y pulsa un horario disponible. Después revisa el resumen, elige entre 1 o 2 horas y confirma con “Enviar reserva”.', 'reservas', 'Ir a Reservas'),
        (('jugador', 'jugadores', 'rival', 'matchmaking', 'pareja'), 'En Matchmaking puedes revisar los perfiles registrados, abrir su información y enviar una solicitud de chat. Cuando la otra persona acepte, podrán conversar.', 'matchmaking', 'Abrir Matchmaking'),
        (('profesor', 'entrenador', 'clase'), 'En Matchmaking puedes encontrar profesores, consultar su perfil y enviarles una propuesta de clase con cancha, fecha y hora. La propuesta queda dentro de la conversación.', 'matchmaking', 'Buscar profesores'),
        (('entrenamiento', 'entrenar', 'rutina', 'ejercicio'), 'La sección Entrenamiento organiza rutinas por día, objetivo, nivel y tipo de cuenta. Puedes consultar ejercicios de técnica, físico, táctica y recuperación.', 'entreno', 'Ver entrenamientos'),
        (('producto', 'comprar', 'tienda', 'raqueta', 'pelota', 'grip', 'zapatilla'), 'En Productos puedes buscar raquetas, pelotas, grips, ropa, calzado y tecnología. Usa los filtros de categoría, marca, talla, color y precio para encontrar una opción adecuada.', 'productos', 'Ver productos'),
        (('premium', 'suscripcion', 'suscripción', 'pago'), 'Premium habilita herramientas avanzadas como Matchmaking, Reservas y funciones especiales de la plataforma. Consulta los planes y elige el que se ajuste a tu forma de jugar.', 'premium', 'Conocer Premium'),
        (('regla', 'puntuacion', 'puntuación', 'set', 'tie break'), 'La puntuación habitual de un game avanza 0, 15, 30 y 40. Un set normalmente se gana con seis juegos y diferencia de dos, aunque algunos formatos usan tie-break.', 'informacion_jugadores', 'Aprender sobre tenis'),
        (('torneo', 'torneos', 'grand slam', 'ranking'), 'En la sección informativa puedes seguir jugadores, torneos, rankings, partidos recientes, noticias semanales y datos para entender mejor el circuito.', 'informacion_jugadores', 'Ver información'),
        (('perfil', 'cuenta', 'contraseña', 'contrasena'), 'Desde el menú de perfil puedes actualizar tus datos, foto, nivel de juego, mano dominante, revés, ubicación y preferencias de visibilidad.', 'editarperfil', 'Editar mi perfil'),
        (('problema', 'error', 'no funciona', 'ayuda'), 'Puedo orientarte con la plataforma. Indícame si el problema ocurre en Reservas, Matchmaking, Productos, Entrenamiento, el chat o tu perfil y te indicaré el siguiente paso.', None, None),
    ]
    encontrado = next((item for item in intenciones if any(palabra in mensaje for palabra in item[0])), None)
    respuesta = encontrado[1] if encontrado else None
    enlace = url_for(encontrado[2]) if encontrado and encontrado[2] else None
    enlace_texto = encontrado[3] if encontrado else None
    if respuesta is None and 'reserva' in pagina:
        respuesta = 'Estás en Reservas. Selecciona una fecha y una cancha, revisa el horario, elige la duración y confirma la reserva. En la parte superior encontrarás tu agenda personal.'
        enlace, enlace_texto = url_for('reservas'), 'Abrir Reservas'
    elif respuesta is None and 'matchmaking' in pagina:
        respuesta = 'Estás en Matchmaking: selecciona un usuario para consultar su perfil y enviar una solicitud de chat.'
        enlace, enlace_texto = url_for('matchmaking'), 'Abrir Matchmaking'
    elif respuesta is None:
        respuesta = 'Soy TennisBot, una asistente virtual de TENNISSEL. Puedo ayudarte con reservas, mis reservas, jugadores, profesores, entrenamientos, productos, Premium, torneos y tu perfil. Escribe una pregunta concreta y te guiaré.'
    return jsonify({'respuesta': respuesta, 'enlace': enlace, 'enlace_texto': enlace_texto})


def comprobar_entorno():
    print('PY=', os.sys.executable)
    print('KEY=', os.environ.get('SPORTRADAR_API_KEY'))
    print('BASE=', os.environ.get('SPORTRADAR_BASE_URL'))
    print('LOCALE=', os.environ.get('SPORTRADAR_LOCALE'))


def probar_api():
    respuesta = requests.get(
        'https://www.thesportsdb.com/api/v1/json/123/searchteams.php',
        params={'t': 'Arsenal'},
        timeout=10
    )
    respuesta.raise_for_status()
    equipo = (respuesta.json().get('teams') or [None])[0]
    if equipo is None:
        print('No se encontro el equipo solicitado.')
        return
    print('Equipo:', equipo.get('strTeam'))
    print('Deporte:', equipo.get('strSport'))
    print('Pais:', equipo.get('strCountry'))
    print('Liga:', equipo.get('strLeague'))
    print('Logo:', equipo.get('strBadge'))


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Servidor y herramientas de TENNISSEL')
    parser.add_argument('--check-environment', action='store_true', help='Muestra la configuracion de Sportradar')
    parser.add_argument('--test-api', action='store_true', help='Prueba la API publica de equipos')
    args = parser.parse_args()

    if args.check_environment:
        comprobar_entorno()
    elif args.test_api:
        probar_api()
    else:
        app.run(debug=True)
