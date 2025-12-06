from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, DecimalField, FileField, BooleanField 
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange, Optional
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
from functools import wraps
from flask_login import current_user
from datetime import timedelta
import re
app = Flask(__name__)


# Configuración de la aplicación
load_dotenv()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_secret_key')
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB máximo
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = False  # Cambiar a True en producción con HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

@app.context_processor
def inject_user():
    """Inyecta current_user en todos los templates automáticamente"""
    return dict(current_user=get_current_user())


# Configuración de MySQL
DATABASE_URL = os.getenv('DATABASE_URL') or os.getenv('JAWSDB_URL')

if DATABASE_URL:
    # Estamos en Heroku - parsear URL de JawsDB
    # Formato: mysql://user:pass@host:port/database
    match = re.match(r'mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', DATABASE_URL)
    if match:
        MYSQL_CONFIG = {
            'user': match.group(1),
            'password': match.group(2),
            'host': match.group(3),
            'port': int(match.group(4)),
            'database': match.group(5)
        }
        print(f"✅ Usando JawsDB: {MYSQL_CONFIG['host']}/{MYSQL_CONFIG['database']}")
    else:
        print("❌ Error parseando DATABASE_URL")
        # Fallback a localhost
        MYSQL_CONFIG = {
            'host': 'localhost',
            'database': 'itaca_boutique',
            'user': 'root',
            'password': ''
        }
else:
    # Desarrollo local
    MYSQL_CONFIG = {
        'host': os.getenv('MYSQL_HOST', 'localhost'),
        'database': os.getenv('MYSQL_DATABASE', 'itaca_boutique'),
        'user': os.getenv('MYSQL_USER', 'root'),
        'password': os.getenv('MYSQL_PASSWORD', '')
    }
    print(f"🏠 Usando MySQL local: {MYSQL_CONFIG['host']}/{MYSQL_CONFIG['database']}")

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Variables globales
APP_NAME = "Itaca Boutique"

# ==================== FUNCIONES DE BASE DE DATOS ====================

def get_db_connection():
    """Establece y retorna una conexión a la base de datos MySQL"""
    try:
        connection = mysql.connector.connect(**MYSQL_CONFIG)
        return connection
    except Error as e:
        print(f"Error conectando a MySQL: {e}")
        return None

def init_db():
    """Inicializa las tablas de la base de datos"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        
        # Crear tabla de usuarios
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(64) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Crear tabla de productos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                description TEXT NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                image_filename VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        connection.commit()
        cursor.close()
        connection.close()
        print("Tablas creadas exitosamente")

# ==================== FUNCIONES DE USUARIO ====================

def create_user(username, email, password):
    """Crea un nuevo usuario en la base de datos"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        password_hash = generate_password_hash(password)
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                (username, email, password_hash)
            )
            connection.commit()
            cursor.close()
            connection.close()
            return True
        except Error as e:
            print(f"Error creando usuario: {e}")
            connection.close()
            return False
    return False

def get_user_by_username_or_email(identifier):
    """Busca un usuario por username o email"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM users WHERE username = %s OR email = %s",
            (identifier, identifier)
        )
        user = cursor.fetchone()
        cursor.close()
        connection.close()
        return user
    return None

def get_user_by_id(user_id):
    """Busca un usuario por ID"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()
        return user
    return None

def check_user_password(user, password):
    """Verifica la contraseña de un usuario"""
    return check_password_hash(user['password_hash'], password)

# ==================== FUNCIONES DE PRODUCTOS ====================

def get_all_products():
    """Obtiene todos los productos"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products ORDER BY created_at DESC")
        products = cursor.fetchall()
        cursor.close()
        connection.close()
        return products
    return []

def get_product_by_id(product_id):
    """Obtiene un producto por su ID"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        cursor.close()
        connection.close()
        return product
    return None

def create_product(name, description, price, image_filename=None):
    """Crea un nuevo producto"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO products (name, description, price, image_filename) VALUES (%s, %s, %s, %s)",
                (name, description, price, image_filename)
            )
            connection.commit()
            product_id = cursor.lastrowid
            cursor.close()
            connection.close()
            return product_id
        except Error as e:
            print(f"Error creando producto: {e}")
            connection.close()
            return None
    return None

def update_product(product_id, name, description, price, image_filename=None):
    """Actualiza un producto existente"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        try:
            if image_filename:
                cursor.execute(
                    "UPDATE products SET name = %s, description = %s, price = %s, image_filename = %s WHERE id = %s",
                    (name, description, price, image_filename, product_id)
                )
            else:
                cursor.execute(
                    "UPDATE products SET name = %s, description = %s, price = %s WHERE id = %s",
                    (name, description, price, product_id)
                )
            connection.commit()
            cursor.close()
            connection.close()
            return True
        except Error as e:
            print(f"Error actualizando producto: {e}")
            connection.close()
            return False
    return False

def delete_product(product_id):
    """Elimina un producto"""
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        try:
            cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
            connection.commit()
            cursor.close()
            connection.close()
            return True
        except Error as e:
            print(f"Error eliminando producto: {e}")
            connection.close()
            return False
    return False

# ==================== DECORADORES ====================

def login_required(f):
    """Decorador para requerir login en rutas protegidas"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Debes iniciar sesión para acceder a esta página.', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# ==================== FORMULARIOS ====================

class ProductForm(FlaskForm):
    name = StringField('Nombre del Producto', validators=[DataRequired(), Length(min=5, max=100)])
    description = TextAreaField('Descripción del Producto', validators=[DataRequired(), Length(min=20)])
    price = DecimalField('Precio', validators=[DataRequired(), NumberRange(min=0)])
    image = FileField('Imagen del Producto', validators=[Optional()])
    submit = SubmitField('Guardar Producto')

class RegisterForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrarse')

class LoginForm(FlaskForm):
    username = StringField('Usuario o Email', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    remember = BooleanField('Recordarme')
    submit = SubmitField('Entrar')

# ==================== FUNCIONES AUXILIARES ====================

def allowed_file(filename):
    """Verifica si el archivo tiene una extensión permitida"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_current_user():
    """Obtiene el usuario actual de la sesión"""
    if 'user_id' in session:
        user_id = session['user_id']
        user = get_user_by_id(user_id)
        
        print(f"🔍 get_current_user llamado: user_id={user_id}, encontrado={user is not None}")
        
        # Si el usuario no existe en la BD, limpiar la sesión
        if user is None:
            print(f"⚠️ Usuario con ID {user_id} no existe en BD. Limpiando sesión...")
            session.clear()
            return None
        
        return user
    
    print("🔍 get_current_user llamado: No hay user_id en sesión")
    return None

@app.route('/clear-session')
def clear_session():
    """Ruta temporal para limpiar sesión corrupta"""
    session.clear()
    flash('Sesión limpiada. Por favor, inicia sesión nuevamente.', 'info')
    return redirect(url_for('login'))

# ==================== RUTAS ====================

@app.route('/')
def index():
    products = get_all_products()
    current_user = get_current_user()
    return render_template('index.html', app_name=APP_NAME, products=products, current_user=current_user)

@app.route('/contacto')
def contacto():
    current_user = get_current_user()
    return render_template('contacto.html', app_name=APP_NAME, current_user=current_user)

@app.route('/producto/<int:product_id>')  # ✅ CORRECTO (singular)
def producto(product_id):  # Cambiar nombre de función también
    product = get_product_by_id(product_id)
    if not product:
        flash('Producto no encontrado', 'error')
        return redirect(url_for('index'))
    current_user = get_current_user()
    return render_template('producto.html', app_name=APP_NAME, product=product, current_user=current_user)

@app.route('/productos')
def productos():
    products = get_all_products()
    current_user = get_current_user()
    return render_template('productos.html', app_name=APP_NAME, products=products, current_user=current_user)

@app.route('/eliminar-producto/<int:product_id>', methods=['POST'])
@login_required
def eliminar_producto(product_id):
    product = get_product_by_id(product_id)
    if product:
        # Eliminar imagen si existe
        if product['image_filename']:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], product['image_filename'])
            if os.path.exists(image_path):
                os.remove(image_path)
        
        if delete_product(product_id):
            flash('Producto eliminado exitosamente', 'success')
        else:
            flash('Error al eliminar el producto', 'error')
    else:
        flash('Producto no encontrado', 'error')
    
    return redirect(url_for('index'))

# ==================== RUTAS DE AUTENTICACIÓN ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Ruta de inicio de sesión"""
    # Si ya está logueado, redirigir
    if 'user_id' in session:
        flash('Ya has iniciado sesión.', 'info')
        return redirect(url_for('index'))
    
    form = LoginForm()
    
    if request.method == 'POST':
        print("=" * 50)
        print("🔐 INTENTO DE LOGIN")
        print(f"📝 Username/Email: {form.username.data}")
        print(f"🔑 Password recibido: {'*' * len(form.password.data or '')}")
        print(f"✅ Form válido: {form.validate_on_submit()}")
        print(f"❌ Errores: {form.errors}")
        
        if form.validate_on_submit():
            user = get_user_by_username_or_email(form.username.data)
            print(f"👤 Usuario encontrado: {user is not None}")
            
            if user:
                print(f"🆔 User ID: {user['id']}")
                print(f"📧 Email: {user['email']}")
                
                password_match = check_user_password(user, form.password.data)
                print(f"🔓 Contraseña coincide: {password_match}")
                
                if password_match:
                    # Guardar en sesión
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session.permanent = True  # Hacer la sesión permanente
                    
                    print(f"✅ Sesión creada: {dict(session)}")
                    flash(f'¡Bienvenido, {user["username"]}!', 'success')
                    
                    next_page = request.args.get('next')
                    print(f"➡️ Redirigiendo a: {next_page or 'index'}")
                    print("=" * 50)
                    return redirect(next_page) if next_page else redirect(url_for('index'))
                else:
                    flash('Contraseña incorrecta.', 'error')
            else:
                flash('Usuario no encontrado.', 'error')
        else:
            flash('Por favor corrige los errores del formulario.', 'error')
        
        print("=" * 50)
    
    return render_template('login.html', form=form, app_name=APP_NAME)

@app.route('/logout')
def logout():
    """Cierra la sesión del usuario"""
    print("=" * 50)
    print("🚪 INTENTO DE LOGOUT")
    print(f"📋 Sesión actual: {dict(session)}")
    
    if 'user_id' in session:
        username = session.get('username', 'Usuario')
        session.clear()
        print(f"✅ Sesión limpiada para: {username}")
        print(f"📋 Sesión después: {dict(session)}")
        flash(f'Hasta pronto, {username}!', 'success')
    else:
        print("⚠️ No hay sesión activa")
        flash('No hay sesión activa.', 'info')
    
    print("=" * 50)
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Ruta de registro de usuarios"""
    # Si ya está logueado, redirigir
    if 'user_id' in session:
        flash('Ya tienes una cuenta activa.', 'info')
        return redirect(url_for('index'))
    
    form = RegisterForm()
    
    if request.method == 'POST':
        print("=" * 50)
        print("📝 INTENTO DE REGISTRO")
        print(f"👤 Username: {form.username.data}")
        print(f"📧 Email: {form.email.data}")
        print(f"✅ Form válido: {form.validate_on_submit()}")
        print(f"❌ Errores: {form.errors}")
    
    if form.validate_on_submit():
        # Verificar si el usuario ya existe
        existing_user = get_user_by_username_or_email(form.username.data)
        existing_email = get_user_by_username_or_email(form.email.data)
        
        print(f"🔍 Usuario existe: {existing_user is not None}")
        print(f"🔍 Email existe: {existing_email is not None}")
        
        if existing_user or existing_email:
            flash('El usuario o email ya está registrado.', 'error')
        else:
            # Crear usuario
            user_created = create_user(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data
            )
            
            print(f"✅ Usuario creado: {user_created}")
            
            if user_created:
                flash(f'¡Registro exitoso! Bienvenido, {form.username.data}. Ya puedes iniciar sesión.', 'success')
                print("=" * 50)
                return redirect(url_for('login'))
            else:
                flash('Error al crear el usuario. Intenta más tarde.', 'error')
        
        print("=" * 50)
    
    return render_template('register.html', form=form, app_name=APP_NAME)


# ==================== RUTAS DE PRODUCTOS ====================

@app.route('/crear-producto', methods=['GET', 'POST'])
@login_required
def crear_producto():
    form = ProductForm()
    if form.validate_on_submit():
        image_filename = None
        
        if form.image.data:
            image_file = form.image.data
            if allowed_file(image_file.filename):
                filename = str(uuid.uuid4()) + "." + image_file.filename.rsplit('.', 1)[1].lower()
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_filename = filename
        
        product_id = create_product(
            form.name.data,
            form.description.data,
            float(form.price.data),
            image_filename
        )
        
        if product_id:
            flash('Producto creado exitosamente', 'success')
            return redirect(url_for('index'))
        else:
            flash('Error al crear el producto', 'error')
    
    current_user = get_current_user()
    return render_template('crear_producto.html', form=form, app_name=APP_NAME, current_user=current_user)

@app.route('/editar-producto/<int:product_id>', methods=['GET', 'POST'])
@login_required
def editar_producto(product_id):
    product = get_product_by_id(product_id)
    if not product:
        flash('Producto no encontrado', 'error')
        return redirect(url_for('index'))
    
    form = ProductForm()
    
    if request.method == 'GET':
        form.name.data = product['name']
        form.description.data = product['description']
        form.price.data = product['price']
    
    if form.validate_on_submit():
        image_filename = product['image_filename']
        
        if form.image.data:
            image_file = form.image.data
            if allowed_file(image_file.filename):
                # Eliminar imagen anterior si existe
                if image_filename:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                filename = str(uuid.uuid4()) + "." + image_file.filename.rsplit('.', 1)[1].lower()
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_filename = filename
        
        if update_product(
            product_id,
            form.name.data,
            form.description.data,
            float(form.price.data),
            image_filename
        ):
            flash('Producto actualizado exitosamente', 'success')
            return redirect(url_for('index'))
        else:
            flash('Error al actualizar el producto', 'error')
    
    current_user = get_current_user()
    return render_template('editar_producto.html', form=form, product=product, app_name=APP_NAME, current_user=current_user)

@app.route('/static/images/<filename>')
def get_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ==================== INICIALIZACIÓN ====================

if __name__ == '__main__':
    # Crear directorio de imágenes si no existe
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Inicializar base de datos
    init_db()
    

    app.run(debug=True)
