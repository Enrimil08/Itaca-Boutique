from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, DecimalField, FileField, BooleanField 
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange, Optional
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from flask import send_from_directory
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv


app = Flask(__name__)

# Configuración de la aplicación
load_dotenv()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')#
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB máximo
app.config['WTF_CSRF_ENABLED'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Verifica si el archivo tiene una extensión permitida"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Variables globales
APP_NAME = "Itaca Boutique"
app.app_context().push()

# Modelos de la Base de Datos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model): # Nuevo modelo de Producto
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False) # Tipo de dato para el precio
    
class ProductForm(FlaskForm):
    name = StringField('Nombre del Producto', validators=[DataRequired(), Length(min=5, max=100)])
    # Asegúrate de que esta línea sea exactamente así
    description = TextAreaField('Descripción del Producto', validators=[DataRequired(), Length(min=20)])
    price = DecimalField('Precio', validators=[DataRequired(), NumberRange(min=0)])
    image = FileField('Imagen del Producto', validators=[Optional()])
    submit = SubmitField('Guardar Producto')    

class RegisterForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Confirmar Contraseña', 
                             validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrarse')        

class LoginForm(FlaskForm):
    username = StringField('Usuario o Email', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    remember = BooleanField('Recordarme')
    submit = SubmitField('Entrar')
    

# Funciones de Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rutas de la Aplicación
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', app_name=APP_NAME, products=products)
    
@app.route('/contacto')
def contacto():
    return render_template('contacto.html', app_name=APP_NAME)

@app.route('/producto/<int:product_id>')
def product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('producto.html', app_name=APP_NAME, product=product)


@app.route('/eliminar-producto/<int:product_id>', methods=['POST'])
@login_required # Protege esta ruta
def eliminar_producto(product_id):
    product_to_delete = Product.query.get_or_404(product_id)
    try:
        db.session.delete(product_to_delete)
        db.session.commit()
        return redirect(url_for('index('))
    except:
        return 'Hubo un problema al eliminar ese producto'

# Rutas de Autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # Buscar usuario por username o email
        user = User.query.filter(
            (User.username == form.username.data) | 
            (User.email == form.username.data)
        ).first()
        
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Inicio de sesión exitoso.', 'success')
            
            # Redirigir a la página que intentaba acceder o al index
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        # Verificar si el usuario ya existe
        existing_user = User.query.filter(
            (User.username == form.username.data) | 
            (User.email == form.email.data)
        ).first()
        
        if existing_user:
            flash('El usuario o email ya está registrado.', 'error')
        else:
            # Crear nuevo usuario
            new_user = User(
                username=form.username.data,
                email=form.email.data
            )
            new_user.set_password(form.password.data)
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registro exitoso. Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html', form=form)
    
@app.route('/crear-producto',methods=['GET', 'POST'])
@login_required
def crear_producto():
    form = ProductForm()
    if form.validate_on_submit():
        new_product = Product(
            name=form.name.data, 
            description=form.description.data, 
            price=form.price.data
        )
        
        if form.image.data:
            image_file = form.image.data
            if allowed_file(image_file.filename):
                filename = str(uuid.uuid4()) + "." + image_file.filename.rsplit('.', 1)[1].lower()
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_product.image_filename = filename
        
        db.session.add(new_product)
        db.session.commit()
        return redirect(url_for('index'))
    
    return render_template('crear_producto.html', form=form)    

@app.route('/editar-producto/<int:product_id>', methods=['GET', 'POST'])
@login_required
def editar_producto(product_id):
    product_to_edit = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product_to_edit)
    if form.validate_on_submit():
        product_to_edit.name = form.name.data
        product_to_edit.description = form.description.data
        product_to_edit.price = form.price.data
        if form.image.data:
            image_file = form.image.data
            if allowed_file(image_file.filename):
                filename = str(uuid.uuid4()) + "." + image_file.filename.rsplit('.', 1)[1].lower()
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # Eliminar la imagen anterior si existe (opcional)
                if product_to_edit.image_filename:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product_to_edit.image_filename))
                product_to_edit.image_filename = filename
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('crear_producto.html', form=form)

@app.route('/static/images/<filename>')
def get_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
                   

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)