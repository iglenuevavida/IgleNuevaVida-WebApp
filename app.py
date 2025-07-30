from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random

app = Flask(__name__)
app.secret_key = 'clave_super_secreta'

# Configuración base de datos
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'iglesia.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
from datetime import timedelta
app.permanent_session_lifetime = timedelta(days=7)  # Mantener sesión por 7 días

db = SQLAlchemy(app)

# Modelos
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    rol = db.Column(db.String(50), default='usuario')  # usuario / pastor / redes

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50))
    apellido = db.Column(db.String(50))
    edad = db.Column(db.Integer)
    lider = db.Column(db.String(50))
    ministerio = db.Column(db.String(50))
    tiempo_en_iglesia = db.Column(db.String(50))
    bautizado = db.Column(db.String(10))

# Versículos
versiculos = [
    "Juan 3:16 - Porque de tal manera amó Dios al mundo...",
    "Salmo 23:1 - Jehová es mi pastor, nada me faltará.",
    "Filipenses 4:13 - Todo lo puedo en Cristo que me fortalece.",
    "Proverbios 3:5 - Confía en Jehová con todo tu corazón..."
]

@app.route('/')
def inicio():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('encuesta'))  # Manda primero al formulario de datos

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verificamos si el usuario ya existe
        if User.query.filter_by(username=username).first():
            error = 'El nombre de usuario ya está registrado.'
        else:
            user = User(username=username, rol='usuario')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            session['username'] = user.username
            session['rol'] = user.rol
            session.permanent = True
            return redirect(url_for('encuesta'))  # O dashboard si querés

    return render_template('registro.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user:
            if user.check_password(password):
                session['user_id'] = user.id
                session['username'] = user.username
                session['rol'] = user.rol
                session.permanent = True
                return redirect(url_for('dashboard'))
            else:
                error = "Contraseña incorrecta"
        else:
            error = "El usuario no está registrado. Registrate primero."

    return render_template('login.html', error=error)

@app.route('/invitado')
def invitado():
    versiculo = random.choice(versiculos)
    return render_template('index.html', versiculo=versiculo)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', rol=user.rol, username=user.username)

@app.route('/encuesta', methods=['GET', 'POST'])
def encuesta():
    if request.method == 'POST':
        nuevo = Usuario(
            nombre=request.form['nombre'],
            apellido=request.form['apellido'],
            edad=request.form['edad'],
            lider=request.form['lider'],
            ministerio=request.form['ministerio'],
            tiempo_en_iglesia=request.form['tiempo_en_iglesia'],
            bautizado=request.form['bautizado']
        )
        db.session.add(nuevo)
        db.session.commit()
        return redirect(url_for('invitado'))
    return render_template('encuesta.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

@app.route('/panel_pastores')
def panel_pastores():
    if 'user_id' not in session or session.get('rol') != 'pastor':
        return redirect(url_for('login'))  # Bloquea si no es pastor
    miembros = Usuario.query.all()
    return render_template('panel_pastores.html', miembros=miembros)