import os
from forms import RegistrationForm, LoginForm
from flask import Flask, render_template, url_for, flash, redirect, request
from config import Config
from passlib.hash import pbkdf2_sha256 as hasher
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
from models import User, Message
from extensions import db

app = Flask(__name__)

# Arquivo config.py
app.config.from_object(Config)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'instance', 'site.db')
csrf = CSRFProtect(app) 

# Config Flask login
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

db.init_app(app)

# Rotas
@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html', title = 'Início')

# Cadastro usuário
@app.route('/register', methods = ['GET', 'POST'])
def register():
    # Caso já esteja logado
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = hasher.hash(form.password.data)
        user = User(username = form.username.data, password = hashed_password, role = form.role.data)
        db.session.add(user)
        db.session.commit()
        flash(f'Conta criada com sucesso para {form.username.data}! Agora você pode fazer o login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title = 'Cadastro', form = form)

# Autenticação usuário
@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user and hasher.verify(form.password.data, user.password): 
            login_user(user)
            flash('Login bem-sucedido!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login sem sucesso. Verifique o nome de usuário e a senha', 'danger')
    return render_template('login.html', title = 'login', form = form)

# Encerrar sessão
@app.route('/logout')
def logout():
    logout_user()
    flash('Você foi desconectado', 'info')
    return redirect(url_for('index'))

# Sessão papel do usuário
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'anjo':
        return render_template('anjo_dashboard.html', title = 'Dashboard Anjo')
    elif current_user.role == 'jogador':
        return render_template('jogador_dashboard.html', title = 'Dashboard Jogador')
    else:
        flash('Seu tipo de usuário não é reconhecido.', 'warning')
        logout_user()
        return redirect(url_for('login'))


if __name__ == '__main__':
    # Cria as tabelas no bd, executar apenas uma vez ou quando alterar seus modelos
    with app.app_context():
        db.create_all()
    app.run(debug=True)