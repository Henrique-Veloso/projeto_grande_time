from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from config import Config
from forms import RegistrationForm, LoginForm
from passlib.hash import pbkdf2_sha256 as hasher
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required

app = Flask(__name__)
# Arquivo config.py
app.config.from_object(Config)  
# Inicializa DB
db = SQLAlchemy(app) 

# Config Flask login
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Modelo do Banco de Dados
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable = False) 
    role = db.Column(db.String(10), nullable = False, default = 'jogador') # 'jogador' ou 'anjo'

    # Anjo pode enviar diversas menssagens 
    sent_messages = db.relationship('Message', foreign_keys = ['Message.sender_id'], backref = 'sender', lazy=True)
    # Jgador pode receber diversas menssagens 
    received_messages = db.relationship('Message', foreign_keys = ['Message.receiver_id'], backref = 'receiver', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    # ID do anjo
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    # ID do jogador
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    # Conteúdo da mensagem
    content = db.Column(db.Text, nullable = False)
    # Data e hora da mensagem
    timestamp = db.Column(db.DateTime, nullable = False, default = db.func.now())

    def __repr__(self):
        return f"Message('{self.content[:20]}...', 'De: {self.sender_id}', 'Para: {self.receiver_id}')"

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