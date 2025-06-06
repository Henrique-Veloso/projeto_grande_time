import os
from flask import Flask, render_template, url_for, flash, redirect, request
from config import Config
from passlib.hash import pbkdf2_sha256 as hasher
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
from extensions import db, mail 
from models import User, Message, Assignment, GeneralChatMessage
from forms import LoginForm, ChangePasswordForm, ForgotPasswordForm, ResetPasswordForm, MessageForm, ProtegidoMessageForm, GeneralChatForm, AssignForm, RegistrationForm 
from flask_migrate import Migrate
from datetime import datetime
from flask_mail import Message as MailMessage 

app = Flask(__name__)
app.config.from_object(Config)

csrf = CSRFProtect(app)

db.init_app(app)
mail.init_app(app) 
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Funções Auxiliares para E-mail
def send_reset_email(user):
    token = user.get_reset_token()
    msg = MailMessage('Redefinição de Senha - Projeto Encontro',
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[user.email])
    msg.body = f'''Para redefinir sua senha, visite o seguinte link:
{url_for('reset_token', token=token, _external=True)}

Se você não solicitou esta redefinição, por favor, ignore este e-mail e sua senha atual permanecerá inalterada.
'''
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Erro ao enviar e-mail: {e}")
        return False

# Rotas da Aplicação

@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html', title='Início')

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first() 
        if user and hasher.verify(form.password.data, user.password):
            login_user(user)
            flash('Login bem-sucedido!', 'success')
            if user.must_change_password:
                return redirect(url_for('change_password'))
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Login sem sucesso. Verifique o email e a senha.', 'danger') 
    return render_template('login.html', title = 'login', form = form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if not current_user.must_change_password:
        return redirect(url_for('dashboard'))

    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not hasher.verify(form.old_password.data, current_user.password):
            flash('Senha antiga incorreta.', 'danger')
            return render_template('change_password.html', title='Alterar Senha', form=form)

        current_user.password = hasher.hash(form.new_password.data)
        current_user.must_change_password = False
        db.session.commit()
        flash('Sua senha foi alterada com sucesso! Você já pode navegar na plataforma.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html', title='Alterar Senha', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if send_reset_email(user):
                flash('Um e-mail foi enviado com instruções para redefinir sua senha.', 'info')
            else:
                flash('Erro ao enviar e-mail. Por favor, tente novamente mais tarde ou entre em contato com o suporte.', 'danger')
        else:
            flash('Nenhuma conta encontrada com este e-mail.', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html', title='Esqueci Minha Senha', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('Token inválido ou expirado.', 'warning')
        return redirect(url_for('forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = hasher.hash(form.password.data)
        user.password = hashed_password
        user.must_change_password = False 
        db.session.commit()
        flash('Sua senha foi redefinida! Agora você pode fazer login com a nova senha.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Redefinir Senha', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.must_change_password:
        return redirect(url_for('change_password'))
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'anjo':
        return redirect(url_for('anjo_dashboard'))
    elif current_user.role == 'protegido':
        return redirect(url_for('protegido_dashboard'))
    else:
        flash('Seu tipo de usuário não é reconhecido.', 'warning')
        logout_user()
        return redirect(url_for('login'))

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Acesso negado. Você não é um administrador.', 'danger')
        return redirect(url_for('dashboard'))
    form = GeneralChatForm()
    if form.validate_on_submit():
        message = GeneralChatMessage(sender_id=current_user.id, content=form.content.data)
        db.session.add(message)
        db.session.commit()
        flash('Mensagem enviada para o chat geral!', 'success')
        return redirect(url_for('admin_dashboard'))
    general_messages = GeneralChatMessage.query.order_by(GeneralChatMessage.timestamp.desc()).limit(20).all()
    return render_template('admin_dashboard.html', title='Dashboard Admin', form=form, general_messages=general_messages)

@app.route('/anjo/dashboard', methods=['GET', 'POST'])
@login_required
def anjo_dashboard():
    if current_user.role != 'anjo':
        flash('Acesso negado. Você não é um anjo.', 'danger')
        return redirect(url_for('dashboard'))
    message_form = MessageForm()
    assigned_protegidos_assignments = Assignment.query.filter_by(anjo_id=current_user.id).all()
    message_form.receiver_id.choices = [(a.protegido.id, a.protegido.username) for a in assigned_protegidos_assignments]
    if message_form.validate_on_submit(): 
        receiver_id = message_form.receiver_id.data
        content = message_form.content.data
        is_assigned = Assignment.query.filter_by(anjo_id=current_user.id, jogador_id=receiver_id).first()
        if is_assigned:
            message = Message(sender_id=current_user.id, receiver_id=receiver_id, content=content)
            db.session.add(message)
            db.session.commit()
            flash('Mensagem privada enviada com sucesso!', 'success')
            return redirect(url_for('anjo_dashboard'))
        else:
            flash('Você não pode enviar mensagens para este protegido (não atribuído ou papel inválido).', 'danger')
    sent_messages_private = Message.query.filter_by(sender_id=current_user.id).order_by(Message.timestamp.desc()).limit(10).all()
    general_messages = GeneralChatMessage.query.order_by(GeneralChatMessage.timestamp.desc()).limit(20).all()
    return render_template('anjo_dashboard.html',
                           title='Dashboard Anjo',
                           message_form=message_form,
                           sent_messages_private=sent_messages_private,
                           general_messages=general_messages)

@app.route('/protegido/dashboard', methods=['GET', 'POST'])
@login_required
def protegido_dashboard():
    if current_user.role != 'protegido':
        flash('Acesso negado. Você não é um protegido.', 'danger')
        return redirect(url_for('dashboard'))
    protegido_message_form = ProtegidoMessageForm()
    assigned_anjo_assignment = Assignment.query.filter_by(jogador_id=current_user.id).first()
    if protegido_message_form.validate_on_submit(): 
        if assigned_anjo_assignment:
            anjo_id = assigned_anjo_assignment.anjo_id
            content = protegido_message_form.content.data
            message = Message(sender_id=current_user.id, receiver_id=anjo_id, content=content)
            db.session.add(message)
            db.session.commit()
            flash('Mensagem enviada para seu anjo!', 'success')
            return redirect(url_for('protegido_dashboard'))
        else:
            flash('Você ainda não tem um anjo atribuído para enviar mensagens.', 'warning')
    received_messages_from_anjo = []
    sent_messages_to_anjo = []
    if assigned_anjo_assignment:
        received_messages_from_anjo = Message.query.filter_by(receiver_id=current_user.id, sender_id=assigned_anjo_assignment.anjo_id).order_by(Message.timestamp.desc()).all()
        sent_messages_to_anjo = Message.query.filter_by(sender_id=current_user.id, receiver_id=assigned_anjo_assignment.anjo_id).order_by(Message.timestamp.desc()).all()
    general_messages = GeneralChatMessage.query.order_by(GeneralChatMessage.timestamp.desc()).limit(20).all()
    return render_template('protegido_dashboard.html',
                           title='Dashboard Protegido',
                           protegido_message_form=protegido_message_form,
                           received_messages_from_anjo=received_messages_from_anjo,
                           sent_messages_to_anjo=sent_messages_to_anjo,
                           general_messages=general_messages)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def admin_create_user():
    if current_user.role != 'admin':
        flash('Acesso negado. Você não é um administrador.', 'danger')
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = hasher.hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=form.role.data, must_change_password=True)
        db.session.add(user)
        db.session.commit()
        flash(f'Usuário {form.username.data} ({form.role.data}) criado com sucesso! Lembre-se de informar a senha inicial ({form.password.data}) e que ele precisará alterá-la no primeiro login.', 'success')
        return redirect(url_for('admin_create_user'))
    return render_template('admin_create_user.html', title='Criar Novo Usuário', form=form)

@app.route('/admin/assign_user', methods=['GET', 'POST'])
@login_required
def admin_assign_user():
    if current_user.role != 'admin':
        flash('Acesso negado. Você não é um administrador.', 'danger')
        return redirect(url_for('dashboard'))
    form = AssignForm()
    form.anjo_id.choices = [(u.id, u.username) for u in User.query.filter_by(role='anjo').order_by(User.username).all()]
    form.jogador_id.choices = [(u.id, u.username) for u in User.query.filter_by(role='protegido').order_by(User.username).all()]
    if form.validate_on_submit():
        anjo_id = form.anjo_id.data
        jogador_id = form.jogador_id.data
        existing_assignment = Assignment.query.filter_by(jogador_id=jogador_id).first()
        if existing_assignment:
            flash(f'O Protegido {User.query.get(jogador_id).username} já está atribuído ao anjo {existing_assignment.anjo.username}.', 'warning')
        else:
            assignment = Assignment(anjo_id=anjo_id, jogador_id=jogador_id)
            db.session.add(assignment)
            db.session.commit()
            flash(f'Anjo {User.query.get(anjo_id).username} atribuído ao Protegido {User.query.get(jogador_id).username} com sucesso!', 'success')
        return redirect(url_for('admin_assign_user'))
    existing_assignments = Assignment.query.all()
    return render_template('admin_assign_user.html',
                           title='Atribuir Anjos a Protegidos',
                           form=form,
                           existing_assignments=existing_assignments)

if __name__ == '__main__':
    with app.app_context():
        admin_user_exists = User.query.filter_by(username='superadmin').first()
        if not admin_user_exists:
            hashed_admin_pass = hasher.hash('superadmin123') 
            superadmin = User(username='superadmin', email='email_admin@exemplo.com', password=hashed_admin_pass, role='admin', must_change_password=True)
            db.session.add(superadmin)
            db.session.commit()
            
    app.run(debug=True)