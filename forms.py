from flask_wtf import FlaskForm
from wtforms import TextAreaField, StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email
from models import User

# Cadastro usuário (apenas para uso do admin)
class RegistrationForm(FlaskForm):
    username = StringField('Apelido (Nome no chat)', validators = [DataRequired(), Length(min = 2, max = 50)])
    email = StringField('Email para Login', validators = [DataRequired(), Email(), Length(max = 255)]) 
    password = PasswordField('Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Tipo de Usuário', choices=[('protegido', 'Protegido'), ('anjo', 'Anjo'), ('admin', 'Administrador')], validators=[DataRequired()])
    submit = SubmitField('Criar Usuário')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Nome de Usuário já existe. Por favor, escolha outro.')
    
    def validate_email(self, email): 
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Este email já está registrado. Por favor, use outro.')

# Login usuário
class LoginForm(FlaskForm):
     email = StringField('Email', validators = [DataRequired(), Email(), Length(min = 5, max = 255)]) 
     password = PasswordField('Senha', validators=[DataRequired()])
     submit = SubmitField('Entrar')

# Formulário de Alteração de Senha
class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Senha Antiga', validators=[DataRequired()])
    new_password = PasswordField('Nova Senha', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirmar Nova Senha', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Alterar Senha')

# Formulário de Esqueci Minha Senha
class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()]) 
    submit = SubmitField('Solicitar Redefinição')

# Formulário de Redefinição de Senha 
class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nova Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Nova Senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Redefinir Senha')

# Formulário de Envio de Mensagem para Anjos (para Protegidos)
class MessageForm(FlaskForm):
    receiver_id = SelectField('Enviar para Protegido', coerce=int, validators=[DataRequired()])
    content = TextAreaField('Sua Mensagem', validators=[DataRequired()])
    submit = SubmitField('Enviar Mensagem Privada')

# Formulário de Envio de Mensagem para Protegidos (para seu Anjo)
class ProtegidoMessageForm(FlaskForm):
    content = TextAreaField('Sua Mensagem para o Anjo', validators=[DataRequired()])
    submit = SubmitField('Enviar ao Anjo')

# Formulário de Envio de Mensagem para o Chat Geral (apenas Admin)
class GeneralChatForm(FlaskForm):
    content = TextAreaField('Mensagem para o Chat Geral', validators=[DataRequired()])
    submit = SubmitField('Enviar para Todos')

# Formulário de Atribuição Anjo-Protegido (Apenas Admin)
class AssignForm(FlaskForm):
    anjo_id = SelectField('Anjo', coerce=int, validators=[DataRequired()])
    jogador_id = SelectField('Protegido', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Atribuir')