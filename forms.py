from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from  wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from app import User

# Cadastro usuário
class RegistrationForm(FlaskForm):
    username = StringField('Nome de usuário', validators = [DataRequired(), Length(min = 2, max = 20)])
    password = PasswordField('Senha', validators = [DataRequired()])
    confirm_password = PasswordField('Confirmar Senha', validators = [DataRequired(), EqualTo('password')])
    role = SelectField('Tipo de Usuário', choices = [('jogador', 'Jogador'), ('anjo', 'Anjo')], validators = [DataRequired()])
    submit = SubmitField('Cadastrar')

    # Verifica se nome já existe no BD
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError ('Nome de Usuário já existe. por favor, escolha outro.')

# Login usuário
class LoginForm(FlaskForm):
     username = StringField('Nome de usuário', validators = [DataRequired(), Length(min = 2, max = 20)])
     password = PasswordField('Senha', validators = [DataRequired()])
     submit = SubmitField('Entrar') 
