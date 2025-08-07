import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'prjt_grn_tm_2025'

    # SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://gt_admin:prjt_grn_tm_2025@localhost:5432/grande_time_db'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///meu_banco.db'

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Configurações de E-mail para Flask-Mail
    MAIL_SERVER = 'smtp.googlemail.com' 
    MAIL_PORT = 587
    MAIL_USE_TLS = True 
    MAIL_USERNAME = os.environ.get('EMAIL_USER') 
    MAIL_PASSWORD = os.environ.get('EMAIL_PASS') 
    MAIL_DEFAULT_SENDER = os.environ.get('EMAIL_USER') 