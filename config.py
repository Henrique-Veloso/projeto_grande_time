import os

class Config:
    # SECRET_KEY usada para proteger dados de sessão e outros elementos de segurança.
    # É CRUCIAL que esta chave seja mantida em segredo!
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'prjt_grn_tm_2025'

    # Configuração do banco de dados SQLite
    # Caminho completo para o arquivo do banco de dados SQLite
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'

    # Desabilita o rastreamento de modificações de objetos
    SQLALCHEMY_TRACK_MODIFICATIONS = False