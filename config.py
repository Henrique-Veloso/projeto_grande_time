import os

class Config:
    # Chave 
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'prjt_grn_tm_2025'

    # Caminho arquivo SQLite
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'

    # Rastreamento de modificações de objetos
    SQLALCHEMY_TRACK_MODIFICATIONS = False