import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Chave 
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'prjt_grn_tm_2025'

    # Rastreamento de modificações de objetos
    SQLALCHEMY_TRACK_MODIFICATIONS = False