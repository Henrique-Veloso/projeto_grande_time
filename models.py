from extensions import db
from flask_login import UserMixin 
from sqlalchemy.orm import relationship 

# Modelo do Banco de Dados
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable = False) 
    role = db.Column(db.String(10), nullable = False, default = 'jogador') # 'jogador' ou 'anjo'

    # Anjo pode enviar diversas menssagens 
    sent_messages = db.relationship('Message', foreign_keys = 'Message.sender_id', backref = 'sender', lazy=True)
    # Jgador pode receber diversas menssagens 
    received_messages = db.relationship('Message', foreign_keys = 'Message.receiver_id', backref = 'receiver', lazy=True)

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