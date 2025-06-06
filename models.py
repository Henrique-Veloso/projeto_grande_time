from extensions import db
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.orm import relationship
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from flask import current_app 

# Modelo do Banco de Dados
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    # Papéis: 'admin', 'anjo', 'protegido'
    role = db.Column(db.String(10), nullable=False, default='protegido')
    must_change_password = db.Column(db.Boolean, default=True, nullable=False)
    email = db.Column(db.String(320), unique=True, nullable=True) 

    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)
    general_chat_messages = db.relationship('GeneralChatMessage', foreign_keys='GeneralChatMessage.sender_id', backref='sender_gc', lazy=True)

    assigned_players = db.relationship('Assignment', foreign_keys='Assignment.anjo_id', backref='anjo', lazy=True)
    assigned_anjo = db.relationship('Assignment', foreign_keys='Assignment.jogador_id', backref='protegido', lazy=True, uselist=False)

    def get_reset_token(self, expires_sec=1800): # Token válido por 30 minutos
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.role}', '{self.email}')"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"Message('{self.content[:20]}...', 'De: {self.sender.username}', 'Para: {self.receiver.username}')"

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    anjo_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    jogador_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

    def __repr__(self):
        return f"Assignment(Anjo: {self.anjo.username}, Protegido: {self.protegido.username})"

class GeneralChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"GeneralChatMessage('{self.content[:20]}...', 'De: {self.sender_gc.username}')"