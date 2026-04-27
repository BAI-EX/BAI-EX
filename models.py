from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Empresa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100))
    email = db.Column(db.String(100))
    senha = db.Column(db.String(200))
    plano = db.Column(db.String(50))

class Funcionario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100))
    email = db.Column(db.String(100))
    senha = db.Column(db.String(200))
    empresa_id = db.Column(db.Integer)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(100))
    senha = db.Column(db.String(200))

class CheckIn(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    funcionario_id = db.Column(db.Integer)
    empresa_id = db.Column(db.Integer)
    data = db.Column(db.DateTime)
    semana = db.Column(db.Integer)
    ano = db.Column(db.Integer)
    score = db.Column(db.Float)
    nivel_risco = db.Column(db.String(20))

    @staticmethod
    def calcular_score(respostas):
        return sum(respostas) / len(respostas) * 20

    @staticmethod
    def classificar_risco(score):
        if score < 30:
            return 'baixo'
        elif score < 60:
            return 'moderado'
        elif score < 80:
            return 'alto'
        return 'critico'