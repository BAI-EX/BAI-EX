from flask import Flask, render_template, redirect, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# 🔐 Segurança básica
app.config['SECRET_KEY'] = 'supersecretkey'

# 🗄️ Banco (SQLite simples pro Render)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =====================================================
# 📦 MODELOS (TUDO NO MESMO ARQUIVO PRA NÃO DAR ERRO)
# =====================================================

class Empresa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    senha = db.Column(db.String(100))

# =====================================================
# 🏠 ROTAS
# =====================================================

@app.route('/')
def index():
    return render_template('index.html')  # LANDING PAGE

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        empresa = Empresa.query.filter_by(email=email, senha=senha).first()

        if empresa:
            session['empresa_id'] = empresa.id
            return redirect('/empresa/dashboard')
        else:
            return "Login inválido"

    return render_template('login.html')

@app.route('/empresa/dashboard')
def dashboard():
    if 'empresa_id' not in session:
        return redirect('/login')

    return "Dashboard da empresa 🚀"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# =====================================================
# 🧪 CRIAR CONTAS DEMO AUTOMATICAMENTE
# =====================================================

def criar_dados_demo():
    if not Empresa.query.first():
        demo = Empresa(
            nome="Empresa Demo",
            email="demo@baiex.com",
            senha="123456"
        )
        db.session.add(demo)
        db.session.commit()
        print("✅ Conta demo criada: demo@baiex.com / 123456")

# =====================================================
# 🚀 START
# =====================================================

with app.app_context():
    db.create_all()
    criar_dados_demo()

if __name__ == '__main__':
    app.run(debug=True)