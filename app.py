import os
from datetime import datetime, timedelta, date
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Empresa, Funcionario, Admin, CheckIn
import random

app = Flask(__name__)

# 🔐 ESSENCIAL PRA LOGIN FUNCIONAR
app.secret_key = os.environ.get("SECRET_KEY", "dev_key_super_secreta")

# 🔗 DATABASE (Render usa DATABASE_URL)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///dev.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# =====================================================
# 🧪 SEED DEMO (ÚNICO E CORRETO)
# =====================================================

def seed_demo():
    if Empresa.query.first():
        return

    # ADMIN
    admin = Admin(
        usuario='admin',
        senha=generate_password_hash('admin123')
    )
    db.session.add(admin)

    # EMPRESA
    empresa = Empresa(
        nome='Empresa Demo BAI-EX',
        email='empresa@demo.com',
        senha=generate_password_hash('empresa123'),
        plano='profissional'
    )
    db.session.add(empresa)
    db.session.commit()

    # FUNCIONÁRIOS
    nomes = ['João', 'Maria', 'Carlos', 'Ana', 'Pedro']
    funcionarios = []

    for nome in nomes:
        f = Funcionario(
            nome=nome,
            email=f"{nome.lower()}@demo.com",
            senha=generate_password_hash('func123'),
            empresa_id=empresa.id,
            departamento='Geral',
            cargo='Analista'
        )
        db.session.add(f)
        funcionarios.append(f)

    db.session.commit()

    # CHECKINS
    for f in funcionarios:
        for i in range(4):
            data = datetime.now() - timedelta(days=7*i)

            respostas = [random.randint(1,5) for _ in range(24)]
            score = CheckIn.calcular_score(respostas)
            nivel = CheckIn.classificar_risco(score)

            ck = CheckIn(
                funcionario_id=f.id,
                empresa_id=empresa.id,
                data=data,
                semana=data.isocalendar()[1],
                ano=data.year,
                score=score,
                nivel_risco=nivel
            )

            db.session.add(ck)

    db.session.commit()
    print("✅ SEED DEMO OK")

# =====================================================
# 🏠 ROTAS BÁSICAS
# =====================================================

@app.route('/')
def index():
    if 'empresa_id' in session:
        return redirect('/empresa/dashboard')
    return render_template('landing.html')

# =====================================================
# 🔐 LOGIN EMPRESA
# =====================================================

@app.route('/empresa/login', methods=['GET', 'POST'])
def login_empresa():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        empresa = Empresa.query.filter_by(email=email).first()

        if empresa and check_password_hash(empresa.senha, senha):
            session['empresa_id'] = empresa.id
            session['tipo'] = 'empresa'
            return redirect('/empresa/dashboard')

        flash('Credenciais inválidas')

    return render_template('empresa/login.html')

# =====================================================
# 📊 DASHBOARD EMPRESA
# =====================================================

@app.route('/empresa/dashboard')
def dashboard_empresa():
    if 'empresa_id' not in session:
        return redirect('/empresa/login')

    empresa_id = session['empresa_id']

    total_func = Funcionario.query.filter_by(empresa_id=empresa_id).count()
    total_checkins = CheckIn.query.filter_by(empresa_id=empresa_id).count()

    return jsonify({
        "empresa_id": empresa_id,
        "funcionarios": total_func,
        "checkins": total_checkins
    })

# =====================================================
# 👤 LOGIN FUNCIONÁRIO
# =====================================================

@app.route('/funcionario/login', methods=['GET', 'POST'])
def login_funcionario():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        f = Funcionario.query.filter_by(email=email).first()

        if f and check_password_hash(f.senha, senha):
            session['funcionario_id'] = f.id
            return redirect('/funcionario/painel')

        flash('Credenciais inválidas')

    return render_template('funcionario/login.html')

# =====================================================
# 👤 PAINEL FUNCIONÁRIO
# =====================================================

@app.route('/funcionario/painel')
def painel_funcionario():
    if 'funcionario_id' not in session:
        return redirect('/funcionario/login')

    fid = session['funcionario_id']

    historico = CheckIn.query.filter_by(funcionario_id=fid)\
        .order_by(CheckIn.data.desc()).limit(5).all()

    return jsonify([
        {"score": c.score, "nivel": c.nivel_risco}
        for c in historico
    ])

# =====================================================
# 🔧 INIT
# =====================================================

with app.app_context():
    try:
        db.create_all()
        seed_demo()
        print("✅ Banco OK")
    except Exception as e:
        print("🔥 ERRO NO INIT:", e)