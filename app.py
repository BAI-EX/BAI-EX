from flask import Flask, render_template, redirect, request, session, url_for

app = Flask(__name__)

# 🔐 Necessário pra sessão funcionar
app.secret_key = 'supersecretkey'


# =====================================================
# 🏠 LANDING PAGE
# =====================================================

@app.route('/')
def index():
    return render_template('index.html')


# =====================================================
# 🔐 LOGIN (SIMPLES - DEMO)
# =====================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('senha')

        # Conta DEMO fixa
        if email == 'demo@baiex.com' and senha == '123456':
            session['empresa_id'] = 1
            return redirect('/empresa/dashboard')

        return "Login inválido"

    return render_template('login.html')


# =====================================================
# 📊 DASHBOARD
# =====================================================

@app.route('/empresa/dashboard')
def dashboard():
    if 'empresa_id' not in session:
        return redirect('/login')

    return "<h1>Dashboard BAI-EX 🚀</h1>"


# =====================================================
# 🚪 LOGOUT
# =====================================================

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# =====================================================
# 🚀 START
# =====================================================

if __name__ == '__main__':
    app.run(debug=True)