import sys
import os
import threading
import webbrowser
import time

# Ajusta caminhos para PyInstaller (modo frozen)
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
    INTERNAL_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    INTERNAL_DIR = BASE_DIR

os.chdir(BASE_DIR)

# Le o .env da pasta do .exe
env_path = os.path.join(BASE_DIR, '.env')
if os.path.exists(env_path):
    with open(env_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

from app import app, db, seed_demo, Admin

PORT = 5000

def abrir_navegador():
    time.sleep(2)
    webbrowser.open(f'http://localhost:{PORT}')

def iniciar_servidor():
    with app.app_context():
        db.create_all()
        if not Admin.query.first():
            seed_demo()
    app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False)

if __name__ == '__main__':
    print("=" * 52)
    print("  BAI-EX - Burnout AI Experience")
    print("=" * 52)
    print(f"  Iniciando em http://localhost:{PORT}")
    print("  Feche esta janela para encerrar.")
    print("=" * 52)
    t = threading.Thread(target=abrir_navegador, daemon=True)
    t.start()
    iniciar_servidor()
