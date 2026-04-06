"""
Entry point para produção (Render/Railway/Heroku).
Roda com: gunicorn wsgi:application
"""
import os
from app import app, db, seed_demo, Admin

# Inicializa banco e seed na primeira execução
with app.app_context():
    db.create_all()
    if not Admin.query.first():
        seed_demo()

application = app
