from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "BAI-EX ONLINE 🚀"

if __name__ == '__main__':
    app.run()