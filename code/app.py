import datetime

from flask import Flask, render_template, redirect

from api_v1.otp_api import api
from models import db, jwt, crypt

app = Flask(__name__)
app.register_blueprint(api, url_prefix='/api/v1')

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:mariadbpw@192.168.1.150:3306/shareotp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True  # Auto Commit

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=14)
app.config['JWT_SECRET_KEY'] = 'super-secrete'

app.config['BCRYPT_LOG_ROUNDS'] = 10

db.init_app(app)
db.app = app
db.create_all()  # TODO 전체 생성 --> 아마도 다른기능으로 빼놓자!

jwt.init_app(app)
jwt.app = app

crypt.init_app(app)
crypt.app = app


@app.route('/')
def index():
    return redirect('login')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/otp')
def otp():
    return render_template('otp.html')


if __name__ == '__main__':
    app.run(debug=True)
