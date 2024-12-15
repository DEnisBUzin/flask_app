from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)

# Конфигурация приложения
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ads_auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def generate_token(self):
        payload = {
            'user_id': self.id,
            'exp': datetime.utcnow() + timedelta(hours=1)  # Токен действует 1 час
        }
        return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')


# Модель объявления
class Ad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref=db.backref('ads', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'owner_id': self.owner_id,
        }


# Инициализация базы данных
with app.app_context():
    db.create_all()


# Хелпер для проверки токена
def get_current_user():
    token = request.headers.get('Authorization')
    if not token:
        abort(401, 'Токен отсутствует')
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return User.query.get(payload['user_id'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        abort(401, 'Неверный токен')


# Регистрация пользователя
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        abort(400, 'Отсутствует email или пароль')

    if User.query.filter_by(email=data['email']).first():
        abort(400, 'Email already exists')

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(email=data['email'], password_hash=hashed_password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Пользователь успешно зарегистрирован!'})


# Авторизация пользователя
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        abort(400, 'Отсутствует email или пароль')

    user = User.query.filter_by(email=data['email']).first()
    if not user or not user.check_password(data['password']):
        abort(401, 'Неверный email или пароль')

    token = user.generate_token()
    return jsonify({'token': token})


# Создание объявления
@app.route('/ads', methods=['POST'])
def create_ad():
    current_user = get_current_user()
    data = request.get_json()
    if not data or 'title' not in data or 'description' not in data:
        abort(400, 'Отсутсвует название или описание')

    ad = Ad(
        title=data['title'],
        description=data['description'],
        owner_id=current_user.id
    )
    db.session.add(ad)
    db.session.commit()

    return jsonify(ad.to_dict()), 201


# Получение объявления
@app.route('/ads/<int:ad_id>', methods=['GET'])
def get_ad(ad_id):
    ad = Ad.query.get(ad_id)
    if not ad:
        abort(404, 'Ad not found')
    return jsonify(ad.to_dict())


# Удаление объявления
@app.route('/ads/<int:ad_id>', methods=['DELETE'])
def delete_ad(ad_id):
    current_user = get_current_user()
    ad = Ad.query.get(ad_id)
    if not ad:
        abort(404, 'Ad not found')

    if ad.owner_id != current_user.id:
        abort(403, 'You are not the owner of this ad')

    db.session.delete(ad)
    db.session.commit()

    return jsonify({'message': 'Ad deleted successfully'})


# Запуск приложения
if __name__ == '__main__':
    app.run(debug=True)
