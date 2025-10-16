from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_socketio import SocketIO, emit, join_room
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, EqualTo, ValidationError
from datetime import datetime
from sqlalchemy import text # ⚠ 
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename
from markupsafe import Markup # ⚠ 
from functools import wraps
import re, os
import random
import string


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*") #http://localhost:5000

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = os.path.join(basedir, 'user_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # <- Гарантирует создание папки, если её нет

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx', 'xlsx', 'jpeg', 'jpg', 'png'}
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB
MAX_FILE_SIZE = 10 * 1024 * 1024 # 10 MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['MAX_FILE_SIZE'] = MAX_FILE_SIZE

# ==================== МОДЕЛЬ ПОЛЬЗОВАТЕЛЯ ====================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Добавляем поле для админа

# ==================== МОДЕЛЬ СООБЩЕНИЯ ====================
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== МОДЕЛЬ ПРИВАТНОГО ЧАТА ====================
class PrivateChat(db.Model):
    id = db.Column(db.String(6), primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', backref='private_chats')

class PrivateChatParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(6), db.ForeignKey('private_chat.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    chat = db.relationship('PrivateChat', backref='participants')
    user = db.relationship('User')

    __table_args__ = (db.UniqueConstraint('chat_id', 'user_id', name='unique_participant'),)

class PrivateChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(6), db.ForeignKey('private_chat.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    chat = db.relationship('PrivateChat', backref='messages')
    user = db.relationship('User')

# ==================== МОДЕЛЬ ХРАНЕНИЯ ФАЙЛОВ ====================
class UserFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(500), nullable=False)
    filepath = db.Column(db.String(512), nullable=False)
    filesize = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='files')

# ==================== МОДЕЛЬ ХРАНЕНИЯ ФЛАГОВ ==================== (API ЭНДПОИНТЫ ДЛЯ РАБОТЫ С check.py ЧЕРЕЗ checker.py)
class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flag_id = db.Column(db.String(64), unique=True, nullable=False)
    flag = db.Column(db.String(128), nullable=False)
    
# ==================== УТИЛИТА ГЕНЕРАЦИИ ID ПРИВАТНОГО ЧАТА ====================
def generate_chat_id():
    for _ in range(10):
        chat_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        if not db.session.get(PrivateChat, chat_id):
            return chat_id
    raise ValueError("Не удалось сгенерировать уникальный ID чата.")

# ==================== УТИЛИТА ДЛЯ ФАЙЛОВ ====================
def allowed_file(filename):
    if not filename:
        return False
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ==================== ЛОГИН ====================
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
    
# ==================== ДЕКОРАТОР ДЛЯ ПРОВЕРКИ АДМИНА ====================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != "admin":
            flash("Доступ запрещен: требуется права администратора", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ОБРАБОТЧИК ОШИБКИ 413 ====================
@app.errorhandler(413)
def request_entity_too_large(error):
    flash("Суммарный размер файлов превышает допустимый лимит. Попробуйте загрузить меньше или более лёгкие файлы.", "danger")
    return redirect(url_for('my_files'))

# ==================== ФОРМЫ ====================
class RegisterForm(FlaskForm):
    username = StringField('Логин', validators=[
        DataRequired(),
        Length(min=3, max=50, message='Логин должен содержать от 3 до 50 символов'),
        Regexp(r'^[A-Za-z0-9_]+$', message='Допустимы только A-Z, a-z, 0-9 и _')
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(), Length(min=8)
    ])
    confirm_password = PasswordField('Подтвердите пароль', validators=[
        DataRequired(), EqualTo('password', message='Пароли должны совпадать')
    ])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Логин уже занят.")

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class CreatePrivateChatForm(FlaskForm):
    password = PasswordField('Пароль', validators=[
        DataRequired(), Length(min=8),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$',
               message='Пароль должен содержать строчную, заглавную буквы, цифру и спецсимвол.')
    ])
    submit = SubmitField('Создать')

class ConnectPrivateChatForm(FlaskForm):
    chat_id = StringField('ID чата', validators=[
        DataRequired(), Length(min=6, max=6),
        Regexp(r'^[A-Z0-9]+$', message='ID может содержать только заглавные буквы и цифры')
    ])
    password = PasswordField('Пароль чата', validators=[DataRequired()])
    submit = SubmitField('Подключиться')

# ==================== МАРШРУТЫ ====================
@app.route('/')
def index():
    return render_template('index.html')

'''
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password = form.password.data
        if not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or \
           not re.search(r'[0-9]', password) or not re.search(r'[\W_]', password):
            flash("Пароль должен содержать заглавную, строчную буквы, цифру и спецсимвол.", "danger")
            return render_template('register.html', form=form)

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Регистрация успешна!", "success")
        return redirect(url_for('index'))
    return render_template('register.html', form=form)
'''

#'''
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # ⚠ Оборачиваем SQL-запрос в text()
        query = text(f"INSERT INTO user (username, password) VALUES ('{username}', '{password}')")
        db.session.execute(query)
        db.session.commit()
        flash("Регистрация успешна!", "success")
        return redirect(url_for('index'))
    return render_template('register.html', form=form)
#'''

@app.route('/check_username')
def check_username():
    username = request.args.get('username', '')
    exists = User.query.filter_by(username=username).first() is not None
    return {'exists': exists}

'''
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('account'))
        flash("Неверный логин или пароль.", "danger")
    return render_template('login.html', form=form)
'''

#'''
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # ⚠ Используем text() для "сырых" SQL-запросов
        query = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
        result = db.session.execute(query).fetchone()
        if result:
            user = User.query.get(result.id)
            login_user(user)
            return redirect(url_for('account'))
        flash("Неверный логин или пароль.", "danger")
    return render_template('login.html', form=form) 
#'''

'''
@app.route('/debug_users')
@admin_required  # Добавляем декоратор проверки админа
def debug_users():
    q = request.args.get("q", "")
    try:
        query = text("SELECT username, password FROM user WHERE username LIKE :q")
        result = db.session.execute(query, {"q": f"%{q}%"}).fetchall()
        return jsonify([{"username": row[0], "password": row[1][:10] + '...'} for row in result])
    except Exception as e:
        return jsonify({"error": str(e)})
'''

#'''
@app.route('/debug_users')
def debug_users():
    q = request.args.get("q", "")
    try:
        # ⚠ Уязвимость: прямой SQL-запрос без параметров
        query = text(f"SELECT username, password FROM user WHERE username LIKE '%{q}%'")
        result = db.session.execute(query).fetchall()
        return jsonify([{"username": row[0], "password": row[1]} for row in result])
    except Exception as e:
        return jsonify({"error": str(e)})
#'''

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

'''
@app.route('/chat')
@login_required
def chat():
    messages = ChatMessage.query.order_by(ChatMessage.timestamp.asc()).all()
    formatted_messages = [
        {
            'username': msg.username,
            'message': msg.message,
            'timestamp': msg.timestamp.strftime('%H:%M-%d/%m/%Y')
        } for msg in messages
    ]
    return render_template('chat.html', username=current_user.username, messages=formatted_messages)
'''

#'''
@app.route('/chat')
@login_required
def chat():
    messages = ChatMessage.query.order_by(ChatMessage.timestamp.asc()).all()
    formatted_messages = [
        {
            'username': msg.username,
            'message': Markup(msg.message),  # ⚠ Разрешаем HTML в сообщениях
            'timestamp': msg.timestamp.strftime('%H:%M-%d/%m/%Y')
        } for msg in messages
    ]
    return render_template('chat.html', username=current_user.username, messages=formatted_messages)
#'''

@app.route('/menu_private_chat')
@login_required
def menu_private_chat():
    return render_template('menu_private_chat.html')

@app.route('/create_private_chat', methods=['GET', 'POST'])
@login_required
def create_private_chat():
    form = CreatePrivateChatForm()
    if form.validate_on_submit():
        password = form.password.data
        if not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or \
           not re.search(r'[0-9]', password) or not re.search(r'[\W_]', password):
            flash("Пароль должен содержать заглавную, строчную буквы, цифру и спецсимвол.", "danger")
            return render_template('create_private_chat.html', form=form)

        try:
            chat_id = generate_chat_id()
        except ValueError:
            flash("Не удалось сгенерировать уникальный ID чата. Попробуйте позже.", "danger")
            return render_template('create_private_chat.html', form=form)

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        chat = PrivateChat(id=chat_id, owner_id=current_user.id, password_hash=hashed_pw)
        db.session.add(chat)
        db.session.commit()
        flash(f"Чат создан: {chat_id}", "success")
        return redirect(url_for('my_private_chats'))
    return render_template('create_private_chat.html', form=form)

@app.route('/delete_private_chat/<chat_id>', methods=['POST'])
@login_required
def delete_private_chat(chat_id):
    chat = PrivateChat.query.get_or_404(chat_id)
    if chat.owner_id != current_user.id:
        flash("Вы не владелец этого чата.", "danger")
        return redirect(url_for('menu_private_chat'))

    PrivateChatParticipant.query.filter_by(chat_id=chat_id).delete()
    PrivateChatMessage.query.filter_by(chat_id=chat_id).delete()
    db.session.delete(chat)
    db.session.commit()

    socketio.emit('chat_deleted', {'chat_id': chat_id}, room=chat_id) #new

    flash("Чат удалён", "success")
    return redirect(url_for('my_private_chats'))

@app.route('/my_private_chats')
@login_required
def my_private_chats():
    chats = PrivateChat.query.filter_by(owner_id=current_user.id).all()
    return render_template('my_private_chats.html', chats=chats)

@app.route('/connect_private_chat', methods=['GET', 'POST'])
@login_required
def connect_private_chat():
    form = ConnectPrivateChatForm()
    if form.validate_on_submit():
        chat = PrivateChat.query.filter_by(id=form.chat_id.data).first()
        if not chat or not bcrypt.check_password_hash(chat.password_hash, form.password.data):
            flash("Неверный ID или пароль", "danger")
        else:
            participant = PrivateChatParticipant.query.filter_by(chat_id=chat.id, user_id=current_user.id).first()
            if not participant:
                db.session.add(PrivateChatParticipant(chat_id=chat.id, user_id=current_user.id))
                db.session.commit()
            return redirect(url_for('private_chat', chat_id=chat.id))
    return render_template('connect_private_chat.html', form=form)

@app.route('/private_chat/<chat_id>')
@login_required
def private_chat(chat_id):
    chat = PrivateChat.query.get_or_404(chat_id)
    participant = PrivateChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()
    if not participant and chat.owner_id != current_user.id:
        flash("У вас нет доступа к этому чату", "danger")
        return redirect(url_for('menu_private_chat'))

    messages = PrivateChatMessage.query.options(joinedload(PrivateChatMessage.user)).filter_by(chat_id=chat_id).order_by(PrivateChatMessage.timestamp.asc()).all()
    
    formatted_messages = [
        {
            'username': msg.user.username,
            'message': msg.message,
            'timestamp': msg.timestamp.strftime('%H:%M-%d/%m/%Y')
        } for msg in messages
    ]

    return render_template('private_chat.html', chat_id=chat_id, username=current_user.username, messages=formatted_messages)

@app.route('/my_files')
@login_required
def my_files():
    all_files = UserFile.query.filter_by(user_id=current_user.id).all()
    valid_files = []
    for f in all_files:
        if os.path.exists(f.filepath):
            valid_files.append(f)
        else:
            db.session.delete(f)
    db.session.commit()

    total_used = sum(f.filesize for f in valid_files)
    max_limit_mb = app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024)

    return render_template('my_files.html', files=valid_files, used=total_used, max_limit=max_limit_mb)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'files[]' not in request.files:
        flash("Нет файлов для загрузки.", "danger")
        return redirect(url_for('my_files'))

    files = request.files.getlist('files[]')
    if not files or all(f.filename == '' for f in files):
        flash("Файл не выбран.", "danger")
        return redirect(url_for('my_files'))

    # Создаём папку пользователя по логину
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    os.makedirs(user_folder, exist_ok=True)

    # Считаем текущий общий размер файлов пользователя
    total_size = sum(f.filesize for f in current_user.files)
    uploaded_any = False

    max_file_size_mb = app.config['MAX_FILE_SIZE'] / (1024 * 1024)
    max_limit_mb = app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024)

    rejected_files = []
    
    for file in files:
        if file.filename == '':
            flash("Файл не выбран.", "warning")
            continue

        if not allowed_file(file.filename):
            flash(f"Вам нельзя загружать такого формата файл: {file.filename}", "danger")
            continue

        filename = secure_filename(file.filename)
        file_path = os.path.join(user_folder, filename)

        # Получаем размер файла
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)

        # Проверка размера отдельного файла
        if file_size > app.config['MAX_FILE_SIZE']:
            rejected_files.append(f"{filename}: слишком большой")
            flash(f"Файл {filename} слишком большой. Максимальный размер — {max_file_size_mb:.0f} МБ.", "danger")
            continue
        
        # Проверка на заполненость хранилища
        if total_size + file_size > app.config['MAX_CONTENT_LENGTH']:
            rejected_files.append(f"{filename}: превышен лимит хранилища")
            flash(f"Превышен лимит хранилища в {max_limit_mb:.0f} МБ. Файл {filename} не загружен.", "danger")
            continue

        # Проверяем, есть ли файл с таким именем у пользователя
        existing_file = UserFile.query.filter_by(user_id=current_user.id, filename=filename).first()

        # Сохраняем файл на диск (перезапишет, если есть)
        file.save(file_path)

        if existing_file:
            # Удаляем старый файл с диска, если имя совпало, чтобы освободить место
            try:
                if existing_file.filepath != file_path and os.path.exists(existing_file.filepath):
                    os.remove(existing_file.filepath)
            except Exception:
                pass

            # Обновляем данные о файле
            existing_file.filepath = file_path
            existing_file.filesize = file_size
            existing_file.uploaded_at = datetime.utcnow()
        else:
            # Создаём новую запись в базе
            new_file = UserFile(
                filename=filename,
                filepath=file_path,
                filesize=file_size,
                user_id=current_user.id,
                uploaded_at=datetime.utcnow()
            )
            db.session.add(new_file)

        total_size += file_size
        uploaded_any = True

    if uploaded_any:
        db.session.commit()
        flash("Файлы загружены.", "success")
    elif rejected_files:
        flash("Ни один файл не был загружен. Причины:\n" + "<br>".join(rejected_files), "warning")
    else:
        flash("Файлы не загружены.", "warning")

    return redirect(url_for('my_files'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    user_file = UserFile.query.get_or_404(file_id)
    if user_file.user_id != current_user.id:
        flash("Нет доступа к файлу.", "danger")
        return redirect(url_for('my_files'))

    if not os.path.exists(user_file.filepath):
        # Удаляем битую запись
        db.session.delete(user_file)
        db.session.commit()
        flash("Файл не найден. Запись удалена из базы.", "warning")
        return redirect(url_for('my_files'))

    return send_file(user_file.filepath, as_attachment=True, download_name=user_file.filename)

'''
@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    user_file = UserFile.query.get_or_404(file_id)
    if user_file.user_id != current_user.id:
        flash("Нет доступа к файлу.", "danger")
        return redirect(url_for('my_files'))

    if not os.path.exists(user_file.filepath):
        # Файл отсутствует — удаляем запись и показываем сообщение
        db.session.delete(user_file)
        db.session.commit()
        flash("Файл не найден. Запись удалена из базы.", "warning")
        return redirect(url_for('my_files'))

    # Если файл есть — удаляем физически и из базы
    try:
        os.remove(user_file.filepath)
    except Exception as e:
        flash(f"Ошибка при удалении файла: {str(e)}", "danger")
        return redirect(url_for('my_files'))

    db.session.delete(user_file)
    db.session.commit()
    flash("Файл удалён.", "success")
    return redirect(url_for('my_files'))
'''

#'''
@app.route('/delete_file/<int:file_id>', methods=['GET', 'POST'])  # ⚠ Добавляем GET
@csrf.exempt  # ⚠ Отключаем CSRF-защиту
@login_required
def delete_file(file_id):
    user_file = UserFile.query.get_or_404(file_id)

    if not os.path.exists(user_file.filepath):
        # Файл отсутствует — удаляем запись и показываем сообщение
        db.session.delete(user_file)
        db.session.commit()
        flash("Файл не найден. Запись удалена из базы.", "warning")
        return redirect(url_for('my_files'))

    # Если файл есть — удаляем физически и из базы
    try:
        os.remove(user_file.filepath)
    except Exception as e:
        flash(f"Ошибка при удалении файла: {str(e)}", "danger")
        return redirect(url_for('my_files'))

    db.session.delete(user_file)
    db.session.commit()
    flash("Файл удалён.", "success")
    return redirect(url_for('my_files'))
#'''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

# ==================== SOCKET.IO ====================
@socketio.on('send_message')
def handle_message(data):
    message_text = data.get('message', '').strip()
    if not message_text or not current_user.is_authenticated:
        return

    timestamp = datetime.now()
    new_message = ChatMessage(
        username=current_user.username,
        message=message_text,
        timestamp=timestamp
    )
    db.session.add(new_message)
    db.session.commit()

    emit('receive_message', {
        'username': current_user.username,
        'message': message_text,
        'timestamp': timestamp.strftime('%H:%M-%d/%m/%Y')
    }, broadcast=True)

# для приватных чатов
@socketio.on('join_private_chat')
def on_join_private_chat(data):
    chat_id = data.get('chat_id')
    if not chat_id or not current_user.is_authenticated:
        return
    
    # Проверка: пользователь перед подключением, он должен быть участником чата
    chat = db.session.get(PrivateChat, chat_id)
    if not chat:
        return

    is_participant = (chat.owner_id == current_user.id) or \
                     PrivateChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()

    if is_participant:
        join_room(chat_id)

@socketio.on('send_private_message')
def handle_private_message(data):
    if not current_user.is_authenticated:
        return

    message_text = data.get('message', '').strip()
    chat_id = data.get('chat_id')

    if not message_text or not chat_id:
        return

    # Проверка: пользователь должен быть участником чата
    chat = db.session.get(PrivateChat, chat_id)
    if not chat:
        return

    is_participant = (chat.owner_id == current_user.id) or \
                     PrivateChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.id).first()

    if not is_participant:
        return

    # Сохраняем в БД
    new_message = PrivateChatMessage(
        chat_id=chat_id,
        user_id=current_user.id,
        message=message_text
    )
    db.session.add(new_message)
    db.session.commit()

    timestamp = new_message.timestamp.strftime('%H:%M-%d/%m/%Y')

    emit('receive_private_message', {
        'username': current_user.username,
        'message': message_text,
        'timestamp': timestamp
    }, room=chat_id)

# ==================== API ЭНДПОИНТЫ ДЛЯ РАБОТЫ С check.py ЧЕРЕЗ checker.py ====================
@app.route('/api/put', methods=['POST'])
@csrf.exempt
def api_put():
    data = request.json
    flag_id = data.get("flag_id")
    flag = data.get("flag")
    if not flag_id or not flag:
        return jsonify({"error": "missing flag_id or flag"}), 400

    f = Flag(flag_id=flag_id, flag=flag)
    db.session.add(f)
    db.session.commit()
    return jsonify({"flag_id": flag_id})

@app.route('/api/get', methods=['POST'])
@csrf.exempt
def api_get():
    data = request.json
    flag_id = data.get("flag_id")
    if not flag_id:
        return jsonify({"error": "missing flag_id"}), 400

    f = Flag.query.filter_by(flag_id=flag_id).first()
    if f is None:
        return jsonify({"error": "flag not found"}), 404

    return jsonify({"flag": f.flag})

# ==================== MAIN ====================
def create_admin():
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            hashed_pw = bcrypt.generate_password_hash("123*qwer!Q").decode('utf-8')
            admin = User(username="admin", password=hashed_pw, is_admin=True)
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()  # Создаем админа при запуске   
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

