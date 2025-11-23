import os
import sqlite3
import secrets
import shutil
import logging
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DATABASE'] = '/app/data/volunteer_network.db'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

# Настройка логирования
if not app.debug:
    if not os.path.exists('/app/data/logs'):
        os.makedirs('/app/data/logs')
    
    file_handler = RotatingFileHandler('/app/data/logs/volunteer_network.log', 
                                     maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Volunteer Network startup')

class RateLimiter:
    def __init__(self):
        self.requests = {}
    
    def is_limited(self, key, limit=5, period=60):
        now = datetime.now()
        if key not in self.requests:
            self.requests[key] = []
        
        # Удаляем старые запросы
        self.requests[key] = [req_time for req_time in self.requests[key] 
                             if now - req_time < timedelta(seconds=period)]
        
        if len(self.requests[key]) >= limit:
            return True
        
        self.requests[key].append(now)
        return False

rate_limiter = RateLimiter()

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if rate_limiter.is_limited(f"{request.remote_addr}_{request.endpoint}"):
            flash('Слишком много запросов. Пожалуйста, подождите.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'moderator':
            flash('Доступ только для модераторов')
            return redirect(url_for('feed'))
        return f(*args, **kwargs)
    return decorated_function

def organizer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') not in ['organizer', 'moderator']:
            flash('Только организаторы могут создавать мероприятия')
            return redirect(url_for('feed'))
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        os.makedirs('/app/data', exist_ok=True)
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

def validate_password(password):
    """Проверка сложности пароля"""
    if len(password) < 8:
        return "Пароль должен содержать минимум 8 символов"
    if not any(c.isupper() for c in password):
        return "Пароль должен содержать хотя бы одну заглавную букву"
    if not any(c.islower() for c in password):
        return "Пароль должен содержать хотя бы одну строчную букву"
    if not any(c.isdigit() for c in password):
        return "Пароль должен содержать хотя бы одну цифру"
    return None

def init_db():
    with app.app_context():
        db = get_db()
        # Таблица пользователей
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                full_name TEXT,
                bio TEXT,
                skills TEXT,
                role TEXT DEFAULT 'volunteer',
                organization_name TEXT,
                organization_description TEXT,
                organization_contact TEXT,
                is_visible BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Таблица постов
        db.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                post_type TEXT DEFAULT 'volunteer',
                location TEXT,
                event_date TEXT,
                needs_volunteers BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Таблица чатов
        db.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1_id INTEGER NOT NULL,
                user2_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user1_id) REFERENCES users (id),
                FOREIGN KEY (user2_id) REFERENCES users (id),
                UNIQUE(user1_id, user2_id)
            )
        ''')
        # Таблица сообщений
        db.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                message_text TEXT NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (chat_id) REFERENCES chats (id),
                FOREIGN KEY (sender_id) REFERENCES users (id)
            )
        ''')
        # Таблица анкет волонтеров
        db.execute('''
            CREATE TABLE IF NOT EXISTS volunteer_forms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL,
                contact_info TEXT NOT NULL,
                age INTEGER NOT NULL,
                experience TEXT NOT NULL,
                comment TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (post_id) REFERENCES posts (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Таблица уведомлений
        db.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Таблица категорий
        db.execute('''
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT
            )
        ''')
        # Таблица связи постов и категорий
        db.execute('''
            CREATE TABLE IF NOT EXISTS post_categories (
                post_id INTEGER,
                category_id INTEGER,
                FOREIGN KEY (post_id) REFERENCES posts (id),
                FOREIGN KEY (category_id) REFERENCES categories (id),
                PRIMARY KEY (post_id, category_id)
            )
        ''')
        # Таблица рейтингов
        db.execute('''
            CREATE TABLE IF NOT EXISTS ratings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user_id INTEGER NOT NULL,
                to_user_id INTEGER NOT NULL,
                post_id INTEGER,
                rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
                comment TEXT,
                is_reported BOOLEAN DEFAULT FALSE,
                report_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (from_user_id) REFERENCES users (id),
                FOREIGN KEY (to_user_id) REFERENCES users (id),
                FOREIGN KEY (post_id) REFERENCES posts (id),
                UNIQUE(from_user_id, to_user_id, post_id)
            )
        ''')
        # Таблица достижений
        db.execute('''
            CREATE TABLE IF NOT EXISTS achievements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                icon TEXT,
                condition TEXT
            )
        ''')
        # Таблица достижений пользователей
        db.execute('''
            CREATE TABLE IF NOT EXISTS user_achievements (
                user_id INTEGER,
                achievement_id INTEGER,
                achieved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (achievement_id) REFERENCES achievements (id),
                PRIMARY KEY (user_id, achievement_id)
            )
        ''')
        # Таблица жалоб
        db.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER NOT NULL,
                reported_rating_id INTEGER,
                reported_post_id INTEGER,
                report_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reporter_id) REFERENCES users (id),
                FOREIGN KEY (reported_rating_id) REFERENCES ratings (id),
                FOREIGN KEY (reported_post_id) REFERENCES posts (id)
            )
        ''')
        
        # Добавляем базовые категории
        default_categories = [
            ('Экология', 'Уборка территорий, посадка деревьев'),
            ('Животные', 'Помощь приютам, забота о животных'),
            ('Дети', 'Работа с детьми, образовательные программы'),
            ('Пожилые', 'Помощь пожилым людям'),
            ('Медицина', 'Медицинская помощь, донорство'),
            ('Культура', 'Культурные мероприятия, события'),
            ('Образование', 'Обучение, репетиторство'),
            ('ЧС', 'Помощь в чрезвычайных ситуациях')
        ]
        
        for category in default_categories:
            try:
                db.execute('INSERT INTO categories (name, description) VALUES (?, ?)', category)
            except sqlite3.IntegrityError:
                pass
        
        # Базовые достижения
        achievements = [
            ('Первый шаг', 'Создал первый пост', '🎯', 'first_post'),
            ('Волонтер', 'Подал 5 заявок', '🤝', 'five_applications'),
            ('Организатор', 'Организовал 3 мероприятия', '⭐', 'three_events'),
            ('Активный участник', '10 одобренных заявок', '🏆', 'ten_approved'),
            ('Супер-волонтер', 'Помог в 10+ мероприятиях', '👑', 'super_volunteer')
        ]
        
        for achievement in achievements:
            try:
                db.execute('INSERT INTO achievements (name, description, icon, condition) VALUES (?, ?, ?, ?)', achievement)
            except sqlite3.IntegrityError:
                pass
        
        # Создаем аккаунты модераторов
        moderators = [
            ('moderator1', 'moderator1@example.com', 'Moderator123!', 'Алексей Модераторов', 'moderator'),
            ('moderator2', 'moderator2@example.com', 'Moderator123!', 'Мария Модераторова', 'moderator'),
            ('moderator3', 'moderator3@example.com', 'Moderator123!', 'Иван Модераторов', 'moderator'),
            ('moderator4', 'moderator4@example.com', 'Moderator123!', 'Елена Модераторова', 'moderator'),
            ('moderator5', 'moderator5@example.com', 'Moderator123!', 'Дмитрий Модераторов', 'moderator')
        ]
        
        for mod in moderators:
            try:
                db.execute(
                    "INSERT INTO users (username, email, password, full_name, role, is_visible) VALUES (?, ?, ?, ?, ?, ?)",
                    (mod[0], mod[1], generate_password_hash(mod[2]), mod[3], mod[4], False)
                )
            except sqlite3.IntegrityError:
                pass
        
        db.commit()

def upgrade_db():
    """Добавляет недостающие колонки в существующую БД"""
    with app.app_context():
        db = get_db()
        
        # Проверяем существование таблицы volunteer_forms
        try:
            db.execute('SELECT 1 FROM volunteer_forms LIMIT 1')
            print("✅ Таблица volunteer_forms уже существует")
        except sqlite3.OperationalError:
            print("🔄 Создаем таблицу volunteer_forms...")
            db.execute('''
                CREATE TABLE volunteer_forms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    post_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    full_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    contact_info TEXT NOT NULL,
                    age INTEGER NOT NULL,
                    experience TEXT NOT NULL,
                    comment TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (post_id) REFERENCES posts (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            db.commit()
            print("✅ Таблица volunteer_forms создана")

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def get_or_create_chat(user1_id, user2_id):
    db = get_db()
    user1_id, user2_id = sorted([user1_id, user2_id])
    
    chat = db.execute(
        'SELECT * FROM chats WHERE user1_id = ? AND user2_id = ?',
        (user1_id, user2_id)
    ).fetchone()
    
    if chat is None:
        cursor = db.execute(
            'INSERT INTO chats (user1_id, user2_id) VALUES (?, ?)',
            (user1_id, user2_id)
        )
        db.commit()
        chat_id = cursor.lastrowid
        chat = db.execute('SELECT * FROM chats WHERE id = ?', (chat_id,)).fetchone()
    
    return chat

def get_user_chats(user_id):
    db = get_db()
    chats = db.execute('''
        SELECT c.*, 
               CASE WHEN c.user1_id = ? THEN u2.id ELSE u1.id END as other_user_id,
               CASE WHEN c.user1_id = ? THEN u2.username ELSE u1.username END as other_username,
               CASE WHEN c.user1_id = ? THEN u2.full_name ELSE u1.full_name END as other_full_name,
               (SELECT message_text FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM messages WHERE chat_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message_time,
               (SELECT COUNT(*) FROM messages WHERE chat_id = c.id AND is_read = FALSE AND sender_id != ?) as unread_count
        FROM chats c
        LEFT JOIN users u1 ON c.user1_id = u1.id
        LEFT JOIN users u2 ON c.user2_id = u2.id
        WHERE c.user1_id = ? OR c.user2_id = ?
        ORDER BY last_message_time DESC
    ''', (user_id, user_id, user_id, user_id, user_id, user_id)).fetchall()
    return chats

def create_notification(user_id, title, message):
    db = get_db()
    db.execute(
        'INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)',
        (user_id, title, message)
    )
    db.commit()

def get_user_rating(user_id):
    db = get_db()
    result = db.execute('''
        SELECT AVG(rating) as avg_rating, COUNT(*) as rating_count 
        FROM ratings 
        WHERE to_user_id = ? AND is_reported = FALSE
    ''', (user_id,)).fetchone()
    return result

def check_achievements(user_id):
    db = get_db()
    
    # Проверяем условия и награждаем достижениями
    user_posts_count = db.execute('SELECT COUNT(*) FROM posts WHERE user_id = ?', 
                                (user_id,)).fetchone()[0]
    user_forms_count = db.execute('SELECT COUNT(*) FROM volunteer_forms WHERE user_id = ?', 
                                (user_id,)).fetchone()[0]
    approved_forms_count = db.execute('SELECT COUNT(*) FROM volunteer_forms WHERE user_id = ? AND status = "approved"', 
                                    (user_id,)).fetchone()[0]
    
    # Проверяем достижения
    achievements_to_check = [
        ('first_post', user_posts_count >= 1),
        ('five_applications', user_forms_count >= 5),
        ('three_events', user_posts_count >= 3),
        ('ten_approved', approved_forms_count >= 10),
        ('super_volunteer', approved_forms_count >= 10)
    ]
    
    for condition, achieved in achievements_to_check:
        if achieved:
            achievement = db.execute('SELECT id FROM achievements WHERE condition = ?', (condition,)).fetchone()
            if achievement:
                try:
                    db.execute('INSERT OR IGNORE INTO user_achievements (user_id, achievement_id) VALUES (?, ?)',
                             (user_id, achievement['id']))
                    db.commit()
                except sqlite3.IntegrityError:
                    pass
    
    user_achievements = db.execute('''
        SELECT a.* FROM achievements a
        JOIN user_achievements ua ON a.id = ua.achievement_id
        WHERE ua.user_id = ?
    ''', (user_id,)).fetchall()
    
    return user_achievements

# Обработчики ошибок
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db = getattr(g, '_database', None)
    if db is not None:
        db.rollback()
    return render_template('500.html'), 500

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('feed'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        role = request.form['role']
        
        db = get_db()
        error = None
        
        if not username or not password or not email:
            error = 'Все поля обязательны для заполнения'
        
        # Проверка сложности пароля
        password_error = validate_password(password)
        if password_error:
            error = password_error
        
        if error is None:
            try:
                if role == 'organizer':
                    organization_name = request.form['organization_name']
                    organization_description = request.form['organization_description']
                    organization_contact = request.form['organization_contact']
                    
                    db.execute(
                        "INSERT INTO users (username, email, password, full_name, role, organization_name, organization_description, organization_contact) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (username, email, generate_password_hash(password), full_name, role, organization_name, organization_description, organization_contact)
                    )
                else:
                    db.execute(
                        "INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)",
                        (username, email, generate_password_hash(password), full_name, role)
                    )
                db.commit()
                flash('Регистрация успешна! Теперь войдите в систему')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'Пользователь с таким именем или email уже существует'
        
        flash(error)
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        
        if user is None or not check_password_hash(user['password'], password):
            error = 'Неверное имя пользователя или пароль'
        
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            
            if user['role'] == 'moderator':
                flash(f'Добро пожаловать, модератор {user["full_name"]}!')
            else:
                flash(f'Добро пожаловать, {user["full_name"] or user["username"]}!')
            return redirect(url_for('feed'))
        
        flash(error)
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if session['role'] in ['organizer', 'moderator']:
        user_posts = db.execute('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],)).fetchall()
    else:
        user_posts = []
    
    # Получаем анкеты пользователя
    user_forms = db.execute('''
        SELECT vf.*, p.title as post_title, u.username as author_username 
        FROM volunteer_forms vf 
        JOIN posts p ON vf.post_id = p.id 
        JOIN users u ON p.user_id = u.id 
        WHERE vf.user_id = ? 
        ORDER BY vf.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Получаем рейтинг пользователя
    user_rating = get_user_rating(session['user_id'])
    
    # Получаем отзывы о пользователе
    user_reviews = db.execute('''
        SELECT r.*, u.username as reviewer_username, u.full_name as reviewer_name, p.title as post_title
        FROM ratings r
        JOIN users u ON r.from_user_id = u.id
        LEFT JOIN posts p ON r.post_id = p.id
        WHERE r.to_user_id = ? AND r.is_reported = FALSE
        ORDER BY r.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Получаем достижения
    user_achievements = check_achievements(session['user_id'])
    
    return render_template('profile.html', user=user, posts=user_posts, forms=user_forms, 
                         user_rating=user_rating, achievements=user_achievements, reviews=user_reviews)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        bio = request.form['bio']
        skills = request.form['skills']
        
        if session['role'] == 'organizer':
            organization_name = request.form['organization_name']
            organization_description = request.form['organization_description']
            organization_contact = request.form['organization_contact']
        
        try:
            if session['role'] == 'organizer':
                db.execute(
                    'UPDATE users SET full_name = ?, email = ?, bio = ?, skills = ?, organization_name = ?, organization_description = ?, organization_contact = ? WHERE id = ?',
                    (full_name, email, bio, skills, organization_name, organization_description, organization_contact, session['user_id'])
                )
            else:
                db.execute(
                    'UPDATE users SET full_name = ?, email = ?, bio = ?, skills = ? WHERE id = ?',
                    (full_name, email, bio, skills, session['user_id'])
                )
            db.commit()
            flash('Профиль успешно обновлен!')
            return redirect(url_for('profile'))
        except sqlite3.IntegrityError:
            flash('Пользователь с таким email уже существует')
    
    return render_template('edit_profile.html', user=user)

@app.route('/profile/delete', methods=['POST'])
@login_required
def delete_profile():
    db = get_db()
    db.execute('DELETE FROM posts WHERE user_id = ?', (session['user_id'],))
    db.execute('DELETE FROM users WHERE id = ?', (session['user_id'],))
    db.commit()
    session.clear()
    flash('Ваш профиль был удален')
    return redirect(url_for('index'))

@app.route('/feed')
@login_required
def feed():
    db = get_db()
    posts = db.execute('''
        SELECT p.*, u.username, u.full_name 
        FROM posts p 
        JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC
    ''').fetchall()
    return render_template('feed.html', posts=posts)

@app.route('/post/create', methods=['GET', 'POST'])
@login_required
@organizer_required
def create_post():
    db = get_db()
    categories = db.execute('SELECT * FROM categories').fetchall()
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post_type = request.form['post_type']
        location = request.form.get('location', '')
        event_date = request.form.get('event_date', '')
        needs_volunteers = 'needs_volunteers' in request.form
        selected_categories = request.form.getlist('categories')
        
        if not title or not content:
            flash('Заголовок и содержание обязательны')
            return redirect(url_for('create_post'))
        
        cursor = db.execute(
            'INSERT INTO posts (user_id, title, content, post_type, location, event_date, needs_volunteers) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (session['user_id'], title, content, post_type, location, event_date, needs_volunteers)
        )
        post_id = cursor.lastrowid
        
        # Добавляем категории
        for category_id in selected_categories:
            db.execute(
                'INSERT INTO post_categories (post_id, category_id) VALUES (?, ?)',
                (post_id, category_id)
            )
        
        db.commit()
        
        # Проверяем достижения
        check_achievements(session['user_id'])
        
        flash('Пост успешно создан!')
        return redirect(url_for('feed'))
    
    return render_template('create_post.html', categories=categories)

@app.route('/post/<int:post_id>')
@login_required
def post_detail(post_id):
    db = get_db()
    post = db.execute('''
        SELECT p.*, u.username, u.full_name 
        FROM posts p 
        JOIN users u ON p.user_id = u.id 
        WHERE p.id = ?
    ''', (post_id,)).fetchone()
    
    if post is None:
        flash('Пост не найден')
        return redirect(url_for('feed'))
    
    # Получаем категории поста
    post_categories = db.execute('''
        SELECT c.* FROM categories c
        JOIN post_categories pc ON c.id = pc.category_id
        WHERE pc.post_id = ?
    ''', (post_id,)).fetchall()
    
    # Проверяем, подавал ли пользователь уже анкету на этот пост
    existing_form = db.execute(
        'SELECT * FROM volunteer_forms WHERE post_id = ? AND user_id = ?',
        (post_id, session['user_id'])
    ).fetchone()
    
    # Для автора поста - показываем список анкет
    volunteer_forms = None
    if post['user_id'] == session['user_id'] or session['role'] == 'moderator':
        volunteer_forms = db.execute('''
            SELECT vf.*, u.username, u.full_name 
            FROM volunteer_forms vf 
            JOIN users u ON vf.user_id = u.id 
            WHERE vf.post_id = ? 
            ORDER BY vf.created_at DESC
        ''', (post_id,)).fetchall()
    
    return render_template('post_detail.html', 
                         post=post, 
                         existing_form=existing_form,
                         volunteer_forms=volunteer_forms,
                         categories=post_categories)

@app.route('/post/<int:post_id>/volunteer', methods=['GET', 'POST'])
@login_required
def volunteer_for_post(post_id):
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    
    if post is None:
        flash('Пост не найден')
        return redirect(url_for('feed'))
    
    # Проверяем, не подавал ли пользователь уже анкету
    existing_form = db.execute(
        'SELECT * FROM volunteer_forms WHERE post_id = ? AND user_id = ?',
        (post_id, session['user_id'])
    ).fetchone()
    
    if existing_form:
        flash('Вы уже подали анкету на это мероприятие')
        return redirect(url_for('post_detail', post_id=post_id))
    
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        contact_info = request.form['contact_info']
        age = request.form['age']
        experience = request.form['experience']
        comment = request.form.get('comment', '')
        
        if not all([full_name, username, contact_info, age, experience]):
            flash('Все обязательные поля должны быть заполнены')
            return redirect(url_for('volunteer_for_post', post_id=post_id))
        
        # Сохраняем анкету
        db.execute(
            'INSERT INTO volunteer_forms (post_id, user_id, full_name, username, contact_info, age, experience, comment) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (post_id, session['user_id'], full_name, username, contact_info, age, experience, comment)
        )
        db.commit()
        
        # Создаем чат с автором поста (если еще нет)
        chat = get_or_create_chat(session['user_id'], post['user_id'])
        
        # Отправляем уведомление в чат
        notification_message = f'''🎯 Новая заявка на мероприятие "{post['title']}"

👤 Волонтер: {full_name} (@{username})
📞 Контакты: {contact_info}
🎂 Возраст: {age} лет
💼 Опыт: {experience}
💬 Комментарий: {comment or "нет комментария"}

Статус: ⏳ Ожидает рассмотрения'''

        db.execute(
            'INSERT INTO messages (chat_id, sender_id, message_text) VALUES (?, ?, ?)',
            (chat['id'], session['user_id'], notification_message)
        )
        db.commit()
        
        # Создаем уведомление для автора поста
        create_notification(post['user_id'], 
                          'Новая заявка на ваше мероприятие', 
                          f'Пользователь {full_name} подал заявку на мероприятие "{post["title"]}"')
        
        # Проверяем достижения
        check_achievements(session['user_id'])
        
        flash('Ваша анкета успешно отправлена! Организатор свяжется с вами.')
        return redirect(url_for('post_detail', post_id=post_id))
    
    return render_template('volunteer_form.html', post=post)

@app.route('/volunteer_form/<int:form_id>/update_status', methods=['POST'])
@login_required
def update_form_status(form_id):
    db = get_db()
    form = db.execute('''
        SELECT vf.*, p.user_id as post_author_id, p.title as post_title 
        FROM volunteer_forms vf 
        JOIN posts p ON vf.post_id = p.id 
        WHERE vf.id = ?
    ''', (form_id,)).fetchone()
    
    if form is None:
        flash('Анкета не найдена')
        return redirect(url_for('profile'))
    
    # Проверяем, что текущий пользователь - автор поста или модератор
    if form['post_author_id'] != session['user_id'] and session['role'] != 'moderator':
        flash('У вас нет прав для изменения этой анкеты')
        return redirect(url_for('profile'))
    
    new_status = request.form['status']
    
    # Обновляем статус
    db.execute(
        'UPDATE volunteer_forms SET status = ? WHERE id = ?',
        (new_status, form_id)
    )
    
    # Отправляем уведомление в чат
    chat = get_or_create_chat(session['user_id'], form['user_id'])
    
    status_text = {
        'approved': '✅ Одобрена',
        'rejected': '❌ Отклонена',
        'pending': '⏳ На рассмотрении'
    }
    
    notification_message = f'''📢 Обновление статуса заявки на "{form['post_title']}"

Статус изменен на: {status_text.get(new_status, new_status)}'''

    db.execute(
        'INSERT INTO messages (chat_id, sender_id, message_text) VALUES (?, ?, ?)',
        (chat['id'], session['user_id'], notification_message)
    )
    
    # Создаем уведомление для волонтера
    create_notification(form['user_id'], 
                      'Обновление статуса заявки', 
                      f'Статус вашей заявки на мероприятие "{form["post_title"]}" изменен на: {status_text.get(new_status, new_status)}')
    
    db.commit()
    
    # Проверяем достижения
    check_achievements(form['user_id'])
    
    flash('Статус анкеты обновлен')
    return redirect(url_for('post_detail', post_id=form['post_id']))

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    db = get_db()
    
    if session['role'] == 'moderator':
        # Модератор может удалить любой пост
        post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    else:
        # Обычный пользователь может удалить только свой пост
        post = db.execute('SELECT * FROM posts WHERE id = ? AND user_id = ?', (post_id, session['user_id'])).fetchone()
    
    if post is None:
        flash('Вы не можете удалить этот пост')
        return redirect(url_for('feed'))
    
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash('Пост удален')
    return redirect(url_for('feed'))

@app.route('/chats')
@login_required
def chats_list():
    user_chats = get_user_chats(session['user_id'])
    return render_template('chats_list.html', chats=user_chats)

@app.route('/chat/<int:user_id>')
@login_required
def chat_with_user(user_id):
    db = get_db()
    other_user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if other_user is None:
        flash('Пользователь не найден')
        return redirect(url_for('chats_list'))
    
    chat = get_or_create_chat(session['user_id'], user_id)
    messages = db.execute('''
        SELECT m.*, u.username, u.full_name 
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE m.chat_id = ? 
        ORDER BY m.created_at ASC
    ''', (chat['id'],)).fetchall()
    
    db.execute(
        'UPDATE messages SET is_read = TRUE WHERE chat_id = ? AND sender_id != ? AND is_read = FALSE',
        (chat['id'], session['user_id'])
    )
    db.commit()
    
    return render_template('chat.html', chat=chat, other_user=other_user, messages=messages)

@app.route('/api/send_message', methods=['POST'])
@login_required
@rate_limit
def send_message():
    data = request.get_json()
    chat_id = data.get('chat_id')
    message_text = data.get('message_text')
    
    if not message_text or not chat_id:
        return jsonify({'success': False, 'error': 'Пустое сообщение'})
    
    db = get_db()
    chat = db.execute(
        'SELECT * FROM chats WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
        (chat_id, session['user_id'], session['user_id'])
    ).fetchone()
    
    if chat is None:
        return jsonify({'success': False, 'error': 'Чат не найден'})
    
    db.execute(
        'INSERT INTO messages (chat_id, sender_id, message_text) VALUES (?, ?, ?)',
        (chat_id, session['user_id'], message_text)
    )
    db.commit()
    
    return jsonify({'success': True})

@app.route('/api/get_messages/<int:chat_id>')
@login_required
def get_messages(chat_id):
    db = get_db()
    chat = db.execute(
        'SELECT * FROM chats WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
        (chat_id, session['user_id'], session['user_id'])
    ).fetchone()
    
    if chat is None:
        return jsonify({'success': False, 'error': 'Чат не найден'})
    
    messages = db.execute('''
        SELECT m.*, u.username, u.full_name 
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE m.chat_id = ? 
        ORDER BY m.created_at ASC
    ''', (chat_id,)).fetchall()
    
    db.execute(
        'UPDATE messages SET is_read = TRUE WHERE chat_id = ? AND sender_id != ? AND is_read = FALSE',
        (chat_id, session['user_id'])
    )
    db.commit()
    
    messages_list = []
    for msg in messages:
        messages_list.append({
            'id': msg['id'],
            'sender_id': msg['sender_id'],
            'sender_name': msg['full_name'] or msg['username'],
            'message_text': msg['message_text'],
            'created_at': msg['created_at'],
            'is_my_message': msg['sender_id'] == session['user_id']
        })
    
    return jsonify({'success': True, 'messages': messages_list})

@app.route('/users')
@login_required
def users_list():
    search_query = request.args.get('q', '')
    db = get_db()
    
    if search_query:
        users = db.execute('''
            SELECT id, username, full_name, bio, skills, role, organization_name
            FROM users 
            WHERE id != ? AND is_visible = TRUE AND (username LIKE ? OR full_name LIKE ? OR bio LIKE ? OR skills LIKE ?)
            ORDER BY username
        ''', (session['user_id'], f'%{search_query}%', f'%{search_query}%', f'%{search_query}%', f'%{search_query}%')).fetchall()
    else:
        users = db.execute('''
            SELECT id, username, full_name, bio, skills, role, organization_name
            FROM users 
            WHERE id != ? AND is_visible = TRUE
            ORDER BY username
        ''', (session['user_id'],)).fetchall()
    
    # Добавляем рейтинги для пользователей
    users_with_ratings = []
    for user in users:
        rating = get_user_rating(user['id'])
        users_with_ratings.append({
            'id': user['id'],
            'username': user['username'],
            'full_name': user['full_name'],
            'bio': user['bio'],
            'skills': user['skills'],
            'role': user['role'],
            'organization_name': user['organization_name'],
            'rating': rating
        })
    
    return render_template('users_list.html', users=users_with_ratings, search_query=search_query)

@app.route('/user/<int:user_id>/rate', methods=['POST'])
@login_required
def rate_user(user_id):
    rating = request.form.get('rating')
    comment = request.form.get('comment', '')
    post_id = request.form.get('post_id')
    
    if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
        flash('Некорректный рейтинг')
        return redirect(request.referrer or url_for('profile'))
    
    db = get_db()
    
    try:
        db.execute(
            'INSERT INTO ratings (from_user_id, to_user_id, post_id, rating, comment) VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], user_id, post_id, rating, comment)
        )
        db.commit()
        flash('Отзыв успешно добавлен!')
    except sqlite3.IntegrityError:
        flash('Вы уже оставляли отзыв этому пользователю')
    
    return redirect(request.referrer or url_for('profile'))

@app.route('/rating/<int:rating_id>/report', methods=['POST'])
@login_required
def report_rating(rating_id):
    reason = request.form.get('reason', '')
    
    if not reason:
        flash('Укажите причину жалобы')
        return redirect(request.referrer or url_for('profile'))
    
    db = get_db()
    
    # Проверяем существование отзыва
    rating = db.execute('SELECT * FROM ratings WHERE id = ?', (rating_id,)).fetchone()
    if not rating:
        flash('Отзыв не найден')
        return redirect(request.referrer or url_for('profile'))
    
    # Создаем жалобу
    db.execute(
        'INSERT INTO reports (reporter_id, reported_rating_id, report_type, reason) VALUES (?, ?, ?, ?)',
        (session['user_id'], rating_id, 'rating', reason)
    )
    
    # Помечаем отзыв как спорный
    db.execute(
        'UPDATE ratings SET is_reported = TRUE WHERE id = ?',
        (rating_id,)
    )
    
    db.commit()
    
    # Уведомляем модераторов
    moderators = db.execute('SELECT id FROM users WHERE role = "moderator"').fetchall()
    for mod in moderators:
        create_notification(mod['id'], 
                          'Новая жалоба на отзыв', 
                          f'Пользователь {session["username"]} пожаловался на отзыв. Причина: {reason}')
    
    flash('Жалоба отправлена модераторам')
    return redirect(request.referrer or url_for('profile'))

# Новые маршруты для дополнительного функционала

@app.route('/notifications')
@login_required
def notifications():
    db = get_db()
    user_notifications = db.execute(
        'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    
    # Помечаем как прочитанные
    db.execute(
        'UPDATE notifications SET is_read = TRUE WHERE user_id = ?',
        (session['user_id'],)
    )
    db.commit()
    
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/api/notifications/count')
@login_required
def notifications_count():
    db = get_db()
    count = db.execute(
        'SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = FALSE',
        (session['user_id'],)
    ).fetchone()[0]
    return jsonify({'count': count})

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    location = request.args.get('location', '')
    post_type = request.args.get('type', '')
    
    db = get_db()
    
    sql = '''
        SELECT DISTINCT p.*, u.username, u.full_name 
        FROM posts p 
        JOIN users u ON p.user_id = u.id 
        LEFT JOIN post_categories pc ON p.id = pc.post_id 
        LEFT JOIN categories c ON pc.category_id = c.id 
        WHERE 1=1
    '''
    params = []
    
    if query:
        sql += ' AND (p.title LIKE ? OR p.content LIKE ? OR p.location LIKE ?)'
        params.extend([f'%{query}%', f'%{query}%', f'%{query}%'])
    
    if category:
        sql += ' AND c.name = ?'
        params.append(category)
    
    if location:
        sql += ' AND p.location LIKE ?'
        params.append(f'%{location}%')
    
    if post_type:
        sql += ' AND p.post_type = ?'
        params.append(post_type)
    
    sql += ' ORDER BY p.created_at DESC'
    
    posts = db.execute(sql, params).fetchall()
    categories = db.execute('SELECT * FROM categories').fetchall()
    
    return render_template('search.html', 
                         posts=posts, 
                         categories=categories,
                         search_query=query)

@app.route('/calendar')
@login_required
def calendar():
    db = get_db()
    events = db.execute('''
        SELECT p.*, u.username, u.full_name 
        FROM posts p 
        JOIN users u ON p.user_id = u.id 
        WHERE p.event_date IS NOT NULL AND p.event_date != ''
        ORDER BY p.event_date
    ''').fetchall()
    
    return render_template('calendar.html', events=events)

@app.route('/api/events')
@login_required
def api_events():
    db = get_db()
    events = db.execute('''
        SELECT id, title, event_date as start, location 
        FROM posts 
        WHERE event_date IS NOT NULL AND event_date != ''
    ''').fetchall()
    
    events_list = []
    for event in events:
        events_list.append({
            'id': event['id'],
            'title': event['title'],
            'start': event['start'],
            'location': event['location'],
            'url': f"/post/{event['id']}"
        })
    
    return jsonify(events_list)

# СЕРВИСНЫЕ ФУНКЦИИ - ТОЛЬКО ДЛЯ МОДЕРАТОРОВ

@app.route('/stats')
@moderator_required
def stats():
    db = get_db()
    
    # Общая статистика
    total_posts = db.execute('SELECT COUNT(*) FROM posts').fetchone()[0]
    total_users = db.execute('SELECT COUNT(*) FROM users WHERE is_visible = TRUE').fetchone()[0]
    total_volunteers = db.execute('SELECT COUNT(DISTINCT user_id) FROM volunteer_forms').fetchone()[0]
    total_moderators = db.execute('SELECT COUNT(*) FROM users WHERE role = "moderator"').fetchone()[0]
    total_organizers = db.execute('SELECT COUNT(*) FROM users WHERE role = "organizer"').fetchone()[0]
    
    # Статистика по категориям
    categories_stats = db.execute('''
        SELECT c.name, COUNT(pc.post_id) as post_count 
        FROM categories c 
        LEFT JOIN post_categories pc ON c.id = pc.category_id 
        GROUP BY c.id 
        ORDER BY post_count DESC
    ''').fetchall()
    
    # Статистика по активностям
    active_posts_last_week = db.execute('''
        SELECT COUNT(*) FROM posts 
        WHERE created_at >= datetime('now', '-7 days')
    ''').fetchone()[0]
    
    active_users_last_week = db.execute('''
        SELECT COUNT(DISTINCT user_id) FROM (
            SELECT user_id FROM posts WHERE created_at >= datetime('now', '-7 days')
            UNION 
            SELECT user_id FROM volunteer_forms WHERE created_at >= datetime('now', '-7 days')
            UNION
            SELECT sender_id as user_id FROM messages WHERE created_at >= datetime('now', '-7 days')
        )
    ''').fetchone()[0]
    
    # Статистика по заявкам
    pending_forms = db.execute('SELECT COUNT(*) FROM volunteer_forms WHERE status = "pending"').fetchone()[0]
    approved_forms = db.execute('SELECT COUNT(*) FROM volunteer_forms WHERE status = "approved"').fetchone()[0]
    rejected_forms = db.execute('SELECT COUNT(*) FROM volunteer_forms WHERE status = "rejected"').fetchone()[0]
    
    return render_template('stats.html',
                         total_posts=total_posts,
                         total_users=total_users,
                         total_volunteers=total_volunteers,
                         total_moderators=total_moderators,
                         total_organizers=total_organizers,
                         categories_stats=categories_stats,
                         active_posts_last_week=active_posts_last_week,
                         active_users_last_week=active_users_last_week,
                         pending_forms=pending_forms,
                         approved_forms=approved_forms,
                         rejected_forms=rejected_forms)

@app.route('/export/my_data')
@login_required
def export_my_data():
    db = get_db()
    
    # Собираем данные пользователя
    user_data = {
        'profile': dict(db.execute('SELECT * FROM users WHERE id = ?', 
                                 (session['user_id'],)).fetchone()),
        'posts': [dict(row) for row in 
                 db.execute('SELECT * FROM posts WHERE user_id = ?', 
                          (session['user_id'],)).fetchall()],
        'volunteer_forms': [dict(row) for row in 
                           db.execute('SELECT * FROM volunteer_forms WHERE user_id = ?', 
                                    (session['user_id'],)).fetchall()],
        'achievements': [dict(row) for row in 
                        db.execute('''
                            SELECT a.* FROM achievements a
                            JOIN user_achievements ua ON a.id = ua.achievement_id
                            WHERE ua.user_id = ?
                        ''', (session['user_id'],)).fetchall()]
    }
    
    return jsonify(user_data)

@app.route('/admin/backup', methods=['POST'])
@moderator_required
def backup_database():
    """Создание резервной копии базы данных - только для модераторов"""
    try:
        backup_path = f"/app/data/backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2(app.config['DATABASE'], backup_path)
        
        # Получаем список всех бэкапов
        backup_files = [f for f in os.listdir('/app/data') if f.startswith('backup_') and f.endswith('.db')]
        backup_files.sort(reverse=True)
        
        # Удаляем старые бэкапы (оставляем только последние 10)
        if len(backup_files) > 10:
            for old_backup in backup_files[10:]:
                os.remove(f"/app/data/{old_backup}")
        
        flash(f'Резервная копия создана: {backup_path}')
    except Exception as e:
        flash(f'Ошибка при создании резервной копии: {str(e)}')
    
    return redirect(url_for('moderator_panel'))

@app.route('/admin/backups')
@moderator_required
def list_backups():
    """Список резервных копий - только для модераторов"""
    backup_files = []
    if os.path.exists('/app/data'):
        for f in os.listdir('/app/data'):
            if f.startswith('backup_') and f.endswith('.db'):
                file_path = f"/app/data/{f}"
                stat = os.stat(file_path)
                backup_files.append({
                    'name': f,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime)
                })
    
    backup_files.sort(key=lambda x: x['created'], reverse=True)
    return render_template('backups.html', backups=backup_files)

@app.route('/health')
def health_check():
    """Эндпоинт для проверки работоспособности"""
    try:
        db = get_db()
        db.execute('SELECT 1')
        
        # Проверяем доступность директории данных
        if not os.path.exists('/app/data'):
            return jsonify({'status': 'unhealthy', 'error': 'Data directory not found'}), 500
            
        return jsonify({
            'status': 'healthy', 
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# Модераторские функции
@app.route('/moderator')
@moderator_required
def moderator_panel():
    db = get_db()
    
    # Получаем жалобы
    reports = db.execute('''
        SELECT r.*, 
               u1.username as reporter_username,
               u2.username as reported_username,
               p.title as post_title,
               rat.comment as rating_comment
        FROM reports r
        LEFT JOIN users u1 ON r.reporter_id = u1.id
        LEFT JOIN users u2 ON r.reported_rating_id IN (SELECT id FROM ratings WHERE to_user_id = u2.id)
        LEFT JOIN posts p ON r.reported_post_id = p.id
        LEFT JOIN ratings rat ON r.reported_rating_id = rat.id
        WHERE r.status = 'pending'
        ORDER BY r.created_at DESC
    ''').fetchall()
    
    # Получаем все посты для возможности удаления
    all_posts = db.execute('''
        SELECT p.*, u.username, u.full_name 
        FROM posts p 
        JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC
    ''').fetchall()
    
    # Получаем все отзывы для возможности удаления
    all_ratings = db.execute('''
        SELECT r.*, u1.username as from_username, u2.username as to_username, p.title as post_title
        FROM ratings r
        JOIN users u1 ON r.from_user_id = u1.id
        JOIN users u2 ON r.to_user_id = u2.id
        LEFT JOIN posts p ON r.post_id = p.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    
    return render_template('moderator_panel.html', 
                         reports=reports, 
                         posts=all_posts, 
                         ratings=all_ratings)

@app.route('/moderator/report/<int:report_id>/resolve', methods=['POST'])
@moderator_required
def resolve_report(report_id):
    action = request.form.get('action')
    db = get_db()
    
    report = db.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()
    if not report:
        flash('Жалоба не найдена')
        return redirect(url_for('moderator_panel'))
    
    if action == 'delete_rating' and report['reported_rating_id']:
        # Удаляем отзыв
        db.execute('DELETE FROM ratings WHERE id = ?', (report['reported_rating_id'],))
        flash('Отзыв удален')
    elif action == 'keep_rating' and report['reported_rating_id']:
        # Оставляем отзыв, снимаем отметку о жалобе
        db.execute('UPDATE ratings SET is_reported = FALSE WHERE id = ?', (report['reported_rating_id'],))
        flash('Отзыв оставлен')
    elif action == 'delete_post' and report['reported_post_id']:
        # Удаляем пост
        db.execute('DELETE FROM posts WHERE id = ?', (report['reported_post_id'],))
        flash('Пост удален')
    
    # Помечаем жалобу как решенную
    db.execute('UPDATE reports SET status = "resolved" WHERE id = ?', (report_id,))
    db.commit()
    
    return redirect(url_for('moderator_panel'))

@app.route('/moderator/rating/<int:rating_id>/delete', methods=['POST'])
@moderator_required
def moderator_delete_rating(rating_id):
    db = get_db()
    db.execute('DELETE FROM ratings WHERE id = ?', (rating_id,))
    db.commit()
    flash('Отзыв удален')
    return redirect(url_for('moderator_panel'))

@app.route('/moderator/post/<int:post_id>/delete', methods=['POST'])
@moderator_required
def moderator_delete_post(post_id):
    db = get_db()
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash('Пост удален')
    return redirect(url_for('moderator_panel'))

# Шаблоны
def render_template(template_name, **context):
    templates = {
        '404.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Страница не найдена</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body class="bg-light">
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/">🎗️ Волонтерская Сеть</a>
                    </div>
                </nav>
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6 text-center">
                            <h1>404</h1>
                            <p>Страница не найдена</p>
                            <a href="/" class="btn btn-primary">На главную</a>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''',
        '500.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Ошибка сервера</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body class="bg-light">
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/">🎗️ Волонтерская Сеть</a>
                    </div>
                </nav>
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6 text-center">
                            <h1>500</h1>
                            <p>Внутренняя ошибка сервера</p>
                            <a href="/" class="btn btn-primary">На главную</a>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''',
        'index.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body text-center">
                                    <h1 class="card-title">🎗️ Волонтерская Сеть</h1>
                                    <p class="text-muted">Объединяем людей для добрых дел</p>
                                    <div class="mt-4">
                                        <a href="/login" class="btn btn-primary me-2">Войти</a>
                                        <a href="/register" class="btn btn-outline-primary">Регистрация</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''',
        'register.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Регистрация - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-8">
                            <div class="card">
                                <div class="card-body">
                                    <h2 class="card-title text-center">Регистрация</h2>
                                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-danger">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                                    <form method="POST" id="registerForm">
                                        <div class="mb-3">
                                            <label class="form-label">Тип аккаунта *</label>
                                            <select class="form-select" name="role" id="roleSelect" required>
                                                <option value="">Выберите тип аккаунта</option>
                                                <option value="volunteer">Волонтер</option>
                                                <option value="organizer">Организатор</option>
                                            </select>
                                        </div>
                                        <div class="mb-3"><label class="form-label">Имя пользователя *</label><input type="text" class="form-control" name="username" required></div>
                                        <div class="mb-3"><label class="form-label">Email *</label><input type="email" class="form-control" name="email" required></div>
                                        <div class="mb-3"><label class="form-label">Полное имя</label><input type="text" class="form-control" name="full_name"></div>
                                        
                                        <!-- Поля для организатора -->
                                        <div id="organizerFields" style="display: none;">
                                            <div class="mb-3">
                                                <label class="form-label">Название организации *</label>
                                                <input type="text" class="form-control" name="organization_name">
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">Описание организации</label>
                                                <textarea class="form-control" name="organization_description" rows="3"></textarea>
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">Контакты организации *</label>
                                                <input type="text" class="form-control" name="organization_contact" placeholder="Телефон, email или сайт">
                                            </div>
                                        </div>
                                        
                                        <div class="mb-3"><label class="form-label">Пароль *</label><input type="password" class="form-control" name="password" required>
                                        <div class="form-text">Пароль должен содержать минимум 8 символов, заглавные и строчные буквы, цифры</div></div>
                                        <button type="submit" class="btn btn-primary w-100">Зарегистрироваться</button>
                                    </form>
                                    <div class="text-center mt-3"><a href="/login">Уже есть аккаунт? Войдите</a></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <script>
                    document.getElementById('roleSelect').addEventListener('change', function() {
                        var organizerFields = document.getElementById('organizerFields');
                        if (this.value === 'organizer') {
                            organizerFields.style.display = 'block';
                            // Делаем поля обязательными
                            organizerFields.querySelectorAll('input, textarea').forEach(function(field) {
                                field.required = true;
                            });
                        } else {
                            organizerFields.style.display = 'none';
                            // Убираем обязательность
                            organizerFields.querySelectorAll('input, textarea').forEach(function(field) {
                                field.required = false;
                            });
                        }
                    });
                </script>
            </body>
            </html>
        ''',
        'login.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Вход - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h2 class="card-title text-center">Вход в систему</h2>
                                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-danger">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                                    <form method="POST">
                                        <div class="mb-3"><label class="form-label">Имя пользователя</label><input type="text" class="form-control" name="username" required></div>
                                        <div class="mb-3"><label class="form-label">Пароль</label><input type="password" class="form-control" name="password" required></div>
                                        <button type="submit" class="btn btn-primary w-100">Войти</button>
                                    </form>
                                    <div class="text-center mt-3"><a href="/register">Нет аккаунта? Зарегистрируйтесь</a></div>
                                    <div class="mt-4">
                                        <h6>Аккаунты модераторов для тестирования:</h6>
                                        <small class="text-muted">
                                            moderator1 / Moderator123!<br>
                                            moderator2 / Moderator123!<br>
                                            moderator3 / Moderator123!<br>
                                            moderator4 / Moderator123!<br>
                                            moderator5 / Moderator123!
                                        </small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''',
        'feed.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Лента - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            {% if session.role in ['organizer', 'moderator'] %}
                            <a class="nav-link" href="/post/create">Создать пост</a>
                            {% endif %}
                            <a class="nav-link" href="/search">Поиск</a>
                            <a class="nav-link" href="/calendar">Календарь</a>
                            <a class="nav-link" href="/chats">Мои чаты</a>
                            <a class="nav-link position-relative" href="/notifications">
                                Уведомления
                                <span id="notificationBadge" class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger" style="display: none;">0</span>
                            </a>
                            <a class="nav-link" href="/users">Все пользователи</a>
                            {% if session.role == 'moderator' %}
                            <a class="nav-link" href="/moderator">Панель модератора</a>
                            <a class="nav-link" href="/stats">Статистика</a>
                            {% endif %}
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-success">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                    <h2>Лента событий</h2>
                    {% for post in posts %}
                    <div class="card mb-3">
                        <div class="card-body">
                            <h5 class="card-title">
                                {{ post.title }}
                                {% if post.needs_volunteers %}<span class="badge bg-success ms-2">Ищет волонтеров</span>{% endif %}
                            </h5>
                            <h6 class="card-subtitle mb-2 text-muted">Автор: {{ post.full_name or post.username }}
                                {% if post.post_type == 'volunteer' %}<span class="badge bg-success">Ищу волонтеров</span>
                                {% elif post.post_type == 'help' %}<span class="badge bg-warning">Нужна помощь</span>
                                {% else %}<span class="badge bg-info">Событие</span>{% endif %}
                            </h6>
                            <p class="card-text">{{ post.content }}</p>
                            {% if post.location %}<p class="card-text"><small>Место: {{ post.location }}</small></p>{% endif %}
                            {% if post.event_date %}<p class="card-text"><small>Дата: {{ post.event_date }}</small></p>{% endif %}
                            <p class="card-text"><small class="text-muted">Опубликовано: {{ post.created_at }}</small></p>
                            
                            <div class="btn-group">
                                <a href="/post/{{ post.id }}" class="btn btn-outline-primary btn-sm">Подробнее</a>
                                {% if post.user_id == session['user_id'] or session.role == 'moderator' %}
                                <form action="/post/{{ post.id }}/delete" method="POST" class="d-inline">
                                    <button type="submit" class="btn btn-outline-danger btn-sm" onclick="return confirm('Удалить пост?')">Удалить</button>
                                </form>
                                {% endif %}
                                <a href="/chat/{{ post.user_id }}" class="btn btn-outline-success btn-sm">Написать автору</a>
                            </div>
                        </div>
                    </div>
                    {% else %}<div class="alert alert-info">Пока нет постов. Будьте первым!</div>{% endfor %}
                </div>
                <script>
                    function updateNotificationCount() {
                        fetch('/api/notifications/count')
                            .then(response => response.json())
                            .then(data => {
                                const badge = document.getElementById('notificationBadge');
                                if (data.count > 0) {
                                    badge.style.display = 'block';
                                    badge.textContent = data.count;
                                } else {
                                    badge.style.display = 'none';
                                }
                            });
                    }
                    setInterval(updateNotificationCount, 30000);
                    updateNotificationCount();
                </script>
            </body>
            </html>
        ''',
        'create_post.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Создать пост - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            <a class="nav-link" href="/search">Поиск</a>
                            <a class="nav-link" href="/chats">Мои чаты</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h2>Создать новый пост</h2>
                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-danger">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                    <form method="POST">
                        <div class="mb-3"><label class="form-label">Тип поста</label><select class="form-select" name="post_type" required><option value="volunteer">Ищу волонтеров</option><option value="help">Нужна помощь</option><option value="event">Событие</option></select></div>
                        <div class="mb-3"><label class="form-label">Заголовок *</label><input type="text" class="form-control" name="title" required></div>
                        <div class="mb-3"><label class="form-label">Содержание *</label><textarea class="form-control" name="content" rows="5" required></textarea></div>
                        <div class="mb-3"><label class="form-label">Место проведения</label><input type="text" class="form-control" name="location"></div>
                        <div class="mb-3"><label class="form-label">Дата события</label><input type="datetime-local" class="form-control" name="event_date"></div>
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" name="needs_volunteers" id="needs_volunteers">
                            <label class="form-check-label" for="needs_volunteers">Ищу волонтеров для этого мероприятия</label>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Категории</label>
                            <div class="row">
                                {% for category in categories %}
                                <div class="col-md-3">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" name="categories" value="{{ category.id }}" id="cat{{ category.id }}">
                                        <label class="form-check-label" for="cat{{ category.id }}">{{ category.name }}</label>
                                    </div>
                                </div>
                                {% endfor %}
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary">Опубликовать</button>
                        <a href="/feed" class="btn btn-secondary">Отмена</a>
                    </form>
                </div>
            </body>
            </html>
        ''',
        'post_detail.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>{{ post.title }} - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            <a class="nav-link" href="/search">Поиск</a>
                            <a class="nav-link" href="/chats">Мои чаты</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-success">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                    
                    <div class="card mb-4">
                        <div class="card-body">
                            <h2 class="card-title">{{ post.title }}</h2>
                            <h6 class="card-subtitle mb-2 text-muted">Автор: {{ post.full_name or post.username }}
                                {% if post.needs_volunteers %}<span class="badge bg-success ms-2">Ищет волонтеров</span>{% endif %}
                            </h6>
                            <p class="card-text">{{ post.content }}</p>
                            {% if post.location %}<p class="card-text"><strong>Место:</strong> {{ post.location }}</p>{% endif %}
                            {% if post.event_date %}<p class="card-text"><strong>Дата:</strong> {{ post.event_date }}</p>{% endif %}
                            {% if categories %}
                            <p class="card-text">
                                <strong>Категории:</strong>
                                {% for category in categories %}
                                <span class="badge bg-secondary me-1">{{ category.name }}</span>
                                {% endfor %}
                            </p>
                            {% endif %}
                            <p class="card-text"><small class="text-muted">Опубликовано: {{ post.created_at }}</small></p>
                        </div>
                    </div>

                    {% if post.needs_volunteers %}
                        {% if post.user_id != session['user_id'] and session.role != 'moderator' %}
                            {% if not existing_form %}
                                <div class="card mb-4">
                                    <div class="card-body text-center">
                                        <h5 class="card-title">Хотите стать волонтером?</h5>
                                        <p class="card-text">Заполните анкету для участия в мероприятии</p>
                                        <a href="/post/{{ post.id }}/volunteer" class="btn btn-success">Подать заявку</a>
                                    </div>
                                </div>
                            {% else %}
                                <div class="alert alert-info">
                                    <h5>Вы уже подали заявку на это мероприятие</h5>
                                    <p>Статус: 
                                        {% if existing_form.status == 'pending' %}⏳ На рассмотрении
                                        {% elif existing_form.status == 'approved' %}✅ Одобрена
                                        {% elif existing_form.status == 'rejected' %}❌ Отклонена
                                        {% else %}{{ existing_form.status }}{% endif %}
                                    </p>
                                </div>
                            {% endif %}
                        {% else %}
                            <!-- Для автора поста или модератора - показываем список заявок -->
                            <div class="card">
                                <div class="card-header">
                                    <h5 class="card-title mb-0">📋 Заявки волонтеров</h5>
                                </div>
                                <div class="card-body">
                                    {% if volunteer_forms %}
                                        {% for form in volunteer_forms %}
                                        <div class="card mb-3">
                                            <div class="card-body">
                                                <h6 class="card-title">{{ form.full_name }} (@{{ form.username }})</h6>
                                                <p class="card-text">
                                                    <strong>Контакты:</strong> {{ form.contact_info }}<br>
                                                    <strong>Возраст:</strong> {{ form.age }} лет<br>
                                                    <strong>Опыт:</strong> {{ form.experience }}<br>
                                                    {% if form.comment %}<strong>Комментарий:</strong> {{ form.comment }}{% endif %}
                                                </p>
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <span class="badge {% if form.status == 'pending' %}bg-warning{% elif form.status == 'approved' %}bg-success{% else %}bg-danger{% endif %}">
                                                        {% if form.status == 'pending' %}⏳ На рассмотрении
                                                        {% elif form.status == 'approved' %}✅ Одобрена
                                                        {% elif form.status == 'rejected' %}❌ Отклонена
                                                        {% else %}{{ form.status }}{% endif %}
                                                    </span>
                                                    <div>
                                                        {% if post.user_id == session['user_id'] or session.role == 'moderator' %}
                                                        <form action="/volunteer_form/{{ form.id }}/update_status" method="POST" class="d-inline">
                                                            <button type="submit" name="status" value="approved" class="btn btn-success btn-sm">Одобрить</button>
                                                            <button type="submit" name="status" value="rejected" class="btn btn-danger btn-sm">Отклонить</button>
                                                        </form>
                                                        {% endif %}
                                                        <a href="/chat/{{ form.user_id }}" class="btn btn-primary btn-sm">Написать</a>
                                                    </div>
                                                </div>
                                                <small class="text-muted">Подана: {{ form.created_at }}</small>
                                            </div>
                                        </div>
                                        {% endfor %}
                                    {% else %}
                                        <p class="text-muted">Пока нет заявок от волонтеров</p>
                                    {% endif %}
                                </div>
                            </div>
                        {% endif %}
                    {% endif %}
                    
                    <div class="mt-3">
                        <a href="/feed" class="btn btn-secondary">← Назад к ленте</a>
                    </div>
                </div>
            </body>
            </html>
        ''',
        'volunteer_form.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Анкета волонтера - {{ post.title }}</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            <a class="nav-link" href="/chats">Мои чаты</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <div class="row justify-content-center">
                        <div class="col-md-8">
                            <div class="card">
                                <div class="card-body">
                                    <h2 class="card-title text-center">Анкета волонтера</h2>
                                    <h5 class="card-subtitle mb-4 text-center text-muted">Мероприятие: "{{ post.title }}"</h5>
                                    
                                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-danger">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                                    
                                    <form method="POST">
                                        <div class="mb-3">
                                            <label class="form-label">Полное имя *</label>
                                            <input type="text" class="form-control" name="full_name" required 
                                                   value="{{ session.get('full_name', '') }}">
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label class="form-label">Имя пользователя *</label>
                                            <input type="text" class="form-control" name="username" required 
                                                   value="{{ session.get('username', '') }}">
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label class="form-label">Контактные данные *</label>
                                            <input type="text" class="form-control" name="contact_info" required 
                                                   placeholder="Телефон, email или другие контакты">
                                            <div class="form-text">Укажите, как с вами связаться</div>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label class="form-label">Возраст *</label>
                                            <input type="number" class="form-control" name="age" required min="14" max="100">
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label class="form-label">Опыт волонтерства *</label>
                                            <select class="form-select" name="experience" required>
                                                <option value="">Выберите опыт</option>
                                                <option value="Нет опыта">Нет опыта</option>
                                                <option value="Менее 1 года">Менее 1 года</option>
                                                <option value="1-3 года">1-3 года</option>
                                                <option value="Более 3 лет">Более 3 лет</option>
                                                <option value="Профессиональный волонтер">Профессиональный волонтер</option>
                                            </select>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label class="form-label">Комментарий</label>
                                            <textarea class="form-control" name="comment" rows="3" 
                                                      placeholder="Расскажите о себе, почему хотите участвовать, какие навыки можете применить..."></textarea>
                                        </div>
                                        
                                        <div class="d-grid gap-2">
                                            <button type="submit" class="btn btn-success btn-lg">Отправить заявку</button>
                                            <a href="/post/{{ post.id }}" class="btn btn-secondary">Отмена</a>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''',
        'profile.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Профиль - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            {% if session.role in ['organizer', 'moderator'] %}
                            <a class="nav-link" href="/post/create">Создать пост</a>
                            {% endif %}
                            <a class="nav-link" href="/chats">Мои чаты</a>
                            {% if session.role == 'moderator' %}
                            <a class="nav-link" href="/stats">Статистика</a>
                            {% endif %}
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-success">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                    <div class="row">
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-body">
                                    <h3 class="card-title">{{ user.full_name or user.username }}</h3>
                                    <p class="text-muted">@{{ user.username }}</p>
                                    <p>
                                        <span class="badge {% if user.role == 'volunteer' %}bg-success{% elif user.role == 'organizer' %}bg-primary{% else %}bg-warning{% endif %}">
                                            {% if user.role == 'volunteer' %}Волонтер
                                            {% elif user.role == 'organizer' %}Организатор
                                            {% else %}Модератор{% endif %}
                                        </span>
                                    </p>
                                    {% if user.role == 'organizer' and user.organization_name %}
                                    <p><strong>Организация:</strong> {{ user.organization_name }}</p>
                                    {% if user.organization_description %}<p>{{ user.organization_description }}</p>{% endif %}
                                    {% if user.organization_contact %}<p><strong>Контакты:</strong> {{ user.organization_contact }}</p>{% endif %}
                                    {% endif %}
                                    {% if user_rating and user_rating.avg_rating %}
                                    <div class="mb-3">
                                        <strong>Рейтинг:</strong>
                                        <div class="text-warning">
                                            {% for i in range(5) %}
                                                {% if i < user_rating.avg_rating|round %}
                                                ★
                                                {% else %}
                                                ☆
                                                {% endif %}
                                            {% endfor %}
                                            ({{ user_rating.rating_count }} отзывов)
                                        </div>
                                    </div>
                                    {% endif %}
                                    {% if user.bio %}<p>{{ user.bio }}</p>{% endif %}
                                    {% if user.skills %}<p><strong>Навыки:</strong> {{ user.skills }}</p>{% endif %}
                                    <p class="text-muted">Участник с {{ user.created_at[:10] }}</p>
                                    <div class="mt-3">
                                        <a href="/profile/edit" class="btn btn-primary me-2">Редактировать</a>
                                        <a href="/export/my_data" class="btn btn-info me-2">Экспорт данных</a>
                                        <form action="/profile/delete" method="POST" class="d-inline" onsubmit="return confirm('Удалить профиль? Это действие нельзя отменить!')">
                                            <button type="submit" class="btn btn-danger">Удалить профиль</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Достижения -->
                            {% if achievements %}
                            <div class="card mt-4">
                                <div class="card-header">
                                    <h5 class="card-title mb-0">🏆 Достижения</h5>
                                </div>
                                <div class="card-body">
                                    {% for achievement in achievements %}
                                    <div class="mb-2">
                                        <strong>{{ achievement.icon }} {{ achievement.name }}</strong>
                                        <br><small class="text-muted">{{ achievement.description }}</small>
                                    </div>
                                    {% endfor %}
                                </div>
                            </div>
                            {% endif %}
                            
                            <!-- Мои заявки -->
                            <div class="card mt-4">
                                <div class="card-header">
                                    <h5 class="card-title mb-0">📨 Мои заявки</h5>
                                </div>
                                <div class="card-body">
                                    {% if forms %}
                                        {% for form in forms %}
                                        <div class="mb-3 p-2 border rounded">
                                            <h6>{{ form.post_title }}</h6>
                                            <span class="badge {% if form.status == 'pending' %}bg-warning{% elif form.status == 'approved' %}bg-success{% else %}bg-danger{% endif %}">
                                                {% if form.status == 'pending' %}⏳ На рассмотрении
                                                {% elif form.status == 'approved' %}✅ Одобрена
                                                {% elif form.status == 'rejected' %}❌ Отклонена
                                                {% else %}{{ form.status }}{% endif %}
                                            </span>
                                            <br>
                                            <small class="text-muted">Подана: {{ form.created_at[:16] }}</small>
                                        </div>
                                        {% endfor %}
                                    {% else %}
                                        <p class="text-muted">У вас пока нет заявок</p>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-8">
                            {% if session.role in ['organizer', 'moderator'] %}
                            <h4>Мои посты ({{ posts|length }})</h4>
                            {% for post in posts %}
                            <div class="card mb-3">
                                <div class="card-body">
                                    <h5 class="card-title">{{ post.title }}</h5>
                                    <p class="card-text">{{ post.content[:200] }}{% if post.content|length > 200 %}...{% endif %}</p>
                                    <p class="card-text"><small class="text-muted">{{ post.created_at }}</small></p>
                                    <div class="btn-group">
                                        <a href="/post/{{ post.id }}" class="btn btn-outline-primary btn-sm">Подробнее</a>
                                        <form action="/post/{{ post.id }}/delete" method="POST" class="d-inline">
                                            <button type="submit" class="btn btn-outline-danger btn-sm" onclick="return confirm('Удалить пост?')">Удалить</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            {% else %}
                            <div class="alert alert-info">У вас пока нет постов</div>
                            {% endfor %}
                            {% endif %}
                            
                            <!-- Отзывы о пользователе -->
                            <div class="card mt-4">
                                <div class="card-header">
                                    <h5 class="card-title mb-0">📝 Отзывы обо мне</h5>
                                </div>
                                <div class="card-body">
                                    {% if reviews %}
                                        {% for review in reviews %}
                                        <div class="card mb-3">
                                            <div class="card-body">
                                                <div class="d-flex justify-content-between">
                                                    <h6 class="card-title">{{ review.reviewer_name or review.reviewer_username }}</h6>
                                                    <div class="text-warning">
                                                        {% for i in range(5) %}
                                                            {% if i < review.rating %}
                                                            ★
                                                            {% else %}
                                                            ☆
                                                            {% endif %}
                                                        {% endfor %}
                                                    </div>
                                                </div>
                                                {% if review.post_title %}
                                                <p class="text-muted">К мероприятию: {{ review.post_title }}</p>
                                                {% endif %}
                                                {% if review.comment %}
                                                <p class="card-text">{{ review.comment }}</p>
                                                {% endif %}
                                                <small class="text-muted">{{ review.created_at[:16] }}</small>
                                                <div class="mt-2">
                                                    <form action="/rating/{{ review.id }}/report" method="POST" class="d-inline">
                                                        <input type="hidden" name="reason" value="Необоснованный отзыв">
                                                        <button type="submit" class="btn btn-outline-danger btn-sm" onclick="return confirm('Пожаловаться на этот отзыв?')">Пожаловаться</button>
                                                    </form>
                                                </div>
                                            </div>
                                        </div>
                                        {% endfor %}
                                    {% else %}
                                        <p class="text-muted">Пока нет отзывов</p>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''',
        'edit_profile.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Редактирование профиля - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h2>Редактирование профиля</h2>
                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-danger">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                    <form method="POST">
                        <div class="mb-3"><label class="form-label">Полное имя</label><input type="text" class="form-control" name="full_name" value="{{ user.full_name or '' }}"></div>
                        <div class="mb-3"><label class="form-label">Email *</label><input type="email" class="form-control" name="email" value="{{ user.email }}" required></div>
                        <div class="mb-3"><label class="form-label">О себе</label><textarea class="form-control" name="bio" rows="3">{{ user.bio or '' }}</textarea></div>
                        <div class="mb-3"><label class="form-label">Навыки (через запятую)</label><input type="text" class="form-control" name="skills" value="{{ user.skills or '' }}"><div class="form-text">Например: организация мероприятий, работа с детьми, медицинская помощь</div></div>
                        
                        {% if user.role == 'organizer' %}
                        <div class="mb-3">
                            <label class="form-label">Название организации *</label>
                            <input type="text" class="form-control" name="organization_name" value="{{ user.organization_name or '' }}" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Описание организации</label>
                            <textarea class="form-control" name="organization_description" rows="3">{{ user.organization_description or '' }}</textarea>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Контакты организации *</label>
                            <input type="text" class="form-control" name="organization_contact" value="{{ user.organization_contact or '' }}" required>
                        </div>
                        {% endif %}
                        
                        <button type="submit" class="btn btn-primary">Сохранить</button>
                        <a href="/profile" class="btn btn-secondary">Отмена</a>
                    </form>
                </div>
            </body>
            </html>
        ''',
        'chats_list.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Мои чаты - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"><style>.chat-item:hover { background-color: #f8f9fa; }.unread-badge { margin-left: 10px; }</style></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a><a class="nav-link" href="/post/create">Создать пост</a><a class="nav-link" href="/users">Все пользователи</a><a class="nav-link" href="/profile">Профиль</a><a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2>Мои чаты</h2><a href="/users" class="btn btn-primary">Начать новый чат</a>
                    </div>
                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-info">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                    {% if chats %}
                    <div class="list-group">
                        {% for chat in chats %}
                        <a href="/chat/{{ chat.other_user_id }}" class="list-group-item list-group-item-action chat-item">
                            <div class="d-flex w-100 justify-content-between">
                                <h5 class="mb-1">{{ chat.other_full_name or chat.other_username }}{% if chat.unread_count > 0 %}<span class="badge bg-danger unread-badge">{{ chat.unread_count }}</span>{% endif %}</h5>
                                <small>{{ chat.last_message_time[:16] if chat.last_message_time }}</small>
                            </div>
                            {% if chat.last_message %}<p class="mb-1 text-muted">{{ chat.last_message[:100] }}{% if chat.last_message|length > 100 %}...{% endif %}</p>{% else %}<p class="mb-1 text-muted">Чат пуст</p>{% endif %}
                        </a>
                        {% endfor %}
                    </div>
                    {% else %}<div class="alert alert-info">У вас пока нет чатов. <a href="/users">Начните общение с кем-нибудь!</a></div>{% endif %}
                </div>
            </body>
            </html>
        ''',
        'chat.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Чат с {{ other_user.full_name or other_user.username }} - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"><style>.chat-container { height: 70vh; overflow-y: auto; border: 1px solid #ddd; border-radius: 10px; padding: 15px; }.message { margin-bottom: 15px; padding: 10px; border-radius: 10px; max-width: 70%; }.my-message { background-color: #007bff; color: white; margin-left: auto; }.other-message { background-color: #f8f9fa; margin-right: auto; }.message-time { font-size: 0.8em; opacity: 0.7; }#messageInput { border-radius: 20px; }</style></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/chats">Все чаты</a><a class="nav-link" href="/feed">Лента</a><a class="nav-link" href="/profile">Профиль</a><a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <div class="d-flex align-items-center mb-3">
                        <a href="/chats" class="btn btn-secondary btn-sm me-2">← Назад</a><h4 class="mb-0">Чат с {{ other_user.full_name or other_user.username }}</h4>
                    </div>
                    <div id="chatContainer" class="chat-container mb-3">
                        {% for message in messages %}
                        <div class="message {% if message.sender_id == session['user_id'] %}my-message{% else %}other-message{% endif %}">
                            <div class="message-text">{{ message.message_text }}</div>
                            <div class="message-time">{{ message.created_at[:16] }}{% if message.sender_id == session['user_id'] %} ✓{% if message.is_read %}✓{% endif %}{% endif %}</div>
                        </div>
                        {% endfor %}
                    </div>
                    <div class="input-group">
                        <input type="text" id="messageInput" class="form-control" placeholder="Введите сообщение..." maxlength="1000">
                        <button id="sendButton" class="btn btn-primary">Отправить</button>
                    </div>
                </div>
                <script>
                    const chatId = {{ chat.id }};const currentUserId = {{ session['user_id'] }};
                    function scrollToBottom() {const container = document.getElementById('chatContainer');container.scrollTop = container.scrollHeight;}
                    document.getElementById('sendButton').addEventListener('click', sendMessage);
                    document.getElementById('messageInput').addEventListener('keypress', function(e) {if (e.key === 'Enter') sendMessage();});
                    function sendMessage() {
                        const input = document.getElementById('messageInput');const messageText = input.value.trim();
                        if (!messageText) return;
                        fetch('/api/send_message', {method: 'POST',headers: {'Content-Type': 'application/json'},body: JSON.stringify({chat_id: chatId,message_text: messageText})})
                        .then(response => response.json()).then(data => {if (data.success) {input.value = '';loadMessages();}});
                    }
                    function loadMessages() {
                        fetch(`/api/get_messages/${chatId}`).then(response => response.json()).then(data => {if (data.success) {updateChat(data.messages);}});
                    }
                    function updateChat(messages) {
                        const container = document.getElementById('chatContainer');container.innerHTML = '';
                        messages.forEach(msg => {
                            const messageDiv = document.createElement('div');messageDiv.className = `message ${msg.is_my_message ? 'my-message' : 'other-message'}`;
                            messageDiv.innerHTML = `<div class="message-text">${msg.message_text}</div><div class="message-time">${msg.created_at.substring(0, 16)}${msg.is_my_message ? '✓✓' : ''}</div>`;
                            container.appendChild(messageDiv);
                        });scrollToBottom();
                    }
                    setInterval(loadMessages, 3000);scrollToBottom();
                </script>
            </body>
            </html>
        ''',
        'users_list.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Все пользователи - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/chats">Мои чаты</a><a class="nav-link" href="/feed">Лента</a><a class="nav-link" href="/profile">Профиль</a><a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2>Все пользователи</h2>
                        <div>
                            <form method="GET" class="d-inline">
                                <div class="input-group">
                                    <input type="text" class="form-control" name="q" placeholder="Поиск пользователей..." value="{{ search_query }}">
                                    <button type="submit" class="btn btn-primary">Найти</button>
                                </div>
                            </form>
                            <a href="/chats" class="btn btn-secondary ms-2">← Назад к чатам</a>
                        </div>
                    </div>
                    <div class="row">
                        {% for user in users %}
                        <div class="col-md-6 mb-3">
                            <div class="card">
                                <div class="card-body">
                                    <h5 class="card-title">{{ user.full_name or user.username }}</h5>
                                    <p class="card-text">
                                        <small class="text-muted">@{{ user.username }}</small>
                                        <span class="badge {% if user.role == 'volunteer' %}bg-success{% else %}bg-primary{% endif %} ms-2">
                                            {% if user.role == 'volunteer' %}Волонтер{% else %}Организатор{% endif %}
                                        </span>
                                        {% if user.organization_name %}
                                        <br><small class="text-muted">Организация: {{ user.organization_name }}</small>
                                        {% endif %}
                                    </p>
                                    {% if user.rating and user.rating.avg_rating %}
                                    <div class="text-warning mb-2">
                                        {% for i in range(5) %}
                                            {% if i < user.rating.avg_rating|round %}
                                            ★
                                            {% else %}
                                            ☆
                                            {% endif %}
                                        {% endfor %}
                                        ({{ user.rating.rating_count }} отзывов)
                                    </div>
                                    {% endif %}
                                    {% if user.bio %}<p class="card-text">{{ user.bio }}</p>{% endif %}
                                    {% if user.skills %}<p class="card-text"><strong>Навыки:</strong> {{ user.skills }}</p>{% endif %}
                                    <div class="btn-group">
                                        <a href="/chat/{{ user.id }}" class="btn btn-primary btn-sm">Написать сообщение</a>
                                        <button type="button" class="btn btn-outline-success btn-sm" data-bs-toggle="modal" data-bs-target="#rateModal{{ user.id }}">Оценить</button>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Модальное окно для оценки -->
                            <div class="modal fade" id="rateModal{{ user.id }}" tabindex="-1">
                                <div class="modal-dialog">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title">Оценить {{ user.full_name or user.username }}</h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                        </div>
                                        <form action="/user/{{ user.id }}/rate" method="POST">
                                            <div class="modal-body">
                                                <div class="mb-3">
                                                    <label class="form-label">Оценка (1-5)</label>
                                                    <select class="form-select" name="rating" required>
                                                        <option value="5">5 - Отлично</option>
                                                        <option value="4">4 - Хорошо</option>
                                                        <option value="3">3 - Удовлетворительно</option>
                                                        <option value="2">2 - Плохо</option>
                                                        <option value="1">1 - Очень плохо</option>
                                                    </select>
                                                </div>
                                                <div class="mb-3">
                                                    <label class="form-label">Комментарий (необязательно)</label>
                                                    <textarea class="form-control" name="comment" rows="3"></textarea>
                                                </div>
                                            </div>
                                            <div class="modal-footer">
                                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Отмена</button>
                                                <button type="submit" class="btn btn-primary">Отправить отзыв</button>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        ''',
        'notifications.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Уведомления - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            <a class="nav-link" href="/chats">Мои чаты</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h2>Уведомления</h2>
                    {% if notifications %}
                    <div class="list-group">
                        {% for notification in notifications %}
                        <div class="list-group-item {% if not notification.is_read %}list-group-item-primary{% endif %}">
                            <div class="d-flex w-100 justify-content-between">
                                <h5 class="mb-1">{{ notification.title }}</h5>
                                <small>{{ notification.created_at[:16] }}</small>
                            </div>
                            <p class="mb-1">{{ notification.message }}</p>
                        </div>
                        {% endfor %}
                    </div>
                    {% else %}
                    <div class="alert alert-info">У вас нет уведомлений</div>
                    {% endif %}
                </div>
            </body>
            </html>
        ''',
        'search.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Поиск - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            {% if session.role in ['organizer', 'moderator'] %}
                            <a class="nav-link" href="/post/create">Создать пост</a>
                            {% endif %}
                            <a class="nav-link" href="/chats">Мои чаты</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h2>Поиск мероприятий</h2>
                    
                    <form method="GET" class="mb-4">
                        <div class="row g-3">
                            <div class="col-md-4">
                                <input type="text" class="form-control" name="q" placeholder="Поиск..." value="{{ search_query }}">
                            </div>
                            <div class="col-md-3">
                                <select class="form-select" name="category">
                                    <option value="">Все категории</option>
                                    {% for category in categories %}
                                    <option value="{{ category.name }}" {% if request.args.get('category') == category.name %}selected{% endif %}>{{ category.name }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-md-3">
                                <input type="text" class="form-control" name="location" placeholder="Местоположение" value="{{ request.args.get('location', '') }}">
                            </div>
                            <div class="col-md-2">
                                <button type="submit" class="btn btn-primary w-100">Найти</button>
                            </div>
                        </div>
                    </form>
                    
                    {% if posts %}
                    <h4>Найдено мероприятий: {{ posts|length }}</h4>
                    {% for post in posts %}
                    <div class="card mb-3">
                        <div class="card-body">
                            <h5 class="card-title">{{ post.title }}</h5>
                            <h6 class="card-subtitle mb-2 text-muted">Автор: {{ post.full_name or post.username }}</h6>
                            <p class="card-text">{{ post.content[:200] }}{% if post.content|length > 200 %}...{% endif %}</p>
                            {% if post.location %}<p class="card-text"><small>Место: {{ post.location }}</small></p>{% endif %}
                            <div class="btn-group">
                                <a href="/post/{{ post.id }}" class="btn btn-outline-primary btn-sm">Подробнее</a>
                                <a href="/chat/{{ post.user_id }}" class="btn btn-outline-success btn-sm">Написать автору</a>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                    {% elif request.args %}
                    <div class="alert alert-info">По вашему запросу ничего не найдено</div>
                    {% endif %}
                </div>
            </body>
            </html>
        ''',
        'calendar.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Календарь - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/fullcalendar@5.10.1/main.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            {% if session.role in ['organizer', 'moderator'] %}
                            <a class="nav-link" href="/post/create">Создать пост</a>
                            {% endif %}
                            <a class="nav-link" href="/chats">Мои чаты</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h2>Календарь мероприятий</h2>
                    <div id="calendar"></div>
                </div>
                
                <script src="https://cdn.jsdelivr.net/npm/fullcalendar@5.10.1/main.min.js"></script>
                <script>
                    document.addEventListener('DOMContentLoaded', function() {
                        var calendarEl = document.getElementById('calendar');
                        var calendar = new FullCalendar.Calendar(calendarEl, {
                            initialView: 'dayGridMonth',
                            events: '/api/events',
                            eventClick: function(info) {
                                info.jsEvent.preventDefault();
                                if (info.event.url) {
                                    window.open(info.event.url, '_self');
                                }
                            }
                        });
                        calendar.render();
                    });
                </script>
            </body>
            </html>
        ''',
        'stats.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Статистика - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            <a class="nav-link" href="/moderator">Панель модератора</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h2>📊 Статистика платформы</h2>
                    
                    <div class="row mt-4">
                        <div class="col-md-3 mb-3">
                            <div class="card text-white bg-primary">
                                <div class="card-body text-center">
                                    <h3>{{ total_posts }}</h3>
                                    <p>Всего мероприятий</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 mb-3">
                            <div class="card text-white bg-success">
                                <div class="card-body text-center">
                                    <h3>{{ total_users }}</h3>
                                    <p>Пользователей</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 mb-3">
                            <div class="card text-white bg-warning">
                                <div class="card-body text-center">
                                    <h3>{{ total_volunteers }}</h3>
                                    <p>Активных волонтеров</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 mb-3">
                            <div class="card text-white bg-info">
                                <div class="card-body text-center">
                                    <h3>{{ total_organizers }}</h3>
                                    <p>Организаторов</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="row mt-4">
                        <div class="col-md-4 mb-3">
                            <div class="card text-white bg-secondary">
                                <div class="card-body text-center">
                                    <h3>{{ total_moderators }}</h3>
                                    <p>Модераторов</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4 mb-3">
                            <div class="card text-white bg-dark">
                                <div class="card-body text-center">
                                    <h3>{{ active_posts_last_week }}</h3>
                                    <p>Постов за неделю</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4 mb-3">
                            <div class="card text-white bg-danger">
                                <div class="card-body text-center">
                                    <h3>{{ active_users_last_week }}</h3>
                                    <p>Активных пользователей</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row mt-4">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h5>📈 Статистика по категориям</h5>
                                </div>
                                <div class="card-body">
                                    {% if categories_stats %}
                                    <ul class="list-group">
                                        {% for stat in categories_stats %}
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            {{ stat.name }}
                                            <span class="badge bg-primary rounded-pill">{{ stat.post_count }}</span>
                                        </li>
                                        {% endfor %}
                                    </ul>
                                    {% else %}
                                    <p class="text-muted">Нет данных</p>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h5>📨 Статистика заявок</h5>
                                </div>
                                <div class="card-body">
                                    <ul class="list-group">
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            Ожидают рассмотрения
                                            <span class="badge bg-warning rounded-pill">{{ pending_forms }}</span>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            Одобренные
                                            <span class="badge bg-success rounded-pill">{{ approved_forms }}</span>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            Отклоненные
                                            <span class="badge bg-danger rounded-pill">{{ rejected_forms }}</span>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-4">
                        <div class="card">
                            <div class="card-header">
                                <h5>🔧 Сервисные функции</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <form action="/admin/backup" method="POST">
                                            <button type="submit" class="btn btn-outline-primary w-100 mb-2">
                                                💾 Создать резервную копию
                                            </button>
                                        </form>
                                    </div>
                                    <div class="col-md-6">
                                        <a href="/admin/backups" class="btn btn-outline-info w-100 mb-2">
                                            📂 Список бэкапов
                                        </a>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-12">
                                        <a href="/health" class="btn btn-outline-success w-100 mb-2" target="_blank">
                                            🩺 Проверить работоспособность
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''',
        'backups.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Резервные копии - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/moderator">Панель модератора</a>
                            <a class="nav-link" href="/stats">Статистика</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2>📂 Резервные копии базы данных</h2>
                        <div>
                            <form action="/admin/backup" method="POST" class="d-inline">
                                <button type="submit" class="btn btn-primary">Создать новую копию</button>
                            </form>
                            <a href="/stats" class="btn btn-secondary ms-2">← Назад к статистике</a>
                        </div>
                    </div>

                    {% with messages = get_flashed_messages() %}
                        {% if messages %}
                            {% for message in messages %}
                            <div class="alert alert-success">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}

                    {% if backups %}
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Имя файла</th>
                                    <th>Размер</th>
                                    <th>Дата создания</th>
                                    <th>Действия</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for backup in backups %}
                                <tr>
                                    <td>{{ backup.name }}</td>
                                    <td>{{ "%.2f"|format(backup.size / 1024 / 1024) }} MB</td>
                                    <td>{{ backup.created.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-info" onclick="alert('Файл: {{ backup.name }}\\nРазмер: {{ "%.2f"|format(backup.size / 1024 / 1024) }} MB\\nСоздан: {{ backup.created.strftime('%Y-%m-%d %H:%M:%S') }}')">
                                            Инфо
                                        </button>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    <div class="alert alert-info">
                        <strong>Информация:</strong> Хранятся только последние 10 резервных копий. Старые копии автоматически удаляются.
                    </div>
                    {% else %}
                    <div class="alert alert-warning">
                        Резервные копии не найдены. Создайте первую копию.
                    </div>
                    {% endif %}
                </div>
            </body>
            </html>
        ''',
        'moderator_panel.html': '''
            <!DOCTYPE html>
            <html>
            <head><title>Панель модератора - Волонтерская Сеть</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            <a class="nav-link" href="/stats">Статистика</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h2>🔧 Панель модератора</h2>
                    
                    <ul class="nav nav-tabs" id="moderatorTabs" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" id="reports-tab" data-bs-toggle="tab" data-bs-target="#reports" type="button" role="tab">Жалобы ({{ reports|length }})</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="posts-tab" data-bs-toggle="tab" data-bs-target="#posts" type="button" role="tab">Все посты ({{ posts|length }})</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="ratings-tab" data-bs-toggle="tab" data-bs-target="#ratings" type="button" role="tab">Все отзывы ({{ ratings|length }})</button>
                        </li>
                    </ul>
                    
                    <div class="tab-content mt-4" id="moderatorTabsContent">
                        <!-- Вкладка жалоб -->
                        <div class="tab-pane fade show active" id="reports" role="tabpanel">
                            {% if reports %}
                            {% for report in reports %}
                            <div class="card mb-3">
                                <div class="card-body">
                                    <h5 class="card-title">
                                        Жалоба от {{ report.reporter_username }}
                                        <span class="badge bg-warning">На рассмотрении</span>
                                    </h5>
                                    <p><strong>Тип:</strong> 
                                        {% if report.reported_rating_id %}Отзыв{% else %}Пост{% endif %}
                                    </p>
                                    <p><strong>Причина:</strong> {{ report.reason }}</p>
                                    {% if report.reported_rating_id %}
                                    <p><strong>Отзыв:</strong> {{ report.rating_comment }}</p>
                                    <p><strong>На пользователя:</strong> {{ report.reported_username }}</p>
                                    {% elif report.reported_post_id %}
                                    <p><strong>Пост:</strong> {{ report.post_title }}</p>
                                    {% endif %}
                                    <p><small class="text-muted">Подана: {{ report.created_at[:16] }}</small></p>
                                    
                                    <div class="btn-group">
                                        {% if report.reported_rating_id %}
                                        <form action="/moderator/report/{{ report.id }}/resolve" method="POST" class="d-inline">
                                            <button type="submit" name="action" value="delete_rating" class="btn btn-danger btn-sm" onclick="return confirm('Удалить отзыв?')">Удалить отзыв</button>
                                            <button type="submit" name="action" value="keep_rating" class="btn btn-success btn-sm" onclick="return confirm('Оставить отзыв?')">Оставить отзыв</button>
                                        </form>
                                        {% elif report.reported_post_id %}
                                        <form action="/moderator/report/{{ report.id }}/resolve" method="POST" class="d-inline">
                                            <button type="submit" name="action" value="delete_post" class="btn btn-danger btn-sm" onclick="return confirm('Удалить пост?')">Удалить пост</button>
                                        </form>
                                        {% endif %}
                                    </div>
                                </div>
                            </div>
                            {% endfor %}
                            {% else %}
                            <div class="alert alert-info">Нет активных жалоб</div>
                            {% endif %}
                        </div>
                        
                        <!-- Вкладка постов -->
                        <div class="tab-pane fade" id="posts" role="tabpanel">
                            {% if posts %}
                            {% for post in posts %}
                            <div class="card mb-3">
                                <div class="card-body">
                                    <h5 class="card-title">{{ post.title }}</h5>
                                    <h6 class="card-subtitle mb-2 text-muted">Автор: {{ post.full_name or post.username }}</h6>
                                    <p class="card-text">{{ post.content[:200] }}{% if post.content|length > 200 %}...{% endif %}</p>
                                    <p class="card-text"><small class="text-muted">Опубликовано: {{ post.created_at }}</small></p>
                                    
                                    <div class="btn-group">
                                        <a href="/post/{{ post.id }}" class="btn btn-outline-primary btn-sm">Просмотреть</a>
                                        <form action="/moderator/post/{{ post.id }}/delete" method="POST" class="d-inline">
                                            <button type="submit" class="btn btn-outline-danger btn-sm" onclick="return confirm('Удалить пост?')">Удалить</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            {% endfor %}
                            {% else %}
                            <div class="alert alert-info">Нет постов</div>
                            {% endif %}
                        </div>
                        
                        <!-- Вкладка отзывов -->
                        <div class="tab-pane fade" id="ratings" role="tabpanel">
                            {% if ratings %}
                            {% for rating in ratings %}
                            <div class="card mb-3">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between">
                                        <h6 class="card-title">{{ rating.from_username }} → {{ rating.to_username }}</h6>
                                        <div class="text-warning">
                                            {% for i in range(5) %}
                                                {% if i < rating.rating %}
                                                ★
                                                {% else %}
                                                ☆
                                                {% endif %}
                                            {% endfor %}
                                        </div>
                                    </div>
                                    {% if rating.post_title %}
                                    <p class="text-muted">К мероприятию: {{ rating.post_title }}</p>
                                    {% endif %}
                                    {% if rating.comment %}
                                    <p class="card-text">{{ rating.comment }}</p>
                                    {% endif %}
                                    <p class="card-text"><small class="text-muted">{{ rating.created_at[:16] }}</small></p>
                                    
                                    <div class="btn-group">
                                        <form action="/moderator/rating/{{ rating.id }}/delete" method="POST" class="d-inline">
                                            <button type="submit" class="btn btn-outline-danger btn-sm" onclick="return confirm('Удалить отзыв?')">Удалить отзыв</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            {% endfor %}
                            {% else %}
                            <div class="alert alert-info">Нет отзывов</div>
                            {% endif %}
                        </div>
                    </div>
                </div>
                
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        '''
    }
    
    template = templates.get(template_name)
    if template:
        return render_template_string(template, **context)
    return f"Template {template_name} not found", 404

if __name__ == '__main__':
    with app.app_context():
        init_db()
        upgrade_db()
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
