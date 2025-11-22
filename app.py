import os
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['DATABASE'] = '/app/data/volunteer_network.db'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        os.makedirs('/app/data', exist_ok=True)
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

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
        db.commit()

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
        
        db = get_db()
        error = None
        
        if not username or not password or not email:
            error = 'Все поля обязательны для заполнения'
        
        if error is None:
            try:
                db.execute(
                    "INSERT INTO users (username, email, password, full_name) VALUES (?, ?, ?, ?)",
                    (username, email, generate_password_hash(password), full_name)
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
    user_posts = db.execute('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],)).fetchall()
    
    # Получаем анкеты пользователя
    user_forms = db.execute('''
        SELECT vf.*, p.title as post_title, u.username as author_username 
        FROM volunteer_forms vf 
        JOIN posts p ON vf.post_id = p.id 
        JOIN users u ON p.user_id = u.id 
        WHERE vf.user_id = ? 
        ORDER BY vf.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    return render_template('profile.html', user=user, posts=user_posts, forms=user_forms)

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
        
        try:
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
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post_type = request.form['post_type']
        location = request.form.get('location', '')
        event_date = request.form.get('event_date', '')
        needs_volunteers = 'needs_volunteers' in request.form
        
        if not title or not content:
            flash('Заголовок и содержание обязательны')
            return redirect(url_for('create_post'))
        
        db = get_db()
        db.execute(
            'INSERT INTO posts (user_id, title, content, post_type, location, event_date, needs_volunteers) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (session['user_id'], title, content, post_type, location, event_date, needs_volunteers)
        )
        db.commit()
        flash('Пост успешно создан!')
        return redirect(url_for('feed'))
    
    return render_template('create_post.html')

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
    
    # Проверяем, подавал ли пользователь уже анкету на этот пост
    existing_form = db.execute(
        'SELECT * FROM volunteer_forms WHERE post_id = ? AND user_id = ?',
        (post_id, session['user_id'])
    ).fetchone()
    
    # Для автора поста - показываем список анкет
    volunteer_forms = None
    if post['user_id'] == session['user_id']:
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
                         volunteer_forms=volunteer_forms)

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
    
    # Проверяем, что текущий пользователь - автор поста
    if form['post_author_id'] != session['user_id']:
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
    db.commit()
    
    flash('Статус анкеты обновлен')
    return redirect(url_for('post_detail', post_id=form['post_id']))

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    db = get_db()
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
    db = get_db()
    users = db.execute('''
        SELECT id, username, full_name, bio, skills 
        FROM users 
        WHERE id != ? 
        ORDER BY username
    ''', (session['user_id'],)).fetchall()
    return render_template('users_list.html', users=users)

def render_template(template_name, **context):
    templates = {
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
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h2 class="card-title text-center">Регистрация</h2>
                                    {% with messages = get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert alert-danger">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}
                                    <form method="POST">
                                        <div class="mb-3"><label class="form-label">Имя пользователя *</label><input type="text" class="form-control" name="username" required></div>
                                        <div class="mb-3"><label class="form-label">Email *</label><input type="email" class="form-control" name="email" required></div>
                                        <div class="mb-3"><label class="form-label">Полное имя</label><input type="text" class="form-control" name="full_name"></div>
                                        <div class="mb-3"><label class="form-label">Пароль *</label><input type="password" class="form-control" name="password" required></div>
                                        <button type="submit" class="btn btn-primary w-100">Зарегистрироваться</button>
                                    </form>
                                    <div class="text-center mt-3"><a href="/login">Уже есть аккаунт? Войдите</a></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
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
                            <a class="nav-link" href="/post/create">Создать пост</a>
                            <a class="nav-link" href="/chats">Мои чаты</a>
                            <a class="nav-link" href="/users">Все пользователи</a>
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
                                {% if post.user_id == session['user_id'] %}
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
                            <p class="card-text"><small class="text-muted">Опубликовано: {{ post.created_at }}</small></p>
                        </div>
                    </div>

                    {% if post.needs_volunteers %}
                        {% if post.user_id != session['user_id'] %}
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
                            <!-- Для автора поста - показываем список заявок -->
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
                                                        <form action="/volunteer_form/{{ form.id }}/update_status" method="POST" class="d-inline">
                                                            <button type="submit" name="status" value="approved" class="btn btn-success btn-sm">Одобрить</button>
                                                            <button type="submit" name="status" value="rejected" class="btn btn-danger btn-sm">Отклонить</button>
                                                        </form>
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
                                                   value="{{ session.get('user_full_name', '') }}">
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
                            <a class="nav-link" href="/post/create">Создать пост</a>
                            <a class="nav-link" href="/chats">Мои чаты</a>
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
                                    {% if user.bio %}<p>{{ user.bio }}</p>{% endif %}
                                    {% if user.skills %}<p><strong>Навыки:</strong> {{ user.skills }}</p>{% endif %}
                                    <p class="text-muted">Участник с {{ user.created_at[:10] }}</p>
                                    <div class="mt-3">
                                        <a href="/profile/edit" class="btn btn-primary me-2">Редактировать</a>
                                        <form action="/profile/delete" method="POST" class="d-inline" onsubmit="return confirm('Удалить профиль? Это действие нельзя отменить!')">
                                            <button type="submit" class="btn btn-danger">Удалить профиль</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            
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
                        <h2>Все пользователи</h2><a href="/chats" class="btn btn-secondary">← Назад к чатам</a>
                    </div>
                    <div class="row">
                        {% for user in users %}
                        <div class="col-md-6 mb-3">
                            <div class="card">
                                <div class="card-body">
                                    <h5 class="card-title">{{ user.full_name or user.username }}</h5>
                                    <p class="card-text"><small class="text-muted">@{{ user.username }}</small>{% if user.bio %}<br>{{ user.bio }}{% endif %}{% if user.skills %}<br><strong>Навыки:</strong> {{ user.skills }}{% endif %}</p>
                                    <a href="/chat/{{ user.id }}" class="btn btn-primary btn-sm">Написать сообщение</a>
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </body>
            </html>
        '''
    }
    
    template = templates.get(template_name)
    if template:
        from flask import render_template_string
        return render_template_string(template, **context)
    return f"Template {template_name} not found", 404

if __name__ == '__main__':
    with app.app_context():
        init_db()
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
