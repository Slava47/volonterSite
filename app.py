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

def upgrade_db():
    """Добавляет недостающие колонки в существующую БД"""
    with app.app_context():
        db = get_db()
        
        # Проверяем и добавляем колонку needs_volunteers если её нет
        try:
            db.execute('SELECT needs_volunteers FROM posts LIMIT 1')
            print("✅ Колонка needs_volunteers уже существует")
        except sqlite3.OperationalError:
            print("🔄 Добавляем колонку needs_volunteers в таблицу posts...")
            db.execute('ALTER TABLE posts ADD COLUMN needs_volunteers BOOLEAN DEFAULT FALSE')
            db.commit()
            print("✅ Колонка needs_volunteers добавлена")
        
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
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>VolunteerHub - Социальная сеть для волонтеров</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                <style>
                    :root {
                        --primary: #2E8B57;
                        --primary-dark: #1f6b4b;
                        --secondary: #6c757d;
                        --success: #28a745;
                        --light: #f8f9fa;
                        --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                    }
                    
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                    }
                    
                    .hero-card {
                        background: rgba(255, 255, 255, 0.95);
                        backdrop-filter: blur(10px);
                        border-radius: 20px;
                        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                    
                    .logo {
                        font-size: 3.5rem;
                        background: var(--gradient);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        margin-bottom: 1rem;
                    }
                    
                    .btn-primary {
                        background: var(--gradient);
                        border: none;
                        padding: 12px 30px;
                        border-radius: 50px;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    }
                    
                    .btn-primary:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                    }
                    
                    .btn-outline-primary {
                        border: 2px solid var(--primary);
                        color: var(--primary);
                        padding: 12px 30px;
                        border-radius: 50px;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    }
                    
                    .btn-outline-primary:hover {
                        background: var(--primary);
                        color: white;
                        transform: translateY(-2px);
                    }
                    
                    .feature-list {
                        list-style: none;
                        padding: 0;
                    }
                    
                    .feature-list li {
                        padding: 8px 0;
                        font-size: 1.1rem;
                    }
                    
                    .feature-list li i {
                        color: var(--primary);
                        margin-right: 10px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="row justify-content-center">
                        <div class="col-lg-8">
                            <div class="hero-card p-5">
                                <div class="text-center">
                                    <div class="logo">
                                        <i class="fas fa-hands-helping"></i>
                                    </div>
                                    <h1 class="display-4 fw-bold text-dark mb-3">VolunteerHub</h1>
                                    <p class="lead text-muted mb-4">
                                        Объединяем сердца для добрых дел. Находите волонтеров, помогайте нуждающимся и меняйте мир вместе с нами.
                                    </p>
                                    
                                    <div class="row mb-5">
                                        <div class="col-md-6">
                                            <ul class="feature-list text-start">
                                                <li><i class="fas fa-check-circle"></i> Находите волонтеров</li>
                                                <li><i class="fas fa-check-circle"></i> Помогайте сообществу</li>
                                                <li><i class="fas fa-check-circle"></i> Организуйте мероприятия</li>
                                            </ul>
                                        </div>
                                        <div class="col-md-6">
                                            <ul class="feature-list text-start">
                                                <li><i class="fas fa-check-circle"></i> Общайтесь в реальном времени</li>
                                                <li><i class="fas fa-check-circle"></i> Создавайте анкеты</li>
                                                <li><i class="fas fa-check-circle"></i> Отслеживайте активность</li>
                                            </ul>
                                        </div>
                                    </div>
                                    
                                    <div class="d-grid gap-3 d-md-flex justify-content-center">
                                        <a href="/login" class="btn btn-primary me-md-3">
                                            <i class="fas fa-sign-in-alt me-2"></i>Войти в систему
                                        </a>
                                        <a href="/register" class="btn btn-outline-primary">
                                            <i class="fas fa-user-plus me-2"></i>Создать аккаунт
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        ''',

        'register.html': '''
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Регистрация - VolunteerHub</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                <style>
                    :root {
                        --primary: #2E8B57;
                        --primary-dark: #1f6b4b;
                        --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                    }
                    
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                    }
                    
                    .auth-card {
                        background: rgba(255, 255, 255, 0.95);
                        backdrop-filter: blur(10px);
                        border-radius: 20px;
                        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                    
                    .logo-small {
                        font-size: 2.5rem;
                        background: var(--gradient);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                    }
                    
                    .btn-primary {
                        background: var(--gradient);
                        border: none;
                        padding: 12px;
                        border-radius: 10px;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    }
                    
                    .btn-primary:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                    }
                    
                    .form-control {
                        border-radius: 10px;
                        padding: 12px 15px;
                        border: 2px solid #e9ecef;
                        transition: all 0.3s ease;
                    }
                    
                    .form-control:focus {
                        border-color: var(--primary);
                        box-shadow: 0 0 0 0.2rem rgba(46, 139, 87, 0.25);
                    }
                    
                    .auth-link {
                        color: var(--primary);
                        text-decoration: none;
                        font-weight: 500;
                    }
                    
                    .auth-link:hover {
                        color: var(--primary-dark);
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="row justify-content-center">
                        <div class="col-md-6 col-lg-5">
                            <div class="auth-card p-4 p-md-5">
                                <div class="text-center mb-4">
                                    <div class="logo-small">
                                        <i class="fas fa-hands-helping"></i>
                                    </div>
                                    <h2 class="fw-bold text-dark mt-2">Добро пожаловать!</h2>
                                    <p class="text-muted">Создайте аккаунт чтобы присоединиться к сообществу</p>
                                </div>
                                
                                {% with messages = get_flashed_messages() %}
                                    {% if messages %}
                                        {% for message in messages %}
                                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                            <i class="fas fa-exclamation-circle me-2"></i>{{ message }}
                                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                        </div>
                                        {% endfor %}
                                    {% endif %}
                                {% endwith %}
                                
                                <form method="POST">
                                    <div class="mb-3">
                                        <label class="form-label fw-semibold">Имя пользователя *</label>
                                        <div class="input-group">
                                            <span class="input-group-text bg-light border-end-0">
                                                <i class="fas fa-user text-muted"></i>
                                            </span>
                                            <input type="text" class="form-control border-start-0" name="username" required placeholder="Придумайте имя пользователя">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label fw-semibold">Email *</label>
                                        <div class="input-group">
                                            <span class="input-group-text bg-light border-end-0">
                                                <i class="fas fa-envelope text-muted"></i>
                                            </span>
                                            <input type="email" class="form-control border-start-0" name="email" required placeholder="your@email.com">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label fw-semibold">Полное имя</label>
                                        <div class="input-group">
                                            <span class="input-group-text bg-light border-end-0">
                                                <i class="fas fa-id-card text-muted"></i>
                                            </span>
                                            <input type="text" class="form-control border-start-0" name="full_name" placeholder="Ваше полное имя">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-4">
                                        <label class="form-label fw-semibold">Пароль *</label>
                                        <div class="input-group">
                                            <span class="input-group-text bg-light border-end-0">
                                                <i class="fas fa-lock text-muted"></i>
                                            </span>
                                            <input type="password" class="form-control border-start-0" name="password" required placeholder="Создайте надежный пароль">
                                        </div>
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary w-100 py-3 fw-semibold">
                                        <i class="fas fa-user-plus me-2"></i>Создать аккаунт
                                    </button>
                                </form>
                                
                                <div class="text-center mt-4">
                                    <p class="text-muted">Уже есть аккаунт? 
                                        <a href="/login" class="auth-link">Войдите здесь</a>
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        ''',

        'login.html': '''
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Вход - VolunteerHub</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                <style>
                    :root {
                        --primary: #2E8B57;
                        --primary-dark: #1f6b4b;
                        --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                    }
                    
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                    }
                    
                    .auth-card {
                        background: rgba(255, 255, 255, 0.95);
                        backdrop-filter: blur(10px);
                        border-radius: 20px;
                        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                    
                    .logo-small {
                        font-size: 2.5rem;
                        background: var(--gradient);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                    }
                    
                    .btn-primary {
                        background: var(--gradient);
                        border: none;
                        padding: 12px;
                        border-radius: 10px;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    }
                    
                    .btn-primary:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                    }
                    
                    .form-control {
                        border-radius: 10px;
                        padding: 12px 15px;
                        border: 2px solid #e9ecef;
                        transition: all 0.3s ease;
                    }
                    
                    .form-control:focus {
                        border-color: var(--primary);
                        box-shadow: 0 0 0 0.2rem rgba(46, 139, 87, 0.25);
                    }
                    
                    .auth-link {
                        color: var(--primary);
                        text-decoration: none;
                        font-weight: 500;
                    }
                    
                    .auth-link:hover {
                        color: var(--primary-dark);
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="row justify-content-center">
                        <div class="col-md-6 col-lg-5">
                            <div class="auth-card p-4 p-md-5">
                                <div class="text-center mb-4">
                                    <div class="logo-small">
                                        <i class="fas fa-hands-helping"></i>
                                    </div>
                                    <h2 class="fw-bold text-dark mt-2">С возвращением!</h2>
                                    <p class="text-muted">Войдите в свой аккаунт</p>
                                </div>
                                
                                {% with messages = get_flashed_messages() %}
                                    {% if messages %}
                                        {% for message in messages %}
                                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                            <i class="fas fa-exclamation-circle me-2"></i>{{ message }}
                                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                        </div>
                                        {% endfor %}
                                    {% endif %}
                                {% endwith %}
                                
                                <form method="POST">
                                    <div class="mb-3">
                                        <label class="form-label fw-semibold">Имя пользователя</label>
                                        <div class="input-group">
                                            <span class="input-group-text bg-light border-end-0">
                                                <i class="fas fa-user text-muted"></i>
                                            </span>
                                            <input type="text" class="form-control border-start-0" name="username" required placeholder="Введите имя пользователя">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-4">
                                        <label class="form-label fw-semibold">Пароль</label>
                                        <div class="input-group">
                                            <span class="input-group-text bg-light border-end-0">
                                                <i class="fas fa-lock text-muted"></i>
                                            </span>
                                            <input type="password" class="form-control border-start-0" name="password" required placeholder="Введите ваш пароль">
                                        </div>
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary w-100 py-3 fw-semibold">
                                        <i class="fas fa-sign-in-alt me-2"></i>Войти в систему
                                    </button>
                                </form>
                                
                                <div class="text-center mt-4">
                                    <p class="text-muted">Нет аккаунта? 
                                        <a href="/register" class="auth-link">Зарегистрируйтесь здесь</a>
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        ''',

        'feed.html': '''
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Лента мероприятий - VolunteerHub</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                <style>
                    :root {
                        --primary: #2E8B57;
                        --primary-dark: #1f6b4b;
                        --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                    }
                    
                    .navbar-brand {
                        font-weight: 700;
                        font-size: 1.5rem;
                    }
                    
                    .nav-gradient {
                        background: var(--gradient) !important;
                    }
                    
                    .btn-primary {
                        background: var(--gradient);
                        border: none;
                        border-radius: 10px;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    }
                    
                    .btn-primary:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                    }
                    
                    .post-card {
                        border: none;
                        border-radius: 15px;
                        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
                        transition: all 0.3s ease;
                        margin-bottom: 1.5rem;
                    }
                    
                    .post-card:hover {
                        transform: translateY(-5px);
                        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
                    }
                    
                    .badge-volunteer {
                        background: linear-gradient(135deg, #28a745, #20c997);
                    }
                    
                    .badge-help {
                        background: linear-gradient(135deg, #ffc107, #fd7e14);
                    }
                    
                    .badge-event {
                        background: linear-gradient(135deg, #17a2b8, #6f42c1);
                    }
                    
                    .user-avatar {
                        width: 40px;
                        height: 40px;
                        border-radius: 50%;
                        background: var(--gradient);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        color: white;
                        font-weight: bold;
                        font-size: 1.1rem;
                    }
                    
                    .action-btn {
                        border-radius: 20px;
                        padding: 6px 15px;
                        font-size: 0.85rem;
                        margin: 2px;
                    }
                </style>
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark nav-gradient shadow-sm">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">
                            <i class="fas fa-hands-helping me-2"></i>VolunteerHub
                        </a>
                        
                        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                            <span class="navbar-toggler-icon"></span>
                        </button>
                        
                        <div class="collapse navbar-collapse" id="navbarNav">
                            <ul class="navbar-nav ms-auto">
                                <li class="nav-item">
                                    <a class="nav-link" href="/post/create">
                                        <i class="fas fa-plus-circle me-1"></i>Создать пост
                                    </a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/chats">
                                        <i class="fas fa-comments me-1"></i>Чаты
                                    </a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/users">
                                        <i class="fas fa-users me-1"></i>Пользователи
                                    </a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/profile">
                                        <i class="fas fa-user me-1"></i>Профиль
                                    </a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/logout">
                                        <i class="fas fa-sign-out-alt me-1"></i>Выйти
                                    </a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </nav>

                <div class="container mt-4">
                    {% with messages = get_flashed_messages() %}
                        {% if messages %}
                            {% for message in messages %}
                            <div class="alert alert-success alert-dismissible fade show" role="alert">
                                <i class="fas fa-check-circle me-2"></i>{{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 class="fw-bold text-dark">
                            <i class="fas fa-stream me-2"></i>Лента мероприятий
                        </h2>
                        <a href="/post/create" class="btn btn-primary">
                            <i class="fas fa-plus me-2"></i>Новый пост
                        </a>
                    </div>
                    
                    {% if posts %}
                        {% for post in posts %}
                        <div class="post-card card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start mb-3">
                                    <div class="d-flex align-items-center">
                                        <div class="user-avatar me-3">
                                            {{ (post.full_name or post.username)[0].upper() }}
                                        </div>
                                        <div>
                                            <h6 class="card-subtitle mb-1 fw-bold">{{ post.full_name or post.username }}</h6>
                                            <small class="text-muted">{{ post.created_at[:16] }}</small>
                                        </div>
                                    </div>
                                    <div>
                                        {% if post.post_type == 'volunteer' %}
                                            <span class="badge badge-volunteer bg-success">Ищу волонтеров</span>
                                        {% elif post.post_type == 'help' %}
                                            <span class="badge badge-help bg-warning">Нужна помощь</span>
                                        {% else %}
                                            <span class="badge badge-event bg-info">Событие</span>
                                        {% endif %}
                                        {% if post.needs_volunteers %}
                                            <span class="badge bg-danger ms-1">
                                                <i class="fas fa-hands-helping me-1"></i>Ищет волонтеров
                                            </span>
                                        {% endif %}
                                    </div>
                                </div>
                                
                                <h5 class="card-title fw-bold">{{ post.title }}</h5>
                                <p class="card-text">{{ post.content }}</p>
                                
                                {% if post.location or post.event_date %}
                                <div class="mb-3">
                                    {% if post.location %}
                                    <small class="text-muted me-3">
                                        <i class="fas fa-map-marker-alt me-1"></i>{{ post.location }}
                                    </small>
                                    {% endif %}
                                    {% if post.event_date %}
                                    <small class="text-muted">
                                        <i class="fas fa-calendar-alt me-1"></i>{{ post.event_date }}
                                    </small>
                                    {% endif %}
                                </div>
                                {% endif %}
                                
                                <div class="d-flex flex-wrap gap-2">
                                    <a href="/post/{{ post.id }}" class="btn btn-outline-primary action-btn">
                                        <i class="fas fa-eye me-1"></i>Подробнее
                                    </a>
                                    {% if post.user_id == session['user_id'] %}
                                    <form action="/post/{{ post.id }}/delete" method="POST" class="d-inline">
                                        <button type="submit" class="btn btn-outline-danger action-btn" onclick="return confirm('Удалить пост?')">
                                            <i class="fas fa-trash me-1"></i>Удалить
                                        </button>
                                    </form>
                                    {% endif %}
                                    <a href="/chat/{{ post.user_id }}" class="btn btn-outline-success action-btn">
                                        <i class="fas fa-comment me-1"></i>Написать
                                    </a>
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    {% else %}
                        <div class="text-center py-5">
                            <i class="fas fa-inbox display-1 text-muted mb-3"></i>
                            <h3 class="text-muted">Пока нет мероприятий</h3>
                            <p class="text-muted">Будьте первым, кто создаст пост!</p>
                            <a href="/post/create" class="btn btn-primary mt-2">
                                <i class="fas fa-plus me-2"></i>Создать первое мероприятие
                            </a>
                        </div>
                    {% endif %}
                </div>
                
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        ''',

        'create_post.html': '''
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Создать пост - VolunteerHub</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                <style>
                    :root {
                        --primary: #2E8B57;
                        --primary-dark: #1f6b4b;
                        --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                    }
                    
                    .navbar-brand {
                        font-weight: 700;
                        font-size: 1.5rem;
                    }
                    
                    .nav-gradient {
                        background: var(--gradient) !important;
                    }
                    
                    .btn-primary {
                        background: var(--gradient);
                        border: none;
                        border-radius: 10px;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    }
                    
                    .btn-primary:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                    }
                    
                    .form-container {
                        background: white;
                        border-radius: 15px;
                        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
                        padding: 2rem;
                    }
                    
                    .form-control, .form-select {
                        border-radius: 10px;
                        padding: 12px 15px;
                        border: 2px solid #e9ecef;
                        transition: all 0.3s ease;
                    }
                    
                    .form-control:focus, .form-select:focus {
                        border-color: var(--primary);
                        box-shadow: 0 0 0 0.2rem rgba(46, 139, 87, 0.25);
                    }
                    
                    .form-check-input:checked {
                        background-color: var(--primary);
                        border-color: var(--primary);
                    }
                </style>
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark nav-gradient shadow-sm">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">
                            <i class="fas fa-hands-helping me-2"></i>VolunteerHub
                        </a>
                        
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">
                                <i class="fas fa-stream me-1"></i>Лента
                            </a>
                            <a class="nav-link" href="/chats">
                                <i class="fas fa-comments me-1"></i>Чаты
                            </a>
                            <a class="nav-link" href="/profile">
                                <i class="fas fa-user me-1"></i>Профиль
                            </a>
                        </div>
                    </div>
                </nav>

                <div class="container mt-4 mb-5">
                    <div class="row justify-content-center">
                        <div class="col-lg-8">
                            <div class="form-container">
                                <div class="text-center mb-4">
                                    <h2 class="fw-bold text-dark">
                                        <i class="fas fa-edit me-2"></i>Создать новое мероприятие
                                    </h2>
                                    <p class="text-muted">Поделитесь информацией о вашем мероприятии</p>
                                </div>
                                
                                {% with messages = get_flashed_messages() %}
                                    {% if messages %}
                                        {% for message in messages %}
                                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                            <i class="fas fa-exclamation-circle me-2"></i>{{ message }}
                                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                        </div>
                                        {% endfor %}
                                    {% endif %}
                                {% endwith %}
                                
                                <form method="POST">
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label fw-semibold">Тип мероприятия *</label>
                                            <select class="form-select" name="post_type" required>
                                                <option value="volunteer">Ищу волонтеров</option>
                                                <option value="help">Нужна помощь</option>
                                                <option value="event">Событие/Мероприятие</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label fw-semibold">Дата события</label>
                                            <input type="datetime-local" class="form-control" name="event_date">
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label fw-semibold">Название мероприятия *</label>
                                        <input type="text" class="form-control" name="title" required 
                                               placeholder="Например: Уборка территории парка">
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label fw-semibold">Описание *</label>
                                        <textarea class="form-control" name="content" rows="6" required 
                                                  placeholder="Опишите подробности мероприятия, задачи для волонтеров, что нужно сделать..."></textarea>
                                    </div>
                                    
                                    <div class="mb-4">
                                        <label class="form-label fw-semibold">Место проведения</label>
                                        <input type="text" class="form-control" name="location" 
                                               placeholder="Адрес или название места">
                                    </div>
                                    
                                    <div class="mb-4">
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" name="needs_volunteers" id="needs_volunteers">
                                            <label class="form-check-label fw-semibold" for="needs_volunteers">
                                                <i class="fas fa-hands-helping me-2"></i>Ищу волонтеров для этого мероприятия
                                            </label>
                                            <div class="form-text">При включении этой опции пользователи смогут подавать заявки на участие</div>
                                        </div>
                                    </div>
                                    
                                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                        <a href="/feed" class="btn btn-outline-secondary me-md-2 px-4">
                                            <i class="fas fa-arrow-left me-2"></i>Отмена
                                        </a>
                                        <button type="submit" class="btn btn-primary px-4">
                                            <i class="fas fa-paper-plane me-2"></i>Опубликовать
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
                
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        ''',

        'post_detail.html': '''
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{{ post.title }} - VolunteerHub</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                <style>
                    :root {
                        --primary: #2E8B57;
                        --primary-dark: #1f6b4b;
                        --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                    }
                    
                    .navbar-brand {
                        font-weight: 700;
                        font-size: 1.5rem;
                    }
                    
                    .nav-gradient {
                        background: var(--gradient) !important;
                    }
                    
                    .btn-primary {
                        background: var(--gradient);
                        border: none;
                        border-radius: 10px;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    }
                    
                    .btn-primary:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                    }
                    
                    .post-header {
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: white;
                        border-radius: 15px;
                        padding: 2rem;
                        margin-bottom: 2rem;
                    }
                    
                    .volunteer-card {
                        border: none;
                        border-radius: 15px;
                        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
                        transition: all 0.3s ease;
                    }
                    
                    .volunteer-card:hover {
                        transform: translateY(-3px);
                        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
                    }
                    
                    .status-badge {
                        padding: 8px 15px;
                        border-radius: 20px;
                        font-weight: 600;
                    }
                </style>
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark nav-gradient shadow-sm">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">
                            <i class="fas fa-hands-helping me-2"></i>VolunteerHub
                        </a>
                        
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">
                                <i class="fas fa-stream me-1"></i>Лента
                            </a>
                            <a class="nav-link" href="/chats">
                                <i class="fas fa-comments me-1"></i>Чаты
                            </a>
                            <a class="nav-link" href="/profile">
                                <i class="fas fa-user me-1"></i>Профиль
                            </a>
                        </div>
                    </div>
                </nav>

                <div class="container mt-4 mb-5">
                    {% with messages = get_flashed_messages() %}
                        {% if messages %}
                            {% for message in messages %}
                            <div class="alert alert-success alert-dismissible fade show" role="alert">
                                <i class="fas fa-check-circle me-2"></i>{{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    <div class="post-header">
                        <div class="row align-items-center">
                            <div class="col-md-8">
                                <h1 class="display-6 fw-bold mb-3">{{ post.title }}</h1>
                                <div class="d-flex flex-wrap gap-3 align-items-center">
                                    <div class="d-flex align-items-center">
                                        <div class="bg-white rounded-circle p-2 me-2">
                                            <i class="fas fa-user text-primary"></i>
                                        </div>
                                        <span class="fw-semibold">{{ post.full_name or post.username }}</span>
                                    </div>
                                    {% if post.needs_volunteers %}
                                    <span class="badge bg-warning px-3 py-2">
                                        <i class="fas fa-hands-helping me-1"></i>Ищет волонтеров
                                    </span>
                                    {% endif %}
                                </div>
                            </div>
                            <div class="col-md-4 text-md-end">
                                <a href="/feed" class="btn btn-light me-2">
                                    <i class="fas fa-arrow-left me-1"></i>Назад
                                </a>
                                <a href="/chat/{{ post.user_id }}" class="btn btn-outline-light">
                                    <i class="fas fa-comment me-1"></i>Написать
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-lg-8">
                            <div class="card border-0 shadow-sm mb-4">
                                <div class="card-body">
                                    <h4 class="card-title fw-bold mb-3">
                                        <i class="fas fa-info-circle me-2 text-primary"></i>Описание мероприятия
                                    </h4>
                                    <p class="card-text fs-5">{{ post.content }}</p>
                                    
                                    <div class="row mt-4">
                                        {% if post.location %}
                                        <div class="col-md-6 mb-3">
                                            <h6 class="fw-semibold text-muted">
                                                <i class="fas fa-map-marker-alt me-2"></i>Место проведения
                                            </h6>
                                            <p class="mb-0">{{ post.location }}</p>
                                        </div>
                                        {% endif %}
                                        {% if post.event_date %}
                                        <div class="col-md-6 mb-3">
                                            <h6 class="fw-semibold text-muted">
                                                <i class="fas fa-calendar-alt me-2"></i>Дата и время
                                            </h6>
                                            <p class="mb-0">{{ post.event_date }}</p>
                                        </div>
                                        {% endif %}
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-lg-4">
                            {% if post.needs_volunteers %}
                                {% if post.user_id != session['user_id'] %}
                                    {% if not existing_form %}
                                        <div class="card border-0 shadow-sm mb-4">
                                            <div class="card-body text-center">
                                                <div class="text-primary mb-3">
                                                    <i class="fas fa-hands-helping fa-3x"></i>
                                                </div>
                                                <h5 class="card-title fw-bold">Хотите помочь?</h5>
                                                <p class="card-text text-muted mb-4">
                                                    Присоединяйтесь к мероприятию в качестве волонтера
                                                </p>
                                                <a href="/post/{{ post.id }}/volunteer" class="btn btn-primary w-100 py-3 fw-semibold">
                                                    <i class="fas fa-user-check me-2"></i>Подать заявку
                                                </a>
                                            </div>
                                        </div>
                                    {% else %}
                                        <div class="card border-0 shadow-sm mb-4">
                                            <div class="card-body text-center">
                                                <div class="text-success mb-3">
                                                    <i class="fas fa-check-circle fa-3x"></i>
                                                </div>
                                                <h5 class="card-title fw-bold">Заявка подана</h5>
                                                <p class="card-text mb-3">
                                                    Статус вашей заявки:
                                                </p>
                                                {% if existing_form.status == 'pending' %}
                                                <span class="status-badge bg-warning text-dark">
                                                    ⏳ На рассмотрении
                                                </span>
                                                {% elif existing_form.status == 'approved' %}
                                                <span class="status-badge bg-success text-white">
                                                    ✅ Одобрена
                                                </span>
                                                {% elif existing_form.status == 'rejected' %}
                                                <span class="status-badge bg-danger text-white">
                                                    ❌ Отклонена
                                                </span>
                                                {% endif %}
                                            </div>
                                        </div>
                                    {% endif %}
                                {% else %}
                                    <!-- Для автора поста -->
                                    <div class="card border-0 shadow-sm">
                                        <div class="card-header bg-primary text-white">
                                            <h5 class="card-title mb-0">
                                                <i class="fas fa-users me-2"></i>Заявки волонтеров
                                            </h5>
                                        </div>
                                        <div class="card-body">
                                            {% if volunteer_forms %}
                                                {% for form in volunteer_forms %}
                                                <div class="volunteer-card card mb-3">
                                                    <div class="card-body">
                                                        <div class="d-flex justify-content-between align-items-start mb-3">
                                                            <h6 class="card-title fw-bold mb-0">{{ form.full_name }}</h6>
                                                            <span class="badge {% if form.status == 'pending' %}bg-warning{% elif form.status == 'approved' %}bg-success{% else %}bg-danger{% endif %}">
                                                                {% if form.status == 'pending' %}⏳
                                                                {% elif form.status == 'approved' %}✅
                                                                {% else %}❌{% endif %}
                                                            </span>
                                                        </div>
                                                        
                                                        <div class="mb-3">
                                                            <small class="text-muted d-block">
                                                                <i class="fas fa-at me-1"></i>@{{ form.username }}
                                                            </small>
                                                            <small class="text-muted d-block">
                                                                <i class="fas fa-phone me-1"></i>{{ form.contact_info }}
                                                            </small>
                                                            <small class="text-muted d-block">
                                                                <i class="fas fa-birthday-cake me-1"></i>{{ form.age }} лет
                                                            </small>
                                                            <small class="text-muted d-block">
                                                                <i class="fas fa-briefcase me-1"></i>{{ form.experience }}
                                                            </small>
                                                            {% if form.comment %}
                                                            <small class="text-muted d-block mt-2">
                                                                <i class="fas fa-comment me-1"></i>{{ form.comment }}
                                                            </small>
                                                            {% endif %}
                                                        </div>
                                                        
                                                        <div class="d-flex flex-wrap gap-2">
                                                            {% if form.status == 'pending' %}
                                                            <form action="/volunteer_form/{{ form.id }}/update_status" method="POST" class="d-inline">
                                                                <button type="submit" name="status" value="approved" class="btn btn-success btn-sm">
                                                                    <i class="fas fa-check me-1"></i>Одобрить
                                                                </button>
                                                            </form>
                                                            <form action="/volunteer_form/{{ form.id }}/update_status" method="POST" class="d-inline">
                                                                <button type="submit" name="status" value="rejected" class="btn btn-danger btn-sm">
                                                                    <i class="fas fa-times me-1"></i>Отклонить
                                                                </button>
                                                            </form>
                                                            {% endif %}
                                                            <a href="/chat/{{ form.user_id }}" class="btn btn-primary btn-sm">
                                                                <i class="fas fa-comment me-1"></i>Чат
                                                            </a>
                                                        </div>
                                                        
                                                        <small class="text-muted d-block mt-2">
                                                            Подана: {{ form.created_at[:16] }}
                                                        </small>
                                                    </div>
                                                </div>
                                                {% endfor %}
                                            {% else %}
                                                <div class="text-center py-4">
                                                    <i class="fas fa-inbox fa-2x text-muted mb-3"></i>
                                                    <p class="text-muted mb-0">Пока нет заявок от волонтеров</p>
                                                </div>
                                            {% endif %}
                                        </div>
                                    </div>
                                {% endif %}
                            {% endif %}
                        </div>
                    </div>
                </div>
                
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        ''',

        
        'volunteer_form.html': '''
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Анкета волонтера - VolunteerHub</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            <style>
                :root {
                    --primary: #2E8B57;
                    --primary-dark: #1f6b4b;
                    --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                }
                
                .navbar-brand {
                    font-weight: 700;
                    font-size: 1.5rem;
                }
                
                .nav-gradient {
                    background: var(--gradient) !important;
                }
                
                .btn-primary {
                    background: var(--gradient);
                    border: none;
                    border-radius: 10px;
                    font-weight: 600;
                    transition: all 0.3s ease;
                }
                
                .btn-primary:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                }
                
                .form-container {
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
                }
                
                .form-control, .form-select {
                    border-radius: 10px;
                    padding: 12px 15px;
                    border: 2px solid #e9ecef;
                    transition: all 0.3s ease;
                }
                
                .form-control:focus, .form-select:focus {
                    border-color: var(--primary);
                    box-shadow: 0 0 0 0.2rem rgba(46, 139, 87, 0.25);
                }
                
                .event-header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border-radius: 15px 15px 0 0;
                    padding: 1.5rem;
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark nav-gradient shadow-sm">
                <div class="container">
                    <a class="navbar-brand" href="/feed">
                        <i class="fas fa-hands-helping me-2"></i>VolunteerHub
                    </a>
                    
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/feed">
                            <i class="fas fa-stream me-1"></i>Лента
                        </a>
                        <a class="nav-link" href="/chats">
                            <i class="fas fa-comments me-1"></i>Чаты
                        </a>
                        <a class="nav-link" href="/profile">
                            <i class="fas fa-user me-1"></i>Профиль
                        </a>
                    </div>
                </div>
            </nav>

            <div class="container mt-4 mb-5">
                <div class="row justify-content-center">
                    <div class="col-lg-8">
                        <div class="form-container">
                            <div class="event-header">
                                <div class="text-center">
                                    <h3 class="fw-bold mb-2">Анкета волонтера</h3>
                                    <p class="mb-0">Мероприятие: "{{ post.title }}"</p>
                                </div>
                            </div>
                            
                            <div class="p-4 p-md-5">
                                <div class="text-center mb-4">
                                    <div class="text-primary mb-3">
                                        <i class="fas fa-user-check fa-3x"></i>
                                    </div>
                                    <h4 class="fw-bold text-dark">Станьте частью команды</h4>
                                    <p class="text-muted">Заполните анкету для участия в мероприятии</p>
                                </div>
                                
                                {% with messages = get_flashed_messages() %}
                                    {% if messages %}
                                        {% for message in messages %}
                                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                            <i class="fas fa-exclamation-circle me-2"></i>{{ message }}
                                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                        </div>
                                        {% endfor %}
                                    {% endif %}
                                {% endwith %}
                                
                                <form method="POST">
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label fw-semibold">Полное имя *</label>
                                            <div class="input-group">
                                                <span class="input-group-text bg-light border-end-0">
                                                    <i class="fas fa-user text-muted"></i>
                                                </span>
                                                <input type="text" class="form-control border-start-0" name="full_name" required 
                                                       value="{{ session.get('user_full_name', '') }}" placeholder="Ваше полное имя">
                                            </div>
                                        </div>
                                        
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label fw-semibold">Имя пользователя *</label>
                                            <div class="input-group">
                                                <span class="input-group-text bg-light border-end-0">
                                                    <i class="fas fa-at text-muted"></i>
                                                </span>
                                                <input type="text" class="form-control border-start-0" name="username" required 
                                                       value="{{ session.get('username', '') }}" placeholder="Ваш username">
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="mb-3">
                                        <label class="form-label fw-semibold">Контактные данные *</label>
                                        <div class="input-group">
                                            <span class="input-group-text bg-light border-end-0">
                                                <i class="fas fa-phone text-muted"></i>
                                            </span>
                                            <input type="text" class="form-control border-start-0" name="contact_info" required 
                                                   placeholder="Телефон, email или другие контакты">
                                        </div>
                                        <div class="form-text">Укажите, как с вами можно связаться</div>
                                    </div>
                                    
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label fw-semibold">Возраст *</label>
                                            <div class="input-group">
                                                <span class="input-group-text bg-light border-end-0">
                                                    <i class="fas fa-birthday-cake text-muted"></i>
                                                </span>
                                                <input type="number" class="form-control border-start-0" name="age" required 
                                                       min="14" max="100" placeholder="Ваш возраст">
                                            </div>
                                        </div>
                                        
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label fw-semibold">Опыт волонтерства *</label>
                                            <select class="form-select" name="experience" required>
                                                <option value="">Выберите опыт</option>
                                                <option value="Нет опыта">Нет опыта</option>
                                                <option value="Менее 1 года">Менее 1 года</option>
                                                <option value="1-3 года">1-3 года</option>
                                                <option value="Более 3 лет">Более 3 лет</option>
                                                <option value="Профессиональный волонтер">Профессиональный волонтер</option>
                                            </select>
                                        </div>
                                    </div>
                                    
                                    <div class="mb-4">
                                        <label class="form-label fw-semibold">Комментарий</label>
                                        <textarea class="form-control" name="comment" rows="4" 
                                                  placeholder="Расскажите о себе, почему хотите участвовать, какие навыки можете применить..."></textarea>
                                        <div class="form-text">Необязательное поле, но поможет организатору лучше вас узнать</div>
                                    </div>
                                    
                                    <div class="d-grid gap-3">
                                        <button type="submit" class="btn btn-primary py-3 fw-semibold">
                                            <i class="fas fa-paper-plane me-2"></i>Отправить заявку
                                        </button>
                                        <a href="/post/{{ post.id }}" class="btn btn-outline-secondary">
                                            <i class="fas fa-arrow-left me-2"></i>Вернуться к мероприятию
                                        </a>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
    ''',

    'profile.html': '''
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Профиль - VolunteerHub</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            <style>
                :root {
                    --primary: #2E8B57;
                    --primary-dark: #1f6b4b;
                    --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                }
                
                .navbar-brand {
                    font-weight: 700;
                    font-size: 1.5rem;
                }
                
                .nav-gradient {
                    background: var(--gradient) !important;
                }
                
                .btn-primary {
                    background: var(--gradient);
                    border: none;
                    border-radius: 10px;
                    font-weight: 600;
                    transition: all 0.3s ease;
                }
                
                .btn-primary:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                }
                
                .profile-card {
                    border: none;
                    border-radius: 15px;
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
                }
                
                .user-avatar-large {
                    width: 80px;
                    height: 80px;
                    border-radius: 50%;
                    background: var(--gradient);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-weight: bold;
                    font-size: 2rem;
                    margin: 0 auto 1rem;
                }
                
                .stats-card {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border-radius: 15px;
                    padding: 1.5rem;
                }
                
                .application-card {
                    border: none;
                    border-radius: 10px;
                    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.08);
                    transition: all 0.3s ease;
                }
                
                .application-card:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.12);
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark nav-gradient shadow-sm">
                <div class="container">
                    <a class="navbar-brand" href="/feed">
                        <i class="fas fa-hands-helping me-2"></i>VolunteerHub
                    </a>
                    
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/feed">
                            <i class="fas fa-stream me-1"></i>Лента
                        </a>
                        <a class="nav-link" href="/post/create">
                            <i class="fas fa-plus-circle me-1"></i>Создать пост
                        </a>
                        <a class="nav-link" href="/chats">
                            <i class="fas fa-comments me-1"></i>Чаты
                        </a>
                    </div>
                </div>
            </nav>

            <div class="container mt-4 mb-5">
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {% for message in messages %}
                        <div class="alert alert-success alert-dismissible fade show" role="alert">
                            <i class="fas fa-check-circle me-2"></i>{{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <div class="row">
                    <!-- Левая колонка - профиль -->
                    <div class="col-lg-4">
                        <div class="profile-card card mb-4">
                            <div class="card-body text-center p-4">
                                <div class="user-avatar-large">
                                    {{ (user.full_name or user.username)[0].upper() }}
                                </div>
                                <h3 class="card-title fw-bold mb-2">{{ user.full_name or user.username }}</h3>
                                <p class="text-muted mb-3">@{{ user.username }}</p>
                                
                                {% if user.bio %}
                                <p class="card-text mb-3">{{ user.bio }}</p>
                                {% endif %}
                                
                                {% if user.skills %}
                                <div class="mb-3">
                                    <h6 class="fw-semibold text-start">
                                        <i class="fas fa-tools me-2 text-primary"></i>Навыки:
                                    </h6>
                                    <p class="text-start">{{ user.skills }}</p>
                                </div>
                                {% endif %}
                                
                                <div class="text-muted mb-4">
                                    <small>
                                        <i class="fas fa-calendar-plus me-1"></i>
                                        Участник с {{ user.created_at[:10] }}
                                    </small>
                                </div>
                                
                                <div class="d-grid gap-2">
                                    <a href="/profile/edit" class="btn btn-primary">
                                        <i class="fas fa-edit me-2"></i>Редактировать профиль
                                    </a>
                                    <form action="/profile/delete" method="POST" onsubmit="return confirm('Вы уверены, что хотите удалить профиль? Это действие нельзя отменить!')">
                                        <button type="submit" class="btn btn-outline-danger w-100">
                                            <i class="fas fa-trash me-2"></i>Удалить профиль
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Статистика -->
                        <div class="stats-card mb-4">
                            <h5 class="fw-bold mb-3">
                                <i class="fas fa-chart-bar me-2"></i>Моя активность
                            </h5>
                            <div class="row text-center">
                                <div class="col-6">
                                    <h4 class="fw-bold mb-1">{{ posts|length }}</h4>
                                    <small>Созданные посты</small>
                                </div>
                                <div class="col-6">
                                    <h4 class="fw-bold mb-1">{{ forms|length }}</h4>
                                    <small>Поданые заявки</small>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Мои заявки -->
                        <div class="profile-card card">
                            <div class="card-header bg-light">
                                <h5 class="card-title mb-0">
                                    <i class="fas fa-clipboard-list me-2 text-primary"></i>Мои заявки
                                </h5>
                            </div>
                            <div class="card-body">
                                {% if forms %}
                                    {% for form in forms %}
                                    <div class="application-card card mb-3">
                                        <div class="card-body">
                                            <h6 class="card-title fw-bold mb-2">{{ form.post_title }}</h6>
                                            <div class="d-flex justify-content-between align-items-center mb-2">
                                                <small class="text-muted">Автор: @{{ form.author_username }}</small>
                                                <span class="badge {% if form.status == 'pending' %}bg-warning{% elif form.status == 'approved' %}bg-success{% else %}bg-danger{% endif %}">
                                                    {% if form.status == 'pending' %}⏳ На рассмотрении
                                                    {% elif form.status == 'approved' %}✅ Одобрена
                                                    {% elif form.status == 'rejected' %}❌ Отклонена
                                                    {% else %}{{ form.status }}{% endif %}
                                                </span>
                                            </div>
                                            <small class="text-muted">
                                                <i class="fas fa-clock me-1"></i>{{ form.created_at[:16] }}
                                            </small>
                                        </div>
                                    </div>
                                    {% endfor %}
                                {% else %}
                                    <div class="text-center py-3">
                                        <i class="fas fa-inbox fa-2x text-muted mb-2"></i>
                                        <p class="text-muted mb-0">У вас пока нет заявок</p>
                                    </div>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                    
                    <!-- Правая колонка - посты -->
                    <div class="col-lg-8">
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h2 class="fw-bold text-dark">
                                <i class="fas fa-newspaper me-2"></i>Мои посты
                            </h2>
                            <span class="badge bg-primary fs-6">{{ posts|length }}</span>
                        </div>
                        
                        {% if posts %}
                            {% for post in posts %}
                            <div class="profile-card card mb-4">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-start mb-3">
                                        <h5 class="card-title fw-bold mb-0">{{ post.title }}</h5>
                                        <div>
                                            {% if post.needs_volunteers %}
                                            <span class="badge bg-success me-1">
                                                <i class="fas fa-hands-helping me-1"></i>Ищет волонтеров
                                            </span>
                                            {% endif %}
                                            <span class="badge bg-secondary">{{ post.post_type }}</span>
                                        </div>
                                    </div>
                                    
                                    <p class="card-text mb-3">{{ post.content[:150] }}{% if post.content|length > 150 %}...{% endif %}</p>
                                    
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            {% if post.location %}
                                            <small class="text-muted me-3">
                                                <i class="fas fa-map-marker-alt me-1"></i>{{ post.location }}
                                            </small>
                                            {% endif %}
                                            {% if post.event_date %}
                                            <small class="text-muted">
                                                <i class="fas fa-calendar-alt me-1"></i>{{ post.event_date }}
                                            </small>
                                            {% endif %}
                                        </div>
                                        <small class="text-muted">{{ post.created_at[:16] }}</small>
                                    </div>
                                    
                                    <div class="d-flex gap-2 mt-3">
                                        <a href="/post/{{ post.id }}" class="btn btn-outline-primary btn-sm">
                                            <i class="fas fa-eye me-1"></i>Подробнее
                                        </a>
                                        <form action="/post/{{ post.id }}/delete" method="POST" class="d-inline">
                                            <button type="submit" class="btn btn-outline-danger btn-sm" onclick="return confirm('Удалить пост?')">
                                                <i class="fas fa-trash me-1"></i>Удалить
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            {% endfor %}
                        {% else %}
                            <div class="text-center py-5">
                                <i class="fas fa-edit display-1 text-muted mb-3"></i>
                                <h3 class="text-muted">У вас пока нет постов</h3>
                                <p class="text-muted">Создайте свой первый пост и найдите волонтеров!</p>
                                <a href="/post/create" class="btn btn-primary mt-2">
                                    <i class="fas fa-plus me-2"></i>Создать первый пост
                                </a>
                            </div>
                        {% endif %}
                    </div>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
    ''',

    'edit_profile.html': '''
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Редактирование профиля - VolunteerHub</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            <style>
                :root {
                    --primary: #2E8B57;
                    --primary-dark: #1f6b4b;
                    --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                }
                
                .navbar-brand {
                    font-weight: 700;
                    font-size: 1.5rem;
                }
                
                .nav-gradient {
                    background: var(--gradient) !important;
                }
                
                .btn-primary {
                    background: var(--gradient);
                    border: none;
                    border-radius: 10px;
                    font-weight: 600;
                    transition: all 0.3s ease;
                }
                
                .btn-primary:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                }
                
                .form-container {
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
                    padding: 2rem;
                }
                
                .form-control, .form-select {
                    border-radius: 10px;
                    padding: 12px 15px;
                    border: 2px solid #e9ecef;
                    transition: all 0.3s ease;
                }
                
                .form-control:focus, .form-select:focus {
                    border-color: var(--primary);
                    box-shadow: 0 0 0 0.2rem rgba(46, 139, 87, 0.25);
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark nav-gradient shadow-sm">
                <div class="container">
                    <a class="navbar-brand" href="/feed">
                        <i class="fas fa-hands-helping me-2"></i>VolunteerHub
                    </a>
                    
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/feed">
                            <i class="fas fa-stream me-1"></i>Лента
                        </a>
                        <a class="nav-link" href="/profile">
                            <i class="fas fa-user me-1"></i>Профиль
                        </a>
                    </div>
                </div>
            </nav>

            <div class="container mt-4 mb-5">
                <div class="row justify-content-center">
                    <div class="col-lg-8">
                        <div class="form-container">
                            <div class="text-center mb-4">
                                <h2 class="fw-bold text-dark">
                                    <i class="fas fa-user-edit me-2"></i>Редактирование профиля
                                </h2>
                                <p class="text-muted">Обновите информацию о себе</p>
                            </div>
                            
                            {% with messages = get_flashed_messages() %}
                                {% if messages %}
                                    {% for message in messages %}
                                    <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                        <i class="fas fa-exclamation-circle me-2"></i>{{ message }}
                                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                    </div>
                                    {% endfor %}
                                {% endif %}
                            {% endwith %}
                            
                            <form method="POST">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label fw-semibold">Полное имя</label>
                                        <div class="input-group">
                                            <span class="input-group-text bg-light border-end-0">
                                                <i class="fas fa-user text-muted"></i>
                                            </span>
                                            <input type="text" class="form-control border-start-0" name="full_name" 
                                                   value="{{ user.full_name or '' }}" placeholder="Ваше полное имя">
                                        </div>
                                    </div>
                                    
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label fw-semibold">Email *</label>
                                        <div class="input-group">
                                            <span class="input-group-text bg-light border-end-0">
                                                <i class="fas fa-envelope text-muted"></i>
                                            </span>
                                            <input type="email" class="form-control border-start-0" name="email" 
                                                   value="{{ user.email }}" required placeholder="your@email.com">
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <label class="form-label fw-semibold">О себе</label>
                                    <textarea class="form-control" name="bio" rows="4" 
                                              placeholder="Расскажите о себе, своих интересах...">{{ user.bio or '' }}</textarea>
                                    <div class="form-text">Краткое описание, которое увидят другие пользователи</div>
                                </div>
                                
                                <div class="mb-4">
                                    <label class="form-label fw-semibold">Навыки</label>
                                    <div class="input-group">
                                        <span class="input-group-text bg-light border-end-0">
                                            <i class="fas fa-tools text-muted"></i>
                                        </span>
                                        <input type="text" class="form-control border-start-0" name="skills" 
                                               value="{{ user.skills or '' }}" placeholder="Организация мероприятий, работа с детьми, медицинская помощь...">
                                    </div>
                                    <div class="form-text">Перечислите свои навыки через запятую</div>
                                </div>
                                
                                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                    <a href="/profile" class="btn btn-outline-secondary me-md-2 px-4">
                                        <i class="fas fa-arrow-left me-2"></i>Отмена
                                    </a>
                                    <button type="submit" class="btn btn-primary px-4">
                                        <i class="fas fa-save me-2"></i>Сохранить изменения
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
    ''',

    'chats_list.html': '''
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Мои чаты - VolunteerHub</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            <style>
                :root {
                    --primary: #2E8B57;
                    --primary-dark: #1f6b4b;
                    --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                }
                
                .navbar-brand {
                    font-weight: 700;
                    font-size: 1.5rem;
                }
                
                .nav-gradient {
                    background: var(--gradient) !important;
                }
                
                .btn-primary {
                    background: var(--gradient);
                    border: none;
                    border-radius: 10px;
                    font-weight: 600;
                    transition: all 0.3s ease;
                }
                
                .btn-primary:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                }
                
                .chat-item {
                    border: none;
                    border-radius: 15px;
                    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.08);
                    transition: all 0.3s ease;
                    margin-bottom: 1rem;
                }
                
                .chat-item:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.12);
                    text-decoration: none;
                }
                
                .user-avatar-chat {
                    width: 50px;
                    height: 50px;
                    border-radius: 50%;
                    background: var(--gradient);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-weight: bold;
                    font-size: 1.2rem;
                }
                
                .unread-badge {
                    background: #dc3545;
                    color: white;
                    border-radius: 50%;
                    width: 20px;
                    height: 20px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 0.7rem;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark nav-gradient shadow-sm">
                <div class="container">
                    <a class="navbar-brand" href="/feed">
                        <i class="fas fa-hands-helping me-2"></i>VolunteerHub
                    </a>
                    
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/feed">
                            <i class="fas fa-stream me-1"></i>Лента
                        </a>
                        <a class="nav-link" href="/post/create">
                            <i class="fas fa-plus-circle me-1"></i>Создать пост
                        </a>
                        <a class="nav-link" href="/users">
                            <i class="fas fa-users me-1"></i>Пользователи
                        </a>
                        <a class="nav-link" href="/profile">
                            <i class="fas fa-user me-1"></i>Профиль
                        </a>
                    </div>
                </div>
            </nav>

            <div class="container mt-4 mb-5">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2 class="fw-bold text-dark">
                        <i class="fas fa-comments me-2"></i>Мои чаты
                    </h2>
                    <a href="/users" class="btn btn-primary">
                        <i class="fas fa-plus me-2"></i>Новый чат
                    </a>
                </div>
                
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {% for message in messages %}
                        <div class="alert alert-info alert-dismissible fade show" role="alert">
                            <i class="fas fa-info-circle me-2"></i>{{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                {% if chats %}
                    <div class="row">
                        {% for chat in chats %}
                        <div class="col-12">
                            <a href="/chat/{{ chat.other_user_id }}" class="chat-item card text-dark">
                                <div class="card-body">
                                    <div class="d-flex align-items-center">
                                        <div class="user-avatar-chat me-3">
                                            {{ (chat.other_full_name or chat.other_username)[0].upper() }}
                                        </div>
                                        <div class="flex-grow-1">
                                            <div class="d-flex justify-content-between align-items-start">
                                                <h5 class="card-title mb-1 fw-bold">
                                                    {{ chat.other_full_name or chat.other_username }}
                                                    {% if chat.unread_count > 0 %}
                                                    <span class="unread-badge ms-2">{{ chat.unread_count }}</span>
                                                    {% endif %}
                                                </h5>
                                                {% if chat.last_message_time %}
                                                <small class="text-muted">{{ chat.last_message_time[:16] }}</small>
                                                {% endif %}
                                            </div>
                                            {% if chat.last_message %}
                                            <p class="card-text text-muted mb-0">
                                                {{ chat.last_message[:80] }}{% if chat.last_message|length > 80 %}...{% endif %}
                                            </p>
                                            {% else %}
                                            <p class="card-text text-muted mb-0">Чат пуст</p>
                                            {% endif %}
                                        </div>
                                    </div>
                                </div>
                            </a>
                        </div>
                        {% endfor %}
                    </div>
                {% else %}
                    <div class="text-center py-5">
                        <i class="fas fa-comments display-1 text-muted mb-3"></i>
                        <h3 class="text-muted">У вас пока нет чатов</h3>
                        <p class="text-muted">Начните общение с другими волонтерами!</p>
                        <a href="/users" class="btn btn-primary mt-2">
                            <i class="fas fa-users me-2"></i>Найти пользователей
                        </a>
                    </div>
                {% endif %}
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
    ''',

    'chat.html': '''
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Чат с {{ other_user.full_name or other_user.username }} - VolunteerHub</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            <style>
                :root {
                    --primary: #2E8B57;
                    --primary-dark: #1f6b4b;
                    --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                }
                
                .navbar-brand {
                    font-weight: 700;
                    font-size: 1.5rem;
                }
                
                .nav-gradient {
                    background: var(--gradient) !important;
                }
                
                .btn-primary {
                    background: var(--gradient);
                    border: none;
                    border-radius: 10px;
                    font-weight: 600;
                    transition: all 0.3s ease;
                }
                
                .btn-primary:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                }
                
                .chat-container {
                    height: 60vh;
                    overflow-y: auto;
                    border: 1px solid #e9ecef;
                    border-radius: 15px;
                    padding: 1rem;
                    background: #f8f9fa;
                }
                
                .message {
                    margin-bottom: 1rem;
                    padding: 12px 16px;
                    border-radius: 18px;
                    max-width: 70%;
                    position: relative;
                    animation: fadeIn 0.3s ease;
                }
                
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                
                .my-message {
                    background: var(--gradient);
                    color: white;
                    margin-left: auto;
                    border-bottom-right-radius: 5px;
                }
                
                .other-message {
                    background: white;
                    color: #333;
                    margin-right: auto;
                    border-bottom-left-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }
                
                .message-time {
                    font-size: 0.75rem;
                    opacity: 0.7;
                    margin-top: 5px;
                }
                
                .chat-header {
                    background: white;
                    border-radius: 15px 15px 0 0;
                    padding: 1rem;
                    border-bottom: 1px solid #e9ecef;
                }
                
                .user-avatar-small {
                    width: 40px;
                    height: 40px;
                    border-radius: 50%;
                    background: var(--gradient);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-weight: bold;
                    font-size: 1rem;
                }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark nav-gradient shadow-sm">
                <div class="container">
                    <a class="navbar-brand" href="/feed">
                        <i class="fas fa-hands-helping me-2"></i>VolunteerHub
                    </a>
                    
                    <div class="navbar-nav ms-auto">
                        <a class="nav-link" href="/chats">
                            <i class="fas fa-arrow-left me-1"></i>Все чаты
                        </a>
                        <a class="nav-link" href="/feed">
                            <i class="fas fa-stream me-1"></i>Лента
                        </a>
                        <a class="nav-link" href="/profile">
                            <i class="fas fa-user me-1"></i>Профиль
                        </a>
                    </div>
                </div>
            </nav>

            <div class="container mt-4 mb-5">
                <!-- Заголовок чата -->
                <div class="chat-header mb-3">
                    <div class="d-flex align-items-center">
                        <a href="/chats" class="btn btn-outline-secondary btn-sm me-3">
                            <i class="fas fa-arrow-left"></i>
                        </a>
                        <div class="user-avatar-small me-3">
                            {{ (other_user.full_name or other_user.username)[0].upper() }}
                        </div>
                        <div>
                            <h5 class="fw-bold mb-0">{{ other_user.full_name or other_user.username }}</h5>
                            <small class="text-muted">@{{ other_user.username }}</small>
                        </div>
                    </div>
                </div>
                
                <!-- Контейнер сообщений -->
                <div id="chatContainer" class="chat-container mb-3">
                    {% for message in messages %}
                    <div class="message {% if message.sender_id == session['user_id'] %}my-message{% else %}other-message{% endif %}">
                        <div class="message-text">{{ message.message_text }}</div>
                        <div class="message-time">
                            {{ message.created_at[:16] }}
                            {% if message.sender_id == session['user_id'] %}
                            <i class="fas fa-check-double ms-1"></i>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
                
                <!-- Форма отправки сообщения -->
                <div class="input-group">
                    <input type="text" id="messageInput" class="form-control" 
                           placeholder="Введите сообщение..." maxlength="1000"
                           style="border-radius: 25px; padding: 12px 20px;">
                    <button id="sendButton" class="btn btn-primary" style="border-radius: 25px; margin-left: 10px;">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                </div>
            </div>

            <script>
                const chatId = {{ chat.id }};
                const currentUserId = {{ session['user_id'] }};
                
                // Автопрокрутка вниз
                function scrollToBottom() {
                    const container = document.getElementById('chatContainer');
                    container.scrollTop = container.scrollHeight;
                }
                
                // Отправка сообщения
                document.getElementById('sendButton').addEventListener('click', sendMessage);
                document.getElementById('messageInput').addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') sendMessage();
                });
                
                function sendMessage() {
                    const input = document.getElementById('messageInput');
                    const messageText = input.value.trim();
                    
                    if (!messageText) return;
                    
                    fetch('/api/send_message', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            chat_id: chatId,
                            message_text: messageText
                        })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            input.value = '';
                            loadMessages();
                        }
                    });
                }
                
                // Загрузка сообщений
                function loadMessages() {
                    fetch(`/api/get_messages/${chatId}`)
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                updateChat(data.messages);
                            }
                        });
                }
                
                // Обновление чата
                function updateChat(messages) {
                    const container = document.getElementById('chatContainer');
                    container.innerHTML = '';
                    
                    messages.forEach(msg => {
                        const messageDiv = document.createElement('div');
                        messageDiv.className = `message ${msg.is_my_message ? 'my-message' : 'other-message'}`;
                        
                        messageDiv.innerHTML = `
                            <div class="message-text">${msg.message_text}</div>
                            <div class="message-time">
                                ${msg.created_at.substring(0, 16)}
                                ${msg.is_my_message ? '<i class="fas fa-check-double ms-1"></i>' : ''}
                            </div>
                        `;
                        
                        container.appendChild(messageDiv);
                    });
                    
                    scrollToBottom();
                }
                
                // Обновление каждые 3 секунды
                setInterval(loadMessages, 3000);
                
                // Инициализация
                scrollToBottom();
            </script>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
    ''',

        'users_list.html': '''
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Все пользователи - VolunteerHub</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                <style>
                    :root {
                        --primary: #2E8B57;
                        --primary-dark: #1f6b4b;
                        --gradient: linear-gradient(135deg, #2E8B57 0%, #3CB371 100%);
                    }
                    
                    .navbar-brand {
                        font-weight: 700;
                        font-size: 1.5rem;
                    }
                    
                    .nav-gradient {
                        background: var(--gradient) !important;
                    }
                    
                    .btn-primary {
                        background: var(--gradient);
                        border: none;
                        border-radius: 10px;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    }
                    
                    .btn-primary:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 5px 15px rgba(46, 139, 87, 0.4);
                    }
                    
                    .user-card {
                        border: none;
                        border-radius: 15px;
                        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
                        transition: all 0.3s ease;
                    }
                    
                    .user-card:hover {
                        transform: translateY(-5px);
                        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
                    }
                    
                    .user-avatar-medium {
                        width: 60px;
                        height: 60px;
                        border-radius: 50%;
                        background: var(--gradient);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        color: white;
                        font-weight: bold;
                        font-size: 1.5rem;
                    }
                    
                    .skills-badge {
                        background: #e9ecef;
                        color: #6c757d;
                        border-radius: 15px;
                        padding: 4px 12px;
                        font-size: 0.8rem;
                        margin: 2px;
                    }
                </style>
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark nav-gradient shadow-sm">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">
                            <i class="fas fa-hands-helping me-2"></i>VolunteerHub
                        </a>
                        
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/chats">
                                <i class="fas fa-comments me-1"></i>Чаты
                            </a>
                            <a class="nav-link" href="/feed">
                                <i class="fas fa-stream me-1"></i>Лента
                            </a>
                            <a class="nav-link" href="/profile">
                                <i class="fas fa-user me-1"></i>Профиль
                            </a>
                        </div>
                    </div>
                </nav>

                <div class="container mt-4 mb-5">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2 class="fw-bold text-dark">
                            <i class="fas fa-users me-2"></i>Все пользователи
                        </h2>
                        <a href="/chats" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left me-2"></i>Назад к чатам
                        </a>
                    </div>
                    
                    <div class="row">
                        {% for user in users %}
                        <div class="col-lg-6 mb-4">
                            <div class="user-card card h-100">
                                <div class="card-body">
                                    <div class="d-flex align-items-start mb-3">
                                        <div class="user-avatar-medium me-3">
                                            {{ (user.full_name or user.username)[0].upper() }}
                                        </div>
                                        <div class="flex-grow-1">
                                            <h5 class="card-title fw-bold mb-1">{{ user.full_name or user.username }}</h5>
                                            <p class="text-muted mb-2">@{{ user.username }}</p>
                                            {% if user.bio %}
                                            <p class="card-text mb-3">{{ user.bio }}</p>
                                            {% endif %}
                                        </div>
                                    </div>
                                    
                                    {% if user.skills %}
                                    <div class="mb-3">
                                        <h6 class="fw-semibold text-muted mb-2">
                                            <i class="fas fa-tools me-1"></i>Навыки:
                                        </h6>
                                        <div class="d-flex flex-wrap">
                                            {% for skill in user.skills.split(',') %}
                                            <span class="skills-badge">{{ skill.strip() }}</span>
                                            {% endfor %}
                                        </div>
                                    </div>
                                    {% endif %}
                                    
                                    <div class="d-grid">
                                        <a href="/chat/{{ user.id }}" class="btn btn-primary">
                                            <i class="fas fa-comment me-2"></i>Написать сообщение
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    
                    {% if not users %}
                    <div class="text-center py-5">
                        <i class="fas fa-users display-1 text-muted mb-3"></i>
                        <h3 class="text-muted">Пока нет других пользователей</h3>
                        <p class="text-muted">Пригласите друзей присоединиться к платформе!</p>
                    </div>
                    {% endif %}
                </div>
                
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        '''
    }  # <-- ЗАКРЫВАЮЩАЯ СКОБКА ДЛЯ СЛОВАРЯ templates
    
    template = templates.get(template_name)
    if template:
        from flask import render_template_string
        return render_template_string(template, **context)
    return f"Template {template_name} not found", 404

if __name__ == '__main__':
    with app.app_context():
        init_db()
        upgrade_db()  # <-- Добавьте эту строку
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
