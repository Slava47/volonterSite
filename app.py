import os
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Измените в продакшене!
app.config['DATABASE'] = 'volunteer_network.db'

# Декоратор для проверки авторизации
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Работа с базой данных
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
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
                post_type TEXT DEFAULT 'volunteer', -- volunteer/help/event
                location TEXT,
                event_date TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Маршруты аутентификации
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

# Маршруты профиля
@app.route('/profile')
@login_required
def profile():
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    
    user_posts = db.execute(
        'SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', 
        (session['user_id'],)
    ).fetchall()
    
    return render_template('profile.html', user=user, posts=user_posts)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        bio = request.form['bio']
        skills = request.form['skills']
        
        try:
            db.execute(
                '''UPDATE users 
                SET full_name = ?, email = ?, bio = ?, skills = ? 
                WHERE id = ?''',
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
    
    # Удаляем посты пользователя
    db.execute('DELETE FROM posts WHERE user_id = ?', (session['user_id'],))
    # Удаляем пользователя
    db.execute('DELETE FROM users WHERE id = ?', (session['user_id'],))
    db.commit()
    
    session.clear()
    flash('Ваш профиль был удален')
    return redirect(url_for('index'))

# Маршруты постов
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
        
        if not title or not content:
            flash('Заголовок и содержание обязательны')
            return redirect(url_for('create_post'))
        
        db = get_db()
        db.execute(
            '''INSERT INTO posts (user_id, title, content, post_type, location, event_date) 
            VALUES (?, ?, ?, ?, ?, ?)''',
            (session['user_id'], title, content, post_type, location, event_date)
        )
        db.commit()
        
        flash('Пост успешно создан!')
        return redirect(url_for('feed'))
    
    return render_template('create_post.html')

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    db = get_db()
    
    # Проверяем, что пост принадлежит пользователю
    post = db.execute(
        'SELECT * FROM posts WHERE id = ? AND user_id = ?', 
        (post_id, session['user_id'])
    ).fetchone()
    
    if post is None:
        flash('Вы не можете удалить этот пост')
        return redirect(url_for('feed'))
    
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    
    flash('Пост удален')
    return redirect(url_for('feed'))

# HTML шаблоны (встроенные в код)
def render_template(template_name, **context):
    templates = {
        'index.html': '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Волонтерская Сеть</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
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
            <head>
                <title>Регистрация - Волонтерская Сеть</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h2 class="card-title text-center">Регистрация</h2>
                                    {% with messages = get_flashed_messages() %}
                                        {% if messages %}
                                            {% for message in messages %}
                                                <div class="alert alert-danger">{{ message }}</div>
                                            {% endfor %}
                                        {% endif %}
                                    {% endwith %}
                                    <form method="POST">
                                        <div class="mb-3">
                                            <label class="form-label">Имя пользователя *</label>
                                            <input type="text" class="form-control" name="username" required>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Email *</label>
                                            <input type="email" class="form-control" name="email" required>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Полное имя</label>
                                            <input type="text" class="form-control" name="full_name">
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Пароль *</label>
                                            <input type="password" class="form-control" name="password" required>
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100">Зарегистрироваться</button>
                                    </form>
                                    <div class="text-center mt-3">
                                        <a href="/login">Уже есть аккаунт? Войдите</a>
                                    </div>
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
            <head>
                <title>Вход - Волонтерская Сеть</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="row justify-content-center">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-body">
                                    <h2 class="card-title text-center">Вход в систему</h2>
                                    {% with messages = get_flashed_messages() %}
                                        {% if messages %}
                                            {% for message in messages %}
                                                <div class="alert alert-danger">{{ message }}</div>
                                            {% endfor %}
                                        {% endif %}
                                    {% endwith %}
                                    <form method="POST">
                                        <div class="mb-3">
                                            <label class="form-label">Имя пользователя</label>
                                            <input type="text" class="form-control" name="username" required>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Пароль</label>
                                            <input type="password" class="form-control" name="password" required>
                                        </div>
                                        <button type="submit" class="btn btn-primary w-100">Войти</button>
                                    </form>
                                    <div class="text-center mt-3">
                                        <a href="/register">Нет аккаунта? Зарегистрируйтесь</a>
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
            <head>
                <title>Лента - Волонтерская Сеть</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/post/create">Создать пост</a>
                            <a class="nav-link" href="/profile">Профиль</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                
                <div class="container mt-4">
                    {% with messages = get_flashed_messages() %}
                        {% if messages %}
                            {% for message in messages %}
                                <div class="alert alert-success">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    <h2>Лента событий</h2>
                    
                    {% for post in posts %}
                    <div class="card mb-3">
                        <div class="card-body">
                            <h5 class="card-title">{{ post.title }}</h5>
                            <h6 class="card-subtitle mb-2 text-muted">
                                Автор: {{ post.full_name or post.username }}
                                {% if post.post_type == 'volunteer' %}
                                    <span class="badge bg-success">Ищу волонтеров</span>
                                {% elif post.post_type == 'help' %}
                                    <span class="badge bg-warning">Нужна помощь</span>
                                {% else %}
                                    <span class="badge bg-info">Событие</span>
                                {% endif %}
                            </h6>
                            <p class="card-text">{{ post.content }}</p>
                            {% if post.location %}
                                <p class="card-text"><small>Место: {{ post.location }}</small></p>
                            {% endif %}
                            {% if post.event_date %}
                                <p class="card-text"><small>Дата: {{ post.event_date }}</small></p>
                            {% endif %}
                            <p class="card-text"><small class="text-muted">Опубликовано: {{ post.created_at }}</small></p>
                            
                            {% if post.user_id == session['user_id'] %}
                            <form action="/post/{{ post.id }}/delete" method="POST" class="d-inline">
                                <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Удалить пост?')">Удалить</button>
                            </form>
                            {% endif %}
                        </div>
                    </div>
                    {% else %}
                    <div class="alert alert-info">Пока нет постов. Будьте первым!</div>
                    {% endfor %}
                </div>
            </body>
            </html>
        ''',
        
        'create_post.html': '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Создать пост - Волонтерская Сеть</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
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
                    <h2>Создать новый пост</h2>
                    
                    {% with messages = get_flashed_messages() %}
                        {% if messages %}
                            {% for message in messages %}
                                <div class="alert alert-danger">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    <form method="POST">
                        <div class="mb-3">
                            <label class="form-label">Тип поста</label>
                            <select class="form-select" name="post_type" required>
                                <option value="volunteer">Ищу волонтеров</option>
                                <option value="help">Нужна помощь</option>
                                <option value="event">Событие</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Заголовок *</label>
                            <input type="text" class="form-control" name="title" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Содержание *</label>
                            <textarea class="form-control" name="content" rows="5" required></textarea>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Место проведения</label>
                            <input type="text" class="form-control" name="location">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Дата события</label>
                            <input type="datetime-local" class="form-control" name="event_date">
                        </div>
                        <button type="submit" class="btn btn-primary">Опубликовать</button>
                        <a href="/feed" class="btn btn-secondary">Отмена</a>
                    </form>
                </div>
            </body>
            </html>
        ''',
        
        'profile.html': '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Профиль - Волонтерская Сеть</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                    <div class="container">
                        <a class="navbar-brand" href="/feed">🎗️ Волонтерская Сеть</a>
                        <div class="navbar-nav ms-auto">
                            <a class="nav-link" href="/feed">Лента</a>
                            <a class="nav-link" href="/post/create">Создать пост</a>
                            <a class="nav-link" href="/logout">Выйти</a>
                        </div>
                    </div>
                </nav>
                
                <div class="container mt-4">
                    {% with messages = get_flashed_messages() %}
                        {% if messages %}
                            {% for message in messages %}
                                <div class="alert alert-success">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    <div class="row">
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-body">
                                    <h3 class="card-title">{{ user.full_name or user.username }}</h3>
                                    <p class="text-muted">@{{ user.username }}</p>
                                    {% if user.bio %}
                                        <p>{{ user.bio }}</p>
                                    {% endif %}
                                    {% if user.skills %}
                                        <p><strong>Навыки:</strong> {{ user.skills }}</p>
                                    {% endif %}
                                    <p class="text-muted">Участник с {{ user.created_at[:10] }}</p>
                                    
                                    <div class="mt-3">
                                        <a href="/profile/edit" class="btn btn-primary me-2">Редактировать</a>
                                        <form action="/profile/delete" method="POST" class="d-inline" onsubmit="return confirm('Удалить профиль? Это действие нельзя отменить!')">
                                            <button type="submit" class="btn btn-danger">Удалить профиль</button>
                                        </form>
                                    </div>
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
                                    
                                    <form action="/post/{{ post.id }}/delete" method="POST" class="d-inline">
                                        <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Удалить пост?')">Удалить</button>
                                    </form>
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
            <head>
                <title>Редактирование профиля - Волонтерская Сеть</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
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
                    
                    {% with messages = get_flashed_messages() %}
                        {% if messages %}
                            {% for message in messages %}
                                <div class="alert alert-danger">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    
                    <form method="POST">
                        <div class="mb-3">
                            <label class="form-label">Полное имя</label>
                            <input type="text" class="form-control" name="full_name" value="{{ user.full_name or '' }}">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Email *</label>
                            <input type="email" class="form-control" name="email" value="{{ user.email }}" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">О себе</label>
                            <textarea class="form-control" name="bio" rows="3">{{ user.bio or '' }}</textarea>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Навыки (через запятую)</label>
                            <input type="text" class="form-control" name="skills" value="{{ user.skills or '' }}">
                            <div class="form-text">Например: организация мероприятий, работа с детьми, медицинская помощь</div>
                        </div>
                        <button type="submit" class="btn btn-primary">Сохранить</button>
                        <a href="/profile" class="btn btn-secondary">Отмена</a>
                    </form>
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
    app.run(host='0.0.0.0', port=5000, debug=True)
