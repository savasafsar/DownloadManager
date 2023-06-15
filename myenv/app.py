import os
import threading
import wget
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask.helpers import get_root_path

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Kullanıcı modeli
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)

# Dosya modeli
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('files', lazy=True))
    progress = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='In Progress')
    is_active = db.Column(db.Boolean, default=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Bu kullanıcı adı zaten kullanılıyor.', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        flash('Kayıt işlemi başarıyla tamamlandı. Giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        urls = request.form.getlist('url')

        threads = []
        for url in urls:
            t = threading.Thread(target=download_file, args=(url, current_user if current_user.is_authenticated else None))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        flash('Dosya indirme işlemi tamamlandı.', 'success')

        return redirect(url_for('home'))

    files = current_user.files
    return render_template('home.html', files=files)

def download_file(url, user):
    try:
        file_name = url.split('/')[-1]
        file_path = os.path.join(get_root_path(__name__), file_name)

        destination_folder = os.path.join(get_root_path(__name__), 'downloaded_files')
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)

        def progress_callback(current, total):
            progress = int((current / total) * 100)
            user_file = File.query.filter_by(name=file_name, user=user).first()
            if user_file:
                user_file.progress = progress
                db.session.commit()

        wget.download(url, file_path, bar=progress_callback)

        os.rename(file_path, os.path.join(destination_folder, file_name))

    except Exception as e:
        print(f"Hata oluştu: {str(e)}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            flash('Geçersiz kullanıcı adı veya parola.', 'error')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('login'))

@app.route('/progress', methods=['POST'])
@login_required
def progress():
    file_id = request.form['file_id']
    user_file = File.query.get(file_id)
    if user_file:
        return jsonify({'progress': user_file.progress})
    else:
        return jsonify({'progress': None})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
