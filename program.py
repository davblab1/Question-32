"""
Завдання: Створити додаток, який реалізує авторизацію на основі ролей (RBAC).
Використайте фреймворк Spring Security, налаштуйте два рівні доступу (наприклад, ROLE_USER та ROLE_ADMIN),
 перевірте доступ до різних URL шляхом конфігурації безпеки.

Оскільки завдання стосується створення додатка на основі Spring Security для авторизації за ролями (RBAC), а мова Python 
не підтримує Spring, я реалізував це завдання за допомогою бібліотеки Flask та Flask-Login для авторизації, 
а також Flask-Principal для ролей та доступу.

Принцип роботи:
#Після запуску переходимо за посиланням http://127.0.0.1:5000, з'являємося на головному меню home.html
Вводимо дані з users
Користувач має доступ лише до сторінки користувача, а адмін - до усіх сторінок.
"""

from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_principal import Principal, RoleNeed, Permission

app = Flask(__name__, template_folder='html')
app.secret_key = 'whatever_key'

login_manager = LoginManager(app)
login_manager.login_view = 'login'
principal = Principal(app)

ROLE_USER = RoleNeed('ROLE_USER')
ROLE_ADMIN = RoleNeed('ROLE_ADMIN')

users = {
    'user': {'password': 'userpass', 'role': 'ROLE_USER'},
    'admin': {'password': 'adminpass', 'role': 'ROLE_ADMIN'}
}

class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role
    
    def get_role(self):
        return self.role

@login_manager.user_loader
def load_user(user_id):
    role = users.get(user_id, {}).get('role', None)
    if role:
        return User(user_id, role)
    return None

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users.get(username)
        if user and user['password'] == password:
            user_obj = User(username, user['role'])
            login_user(user_obj)
            return redirect(url_for('home'))
        else:
            return 'Невірний логін або пароль'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/user')
@login_required
def user_page():
    if current_user.get_role() != 'ROLE_USER' and current_user.get_role() != 'ROLE_ADMIN':
        return 'У вас немає доступу до цієї сторінки.'
    return 'Сторінка користувача'

@app.route('/admin')
@login_required
def admin_page():
    if current_user.get_role() != 'ROLE_ADMIN':
        return 'У вас немає доступу до цієї сторінки.'
    return 'Сторінка адміністратора'

if __name__ == '__main__':
    app.run(debug=True)