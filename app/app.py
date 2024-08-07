# app.py
from flask import Flask, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import secrets

# Create the Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16) # Generate a random secret key

# Create the LoginManager object
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, id):
        self.id = id

    
# Create a user loader function
@login_manager.user_loader
def load_user(user_id):
    # For this example, we are just creating a new User object with the given user_id
    # In a real application, you would query your database to get the user object
    return User(user_id)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    user = User(id=1) #EXAMPLE USER
    login_user(user)
    return 'Logged in as: ' + str(current_user.id)

@app.route('/protected')
@login_required
def protected():
    return 'Logged in as: ' + str(current_user.id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out'


if __name__ == '__main__':
    app.run(debug=True)