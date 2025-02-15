from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    address = db.Column(db.String(200))
    aadhar_number = db.Column(db.String(12), unique=True)
    occupation = db.Column(db.String(100))
    monthly_salary = db.Column(db.Integer)
    loan_amount = db.Column(db.Integer)
    status = db.Column(db.String(20), default="Pending")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@login_required
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if the email and password match the hardcoded admin credentials
        if email == "admin@gmail.com" and password == "admin123":
            admin = User.query.filter_by(email=email).first()

            # If the admin user doesn't exist, create one
            if not admin:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                admin = User(email=email, password=hashed_password, is_admin=True)
                db.session.add(admin)
                db.session.commit()

            login_user(admin)
            return redirect(url_for('admin_dashboard'))

        # Check for regular users
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('user_dashboard'))

        flash('Login failed. Check email and password.', 'danger')

    return render_template('login.html')


@app.route('/user_dashboard', methods=['GET', 'POST'])

def user_dashboard():
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.age = request.form['age']
        current_user.address = request.form['address']
        current_user.aadhar_number = request.form['aadhar_number']
        current_user.occupation = request.form['occupation']
        current_user.monthly_salary = request.form['monthly_salary']
        current_user.loan_amount = request.form['loan_amount']
        db.session.commit()
        flash('Loan request submitted successfully!', 'success')
    return render_template('user_dashboard.html', user=current_user)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    users = User.query.filter(User.is_admin == False).all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/approve_loan/<int:user_id>')
@login_required
def approve_loan(user_id):
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))

    user = User.query.get(user_id)
    if user:
        user.status = "Approved"
        db.session.commit()
        send_email(user.email, "Loan Approved", "Your loan request has been approved!")
        flash(f'Loan approved for {user.email}', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# Email Function
def send_email(to, subject, message):
    msg = Message(subject, sender="your_email@gmail.com", recipients=[to])
    msg.body = message
    mail.send(msg)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
