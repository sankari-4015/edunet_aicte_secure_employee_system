from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import random

# ------------------- INIT -------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "home"

# ------------------- MODELS -------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="employee")  # 'admin' or 'employee'
    failed_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    leave_balance = db.Column(db.Integer, default=12)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.Date, default=datetime.utcnow().date)
    check_in = db.Column(db.DateTime)
    check_out = db.Column(db.DateTime)
    late = db.Column(db.Boolean, default=False)
    overtime_hours = db.Column(db.Float, default=0)

class Leave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    from_date = db.Column(db.Date)
    to_date = db.Column(db.Date)
    reason = db.Column(db.String(200))
    status = db.Column(db.String(20), default="Pending")
# ------------------- LOGIN MANAGER -------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for("home"))

# ------------------- HELPER FUNCTIONS -------------------
def generate_captcha():
    num1 = random.randint(1, 9)
    num2 = random.randint(1, 9)
    session['captcha'] = num1 + num2
    return f"{num1} + {num2} = ?"

def login_handler(role_type):
    if current_user.is_authenticated:
        logout_user()

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        try:
            captcha_answer = int(request.form.get("captcha", 0))
        except:
            captcha_answer = 0

        if captcha_answer != session.get("captcha"):
            flash("Invalid CAPTCHA")
            return redirect(request.url)

        user = User.query.filter_by(email=email, role=role_type).first()

        if not user:
            flash("No user found with this role")
            return redirect(request.url)

        if user.account_locked:
            flash("Account locked! Contact Admin.")
            return redirect(request.url)

        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            user.failed_attempts = 0
            db.session.add(LoginAttempt(email=email, success=True))
            db.session.commit()

            flash(f"{role_type.capitalize()} login successful!")
            if role_type == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("employee_dashboard"))

        else:
            user.failed_attempts += 1
            remaining_attempts = 3 - user.failed_attempts
            if remaining_attempts <= 0:
                user.account_locked = True
                flash("Account locked due to too many invalid attempts!")
            else:
                flash(f"Invalid credentials! {remaining_attempts} attempts left before lock.")

            db.session.add(LoginAttempt(email=email, success=False))
            db.session.commit()
            return redirect(request.url)

    captcha_question = generate_captcha()
    return render_template("login.html", role=role_type, captcha=captcha_question)

# ------------------- ROUTES -------------------
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/employee-login", methods=["GET", "POST"])
def employee_login():
    return login_handler("employee")

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    return login_handler("admin")

@app.route("/employee-dashboard")
@login_required
def employee_dashboard():
    if current_user.role != "employee":
        flash("Unauthorized Access")
        return redirect(url_for("home"))

    attendances = Attendance.query.filter_by(employee_id=current_user.id).order_by(Attendance.date.desc()).all()
    leaves = Leave.query.filter_by(employee_id=current_user.id).order_by(Leave.from_date.desc()).all()

    return render_template("employee_dashboard.html", attendances=attendances, leaves=leaves)

@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Unauthorized Access")
        return redirect(url_for("home"))

    users = User.query.all()
    leaves = Leave.query.order_by(Leave.from_date.desc()).all()
    attendances = Attendance.query.order_by(Attendance.date.desc()).all()
    return render_template("admin_dashboard.html", users=users, leaves=leaves, attendances=attendances)

@app.route("/unlock/<int:user_id>")
@login_required
def unlock(user_id):
    if current_user.role != "admin":
        flash("Unauthorized Access")
        return redirect(url_for("home"))
    user = User.query.get(user_id)
    if user:
        user.account_locked = False
        user.failed_attempts = 0
        db.session.commit()
        flash(f"{user.name}'s account unlocked!")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/login-attempts")
@login_required
def login_attempts():
    if current_user.role != "admin":
        flash("Unauthorized Access")
        return redirect(url_for("home"))
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(20).all()
    return render_template("login_attempts.html", attempts=attempts)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter_by(email=email).first():
            flash("Email already exists!")
            return redirect(url_for("register"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(name=name, email=email, password=hashed_pw, role="employee")
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully! Please login.")
        return redirect(url_for("employee_login"))

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!")
    return redirect(url_for("home"))

# ------------------- ATTENDANCE ROUTES -------------------
@app.route("/checkin")
@login_required
def checkin():
    if current_user.role != "employee":
        flash("Unauthorized Access")
        return redirect(url_for("home"))

    today = datetime.utcnow().date()
    existing = Attendance.query.filter_by(employee_id=current_user.id, date=today).first()

    if existing:
        flash("Already checked in today!")
        return redirect(url_for("employee_dashboard"))

    now = datetime.utcnow()
    late = now.hour > 9  # after 9 AM = late

    attendance = Attendance(employee_id=current_user.id, check_in=now, late=late)
    db.session.add(attendance)
    db.session.commit()
    flash("Checked in successfully!")
    return redirect(url_for("employee_dashboard"))

@app.route("/checkout")
@login_required
def checkout():
    if current_user.role != "employee":
        flash("Unauthorized Access")
        return redirect(url_for("home"))

    today = datetime.utcnow().date()
    attendance = Attendance.query.filter_by(employee_id=current_user.id, date=today).first()

    if not attendance or not attendance.check_in:
        flash("No check-in found!")
        return redirect(url_for("employee_dashboard"))

    if attendance.check_out:
        flash("Already checked out!")
        return redirect(url_for("employee_dashboard"))

    now = datetime.utcnow()
    attendance.check_out = now

    work_hours = (now - attendance.check_in).seconds / 3600
    if work_hours > 8:
        attendance.overtime_hours = work_hours - 8

    db.session.commit()
    flash("Checked out successfully!")
    return redirect(url_for("employee_dashboard"))

# ------------------- LEAVE ROUTES -------------------
@app.route("/apply-leave", methods=["POST"])
@login_required
def apply_leave():
    if current_user.role != "employee":
        flash("Unauthorized Access")
        return redirect(url_for("home"))

    from_date = datetime.strptime(request.form.get("from_date"), "%Y-%m-%d").date()
    to_date = datetime.strptime(request.form.get("to_date"), "%Y-%m-%d").date()
    reason = request.form.get("reason")

    leave = Leave(employee_id=current_user.id, from_date=from_date, to_date=to_date, reason=reason)
    db.session.add(leave)
    db.session.commit()

    flash("Leave request submitted!")
    return redirect(url_for("employee_dashboard"))

@app.route("/approve-leave/<int:leave_id>")
@login_required
def approve_leave(leave_id):
    if current_user.role != "admin":
        flash("Unauthorized Access")
        return redirect(url_for("home"))

    leave = Leave.query.get(leave_id)
    if leave:
        leave.status = "Approved"
        # Deduct leave balance
        days = (leave.to_date - leave.from_date).days + 1
        user = User.query.get(leave.employee_id)
        user.leave_balance -= days
        db.session.commit()
        flash("Leave approved!")

    return redirect(url_for("admin_dashboard"))

# ------------------- NEW PAGES FOR ATTENDANCE AND LEAVE FORM -------------------
@app.route("/attendance")
@login_required
def attendance_page():
    if current_user.role != "employee":
        flash("Unauthorized Access")
        return redirect(url_for("home"))
    return render_template("attendance.html")

@app.route("/leave-request")
@login_required
def leave_request_page():
    if current_user.role != "employee":
        flash("Unauthorized Access")
        return redirect(url_for("home"))
    return render_template("leave_request.html")

# ------------------- MAIN -------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Auto-create admin if not exists
        if not User.query.filter_by(email="admin@gmail.com").first():
            hashed_pw = bcrypt.generate_password_hash("admin123").decode("utf-8")
            admin = User(name="Admin", email="admin@gmail.com", password=hashed_pw, role="admin")
            db.session.add(admin)
            db.session.commit()
            print("Admin Created Successfully!")

    app.run(debug=True)
