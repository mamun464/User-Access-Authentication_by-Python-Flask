import base64
import os

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from sqlalchemy import exc, LargeBinary
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length, EqualTo

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/Profile Img'
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100),nullable=False)
    name = db.Column(db.String(1000),nullable=False)
    image_data = db.Column(LargeBinary,nullable=False)
#Line below only required once, when creating DB. 
with app.app_context():
    db.create_all()

def user_data_loader():
    if current_user.is_authenticated:
        account_name = current_user.name
        if current_user.image_data:
            image_data = current_user.image_data
            profile_image_url = f"data:image/jpeg;base64,{base64.b64encode(image_data).decode('utf-8')}"
            return (account_name,profile_image_url)
        else:
            return ("","")
    else:
        return ("", "")

@app.route('/')
def home():

    data=user_data_loader()
    return render_template("index.html", name=data[0],profile_image_url=data[1], logged_in=current_user.is_authenticated)


class ContactRegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(message='* Password is required.'),
        Length(min=8, message='* Password must be at least 8 characters long.'),
        EqualTo('confirm_password', message='* Passwords must match.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='* Please confirm your password.')
    ])
    image = FileField('Profile Image', validators=[FileAllowed(['jpg', 'jpeg', 'png'], '* Support "jpeg, jpg, png" format only ')])


@app.route('/register', methods=["POST", "GET"])
def register():
    logout_user()
    register_form = ContactRegisterForm()
    if register_form.validate_on_submit():
        #Process the form data

        try:
            image_filename = None
            error_img=None
            error_email=None
            print(register_form.image.data)
            if register_form.image.data:
                image = register_form.image.data
                #image_filename = secure_filename(image.filename)
                image_data = image.read()  # Read image file as binary data
                image.seek(0)  # Reset file pointer to the beginning
                #image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))  # Save the file to disk
            else:
                print("Update The form")
            New_user= User(
                name=register_form.name.data,
                email = register_form.email.data,
                password = generate_password_hash(register_form.password.data,method='pbkdf2:sha256',salt_length=8),
                image_data=image_data
            )
            db.session.add(New_user)
            db.session.commit()
            login_user(New_user)
            return redirect(url_for("secrets"))
        except exc.IntegrityError as e:
            db.session.rollback()
            error_message = e.args[0]
            if "UNIQUE" in error_message.upper():
                error_email = "* Email address already exists."

            elif "user.image_data" in error_message:
                error_img = "* Required Profile Picture."
            return render_template('register.html', error_email=error_email,error_img=error_img, form=register_form)


    return render_template('register.html', form=register_form)


@app.route('/download/')
def download_file():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):

    email = StringField('Email Address', validators=[DataRequired(message='* Email is required.'), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(message='* Password is required.'),
        Length(min=8, message='* Password must be at least 8 characters long.')
    ])



@app.route('/login',methods=["POST", "GET"])
def login():
    logout_user()

    login_form=LoginForm()
    Unauthorized_error=request.args.get("Unauthorized_error")
    if Unauthorized_error:
        flash(Unauthorized_error)

    if login_form.validate_on_submit():
        if request.method == "POST":
            email=login_form.email.data
            password = login_form.password.data
            user=User.query.filter_by(email=email).first()
            if user is not None:
                if check_password_hash(user.password, password):
                    login_user(user)

                    return redirect(url_for('secrets'))
                else:
                    error = "Incorrect Password. Please try again."
                    return render_template("login.html", error_pass=error, form=login_form)
            else:
                error="* No account found. Try again or Sign Up."
                return render_template("login.html",error_email= error,form=login_form,logged_in=current_user.is_authenticated)


    return render_template("login.html",form=login_form)


@app.errorhandler(401)
def unauthorized(error):
    # Handle the unauthorized error here
    # For example, you can redirect the user to the login page with an error message
    return redirect(url_for('login', Unauthorized_error="Unauthorized Access. Please login first."))

@app.route('/secrets')
@login_required
def secrets():
    data = user_data_loader()
    return render_template("secrets.html",name=data[0],profile_image_url=data[1],logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/download')
def download():
    pass


if __name__ == "__main__":
    app.run(debug=True)
