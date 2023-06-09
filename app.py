from flask import Flask, flash, render_template, url_for, redirect,session, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TelField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import bcrypt
from datetime import datetime
from flask_migrate import Migrate
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView








app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'Achraf123'
app.config['TIMEZONE'] = 'your_timezone_here'
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)




    

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(30), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='user', passive_deletes=True)
    comments = db.relationship('Comment', backref='user', passive_deletes=True)








class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    email = StringField(validators=[
        InputRequired(), Length(min=10, max=30)], render_kw={"placeholder": "Email"})
    
    phone = TelField(validators=[
                           InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Phone Number"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')
        





class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=26)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if not existing_user_username:
            raise ValidationError(
                "That username dosent exists.")


class Post(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(60), nullable=False)
    text = db.Column(db.String(255), nullable=False)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    author = db.Column(db.Integer(), db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)
    comments = db.relationship('Comment', backref="post", passive_deletes=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    author = db.Column(db.Integer, db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey(
        'post.id', ondelete="CASCADE"), nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    start = db.Column(db.DateTime(timezone=True))
    end = db.Column(db.DateTime(timezone=True))
    url = db.Column(db.String(200))
    


class CommentForm(FlaskForm):
    text = StringField(validators=[
        InputRequired(), Length(min=4, max=26)], render_kw={"placeholder": "comment some"})

    submit = SubmitField('Comment')


class PostForm(FlaskForm):
    text = StringField(validators=[
        InputRequired(), Length(min=4, max=500)], render_kw={"placeholder": "Your Post here"})
    
    title = StringField(validators=[
        InputRequired(), Length(min=4, max=60)], render_kw={"placeholder": "Your Title here"})
    
    

    submit = SubmitField('Post')


class UserModelView(ModelView):
    def is_accessible(self):
        
        if current_user.is_authenticated and current_user.is_admin:
            return True
        return False

    def inaccessible_callback(self):
        
        if not current_user.is_authenticated:
            return redirect(url_for('admin_login'))
        else:
            flash('ERROR',category='error')


class PostModelView(ModelView):
    def is_accessible(self):
        
        if current_user.is_authenticated and current_user.is_admin:
            return True
        return False

    def inaccessible_callback(self):
        
        if not current_user.is_authenticated:
            return redirect(url_for('admin_login'))
        else:
            flash('ERROR',category='error')

class CommentModelView(ModelView):
    def is_accessible(self):
        
        if current_user.is_authenticated and current_user.is_admin:
            return True
        return False

    def inaccessible_callback(self):
        
        if not current_user.is_authenticated:
            return redirect(url_for('admin_login'))
        else:
            flash('ERROR',category='error')

class EventModelView(ModelView):
    def is_accessible(self):
        
        if current_user.is_authenticated and current_user.is_admin:
            return True
        return False

    def inaccessible_callback(self):
        
        if not current_user.is_authenticated:
            return redirect(url_for('admin_login'))
        else:
            flash('ERROR',category='error')

class UserModelView(ModelView):
    column_searchable_list = ['username', 'email']
    column_filters = ['is_admin']
    form_columns = ['username', 'email', 'phone', 'is_admin']

class PostModelView(ModelView):
    column_searchable_list = ['title', 'text']
    column_filters = ['author']

class CommentModelView(ModelView):
    column_searchable_list = ['text']
    column_filters = ['author']

class EventModelView(ModelView):
    column_searchable_list = ['title']
    column_filters = ['start', 'end']

admin = Admin(app, name='Admin Dashboard')

admin.add_view(UserModelView(User, db.session))
admin.add_view(PostModelView(Post, db.session))
admin.add_view(CommentModelView(Comment, db.session))
admin.add_view(EventModelView(Event, db.session))

@app.before_first_request
def create_tables():


    return db.create_all()


@app.route('/')
def home():
    return render_template('home.html', user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        phone = request.form.get("phone")
        user_ex = User.query.filter_by(username=username).first()
        email_ex = User.query.filter_by(email=email).first()
        phone_ex = User.query.filter_by(phone=phone).first()
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        is_admin = False

        if user_ex:
            flash('Username already exist. PLease try a different  one',
                  category="error")

        elif email_ex:
            flash('Email already exist. PLease try a different one', category="error")

        elif phone_ex:
            flash('Phone Number already exist. PLease try a different one', category="error")

        else:
            new_user = User(username=form.username.data,
                            password=hashed_password, email=form.email.data, phone= form.phone.data)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))

    return render_template('register.html', form=form, user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Username or password incorrect. Please try again. ',
                      category="error")

    return render_template('login.html', form=form, user=current_user)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


#################################################################################################

# admin stuff

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    form = RegisterForm()
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        is_admin = True  
        admin_user = User(username=username, email=email, password=hashed_password, phone=phone,  is_admin=is_admin)
        db.session.add(admin_user)
        db.session.commit()

        return redirect(url_for('admin_login'))
    
    return render_template('admin_register.html',user= current_user,form=form)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form= LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        admin = User.query.filter_by(username=username, is_admin=True).first()

        if admin and bcrypt.check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials', category='error')

    return render_template('admin_login.html',user= current_user, form=form)


@app.route('/admin/logout', methods=['GET', 'POST'])
def admin_logout():
    session.pop('admin_id', None)  
    return redirect(url_for('admin_login'))


    

@app.route('/admin/dashboard',methods=['GET', 'POST'])
def admin_dashboard():
    form= LoginForm()
    if 'admin_id' in session:
        admin_id = session['admin_id']
        admin = User.query.get(admin_id)
        return redirect(url_for('admin.index'))
    
    else:
        flash('Permission denied. Please log in as an admin.') 
        
       

    return render_template('admin_login.html',user= current_user,form=form)

######################################################################################


@app.route("/dashboard")
@login_required
def dashboard():
    form = CommentForm()
    posts = Post.query.all()
    post = post = Post.query.filter_by().first()

    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))

    return render_template("dashboard.html",  user=current_user, posts=posts,  post=post, form=form)


@app.route("/create-post", methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        text = form.text.data 
        post = Post(text=text, title=title, author=current_user.id)
        db.session.add(post)
        db.session.commit()
        flash('Post created!', category='success')
        return redirect(url_for('dashboard'))

    return render_template('create_post.html', user=current_user, form=form)


@app.route("/posts/<username>")
@login_required
def posts(username):
    form = CommentForm()
    post = Post.query.filter_by().first()
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("No User with that username exists.", category="error")
        return redirect(url_for('dashboard'))
    posts = user.posts
    return render_template('posts.html', user=current_user, posts=posts, post=post, username=username, form=form)


@app.route('/update/post/<id>', methods=['GET', 'POST'])
@login_required
def update_post(id):
    form = PostForm()
    post_to_up = Post.query.get(id)
    if post_to_up:
        if request.method == 'POST':
            new_text = form.text.data
            post_to_up.text = new_text
            post_to_up.date_created = func.now()
            db.session.commit()
            flash("Your post has been updated", category='success')
            return redirect(url_for("dashboard"))

        return render_template('update_post.html', user=current_user, post=post_to_up, form=form)
    else:
        flash("Post not found", category='error')
        return redirect(url_for("dashboard"))


@app.route("/delete-post/<id>", methods=['GET', 'POST'])
@login_required
def delete_post(id):
    post = Post.query.filter_by(id=id).first()
    if post:
        db.session.delete(post)
        db.session.commit()
        flash("Post Deleted.", category='success')
    return redirect(url_for('dashboard'))


@app.route("/create-comment/<post_id>", methods=['POST'])
@login_required
def create_comment(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        text = form.text.data
        post = Post.query.filter_by(id=post_id).first()
        if post:
            comment = Comment(
                text=text, author=current_user.id, post_id=post_id)
            db.session.add(comment)
            db.session.commit()
            flash('Comment created', category='success')
        else:
            flash('Post does not exist!', category='error')
    else:
        flash('Invalid comment form', category='error')

    return redirect(url_for("dashboard"))


@app.route('/update-comment/<id>', methods=['GET', 'POST'])
@login_required
def update_comment(id):
    form = CommentForm()
    comment_to_up = Comment.query.filter_by(id=id).first()
    post = Post.query.get(id)
    if comment_to_up:
        if request.method == 'POST':
            new_comment = form.text.data
            comment_to_up.text = new_comment
            comment_to_up.date = func.now()
            db.session.commit()
            flash("Your comment has been updated", category='success')
            return redirect(url_for("dashboard"))

        return render_template('update_comment.html', user=current_user, comment=comment_to_up, post=post, form=form)
    else:
        flash("Post not found", category='error')
        return redirect(url_for("dashboard"))


@app.route('/delete-comment/<id>', methods=['GET', 'POST'])
@login_required
def delete_comment(id):
    comment = Comment.query.filter_by(id=id).first()
    if comment:
        db.session.delete(comment)
        db.session.commit()
        flash('comment deleted!.', category='success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = CommentForm()
    post = Post.query.all()
    if current_user.is_authenticated:
        return render_template('profile.html',user =current_user, post=post, form=form)


# @app.route('/change_password/<id>', methods=['POST'])
# def change_password(id):
#     form= LoginForm()
#     user = User.query.filter_by(username=form.username.data).first()
#     password_to_change = User.query.get(id)
#     if password_to_change :
#         if not bcrypt.check_password_hash(current_user.password, form.password.data):
#             flash('Incorrect current password. Please try again.')
#             return redirect(url_for('profile'))
#         else:
#             new_password = bcrypt.generate_password_hash(form.password.data)
#             password_to_change.password = new_password
#             db.session.commit()
#         flash('your pass changed', category='success')

        





# create calendar 


@app.route('/calendar', methods=['GET', 'POST'])
@login_required
def calendar():
    posts = Post.query.all()
    events=Event.query.all()
    post =  Post.query.filter_by().first()
    return render_template("calendar.html", user=current_user, posts=posts,events=events , post=post)





@app.route('/calendar/add-event', methods=['GET', 'POST'])
def add_event():
    if request.method == 'POST':
        title = request.form['title']
        start_str = request.form['start']
        end_str = request.form['end']
        url = request.form['url']

        start = datetime.strptime(start_str, '%Y-%m-%d')
        end = datetime.strptime(end_str, '%Y-%m-%d') if end_str else start
         
        event = Event(title=title, start=start, end=end,url=url)
        db.session.add(event)
        db.session.commit()
        flash('Event added successfully', category='success')
        return redirect(url_for('calendar'))

    return render_template('add_event.html',user=current_user)



if __name__ == "__main__":
   
    app.run(debug=True)
