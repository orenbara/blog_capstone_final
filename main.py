from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, Integer
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# Gravatar:
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure LoginManger - required for flask_login system.
login_manager = LoginManager()
login_manager.init_app(app)


# Login Manger, is required to reload the user-id from the session:
@login_manager.user_loader
def load_user(user_id):
    # print(type(User.query.get(int(user_id))))
    return User.query.get(int(user_id))


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    # One to many bidirectional relationship
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    ## Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    ## Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Relationship with Comments:
    comments = relationship("Comment", back_populates="blog_post")


class Comment(UserMixin, db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    # Relations with User
    comment_author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    # Relations with comments:
    blog_post = relationship("BlogPost", back_populates="comments")
    blog_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))

# Run once to create db
# db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=("GET", "POST"))
def register():
    form = RegisterForm()
    if request.method == "POST":
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        if form.validate_on_submit():
            if User.query.filter_by(email=form.email.data).first():
                flash("Email already exists in db, you were redirected to login page")
                return redirect(url_for("login"))

            new_user = User(
                name=form.name.data,
                password=hash_and_salted_password,
                email=form.email.data,
            )

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts", logged_in=new_user.is_authenticated))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=("GET", "POST"))
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            email = request.form.get('email')
            password = request.form.get('password')

            # Find user by email entered.
            user = User.query.filter_by(email=email).first()
            if not user:
                flash("That email does not exist, please try again.")
                return redirect(url_for('login'))

            # Check stored password hash against entered password hashed.
            if not check_password_hash(user.password, password):
                flash('Password incorrect, please try again.')
                return redirect(url_for('login'))
            else:
                login_user(user)
                return redirect(url_for('get_all_posts', current_user=current_user, logged_in=current_user.is_authenticated))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=("GET", "POST"))
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if request.method == "POST":
        if comment_form.validate_on_submit():
            if not current_user.is_authenticated:
                flash("Only logged-in user can comment, you were redirected to login page")
                return redirect(url_for("login"))
        new_comment = Comment(
           text=comment_form.comment.data,
           comment_author=current_user,
           author_id=current_user.id,
           blog_post_id=requested_post.id
        )
        db.session.add(new_comment)
        db.session.commit()
        # return redirect(url_for("show_post", post_id=post_id))
        print(f"Logsssss:   {requested_post.comments}")
    return render_template("post.html", post=requested_post, form=comment_form, all_comments=requested_post.comments, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1 and current_user.id != 2:
            print(current_user.id)
            return abort(403, description="You are not admin - user id 1")
        return f(*args, **kwargs)

    return decorated_function


@app.route("/new-post", methods=("GET", "POST"))
@login_required
def add_new_post():
    form = CreatePostForm()
    if request.method == "POST":
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y"),
                author_id=current_user.id
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts", logged_in=current_user.is_authenticated))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=("GET", "POST"))
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, logged_in=current_user.is_authenticated))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
