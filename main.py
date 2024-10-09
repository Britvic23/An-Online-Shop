import secrets
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, current_user, login_required, LoginManager
from werkzeug.security import check_password_hash, generate_password_hash
import stripe
import os
from flask_login import UserMixin
from sqlalchemy.orm import DeclarativeBase
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)

app.config['SECRET_KEY'] = secrets.token_hex(32)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(500), nullable=False)
    image = db.Column(db.String(200), nullable=False)


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, nullable=False)
    product = db.relationship('Product', backref='cart_items')
    user = db.relationship('User', backref='cart_items')


with app.app_context():
    db.create_all()


def seed_data():
    with app.app_context():
        if not Product.query.first():  
            products = [
                Product(name='Cozy Orthopedic Dog Bed', price=49.99, stock=10, description='Orthopedic dog bed for superior comfort.', image='assets/img/dog_bed.jpg'),
                Product(name='Squeaky Dog Toy', price=14.99, stock=20, description='Fun and interactive dog toy.', image='assets/img/download (3).jpg'),
                Product(name='Premium Dog Food', price=34.99, stock=15, description='Grain-free, all-natural dog food.', image='assets/img/dog_food.jpg'),
                Product(name='Stylish Dog Collar', price=19.99, stock=30, description='Durable and stylish collar for your dog.', image='assets/img/dog_collar.jpg')
            ]
            db.session.bulk_save_objects(products)
            db.session.commit()


seed_data()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate input
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please log in.', 'danger')
            return render_template('register.html')

        # Hash the password before saving
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Create a new user and add them to the database
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # check if the user exists
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        elif email and password != user:
            flash('Invalid email and password', 'danger')
            return render_template('login.html')
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)


@app.route('/cart')
@login_required
def cart():
    items = Cart.query.filter_by(user_id=current_user.id).all()
    return render_template('cart.html', items=items)


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    quantity = int(request.form.get('quantity', 1))

    cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product.id).first()

    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = Cart(user_id=current_user.id, product_id=product.id, quantity=quantity)
        db.session.add(cart_item)

    db.session.commit()
    flash(f'{product.name} added to your cart!', 'success')

    return redirect(url_for('index'))


@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    # Get items in the user's cart
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()

    # Calculate the total amount
    total_amount = sum(item.product.price * item.quantity for item in cart_items)

    token = request.form.get('stripeToken')
    print(f'Stripe token: {token}')
    if not token:
        flash('Payment failed: Stripe token missing', 'danger')
        return redirect(url_for('cart'))

    try:
        # Stripe payment processing
        charge = stripe.Charge.create(
            amount=int(total_amount * 100),  # Convert dollars to cents for Stripe
            currency='usd',
            description='Ecommerce purchase',
            source=token
        )
        flash('Payment Successful!', 'success')

        # Clear the cart after successful payment
        Cart.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()

        return redirect(url_for('index'))
    except stripe.error.StripeError as e:
        flash(f'Payment failed: {str(e)}', 'danger')
        return redirect(url_for('cart'))


if __name__ == '__main__':
    app.run(debug=True)