import os
import pytz
import stripe
from decimal import Decimal, ROUND_HALF_UP
import pathlib
from sqlite3 import IntegrityError
from forms import ContactForm, LoginForm, RegistrationForm, GenderForm, ProfileForm,EditUserForm,DeleteUserForm,ForgotPasswordForm,OTPForm,ResetPasswordForm,ProductEditForm,DeleteProductForm,AddProductForm,AddCategoryForm,CategoryForm
from flask import Flask, render_template, redirect, url_for, flash, session, abort, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Text, DateTime, Boolean, Float, ForeignKey,JSON
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from typing import List, Dict
import smtplib
import secrets
from dotenv import load_dotenv
from sqlalchemy import func
from functools import wraps
import requests
from datetime import datetime,timedelta
from functools import wraps
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Configure Flask-Login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create a user_loader callback to reload the user from the user_id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Base(db.Model):
    __abstract__ = True

# User Model
class User(UserMixin, Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    gender: Mapped[str] = mapped_column(String(50), nullable=True)

    orders: Mapped[List['Order']] = relationship("Order", back_populates="user")
    cart: Mapped["Cart"] = relationship("Cart", back_populates="user", uselist=False)

# Category Model
class Category(Base):
    __tablename__ = 'categories'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    thumbnail: Mapped[str] = mapped_column(String(255), nullable=True)

    products: Mapped[List['Product']] = relationship('Product', back_populates='category')

# Product Model
class Product(Base):
    __tablename__ = 'products'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    price: Mapped[float] = mapped_column(Float, nullable=False)
    stock: Mapped[int] = mapped_column(Integer, default=0)
    rating: Mapped[float] = mapped_column(Float, nullable=True)  # Updated to Mapped

    # Additional Fields
    tags: Mapped[Dict] = mapped_column(JSON, nullable=True)  # JSON type to store tags as an array
    brand: Mapped[str] = mapped_column(String(100), nullable=True)
    sku: Mapped[str] = mapped_column(String(50), nullable=True)
    weight: Mapped[float] = mapped_column(Float, nullable=True)

    # Nested dimensions as JSON to store width, height, and depth
    dimensions: Mapped[Dict] = mapped_column(JSON, nullable=True)

    warranty_information: Mapped[str] = mapped_column(String(100), nullable=True)
    shipping_information: Mapped[str] = mapped_column(String(100), nullable=True)
    availability_status: Mapped[str] = mapped_column(String(50), nullable=True)
    return_policy: Mapped[str] = mapped_column(String(100), nullable=True)
    minimum_order_quantity: Mapped[int] = mapped_column(Integer, nullable=True)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, onupdate=datetime.utcnow)
    barcode: Mapped[str] = mapped_column(String(50), nullable=True)
    qr_code: Mapped[str] = mapped_column(String(255), nullable=True)  # Store URL to QR code image

    # Images
    images: Mapped[List[str]] = mapped_column(JSON, nullable=True)  # JSON type to store list of image URLs
    thumbnail: Mapped[str] = mapped_column(String(255), nullable=True)

    sales_count: Mapped[int] = mapped_column(Integer, default=0)
    featured: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    category_id: Mapped[int] = mapped_column(Integer, ForeignKey('categories.id'), nullable=False)
    category: Mapped["Category"] = relationship("Category", back_populates="products")

    reviews: Mapped[List['Review']] = relationship("Review", back_populates="product")


# Order Model
class Order(Base):
    __tablename__ = 'orders'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    total_amount: Mapped[float] = mapped_column(Float, nullable=False)

    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    user: Mapped[User] = relationship("User", back_populates="orders")

    # Assuming an order can have multiple products
    order_items: Mapped[List['OrderItem']] = relationship("OrderItem", back_populates="order")

# OrderItem Model
class OrderItem(Base):
    __tablename__ = 'order_items'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)

    order_id: Mapped[int] = mapped_column(Integer, ForeignKey('orders.id'), nullable=False)
    order: Mapped[Order] = relationship("Order", back_populates="order_items")

    product_id: Mapped[int] = mapped_column(Integer, ForeignKey('products.id'), nullable=False)
    product: Mapped[Product] = relationship("Product")

# Review Model
class Review(Base):
    __tablename__ = 'reviews'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rating: Mapped[int] = mapped_column(Integer, nullable=False)  # Rating on a scale (e.g., 1-5)
    review_text: Mapped[str] = mapped_column(Text, nullable=True)  # Optional review text
    comment: Mapped[str] = mapped_column(Text, nullable=True)  # Add this field for the comment
    date: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Relationships with other tables
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    user: Mapped[User] = relationship("User")



    product_id: Mapped[int] = mapped_column(Integer, ForeignKey('products.id'), nullable=False)
    product: Mapped[Product] = relationship("Product", back_populates="reviews")

class Cart(Base):
    __tablename__ = 'carts'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    user: Mapped["User"] = relationship("User", back_populates="cart")

    # Cart can contain multiple products and quantities
    cart_items: Mapped[List['CartItem']] = relationship("CartItem", back_populates="cart", cascade="all, delete-orphan")

# CartItem Model
class CartItem(Base):
    __tablename__ = 'cart_items'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)

    cart_id: Mapped[int] = mapped_column(Integer, ForeignKey('carts.id'), nullable=False)
    cart: Mapped[Cart] = relationship("Cart", back_populates="cart_items")

    product_id: Mapped[int] = mapped_column(Integer, ForeignKey('products.id'), nullable=False)
    product: Mapped[Product] = relationship("Product")

    # Check if item is marked for deletion or has been removed
    removed: Mapped[bool] = mapped_column(Boolean, default=False)





def load_products_from_apis():
    # API URLs
    url_1 = 'https://dummyjson.com/products'
    url_2 = 'https://fakestoreapi.com/products'

    # Fetch data from both APIs
    products_from_url_1 = fetch_data_from_api(url_1)
    products_from_url_2 = fetch_data_from_api(url_2)

    # Combine the results from both APIs
    all_products = products_from_url_1 + products_from_url_2

    # Start a session
    session = db.session

    for product_data in all_products:
        # Ensure category exists, or create a new one
        category = session.query(Category).filter_by(name=product_data['category']).first()
        if category is None:
            category = Category(name=product_data['category'])
            session.add(category)
            session.flush()  # Ensure category is flushed so that its ID is available

        # Handle Product Data
        rating = 0
        if isinstance(product_data.get('rating'), dict):
            rating = product_data.get('rating', {}).get('rate', 0)
        elif isinstance(product_data.get('rating'), (int, float)):
            rating = product_data['rating']  # For API_2

        # Construct the Product object
        product = Product(
            name=product_data['title'],  # 'title' for both APIs
            description=product_data.get('description', ''),
            price=product_data['price'],
            stock=product_data.get('stock', 0),
            tags=product_data.get('tags', []),  # Only for API_1
            brand=product_data.get('brand', ''),  # Only for API_1
            sku=product_data.get('sku', ''),  # Only for API_1
            weight=product_data.get('weight', 0),  # Only for API_1
            dimensions=product_data.get('dimensions', {}),  # Only for API_1
            rating=rating,  # Use the correct rating
            created_at=datetime.now(pytz.UTC),
            updated_at=datetime.now(pytz.UTC),
            barcode=product_data.get('barcode', ''),  # Only for API_1
            qr_code=product_data.get('qrCode', ''),  # Only for API_1
            images=product_data.get('images', [product_data.get('image', '')]),  # Default image URL
            thumbnail=product_data.get('thumbnail', ''),  # Only for API_1
            category_id=category.id  # Now we can safely assign the category ID
        )

        # Add product to session
        session.add(product)

    # Commit all the changes at once
    session.commit()

def fetch_data_from_api(url):
    response = requests.get(url)
    if response.status_code == 200:
        if url == 'https://dummyjson.com/products':  # API 1
            return response.json()['products']  # Return the 'products' list
        elif url == 'https://fakestoreapi.com/products':  # API 2
            return response.json()  # Directly return the list of products
    else:
        print(f"Failed to fetch data from {url}. Status code: {response.status_code}")
        return []


# Create the database
with app.app_context():
    db.create_all()
    if db.session.query(Product).count() == 0:
        load_products_from_apis()





def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If the current user's ID is not 1, render an access denied template and abort
        if current_user.id != 1:
            # Optionally log the unauthorized access attempt here
            return render_template('404.html'), 403  # Return 403 status code
        # Otherwise, continue with the route function
        return f(*args, **kwargs)

    return decorated_function
load_dotenv()


# Google OAuth configuration
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Allow HTTP traffic for local dev
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://127.0.0.1:5001/callback")

# Initialize Google OAuth flow
flow = Flow.from_client_config(
    {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    },
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
    ],
    redirect_uri=REDIRECT_URI,
)


app.config['SECRET_KEY'] = os.getenv('API_KEY')
MAIL_ADDRESS = os.environ.get("EMAIL_KEY")
MAIL_APP_PW = os.environ.get("PASSWORD_KEY")
API_KEY = os.environ.get("API_KEY")
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
YOUR_STRIPE_PUBLIC_KEY = os.getenv('STRIPE_PUBLIC_KEY')





@app.route('/add_review@<int:product_id>', methods=['GET', 'POST'])
@login_required
def add_review(product_id):
    # Retrieve the product regardless of the request method (GET or POST)
    product = db.session.query(Product).filter_by(id=product_id).first()

    if request.method == 'POST':
        # Retrieve data from form
        rating = request.form.get('rating', type=int)
        review_text = request.form.get('review_text')
        comment = request.form.get('comment')

        # Create a new Review object
        review = Review(
            rating=rating,
            review_text=review_text,
            comment=comment,
            date=datetime.now(),
            user_id=current_user.id,
            product_id=product_id
        )

        # Add to the session and commit
        db.session.add(review)
        db.session.commit()

        # Display success message
        flash("Your review has been added successfully!", "success")
        return redirect(url_for('product_details', product_id=product_id))

    # Render review form if request method is GET
    return render_template('add_comment.html', product_id=product_id, product=product)


@app.route('/checkout@<total_amount>', methods=['GET', 'POST'])
@login_required
def checkout(total_amount):
    user_id = current_user.id  # Get the logged-in user's ID

    # Retrieve the user's cart
    cart = db.session.query(Cart).filter(Cart.user_id == user_id).first()

    if not cart:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('home'))  # Redirect to home page if cart is empty

    if request.method == 'POST':
        # Calculate total amount and create order items
        total_amount = 0
        order_items = []
        for cart_item in cart.cart_items:
            product = cart_item.product
            quantity = cart_item.quantity
            total_amount += product.price * quantity

            # Create order item
            order_item = OrderItem(
                product_id=product.id,
                quantity=quantity
            )
            order_items.append(order_item)

            # Reduce stock of the product
            product.stock -= quantity
            db.session.add(product)

        # Create the order
        order = Order(
            user_id=user_id,
            total_amount=total_amount,
            order_items=order_items
        )
        db.session.add(order)
        db.session.commit()

        # Clear the cart
        for cart_item in cart.cart_items:
            db.session.delete(cart_item)
        db.session.commit()

        # Flash success message and redirect to the success page
        flash("Your order has been placed successfully!", "success")
        return redirect(url_for('order_success', order_id=order.id))

    # Display the checkout page with cart items (GET request)
    return render_template('checkout.html', cart=cart,total_amount=total_amount)




@app.route('/payment-success', methods=['POST'])
def payment_success():
    # Set session variable to indicate payment success
    session['payment_success'] = True
    return redirect(url_for('thank_you'))




@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        # Retrieve the amount in dollars from the form data and convert to cents
        amount_dollars = float(request.form['amount'])  # Amount in dollars
        amount_cents = int(amount_dollars * 100)  # Convert to cents

        # Create a Stripe Checkout session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'cad',
                    'product_data': {
                        'name': 'Total Purchase',
                    },
                    'unit_amount': amount_cents,  # Amount in cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('success', _external=True),
            cancel_url=url_for('cancel', _external=True),
        )

        session['checkout_in_progress'] = True
        # Redirect the user to Stripe's hosted Checkout page
        return redirect(checkout_session.url, code=303)

    except Exception as e:
        return jsonify(error=str(e)), 403


@app.route('/thank-you')
@login_required
def success():
    if session.get('checkout_in_progress'):
        try:
            # Retrieve the current user
            user = current_user

            # Create a new order
            total_amount = 0  # Initialize total amount

            # Get cart items for the user
            cart_items = user.cart.cart_items

            # Create a new order in the database
            order = Order(user_id=user.id, order_date=datetime.utcnow(), total_amount=total_amount)
            db.session.add(order)
            db.session.commit()  # Commit the order so we can use its ID

            # Add each item to the order
            for cart_item in cart_items:
                product = cart_item.product
                quantity = cart_item.quantity
                item_total = product.price * quantity
                total_amount += item_total

                # Create an OrderItem for each cart item
                order_item = OrderItem(order_id=order.id, product_id=product.id, quantity=quantity)
                db.session.add(order_item)

                # Update the stock and sales count of the product
                product.stock -= quantity
                product.sales_count += quantity  # Increment sales count by the purchased quantity
                db.session.add(product)  # Add the updated product to the session

                # Mark the cart item as removed after processing
                cart_item.removed = True
                db.session.add(cart_item)

            # Update the total amount of the order
            order.total_amount = total_amount
            db.session.commit()

            # Clear the session flag after successful payment
            session.pop('checkout_in_progress', None)

            # Render the thank you page
            return render_template('thank_you.html')

        except Exception as e:
            db.session.rollback()  # Rollback in case of an error
            return str(e), 500  # You can customize this error response
    else:
        # Redirect to home if unauthorized access
        return redirect(url_for('home'))

@app.route('/cancelled')
@login_required
def cancel():
    if session.get('checkout_in_progress'):
        # Clear the session flag on cancel
        session.pop('checkout_in_progress', None)
        return render_template('cancel.html')
    else:
        # Redirect to home or an error page if unauthorized access
        return redirect(url_for('home'))



@app.route('/cart')
@login_required
def cart():
    cart = session.get('cart', {})

    # Calculate total quantity
    total_quantity = sum(cart.values())  # Add up the quantities of each item in the cart

    # Calculate total amount
    total_amount = 0
    for product_id, quantity in cart.items():
        product = Product.query.get(product_id)
        if product:
            total_amount += product.price * quantity

    return render_template('cart.html', cart=cart, total_amount=total_amount, total_quantity=total_quantity)


@app.route('/all_products')
def all_products():
    logged_in = current_user.is_authenticated
    products = Product.query.all()
    return render_template('all_products.html',products=products,logged_in=logged_in)


@app.route('/test_route')
def test():
    users = User.query.all()
    return render_template('404.html',users=users)

@app.route('/faq', methods=['GET'])
def faq():
   return render_template('faq.html')

@app.route('/admin', methods=['GET'])
@login_required
@admin_only
def admin_dashboard():
   return render_template('admin.html')

@app.route('/edit_category@<int:category_id>', methods=['GET', 'POST'])
@login_required
@admin_only
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)  # Get the category by its ID

    # Assuming you are using a form to edit category details
    form = CategoryForm()  # Create a form for category editing
    if form.validate_on_submit():
        category.name = form.category_name.data  # Update the category name from the form
        category.thumbnail = form.thumbnail.data
        db.session.commit()  # Commit the changes to the database
        flash('Category updated successfully!', 'success')
        return redirect(url_for('view_categories'))  # Redirect to the admin dashboard

    # Pre-fill the form with current category data
    form.category_name.data = category.name
    return render_template('edit_category.html', form=form, category=category)

@app.route('/delete_category@<int:category_id>', methods=['GET','POST'])
@login_required
@admin_only
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)  # Get the category by its ID
    db.session.delete(category)  # Delete the category from the database
    db.session.commit()  # Commit the changes
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('view_categories'))  # Redirect to the admin dashboard

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_only
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm()

    if form.validate_on_submit():
        user.email = form.email.data
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.gender = form.gender.data
        db.session.commit()
        flash('User details updated successfully!', 'success')
        return redirect(url_for('view_users'))

    form.email.data = user.email  # Prepopulate form
    form.first_name.data = user.first_name
    form.last_name.data = user.last_name
    form.gender.data = user.gender
    return render_template('edit_user.html', form=form, user=user)

@app.route('/admin@view_users', methods=['GET', 'POST'])
@login_required
@admin_only
def view_users():
    users = User.query.all()
    return render_template('user_list.html',users=users)

@app.route('/admin@view_products', methods=['GET', 'POST'])
@login_required
@admin_only
def view_products():
    products = Product.query.all()
    return render_template('product_list.html',products=products)

@app.route('/admin@view_categories', methods=['GET', 'POST'])
@login_required
@admin_only
def view_categories():
    categories = Category.query.all()
    return render_template('category_list.html',categories=categories)






@app.route('/admin@edit_product@<int:product_id>', methods=['GET', 'POST'])
@login_required
@admin_only
def edit_product(product_id):
    # Fetch the product by ID, or return a 404 if not found
    product = Product.query.get_or_404(product_id)

    # Create a form instance pre-populated with product details
    form = ProductEditForm(obj=product)

    # Populate the category choices dynamically
    form.category.choices = [(category.id, category.name) for category in Category.query.all()]

    # Process form submission
    if form.validate_on_submit():
        # Update the product fields
        product.name = form.name.data
        product.description = form.description.data
        product.price = form.price.data
        product.stock = form.stock.data
        product.sales_count = form.sales.data
        product.rating = form.rating.data
        product.category_id = form.category.data
        product.discountPercentage = form.discountPercentage.data
        product.thumbnail = form.thumbnail.data
        product.featured = form.featured.data
        try:
            db.session.commit()
            flash('Product updated successfully', 'success')
            return redirect(url_for('view_products'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating product: {str(e)}', 'danger')

    return render_template('edit_product.html', form=form, product=product)

@app.route('/admin@delete_product@<int:product_id>', methods=['GET', 'POST'])
@login_required
@admin_only
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = DeleteProductForm()  # You should have a form for this, or handle it directly

    if form.validate_on_submit():
        try:
            db.session.delete(product)
            db.session.commit()
            flash('Product deleted successfully!', 'success')
            return redirect(url_for('view_products'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting product: {str(e)}', 'danger')

    return render_template('delete_product.html', form=form, product=product)

@app.route('/admin/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_only
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    form = DeleteUserForm()

    if form.validate_on_submit():
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
        return redirect(url_for('view_users'))

    return render_template('delete_user.html', form=form, user=user)


@app.route('/admin@add-product', methods=['GET', 'POST'])
@login_required
@admin_only
def add_product():
    form = AddProductForm()

    # Fetch available categories to populate the category dropdown
    form.category_id.choices = [(category.id, category.name) for category in Category.query.all()]

    if form.validate_on_submit():
        # Get the form data
        name = form.name.data
        description = form.description.data
        price = form.price.data
        stock = form.stock.data
        rating = form.rating.data or 0.0  # Default to 0 if no rating provided
        tags = form.tags.data.split(',') if form.tags.data else []  # Convert tags to a list
        brand = form.brand.data
        sku = form.sku.data
        weight = form.weight.data
        dimensions = {
            "width": form.dimensions_width.data,
            "height": form.dimensions_height.data,
            "depth": form.dimensions_depth.data
        }
        warranty_information = form.warranty_information.data
        shipping_information = form.shipping_information.data
        availability_status = form.availability_status.data
        return_policy = form.return_policy.data
        minimum_order_quantity = form.minimum_order_quantity.data
        barcode = form.barcode.data
        qr_code = form.qr_code.data
        images = form.images.data or '[]'  # Default to empty list if no images provided
        thumbnail = form.thumbnail.data
        created_at = datetime.now(pytz.UTC)
        updated_at = datetime.now(pytz.UTC)

        # Create a new Product object
        new_product = Product(
            name=name,
            description=description,
            price=price,
            stock=stock,
            rating=rating,
            tags=tags,
            brand=brand,
            sku=sku,
            weight=weight,
            dimensions=dimensions,
            warranty_information=warranty_information,
            shipping_information=shipping_information,
            availability_status=availability_status,
            return_policy=return_policy,
            minimum_order_quantity=minimum_order_quantity,
            barcode=barcode,
            qr_code=qr_code,
            images=images,
            thumbnail=thumbnail,
            category_id=form.category_id.data,  # Set category ID from the form
            created_at = created_at,
            updated_at =  updated_at
        )

        try:
            # Add the new product to the database
            db.session.add(new_product)
            db.session.commit()
            flash('Product has been successfully added!', 'success')
            return redirect(url_for('view_products'))  # Redirect to admin dashboard after successful product creation
        except Exception as e:
            # Rollback in case of error
            db.session.rollback()
            flash(f'Error occurred while adding product: {str(e)}', 'danger')

    return render_template('add_product.html', form=form)


@app.route('/add_category', methods=['GET', 'POST'])
@login_required
@admin_only
def add_category():
    form = AddCategoryForm()

    if form.validate_on_submit():
        category_name = form.category_name.data

        # Check if the category already exists
        existing_category = Category.query.filter_by(name=category_name).first()
        if existing_category:
            flash(f'Category "{category_name}" already exists!', 'warning')
            return redirect(url_for('add_category'))  # Redirect back to the same page to show the message

        # Proceed to add the new category to the database
        try:
            new_category = Category(name=category_name)
            db.session.add(new_category)
            db.session.commit()
            flash(f'Category "{category_name}" added successfully!', 'success')
        except Exception as e:
            # Handle any errors that occur during the database commit
            db.session.rollback()  # Rollback the transaction to ensure the database remains consistent
            flash('An error occurred while adding the category. Please try again later.', 'danger')
            print(f"Error: {e}")  # Log the error (consider logging to a file or monitoring system)

        return redirect(url_for('view_categories'))  # Redirect to the admin dashboard or category list page

    return render_template('add_category.html', form=form)






def send_email(name, email, subject, message):
    email_message = f"Subject: {subject}\n\nName: {name}\nEmail: {email}\nMessage: {message}"
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(MAIL_ADDRESS, MAIL_APP_PW)
        connection.sendmail(MAIL_ADDRESS, email, email_message)
def rand_otp():
    otp = [secrets.randbelow(10) for _ in range(6)]
    return ''.join(map(str,otp))

@app.route('/google/login')
def google_login():
    authorization_url, state = flow.authorization_url(prompt='select_account')
    session["state"] = state  # Store state for verification
    return redirect(authorization_url)

@app.route('/callback')
def google_callback():
    try:
        flow.fetch_token(authorization_response=request.url)

        if session.get("state") != request.args.get("state"):
            abort(500)  # State does not match! Potential CSRF attack

        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        # Verify the ID token
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )

        # Add a grace period
        issued_at = id_info.get("iat")
        expiration_time = id_info.get("exp")

        current_time = datetime.utcnow().timestamp()

        # If the token is not yet valid, allow a 1-minute grace period
        if issued_at > current_time + 60:  # Token used too early
            flash('Token is not yet valid. Please try again later.', 'danger')
            return redirect(url_for('login'))

        email = id_info.get("email")
        first_name = id_info.get("given_name") or "N/A"
        last_name = id_info.get("family_name") or "N/A"

        # Check if the user exists in the local database
        user = User.query.filter_by(email=email).first()

        hashed_password = generate_password_hash("it was googled", method='pbkdf2:sha256')
        if not user:
            # Create a new user without a password
            user = User(email=email, first_name=first_name, last_name=last_name, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('Account created successfully! Please provide your gender.', 'success')
            return redirect(url_for('gender', email=email))
        else:
            login_user(user)
            return redirect(url_for('home'))

    except Exception as e:
        flash(f'An error occurred during the login process: {str(e)}', 'danger')
        return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            # Update user profile logic here
            current_user.first_name = form.first_name.data
            current_user.last_name = form.last_name.data
            current_user.gender = form.gender.data

            # Save changes to the database
            db.session.commit()
            flash('Your profile has been updated!', 'success')
            return redirect(url_for('profile'))

    # Populate form fields with current user data for display
    if request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.gender.data = current_user.gender

    return render_template('profile.html', form=form, user=current_user)


def otp_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if OTP has been verified
        if 'otp_verified' not in session or not session['otp_verified']:
            flash('Please verify your OTP/email before resetting your password.', 'danger')
            return redirect(url_for('otp'))  # Redirect to OTP verification page
        return f(*args, **kwargs)
    return decorated_function


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        logout_user()
        session.clear()
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if check_password_hash(existing_user.password,'it was googled'):  # Assuming you have a field to check this
                flash(
                    'You cannot reset your password for this Google account. Try logging with Google.',
                    'warning')
                return redirect(url_for('login'))

            generated_OTP = rand_otp()
            session['OTP'] = generated_OTP
            message = (f"Dear {existing_user.first_name},\n"
                       f"Your one-time password (OTP) is: {generated_OTP}\n"
                       "Please use this code to complete your login or verification process. "
                       "This OTP is valid for 10 minutes and can only be used once.\n"
                       "If you did not request this code, please ignore this message.\n"
                       "Thank you,\nGizmo")
            subject = "Verification Code: Complete Your Login"
            send_email(existing_user.first_name, "anirudh050504@gmail.com", subject, message)  # Send to user's email
            flash('OTP sent successfully', 'success')
            session['user_email'] = email  # Store email in session for later use
            session['otp_timestamp'] = datetime.now().timestamp()
            return redirect(url_for('otp'))
        flash('Email not found in our system. Please register to create an account and log in.', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'user_email' not in session:
        flash('Please enter your registered email first.', 'danger')
        return redirect(url_for('forgot_password'))
    form = OTPForm()
    if form.validate_on_submit():
        otp_value = int(form.otp.data)
        current_time = datetime.now().timestamp()
        otp_timestamp = session.get('otp_timestamp', 0)

        if otp_value == int(session.get('OTP')) and (current_time - otp_timestamp < 600):  # Check if OTP is valid for 10 minutes
            flash('OTP verified. You can now reset your password!', 'success')
            session['otp_verified'] = True
            return redirect(url_for('reset_password'))
        flash('OTP is incorrect or expired', 'danger')
        return redirect(url_for('otp'))
    return render_template('otp.html', form=form)

@app.route('/resend_otp', methods=['GET','POST'])
def resend_otp():
    if 'user_email' not in session:
        flash('Please enter your registered email first.', 'danger')
        return redirect(url_for('forgot_password'))

    current_time = datetime.now().timestamp()
    otp_timestamp = session.get('otp_timestamp', 0)

    if current_time - otp_timestamp >= 120:  # Check if 2 minutes have passed since last OTP
        generated_OTP = rand_otp()
        session['OTP'] = generated_OTP  # Update OTP in session
        email = session['user_email']
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            message = (f"Dear {existing_user.first_name},\n"
                       f"Your new one-time password (OTP) is: {generated_OTP}\n"
                       "Please use this code to complete your login or verification process. "
                       "This OTP is valid for 10 minutes and can only be used once.\n"
                       "If you did not request this code, please ignore this message.\n"
                       "Thank you,\nGizmo")
            subject = "Verification Code: Complete Your Login"
            send_email(existing_user.first_name, "anirudh050504@gmail.com", subject, message)  # Send new OTP
            session['otp_timestamp'] = current_time  # Update the OTP timestamp
            flash('New OTP sent successfully', 'success')
        else:
            flash('Email not found in our system.', 'danger')
    else:
        remaining_time = 120 - (current_time - otp_timestamp)
        flash(f'Please wait {int(remaining_time)} seconds before requesting a new OTP.', 'warning')

    return redirect(url_for('otp'))







@app.route('/reset_password', methods=['GET', 'POST'])
@otp_required
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data  # Correctly access the data

        # Check if the new password and confirm password match
        if new_password == confirm_password:
            try:
                # Retrieve the user's email from the session
                email = session.get('user_email')
                user = User.query.filter_by(email=email).first()  # Use the email from the session

                if user:  # If the user is found
                    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                    user.password = hashed_password  # Update the user's password
                    db.session.commit()  # Save the changes

                    flash('Your password has been reset successfully!', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('User not found. Please try again.', 'danger')
                    return redirect(url_for('reset_password'))

            except IntegrityError:
                db.session.rollback()  # Rollback if there's an integrity error
                flash('An error occurred while resetting your password. Please try again.', 'danger')
                return redirect(url_for('reset_password'))

            except Exception as e:
                db.session.rollback()  # Rollback for other exceptions
                flash('Error occurred while resetting password: {}'.format(str(e)), 'danger')
                return redirect(url_for('reset_password'))
        else:
            flash('Confirm password does not match. Please try again.', 'danger')
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html', form=form)


@app.route('/products', methods=['GET'])
def get_products():
    try:
        # Make a GET request to the Fake Store API
        response = requests.get('https://fakestoreapi.com/products')
        response.raise_for_status()  # Raise an error for bad responses
        products = response.json()  # Parse the JSON response

        return render_template('products.html', products=products)
    except requests.exceptions.RequestException as e:
        return f"An error occurred: {str(e)}", 500


@app.route('/gender<email>', methods=["GET", "POST"])
@login_required
def gender(email):
    form = GenderForm()  # Assume you have a form defined to collect gender
    user = User.query.filter_by(email=email).first()  # Fetch user info based on email

    if form.validate_on_submit():
        gender = form.gender.data
        user.gender = gender  # Update the user's gender
        db.session.commit()  # Commit the changes to the database
        return redirect(url_for('home'))  # Redirect to home after updating

    return render_template('gender.html', form=form, user=user)


@app.route('/logout')
@login_required
def logout():
    logout_user()  # Logs out the user from the Flask session
    session.clear()  # Clear the session
    return redirect(url_for('home'))

@app.context_processor
def inject_current_year():
    return dict(current_year=datetime.now().year)

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/remove_from_cart/<int:product_id>', methods=['GET','POST'])
@login_required
def remove_from_cart(product_id):
    user = current_user
    cart = user.cart  # Assuming each user has one cart

    if not cart:
        return redirect(url_for('view_cart'))

    # Find the cart item by product ID
    cart_item = next((item for item in cart.cart_items if item.product_id == product_id), None)
    if cart_item:
        cart.cart_items.remove(cart_item)  # Remove the item from the cart
        db.session.commit()  # Commit the changes to the database
    else:
        # If the product isn't in the cart, return an error message or handle as needed
        return redirect(url_for('view_cart'))

    return redirect(url_for('view_cart'))  # Redirect to view cart page after removing the item


@app.route('/view_cart')
@login_required
def view_cart():
    user = current_user
    cart = user.cart  # Assuming each user has one cart

    if not cart or not cart.cart_items:
        # Render empty cart view if no cart or items in the cart
        return render_template('view_cart.html',empty=True)

    # Calculate the total amount and fetch products for cart items
    cart_items = []
    total_amount = Decimal('0.00')  # Initialize total amount as Decimal
    product_ids = [item.product_id for item in cart.cart_items]  # Get all product IDs
    products = Product.query.filter(Product.id.in_(product_ids)).all()  # Retrieve all products in a single query

    # Create a dictionary to map product ID to product
    product_dict = {product.id: product for product in products}

    for item in cart.cart_items:
        product = product_dict.get(item.product_id)  # Get the product from the dictionary
        if product:
            total_amount += Decimal(str(product.price)) * Decimal(str(item.quantity))  # Multiply with Decimal precision
            cart_items.append({
                'product': product,
                'quantity': item.quantity
            })

    # Round the total amount to 2 decimal places using ROUND_HALF_UP to avoid precision issues
    total_amount = total_amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    print(total_amount)

    return render_template('view_cart.html', cart_items=cart_items, total_amount=total_amount)





@app.route('/add_to_cart/<int:product_id>', methods=['GET','POST'])
@login_required
def add_to_cart(product_id):

    user = current_user  # Corrected to use current_user directly
    quantity = int(request.form.get('quantity', 1))

    # Check if the product is already in the cart
    cart = user.cart
    if cart:
        # Check if the product already exists in the cart
        existing_item = next((item for item in cart.cart_items if item.product_id == product_id), None)
        if existing_item:
            # Update the quantity of the existing product
            existing_item.quantity += quantity
        else:
            # Add new product to the cart
            new_cart_item = CartItem(quantity=quantity, product_id=product_id)
            cart.cart_items.append(new_cart_item)
    else:
        # If the user doesn't have a cart, create one and add the product
        new_cart = Cart(user_id=user.id)
        db.session.add(new_cart)
        new_cart_item = CartItem(quantity=quantity, product_id=product_id)
        new_cart.cart_items.append(new_cart_item)

    db.session.commit()
    return redirect(url_for('view_cart'))



@app.route('/category@<int:category_id>')
def view_category_items(category_id):
    # Query to get the category by ID
    category = db.session.query(Category).filter_by(id=category_id).first()
    logged_in = current_user.is_authenticated

    # If the category doesn't exist, return a 404 page
    if not category:
        return render_template('404.html'), 404

    # Query to get products that belong to this category
    products = db.session.query(Product).filter_by(category_id=category_id).all()

    # Render the category page template with the products
    return render_template('category_items.html', category=category, products=products,logged_in = logged_in)

@app.route('/product_details@<int:product_id>')
def product_details(product_id):
    # Fetch the product from the database using the product_id
    logged_in = current_user.is_authenticated  # Check if the user is authenticated
    product = Product.query.get(product_id)

    # Fetch all reviews for the product
    reviews = Review.query.filter_by(product_id=product_id).order_by(Review.date.desc()).all()


    if product is None:
        return render_template('404.html'), 404  # If product is not found, return a 404 error

    # Render the template with the fetched product details
    return render_template('product_details.html', product=product, logged_in=logged_in,reviews=reviews)

@app.route('/')
def home():
    # Check if the user is an admin
    is_admin = current_user.is_authenticated and current_user.id == 1
    first_name = current_user.first_name if current_user.is_authenticated else 'N/A'
    last_name = current_user.last_name if current_user.is_authenticated else 'N/A'

    try:
        if current_user.is_authenticated:
            # Get the user's cart if it exists, else set an empty cart
            cart = current_user.cart
            cart_items = cart.cart_items if cart else []
            total_amount = sum(item.product.price * item.quantity for item in cart_items)
            total_quantity = sum(item.quantity for item in cart_items)  # Calculate total quantity of items
        else:
            cart_items = []
            total_amount = 0
            total_quantity = 0

        products = Product.query.all()  # Fetch all products from the database
        categories = Category.query.all()  # Fetch all categories from the database

        # Get quantity from session (this part remains unchanged)
        quantity = session.get('quantity', 0)

    except Exception as e:
        return f"An error occurred: {str(e)}", 500  # Handle any errors that might occur in the database query

    # Create the form object for the contact form
    form = ContactForm()

    # Render the template with the fetched data
    return render_template('index.html',
                           quantity=quantity,
                           form=form,
                           first_name=first_name,
                           last_name=last_name,
                           is_admin=is_admin,
                           logged_in=current_user.is_authenticated,
                           products=products,
                           categories=categories,
                           total_quantity=total_quantity,
                           total_amount=total_amount)


#Login Route
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        # Check if the user exists and the password is correct
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/submit', methods=['POST'])
def submit():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data
        subject = form.subject.data
        send_email(name, email, subject, message)
        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('home') + "#contact")  # Redirect to home and scroll to contact section

    flash('There was an issue with your submission.', 'error')
    return redirect(url_for('home') + "#contact")


@app.route('/about')
def about():
    return render_template('about.html')

# Route for registering a new user
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        password = form.password.data
        repeated_password = form.repeat_password.data
        gender = form.gender.data


        # Uncomment to enable user registration logic
        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please choose a different email.', 'danger')
            return redirect(url_for('register'))

        try:
            # Check if the password and repeated password match
            if password != repeated_password:
                flash('Passwords do not match. Please try again.', 'danger')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

            # Create a new user and add to the database
            new_user = User(email=email, first_name=first_name, last_name=last_name, password=hashed_password, gender=gender)
            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))

        except IntegrityError:
            # Rollback in case of IntegrityError
            # db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'danger')
            return redirect(url_for('register'))

        except Exception as e:
            # Rollback in case of other errors
            # db.session.rollback()
            flash('Error occurred while creating account: {}'.format(str(e)), 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)

if __name__ == "__main__":
    app.run(debug=True, port=5001)
