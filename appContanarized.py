from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import redis  # Import Redis if using Redis for Flask-Limiter
from flask_migrate import Migrate  # Import Flask-Migrate
from flask.cli import with_appcontext
import click


app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'mysql+pymysql://root:esponjaxd@localhost/projectdb')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')  # Use environment variable in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Initialize extensions
db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate


# Optional: Initialize Redis for Flask-Limiter
redis_host = os.getenv('REDIS_HOST', 'redis')
redis_port = os.getenv('REDIS_PORT', 6379)
redis_client = redis.Redis(host=redis_host, port=int(redis_port))

# Setup rate limiter with Redis storage
def get_user_identifier():
    try:
        return str(get_jwt_identity())
    except:
        return get_remote_address()

limiter = Limiter(
    app=app,
    key_func=get_user_identifier,
    default_limits=["100 per minute"],
    storage_uri=f"redis://{redis_host}:{redis_port}"
)



# Models for RBAC
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'))
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    email = db.Column(db.String(120), unique=True,nullable=False)
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name):
        for role in self.roles:
            for permission in role.permissions:
                if permission.name == permission_name:
                    return True
        return False

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    permissions = db.relationship('Permission', secondary=role_permissions, back_populates='roles')
    users = db.relationship('User', secondary=user_roles, back_populates='roles')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    roles = db.relationship('Role', secondary=role_permissions, back_populates='permissions')

# Audit Log model
class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    endpoint = db.Column(db.String(120), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status_code = db.Column(db.Integer, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)

# Models
class Supplier(db.Model):
    SupplierID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100))
    ContactName = db.Column(db.String(100))
    PhoneNumber = db.Column(db.String(100))
    Email = db.Column(db.String(100))

class Customer(db.Model):
    CustomerID = db.Column(db.Integer, primary_key=True)
    FirstName = db.Column(db.String(100))
    LastName = db.Column(db.String(100))
    Email = db.Column(db.String(100))
    PhoneNumber = db.Column(db.String(100))

class Product(db.Model):
    ProductID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100))
    Category = db.Column(db.String(100))
    Price = db.Column(db.Float)
    QuantityInStock = db.Column(db.Integer)
    SupplierID = db.Column(db.Integer, db.ForeignKey('supplier.SupplierID'))

class Order(db.Model):
    OrderID = db.Column(db.Integer, primary_key=True)
    CustomerID = db.Column(db.Integer, db.ForeignKey('customer.CustomerID'))
    OrderDate = db.Column(db.Date)
    order_details = db.relationship('OrderDetail', backref='order', lazy=True)

    @property
    def TotalAmount(self):
        return sum([detail.Quantity * detail.Price for detail in self.order_details])

class OrderDetail(db.Model):
    OrderDetailID = db.Column(db.Integer, primary_key=True)
    OrderID = db.Column(db.Integer, db.ForeignKey('order.OrderID'))
    ProductID = db.Column(db.Integer, db.ForeignKey('product.ProductID'))
    Quantity = db.Column(db.Integer)
    Price = db.Column(db.Float)

class InventoryRestock(db.Model):
    InventoryRestockID = db.Column(db.Integer, primary_key=True)
    ProductID = db.Column(db.Integer, db.ForeignKey('product.ProductID'))
    Quantity = db.Column(db.Integer)
    RestockDate = db.Column(db.Date)

# Schemas
class SupplierSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Supplier
        include_fk = True

class CustomerSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Customer
        include_fk = True

class ProductSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Product
        include_fk = True

class OrderSchema(ma.SQLAlchemyAutoSchema):
    TotalAmount = ma.Method("get_total_amount")

    class Meta:
        model = Order
        include_fk = True

    def get_total_amount(self, obj):
        return obj.TotalAmount

class OrderDetailSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = OrderDetail
        include_fk = True

class InventoryRestockSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = InventoryRestock
        include_fk = True

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        exclude = ('password_hash',)

supplier_schema = SupplierSchema()
suppliers_schema = SupplierSchema(many=True)

customer_schema = CustomerSchema()
customers_schema = CustomerSchema(many=True)

product_schema = ProductSchema()
products_schema = ProductSchema(many=True)

order_schema = OrderSchema()
orders_schema = OrderSchema(many=True)

order_detail_schema = OrderDetailSchema()
order_details_schema = OrderDetailSchema(many=True)

inventory_restock_schema = InventoryRestockSchema()
inventory_restocks_schema = InventoryRestockSchema(many=True)

user_schema = UserSchema()
users_schema = UserSchema(many=True)

# Permission decorator
def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            try:
                user_id = int(get_jwt_identity())
            except (ValueError, TypeError):
                return jsonify({'msg': 'Invalid token identity'}), 422

            user = User.query.get(user_id)
            if not user or not user.has_permission(permission_name):
                return jsonify({'error': 'Permission denied'}), 403
            g.current_user = user  # Set the current user in 'g' for later use
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Audit log after each request
@app.after_request
def after_request(response):
    try:
        user_id = get_jwt_identity()
    except:
        user_id = None
    audit_log = AuditLog(
        user_id=user_id,
        endpoint=request.path,
        method=request.method,
        timestamp=datetime.utcnow(),
        status_code=response.status_code,
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    return response

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")  # Example rate limit
def login():
    data = request.get_json()
    if not data:
        return jsonify({'msg': 'Missing JSON in request'}), 400
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'msg': 'Missing username or password'}), 400
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    if not user.verify_password(password):
        return jsonify({'msg': 'Incorrect password'}), 401
    # Convert user.id to string
    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token), 200




# Health Check Endpoints
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200

@app.route('/ready', methods=['GET'])
def readiness_check():
    # Implement any logic to verify readiness, e.g., database connection
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify({'status': 'ready'}), 200
    except Exception as e:
        return jsonify({'status': 'not ready', 'error': str(e)}), 503


# Routes with updated authentication and decorators

# Suppliers Routes
@app.route('/suppliers', methods=['POST'])
@limiter.limit("10 per minute")
@permission_required('add_supplier')
def add_supplier():
    data = request.json
    new_supplier = Supplier(
        Name=data['Name'],
        ContactName=data['ContactName'],
        PhoneNumber=data['PhoneNumber'],
        Email=data['Email']
    )
    db.session.add(new_supplier)
    db.session.commit()
    return supplier_schema.jsonify(new_supplier), 201

@app.route('/suppliers/<int:id>', methods=['PUT'])
@limiter.limit("10 per minute")
@permission_required('update_supplier')
def update_supplier(id):
    data = request.json
    supplier = db.session.get(Supplier, id)
    if not supplier:
        return jsonify({"error": "Supplier not found"}), 404

    supplier.Name = data['Name']
    supplier.ContactName = data['ContactName']
    supplier.PhoneNumber = data['PhoneNumber']
    supplier.Email = data['Email']
    db.session.commit()
    return supplier_schema.jsonify(supplier)

@app.route('/suppliers', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_supplier')
def get_suppliers():
    suppliers = Supplier.query.all()
    return suppliers_schema.jsonify(suppliers)

@app.route('/suppliers/<int:id>', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_supplier')
def get_supplier(id):
    supplier = Supplier.query.get(id)
    if supplier:
        return supplier_schema.jsonify(supplier)
    else:
        return jsonify({"message": "Supplier not found"}), 404

@app.route('/suppliers/<int:id>', methods=['DELETE'])
@limiter.limit("10 per minute")
@permission_required('delete_supplier')
def delete_supplier(id):
    supplier = db.session.get(Supplier, id)
    if not supplier:
        return jsonify({"error": "Supplier not found"}), 404

    db.session.delete(supplier)
    db.session.commit()
    return supplier_schema.jsonify(supplier)

# Customers Routes
@app.route('/customers', methods=['POST'])
@limiter.limit("10 per minute")
@permission_required('add_customer')
def add_customer():
    data = request.json
    new_customer = Customer(
        FirstName=data['FirstName'],
        LastName=data['LastName'],
        Email=data['Email'],
        PhoneNumber=data['PhoneNumber']
    )
    db.session.add(new_customer)
    db.session.commit()
    return customer_schema.jsonify(new_customer), 201

@app.route('/customers/<int:id>', methods=['PUT'])
@limiter.limit("10 per minute")
@permission_required('update_customer')
def update_customer(id):
    data = request.json
    customer = db.session.get(Customer, id)
    if not customer:
        return jsonify({"error": "Customer not found"}), 404

    customer.FirstName = data['FirstName']
    customer.LastName = data['LastName']
    customer.Email = data['Email']
    customer.PhoneNumber = data['PhoneNumber']
    db.session.commit()
    return customer_schema.jsonify(customer)

@app.route('/customers', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_customer')
def get_customers():
    customers = Customer.query.all()
    return customers_schema.jsonify(customers)

@app.route('/customers/<int:id>', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_customer')
def get_customer(id):
    customer = Customer.query.get(id)
    if customer:
        return customer_schema.jsonify(customer)
    else:
        return jsonify({"message": "Customer not found"}), 404

@app.route('/customers/<int:id>', methods=['DELETE'])
@limiter.limit("10 per minute")
@permission_required('delete_customer')
def delete_customer(id):
    customer = db.session.get(Customer, id)
    if not customer:
        return jsonify({"error": "Customer not found"}), 404

    db.session.delete(customer)
    db.session.commit()
    return customer_schema.jsonify(customer)

# Products Routes
@app.route('/products', methods=['POST'])
@limiter.limit("10 per minute")
@permission_required('add_product')
def add_product():
    data = request.json
    new_product = Product(
        Name=data['Name'],
        Category=data['Category'],
        Price=data['Price'],
        QuantityInStock=data['QuantityInStock'],
        SupplierID=data['SupplierID']
    )
    db.session.add(new_product)
    db.session.commit()
    return product_schema.jsonify(new_product), 201

@app.route('/products/<int:id>', methods=['PUT'])
@limiter.limit("10 per minute")
@permission_required('update_product')
def update_product(id):
    data = request.json
    product = db.session.get(Product, id)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    product.Name = data['Name']
    product.Category = data['Category']
    product.Price = data['Price']
    product.QuantityInStock = data['QuantityInStock']
    product.SupplierID = data['SupplierID']
    db.session.commit()
    return product_schema.jsonify(product)

@app.route('/products', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_product')
def get_products():
    products = Product.query.all()
    return products_schema.jsonify(products)

@app.route('/products/<int:id>', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_product')
def get_product(id):
    product = Product.query.get(id)
    if product:
        return product_schema.jsonify(product)
    else:
        return jsonify({"message": "Product not found"}), 404

@app.route('/products/<int:id>', methods=['DELETE'])
@limiter.limit("10 per minute")
@permission_required('delete_product')
def delete_product(id):
    product = db.session.get(Product, id)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    db.session.delete(product)
    db.session.commit()
    return product_schema.jsonify(product)

# Orders Routes
@app.route('/orders', methods=['POST'])
@limiter.limit("10 per minute")
@permission_required('add_order')
def add_order():
    data = request.json
    new_order = Order(
        CustomerID=data['CustomerID'],
        OrderDate=datetime.strptime(data['OrderDate'], '%Y-%m-%d').date()
    )
    db.session.add(new_order)
    db.session.commit()
    return order_schema.jsonify(new_order), 201

@app.route('/orders/<int:id>', methods=['PUT'])
@limiter.limit("10 per minute")
@permission_required('update_order')
def update_order(id):
    data = request.json
    order = db.session.get(Order, id)
    if not order:
        return jsonify({"error": "Order not found"}), 404

    order.CustomerID = data['CustomerID']
    order.OrderDate = datetime.strptime(data['OrderDate'], '%Y-%m-%d').date()
    db.session.commit()
    return order_schema.jsonify(order)

@app.route('/orders', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_order')
def get_orders():
    orders = Order.query.all()
    return orders_schema.jsonify(orders)

@app.route('/orders/<int:id>', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_order')
def get_order(id):
    order = Order.query.get(id)
    if order:
        return order_schema.jsonify(order)
    else:
        return jsonify({"message": "Order not found"}), 404

@app.route('/orders/<int:id>', methods=['DELETE'])
@limiter.limit("10 per minute")
@permission_required('delete_order')
def delete_order(id):
    order = db.session.get(Order, id)
    if not order:
        return jsonify({"error": "Order not found"}), 404

    db.session.delete(order)
    db.session.commit()
    return order_schema.jsonify(order)

# Order Details Routes
@app.route('/orderdetails', methods=['POST'])
@limiter.limit("10 per minute")
@permission_required('add_order_detail')
def add_order_detail():
    data = request.get_json()
    product = db.session.get(Product, data['ProductID'])
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    if product.QuantityInStock < data['Quantity']:
        return jsonify({'error': 'Not enough stock available'}), 400

    new_order_detail = OrderDetail(
        OrderID=data['OrderID'],
        ProductID=data['ProductID'],
        Quantity=data['Quantity'],
        Price=product.Price
    )
    product.QuantityInStock -= data['Quantity']
    db.session.add(new_order_detail)
    db.session.commit()
    return order_detail_schema.jsonify(new_order_detail), 201

@app.route('/orderdetails/<int:id>', methods=['PUT'])
@limiter.limit("10 per minute")
@permission_required('update_order_detail')
def update_order_detail(id):
    data = request.get_json()
    order_detail = db.session.get(OrderDetail, id)
    if not order_detail:
        return jsonify({'error': 'OrderDetail not found'}), 404

    product = db.session.get(Product, data['ProductID'])
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    if data['Quantity'] > order_detail.Quantity:
        difference = data['Quantity'] - order_detail.Quantity
        if product.QuantityInStock < difference:
            return jsonify({'error': 'Not enough stock available'}), 400
        product.QuantityInStock -= difference
    else:
        difference = order_detail.Quantity - data['Quantity']
        product.QuantityInStock += difference

    order_detail.OrderID = data['OrderID']
    order_detail.ProductID = data['ProductID']
    order_detail.Quantity = data['Quantity']
    order_detail.Price = product.Price
    db.session.commit()
    return order_detail_schema.jsonify(order_detail)

@app.route('/orderdetails', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_order_detail')
def get_order_details():
    order_details = OrderDetail.query.all()
    return order_details_schema.jsonify(order_details)

@app.route('/orderdetails/<int:id>', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_order_detail')
def get_order_detail(id):
    order_detail = OrderDetail.query.get(id)
    if order_detail:
        return order_detail_schema.jsonify(order_detail)
    else:
        return jsonify({"message": "Order Detail not found"}), 404

@app.route('/orderdetails/<int:id>', methods=['DELETE'])
@limiter.limit("10 per minute")
@permission_required('delete_order_detail')
def delete_order_detail(id):
    order_detail = db.session.get(OrderDetail, id)
    if not order_detail:
        return jsonify({'error': 'OrderDetail not found'}), 404

    product = db.session.get(Product, order_detail.ProductID)
    product.QuantityInStock += order_detail.Quantity
    db.session.delete(order_detail)
    db.session.commit()
    return order_detail_schema.jsonify(order_detail)

# Inventory Restocks Routes
@app.route('/inventoryrestocks', methods=['POST'])
@limiter.limit("10 per minute")
@permission_required('add_inventory_restock')
def add_inventory_restock():
    data = request.json
    new_inventory_restock = InventoryRestock(
        ProductID=data['ProductID'],
        Quantity=data['Quantity'],
        RestockDate=datetime.strptime(data['RestockDate'], '%Y-%m-%d').date()
    )
    product = db.session.get(Product, data['ProductID'])
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    product.QuantityInStock += data['Quantity']
    db.session.add(new_inventory_restock)
    db.session.commit()
    return inventory_restock_schema.jsonify(new_inventory_restock), 201

@app.route('/inventoryrestocks/<int:id>', methods=['PUT'])
@limiter.limit("10 per minute")
@permission_required('update_inventory_restock')
def update_inventory_restock(id):
    data = request.json
    inventory_restock = db.session.get(InventoryRestock, id)
    if not inventory_restock:
        return jsonify({"error": "InventoryRestock not found"}), 404

    product = db.session.get(Product, inventory_restock.ProductID)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    # Adjust stock levels
    product.QuantityInStock -= inventory_restock.Quantity  # Remove old quantity
    product.QuantityInStock += data['Quantity']            # Add new quantity

    inventory_restock.ProductID = data['ProductID']
    inventory_restock.Quantity = data['Quantity']
    inventory_restock.RestockDate = datetime.strptime(data['RestockDate'], '%Y-%m-%d').date()
    db.session.commit()
    return inventory_restock_schema.jsonify(inventory_restock)

@app.route('/inventoryrestocks', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_inventory_restock')
def get_inventory_restocks():
    inventory_restocks = InventoryRestock.query.all()
    return inventory_restocks_schema.jsonify(inventory_restocks)

@app.route('/inventoryrestocks/<int:id>', methods=['GET'])
@limiter.limit("30 per minute")
@permission_required('get_inventory_restock')
def get_inventory_restock(id):
    inventory_restock = InventoryRestock.query.get(id)
    if inventory_restock:
        return inventory_restock_schema.jsonify(inventory_restock)
    else:
        return jsonify({"message": "Inventory Restock not found"}), 404

@app.route('/inventoryrestocks/<int:id>', methods=['DELETE'])
@limiter.limit("10 per minute")
@permission_required('delete_inventory_restock')
def delete_inventory_restock(id):
    inventory_restock = db.session.get(InventoryRestock, id)
    if not inventory_restock:
        return jsonify({"error": "InventoryRestock not found"}), 404

    product = db.session.get(Product, inventory_restock.ProductID)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    product.QuantityInStock -= inventory_restock.Quantity

    db.session.delete(inventory_restock)
    db.session.commit()
    return inventory_restock_schema.jsonify(inventory_restock)

def create_roles_permissions():
    permissions = [
        'add_supplier', 'update_supplier', 'delete_supplier', 'get_supplier',
        'add_customer', 'update_customer', 'delete_customer', 'get_customer',
        'add_product', 'update_product', 'delete_product', 'get_product',
        'add_order', 'update_order', 'delete_order', 'get_order',
        'add_order_detail', 'update_order_detail', 'delete_order_detail', 'get_order_detail',
        'add_inventory_restock', 'update_inventory_restock', 'delete_inventory_restock', 'get_inventory_restock'
    ]

    # Create or get existing permissions
    permission_objects = {}
    for perm_name in permissions:
        perm = Permission.query.filter_by(name=perm_name).first()
        if not perm:
            perm = Permission(name=perm_name)
            db.session.add(perm)
        permission_objects[perm_name] = perm

    db.session.commit()

    # Create or get existing roles
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin')
        admin_role.permissions = list(permission_objects.values())
        db.session.add(admin_role)

    manager_role = Role.query.filter_by(name='manager').first()
    if not manager_role:
        manager_role = Role(name='manager')
        manager_perms = [permission_objects[perm_name] for perm_name in permissions if 'delete' not in perm_name]
        manager_role.permissions = manager_perms
        db.session.add(manager_role)

    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        user_role = Role(name='user')
        user_perms = [
            permission_objects['get_product'],
            permission_objects['add_order'],
            permission_objects['get_order']
        ]
        user_role.permissions = user_perms
        db.session.add(user_role)

    db.session.commit()
    print("Roles and permissions initialized.")

def create_admin_user():
    username = os.getenv('ADMIN_USERNAME', 'admin')
    password = os.getenv('ADMIN_PASSWORD', 'adminpassword')
    email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        print("Admin role does not exist. Cannot create admin user.")
        return
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, email=email)
        user.password_hash = generate_password_hash(password)
        user.roles.append(admin_role)
        db.session.add(user)
        db.session.commit()
        print("Admin user created.")
    else:
        print("Admin user already exists.")


def create_manager_user():
    username = os.getenv('MANAGER_USERNAME','manager')
    password = os.getenv('MANAGER_PASSWORD', 'managerpassword')
    email = os.getenv('MANAGER_EMAIL', 'manager@example.com')
    manager_role = Role.query.filter_by(name='manager').first()
    if not manager_role:
        print("Manager role does not exist. Cannot create manager user.")
        return
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, email=email)
        user.password_hash = generate_password_hash(password)
        user.roles.append(manager_role)
        db.session.add(user)
        db.session.commit()
        print("Manager user created.")
    else:
        print("Manager user already exists.")

def create_regular_user():
    username = os.getenv('USER_USERNAME','user')
    password = os.getenv('USER_PASSWORD', 'userpassword')
    email = os.getenv('USER_EMAIL', 'user@example.com')
    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        print("User role does not exist. Cannot create regular user.")
        return
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, email=email)
        user.password_hash = generate_password_hash(password)
        user.roles.append(user_role)
        db.session.add(user)
        db.session.commit()
        print("Regular user created.")
    else:
        print("Regular user already exists.")

@app.cli.command("init-db")
@with_appcontext
def init_db():
    """Initialize the database with roles, permissions, and default users."""
    create_roles_permissions()
    create_admin_user()
    create_manager_user()
    create_regular_user()
    click.echo("Database initialized with roles, permissions, and users.")
