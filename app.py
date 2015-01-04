from flask import *

from flask.ext.api import status
from flask.ext.httpauth import HTTPBasicAuth
from models import *

app = Flask(__name__)

auth = HTTPBasicAuth()

def get_object_or_404(model, *expressions):
    try:
        return model.get(*expressions)
    except model.DoesNotExist:
        abort(status.HTTP_404_NOT_FOUND)


def format_response(data, code):
    return jsonify({'data': data}), code


def format_error(message, code):
    return jsonify({'error': {'code': code, 'error_message': message}, 'data': None}), code


def strip_data(d):
    return dict([(k, v.strip()) if isinstance(v, basestring) else (k, v) for k, v in d])


def product_to_dict(p):
    return {
        'product_id': p.product_id,
        'name': p.name,
        'adult_price': p.adult_price,
        'child_price': p.child_price,
        'product_type': p.product_type,
        'available': p.available
    }


def customer_to_dict(c):
    return {
        'customer_id': c.customer_id,
        'name': c.name,
        'height': c.height,
        'foot_size': c.foot_size,
        'child': c.child,
        'products': []
    }


def order_to_dict(o):
    return {
        'order_id': o.order_id,
        'time_group': o.time_group,
        'name': o.name,
        'phone': o.phone,
        'email': o.email,
        'discount': o.discount,
        'discount_message': o.discount_message,
        'delivered': o.delivered,
        'hotel': o.hotel,
        'tutoring': o.tutoring,
        'finished': o.finished,
        'created': o.created,
        'returned': o.returned
    }


def user_to_dict(u):
    return {
        'user_id': u.user_id,
        'username': u.username
    }


##### USERS #####

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.get(User.username == username_or_token)
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        abort(status.HTTP_400_BAD_REQUEST)

    username = request.json.get('username')
    password = request.json.get('password')

    if User.get(User.username == username) is not None:
        abort(status.HTTP_400_BAD_REQUEST)    # existing user
    user = User(username=username)
    user.hash_password(password)
    user.save()
    return format_response({'user_id': user.user_id}, status.HTTP_201_CREATED)


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@auth.login_required
def update_user(user_id):
    if not request.json or 'password' not in request.json:
        abort(status.HTTP_400_BAD_REQUEST)

    ### ONLY LOGGED IN USER WITH ID=1 CAN CHANGE PASSWORDS
    if g.user.user_id != 1:
        about(status.HTTP_401_UNAUTHORIZED)

    new_password = request.json.get('password')

    user = get_object_or_404(User, User.user_id == user_id)
    user.hash_password(new_password)
    user.save()
    return format_response({'user_id': user.user_id}, status.HTTP_200_OK)


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@auth.login_required
def delete_user(user_id):
    ### ONLY LOGGED IN USER WITH ID=1 CAN DELETE USERS
    if g.user.user_id != 1:
        about(status.HTTP_401_UNAUTHORIZED)

    user = get_object_or_404(User, User.user_id == user_id)
    user.delete()
    return format_response({'deleted': True}, status.HTTP_200_OK)


@app.route('/api/users', methods=['GET'])
@auth.login_required
def get_users():
    ### ONLY LOGGED IN USER WITH ID=1 CAN VIEW ALL USERS
    if g.user.user_id != 1:
        about(status.HTTP_401_UNAUTHORIZED)

    users = list(map(user_to_dict, User.select()))

    return format_response({'users': users}, status.HTTP_200_OK)


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return format_response({'token': token.decode('ascii'), 'duration': 600}, status.HTTP_200_OK)



##### ORDERS #####

@app.route('/api/orders', methods=['GET'])
@auth.login_required
def get_orders():

    page, number = 1, 20

    if 'page' in request.args:
        page = request.args.get('page')
    if 'number' in request.args:
        number = request.args.get('number')
    orders = list(map(order_to_dict, Order.select().order_by(Order.order_id.desc()).paginate(page, number)))
    return format_response({'orders': orders}, status.HTTP_200_OK)


@app.route('/api/orders/<int:order_id>', methods=['GET'])
@auth.login_required
def get_order(order_id):
    order = get_object_or_404(Order, Order.order_id == order_id)
    return format_response(order_to_dict(order), status.HTTP_200_OK)


def set_order(order, data):

    clean_data = strip_data(data)

    if 'name' in clean_data and clean_data['name']:
        order.name = clean_data['name']

    if 'phone' in clean_data and clean_data['phone']:
        order.phone = clean_data['phone']

    if 'email' in clean_data and clean_data['email']:
        order.email = clean_data['email']

    if 'discount' in clean_data and clean_data['discount']:
        order.discount = clean_data['discount']

    if 'discount_message' in clean_data and clean_data['discount_message']:
        order.discount_message = clean_data['discount_message']

    if 'delivered' in clean_data and clean_data['delivered']:
        order.delivered = clean_data['delivered']

    if 'hotel' in clean_data and clean_data['hotel']:
        order.hotel = clean_data['hotel']

    if 'tutoring' in clean_data and clean_data['tutoring']:
        order.tutoring = clean_data['tutoring']

    if 'returned' in clean_data and clean_data['returned']:
        order.returned = datetime.datetime.now

    return order


@app.route('/api/orders', methods=['POST'])
@auth.login_required
def create_order():
    if not request.json:
        abort(status.HTTP_400_BAD_REQUEST)

    order = Order()
    order = set_order(order, request.json)
    order.save()

    return format_response({'order_id': order.order_id}, status.HTTP_201_CREATED)


@app.route('/api/orders/<int:order_id>', methods=['DELETE'])
@auth.login_required
def delete_order(order_id):
    order = get_object_or_404(Order, Order.order_id == order_id)
    order.delete_instance()

    return format_response({'order_id': order.order_id}, status.HTTP_200_OK)


@app.route('/api/orders/<int:order_id>', methods=['PUT'])
@auth.login_required
def update_order(order_id):
    if not request.json:
        abort(status.HTTP_400_BAD_REQUEST)

    order = get_object_or_404(Order, Order.order_id == order_id)
    order = set_order(order, request.json)
    order.save()

    return format_response({'order_id': order.order_id}, status.HTTP_200_OK)

##### CUSTOMERS #####

@app.route('/api/orders/<int:order_id>/customers', methods=['POST'])
@auth.login_required
def create_customers(order_id):
    if not request.json and 'customers' not in request.json:
        abort(status.HTTP_400_BAD_REQUEST)

    order = get_object_or_404(Order, Order.order_id == order_id)

    order.insert_customers(request.json['customers'])
    ## TODO: return customers ids
    return format_response({'order_id': order.order_id}, status.HTTP_201_CREATED)


@app.route('/api/orders/<int:order_id>/customers', methods=['GET'])
def get_customers(order_id):
    order = get_object_or_404(Order, Order.order_id == order_id)

    customers = []
    curr_customer = {}
    last = None
    for cp in order.get_customers():
        customer = cp.customer
        if customer != last:
            last = customer
            customers.append(curr_customer)
            curr_customer = customer_to_dict(customer)
        curr_customer['products'].append(product_to_dict(cp.product))

    return format_response({'customers': customers}, status.HTTP_200_OK)


@app.route('/api/orders/<int:order_id>/customers/<int:customer_id>', methods=['PUT'])
@auth.login_required
def edit_customer(order_id, customer_id):
    if not request.json:
        abort(status.HTTP_400_BAD_REQUEST)

    c = get_object_or_404(Customer, Customer.order_id == order_id, Customer.customer_id == customer_id)

    if 'name' in request.json and request.json['name']:
        c.name = request.json['name']

    if 'height' in request.json and request.json['height']:
        c.height = request.json['height']

    if 'foot_size' in request.json and request.json['foot_size']:
        c.foot_size = request.json['foot_size']

    if 'child' in request.json and request.json['child']:
        c.child = request.json['child']

    c.save()

    if 'product_ids' in request.json:
        c.update_products(request.json[product_ids])

    return format_response({'order_id': c.order_id, 'customer_id': c.customer_id}, status.HTTP_200_OK)


@app.route('/api/orders/<int:order_id>/customers/<int:customer_id>', methods=['DELETE'])
@auth.login_required
def delete_customer(order_id, customer_id):
    c = get_object_or_404(Customer, Customer.order_id == order_id, Customer.customer_id == customer_id)
    c.delete_instance()

    return format_response({'order_id': c.order_id, 'customer_id': c.customer_id}, status.HTTP_200_OK)


##### PRODUCTS ######

@app.route('/api/products', methods=['GET'])
def get_products(order_id):
    products = list(map(product_to_dict, Products.select().execute()))

    return format_response({'products': products}, 'OK', status.HTTP_200_OK)


@app.route('/api/products/<int:product_id>', methods=['PUT'])
@auth.login_required
def update_product(product_id):
    if not request.json:
        abort(status.HTTP_400_BAD_REQUEST)

    p = get_object_or_404(Product, Product.product_id == product_id)

    if 'name' in request.json and request.json['name']:
        c.name = request.json['name']

    if 'adult_price' in request.json and request.json['adult_price']:
        c.adult_price = request.json['adult_price']

    if 'child_price' in request.json and request.json['child_price']:
        c.child_price = request.json['child_price']

    if 'time_group' in request.json and request.json['time_group']:
        c.time_group = request.json['time_group']

    if 'available' in request.json and request.json['available']:
        c.available = request.json['available']

    if 'day' in request.json and request.json['day']:
        c.day = request.json['day']

    p.save()

    return format_response({'products': products}, status.HTTP_200_OK)


##### ORDER PRODUCTS #####

@app.route('/api/orders/<int:order_id>/products', methods=['GET'])
def get_order_products(order_id):
    order = get_object_or_404(Order, Order.order_id == order_id)

    products = list(map(product_to_dict, order.order_products))

    return format_response({'order_id': order.order_id, 'products': products}, status.HTTP_200_OK)


@app.route('/api/orders/<int:order_id>/products', methods=['POST'])
@auth.login_required
def create_order_products(order_id):
    if not request.json:
        abort(status.HTTP_400_BAD_REQUEST)

    order = get_object_or_404(Order, Order.order_id == order_id)

    ps = ({'order': order_id, 'product': p.product_id, 'quantity': p.quantity} for p in products)

    with db.transaction():
        OrderProducts.insert_many(ps).execute()

    return format_response({'order_id': order.order_id}, status.HTTP_201_CREATED)


@app.route('/api/orders/<int:order_id>/products', methods=['PUT'])
@auth.login_required
def update_order_products(order_id):
    if not request.json:
        abort(status.HTTP_400_BAD_REQUEST)

    order = get_object_or_404(Order, Order.order_id == order_id)

    if 'product_ids' in request.json:
        order.update_products(request.json['product_ids'])

    return format_response({'order_id': order.order_id}, status.HTTP_200_OK)


@app.errorhandler(status.HTTP_400_BAD_REQUEST)
def bad_request_error(e):
    return format_error('Invalid request format.', status.HTTP_400_BAD_REQUEST)


@app.errorhandler(status.HTTP_404_NOT_FOUND)
def not_found_error(e):
    return format_error('Resource doesn\'t exist.', status.HTTP_404_NOT_FOUND)


@app.errorhandler(status.HTTP_401_UNAUTHORIZED)
def unauthorized_error(e):
    return format_error('Only admin can change passwords.', status.HTTP_401_UNAUTHORIZED)


@app.before_request
def before_request():
    g.db = db
    g.db.connect()


@app.after_request
def after_request(response):
    g.db.close()
    return response

if __name__ == '__main__':
    app.run(debug=True)