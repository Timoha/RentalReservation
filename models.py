from os import environ
from urllib.parse import urlparse
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


SECRET_KEY = 'lololololololo'

from peewee import *
import datetime

import db_settings

if "HEROKU" in environ:
    uses_netloc.append("postgres")
    url = urlparse(environ["DATABASE_URL"])
    DATABASE = {
        "name": url.path[1:],
        "user": url.username,
        "password": url.password,
        "host": url.hostname,
        "port": url.port,
    }
else:
    DATABASE = db_settings.DATABASE



db = PostgresqlDatabase(
    DATABASE["name"], user=DATABASE["user"],
    password=DATABASE["password"],
    host=DATABASE["host"],
    port=DATABASE["port"])


class BaseModel(Model):
    class Meta:
        database = db


class User(BaseModel):
    user_id = PrimaryKeyField()
    username = TextField()
    password_hash = TextField()

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password) ### ???????

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(SECRET_KEY, expires_in=expiration)
        return s.dumps({'user_id': self.user_id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(SECRET_KEY)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.get(User.user_id == data['user_id'])
        return user


class Order(BaseModel):
    order_id = PrimaryKeyField()
    time_group = IntegerField()
    name = TextField(null=True)
    phone = TextField(null=True)
    email = TextField(null=True)
    discount = FloatField(null=True)
    discout_message = TextField(null=True)
    delivered = BooleanField(default=False)
    finished = BooleanField(default=False)
    hotel = BooleanField(default=False)
    tutoring = BooleanField(default=False)
    created = DateTimeField(default=datetime.datetime.now)
    returned = DateTimeField(null=True)

    def get_customers(self):
        return (CustomerProduct
                    .select(Customer, CustomerProduct, Product)
                    .join(Product)
                    .switch(CustomerProduct)
                    .join(Customer)
                    .where(Customer.order == self)
                    .order_by(Customer.customer_id))

    def insert_customers(self, customers):

        ## TODO: set to None if empty field
        cs = ({
            'order': self.order_id,
            'name': c['name'],
            'height': c['height'],
            'foot_size': c['foot_size'],
            'child': c['child'],
            'message': c['message']}
            for c in customers)

        with db.transaction():
            Customer.insert_many(cs).execute()

        newCs = list(Customer
            .select(Customer.customer_id)
            .where(Customer.order == self)
            .execute())

        def relate_products():
            for i, c in enumerate(customers):
                for pid in c['product_ids']:
                    yield {'customer': newCs[i].customer_id, 'product': pid}

        with db.transaction():
            CustomerProduct.insert_many(relate_products()).execute()

    def update_products(products):
        OrderProduct.delete().where(OrderProduct.order == self).execute()

        ps = ({'order': self.order_id, 'product': p.product_id, 'quantity': p.quantity} for p in products)

        with db.transaction():
            OrderProduct.insert_many(ps).execute()


class Customer(BaseModel):
    customer_id = PrimaryKeyField()
    order = ForeignKeyField(Order, related_name='customers', on_delete='CASCADE')
    name = TextField(null=True)
    height = IntegerField(null=True, default=0)
    foot_size = IntegerField(null=True, default=0)
    child = BooleanField(default=False)
    message = TextField(null=True)

    def update_products(product_ids):
        CustomerProduct.delete().where(CustomerProduct.customer == self).execute()

        pids = ({'customer': self.customer_id, 'product': pid} for pid in product_ids)

        with db.transaction():
            CustomerProduct.insert_many(pids).execute()


class Product(BaseModel):
    product_id = PrimaryKeyField()
    name = TextField()
    adult_price = FloatField()
    child_price = FloatField()
    product_type = TextField()
    time_group = IntegerField()
    available = BooleanField()
    day = TextField()


class OrderProduct(BaseModel):
    order = ForeignKeyField(Order, related_name='order_products', on_delete='CASCADE')
    product = ForeignKeyField(Product, related_name='order_rents')
    quantity = IntegerField(default=1)

    class Meta:
        indexes = (
            (('order', 'product'), True),
        )


class CustomerProduct(BaseModel):
    customer = ForeignKeyField(Customer, related_name='customer_products', on_delete='CASCADE')
    product = ForeignKeyField(Product, related_name='customer_rents')

    class Meta:
        indexes = (
            (('customer', 'product'), True),
        )


def create_tables():
    db.connect()
    db.create_tables([User, Order, Customer, Product, OrderProduct, CustomerProduct])


def drop_tables():
    db.connect()
    db.drop_tables([User, Order, Customer, Product, OrderProduct, CustomerProduct])
