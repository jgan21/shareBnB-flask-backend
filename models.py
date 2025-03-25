"""SQLAlchemy models for shareBnB."""

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

from helper import create_token

bcrypt = Bcrypt()
db = SQLAlchemy()


def connect_db(app):
    """Connect to database."""

    app.app_context().push()
    db.app = app
    db.init_app(app)


class Property(db.Model):
    """Current properties in the system. """

    __tablename__ = 'properties'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    name = db.Column(
        db.String(50),
        nullable=False,
    )

    description = db.Column(
        db.Text,
        nullable=False,
        default="",
    )

    address = db.Column(
        db.String(50),
        nullable=False,
    )

    price = db.Column(
        db.Integer,
        nullable=False,
    )

    backyard = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
    )

    pool = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
    )

    images = db.relationship('Image', backref="property")
    # backref'ed in User Model
    # user = db.relationship('Property', backref="properties")

    def serialize(self):
        """Serialize property to a dict of property info."""

        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "address": self.address,
            "price": self.price,
            "backyard": self.backyard,
            "pool": self.pool,
            "user_id": self.user_id,
            "images": [image.serialize() for image in self.images],
        }


class User(db.Model):
    """Current users in the system. """

    __tablename__ = 'users'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False,
    )

    password = db.Column(
        db.String(200),
        nullable=False,
    )

    first_name = db.Column(
        db.String(50),
        nullable=False,
    )

    last_name = db.Column(
        db.String(50),
        nullable=False,
    )

    email = db.Column(
        db.String(100),
        nullable=False,
    )

    is_admin = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
    )

    properties = db.relationship('Property', backref="user")

    def serialize(self):
        """Serialize property to a dict of property info."""

        return {
            "id": self.id,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
        }

    @classmethod
    def signup(cls, username, password, first_name, last_name, email, is_admin=False):
        """Sign up user.

        Hashes password and adds user to session.
        """

        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user = User(
            username=username,
            password=hashed_pwd,
            first_name=first_name,
            last_name=last_name,
            email=email,
            is_admin=is_admin,
        )

        db.session.add(user)

        return user

    @classmethod
    def authenticate(cls, username, password):
        """Find user with 'username' and 'password'.

        This class method searches for a user who password hash
        matches this password. If it finds such a user, returns
        that user object. Else, returns False.
        """

        user = cls.query.filter_by(username=username).one_or_none()

        if user:
            is_auth = bcrypt.check_password_hash(user.password, password)
            if is_auth:
                return user

        return False


class Image(db.Model):
    """Current images for properties in the system."""

    __tablename__ = 'images'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    property_id = db.Column(
        db.Integer,
        db.ForeignKey('properties.id', ondelete='CASCADE'),
        nullable=False,
    )

    aws_key = db.Column(
        db.String,
        nullable=False
    )

    url = db.Column(
        db.String,
        nullable=False,
    )

    # backref'd in Property Model
    # property = db.relationship('Property', backref="images")

    def serialize(self):
        """Serialize property to a dict of property info."""

        return {
            "id": self.id,
            "property_id": self.property_id,
            "aws_key": self.aws_key,
            "url":self.url,
        }