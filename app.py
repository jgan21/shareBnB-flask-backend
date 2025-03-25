import os
import datetime
import jwt

# from dotenv import load_dotenv
from uuid import uuid4
from helper import upload_image, generate_image_url, create_token
from flask_cors import CORS

from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    g,
)
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError

from models import (
    db, connect_db, User, Property, Image)

# CURR_USER_KEY = "curr_user"

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "DATABASE_URL", 'postgresql:///sharebnb')
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ.get(
    'JWT_SECRET_KEY', 'secret')

toolbar = DebugToolbarExtension(app)

connect_db(app)

##############################################################################
# TEST form at root, so we can try our POST route and see if AWS works


@app.get("/")
def root():
    """TEST form."""

    return render_template("index.html")

##############################################################################
# Auth Routes

@app.before_request
def add_user_to_g():
    """If user is logged in, add curr user to Flask global object `g`."""

    user = authenticateJWT()
    print("Before request - User:", user, flush=True)

    if isinstance(user, User):
        g.user = user
    else:
        g.user = None


def authenticateJWT():
    """Verifies that JWT is valid. Returns user object if valid, else None."""

    auth_header = request.headers.get('Authorization', '')
    print("Auth Header:", auth_header, flush=True)
    parts = auth_header.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        print("Invalid auth header:", auth_header, flush=True)
        return None

    token = parts[1]
    print("Extracted Token:", token, flush=True)

    try:
        data = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        print("Decoded Token Data:", data, flush=True)

        username = data.get("username")
        if not username:
            print("Token missing 'username' field", flush=True)
            return None

        # Find user in DB
        user = User.query.filter_by(username=username).first()
        print("Queried User:", user, flush=True)  # Check if user is found

        return user

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception as e:
        return None


@app.route('/signup', methods=["POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB.

    If form not valid, present form.
    """
    data = request.json

    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')

    if not (username and password and email and first_name and last_name):
        return jsonify({"error": "All fields are required."}), 400

    try:
        user = User.signup(username, password, first_name, last_name, email)

        db.session.commit()
        token = create_token(user)

        return jsonify({
            "token": token
        }), 201

    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username or email already taken."}), 400
    except Exception as e:
        # Generic error handler for unexpected errors
        print(f"Unexpected error: {str(e)}")
        return jsonify(
            {"error": "An unexpected error occurred during signup."}
        ), 500


@app.route('/login', methods=['POST'])
def login():
    """Logs in a user if valid credentials are provided, returns JWT token."""

    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400

    username = data['username']
    password = data['password']

    user = User.authenticate(username, password)
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401

    token = create_token(user)

    return jsonify({
        "user": user.serialize(),
        "token": token
    }), 200

##############################################################################
# User

@app.route('/users/<username>', methods=['GET'])
def get_users_by_username(username):
    """Fetch user data by username if authenticated and authorized."""

    print("g.user:", g.user)
    if not g.user:
        return jsonify({"error": "Unauthorized"}), 403

    if g.user.username != username:
        return jsonify(
            {"error": "Forbidden: You can only access your own data"}
        ), 403

    user = User.query.filter_by(username=username).first()

    if user:
        return jsonify({
            'user': user.serialize()
        }), 200
    else:
        return jsonify({"error": "User not found"}), 404


##############################################################################
# Properties

@app.get('/properties')
def get_properties():
    """ Returns all properties.
            JSON like:
                { properties: [
                    {id, name, price, address, pool, backyard, images }], ...}
    """

    search = request.args.get("term")
    print("get search term=", search)

    if not search:
        properties = Property.query.all()
    else:
        properties = Property.query.filter(
            Property.name.ilike(f"%{search}%")).all() or Property.query.filter(
                Property.address.ilike(f"%{search}%")).all()

    serialized = [property.serialize() for property in properties]
    print("get properties serialized= ", serialized)

    return jsonify(properties=serialized)


@app.post('/properties')
def add_property():
    """ Add property,
            {name, description, address, price, backyard, pool, images}
        Returns confirmation message.
    """

    data = request.form
    print('request form data: ', data)

    property = Property(
        name=data['name'],
        description=data['description'],
        address=data['address'],
        price=data['price'],
        backyard=True if data['backyard'] == 'true' else False,
        pool=True if data['pool'] == 'true' else False,
        user_id=1
    )

    property_image_file = request.files['image']
    print("img_file:", property_image_file)
    print("inside_img_file", property_image_file.content_type)

    db.session.add(property)
    db.session.commit()

    aws_key = uuid4()

    image = Image(
        property_id=property.id,
        aws_key=aws_key,
        url=generate_image_url(aws_key)
    )

    db.session.add(image)
    db.session.commit()

    upload_image(property_image_file, image.aws_key)

    print("current image uuid=", image.aws_key)
    serialized = property.serialize()

    return (jsonify(property=serialized), 201)
