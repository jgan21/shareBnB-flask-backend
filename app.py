import os
from dotenv import load_dotenv
from uuid import uuid4
from helper import upload_image, generate_image_url
from flask_cors import CORS, cross_origin

from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    g,
    session
)
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError

import jwt

from models import (
    db, connect_db, User, Property, Image)

CURR_USER_KEY = "curr_user"

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "DATABASE_URL", 'postgresql:///sharebnb')
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY', 'secret')

toolbar = DebugToolbarExtension(app)

connect_db(app)

##############################################################################
# TEST form at root, so we can try our POST route and see if AWS works


@app.get("/")
def root():
    """TEST form."""

    return render_template("index.html")

##############################################################################
# User signup/login/logout

@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if 'token' in request.headers:
        token = request.headers['token']

        try:
            payload = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms=['HS256'],
            )
            g.user = payload
        except jwt.exceptions.InvalidSignatureError as err:
            print("Invalid Sig, error is", err)
            g.user = None

    else:
        g.user = None

@app.route('/signup', methods=["POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If there already is a user with that username: flash message and re-present
    form.
    """
    data = request.json

    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')

    if not(username and password and email and first_name and last_name):
        return jsonify({"error": "All fields are required."}), 400

    try:
        token = User.signup(username, password, first_name, last_name, email)

        db.session.commit()

    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username or email already taken."}), 400

    return jsonify({"token": token}), 201


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
        url = generate_image_url(aws_key)
    )

    db.session.add(image)
    db.session.commit()

    upload_image(property_image_file, image.aws_key)

    print("current image uuid=", image.aws_key)
    serialized = property.serialize()

    return (jsonify(property=serialized), 201)

