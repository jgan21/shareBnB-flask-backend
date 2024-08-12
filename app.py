import os
from dotenv import load_dotenv
from uuid import uuid4
from helper import upload_image, generate_image_url
from flask_cors import CORS, cross_origin

from flask import (
    Flask, render_template, jsonify, request, g, session
)
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError

from forms import(
    CSRFProtection
)

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

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None

@app.before_request
def add_csrf_only_form():
    """Add a CSRF-only form so that every route can use it."""

    g.csrf_form = CSRFProtection()

def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id

def do_logout():
    """Log out user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]

@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If there already is a user with that username: flash message and re-present
    form.
    """

    do_logout()

    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(

            )

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

