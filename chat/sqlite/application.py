try:
    from hmac import compare_digest
except ImportError:
    def compare_digest(a, b):
        return a == b
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.automap import automap_base
import binascii
from datetime import datetime
from functools import wraps
from hashing import hash_token
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = r'sqlite:///C:\Users\OGUNTADE\Desktop\chat\sqlite\db.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
prefix = 'Token'
Test_tokent = 'Token c518e5b6b11634784ac60db7e027c8626c3fdf9323d990d0cfbb4a2f99a90421'
User = db.Table('auth_user', db.metadata, autoload=True, autoload_with=db.engine)
Lawyerdetails = db.Table('lawyer_lawyerdetails', db.metadata, autoload=True, autoload_with=db.engine)
Lawyer = db.Table('lawyer_lawyer', db.metadata, autoload=True, autoload_with=db.engine)
Base = automap_base()
Base.prepare(db.engine, reflect=True)
UserforAuthtoken = Base.classes.auth_user
AuthToken = Base.classes.knox_authtoken

def cleanup_token(auth_token):
    for other_token in db.session.query(AuthToken).join(UserforAuthtoken).filter(UserforAuthtoken.id == auth_token.user_id).all():
        if other_token.digest != auth_token.digest and other_token.expiry:
             if other_token.expiry < datetime.now():
                db.session.delete(other_token)
                db.session.commit()            
    if auth_token.expiry is not None:
            if auth_token.expiry < datetime.now():
                db.session.delete(auth_token)
                db.session.commit()
                return True                   
    return False   

def validate_user(auth_token):
        status = 200
        owner = db.session.query(User).filter_by(id=auth_token.user_id).first()
        if not owner.is_active:
            msg =  'User inactive or deleted.'
            status = 401   
            return(msg,status)
        return (owner, status)

def authenticate_credentials(token):
    msg = ('Invalid token.')
    status = 401
    for auth_token in db.session.query(AuthToken).filter_by(
                token_key=token[:8]).all():
        if cleanup_token(auth_token):
            continue
        try:
            digest = hash_token(token, auth_token.salt)
        except (TypeError, binascii.Error):
            return (msg, status)
        if compare_digest(digest, auth_token.digest):
            return validate_user(auth_token)
    return (msg, status)

def authenticate(test_token): 
    Test_token = str(test_token)
    auth = Test_token.split()
    status = 401
    if not auth or auth[0].lower() != prefix.lower():
        return None
    if len(auth) == 1:
            msg = ('Invalid token header. No credentials provided.')
            return (msg, status)
    elif len(auth) > 2:
            msg = ('Invalid token header.', 'Token string should not contain spaces.',)   
            return (msg, status)   
    user, status = authenticate_credentials(auth[1])            
    return (user, status)  


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
           return jsonify({'message': 'Authentication is required'}), 401
        try: 
            user, status = authenticate(token)  
            if status == 401:
              return jsonify({'message': user}), status  
        except:
            return jsonify({'message': 'Invalid Token'}), 401
        return f(user, status, *args, **kwargs)   
    return decorated        

@app.route("/")
def index():
    result = db.session.query(User, Lawyer, Lawyerdetails).filter(User.c.id == Lawyer.c.user_id == Lawyerdetails.c.user_id).filter_by(id=30).first()
    #result = db.session.query(User).filter_by(id=30).first()
    return ''


@app.route("/protected", methods=["GET", "POST"])
@token_required
def protected(user, status):
    auth = request.headers.get('Authorization')
    return jsonify({'message': (user.username, status)}) 
 