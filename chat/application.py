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
from hashing import hash_token
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = r'sqlite:///C:\Users\OGUNTADE\Desktop\chat\sqlite\db.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
prefix = 'Token'
Test_token = 'Token c518e5b6b11634784ac60db7e027c8626c3fdf9323d990d0cfbb4a2f99a90421'
User = db.Table('auth_user', db.metadata, autoload=True, autoload_with=db.engine)
Lawyerdetails = db.Table('lawyer_lawyerdetails', db.metadata, autoload=True, autoload_with=db.engine)
Lawyer = db.Table('lawyer_lawyer', db.metadata, autoload=True, autoload_with=db.engine)
Base = automap_base()
Base.prepare(db.engine, reflect=True)
UserforAuthtoken = Base.classes.auth_user
AuthToken = Base.classes.knox_authtoken

def cleanup_token(auth_token):
    print("yellow")
    for other_token in db.session.query(AuthToken).join(UserforAuthtoken).filter(UserforAuthtoken.id == auth_token.user_id).all():
        print(other_token.digest, other_token.token_key, other_token.user_id)
        print("after")
        if other_token.digest != auth_token.digest and other_token.expiry:
             if other_token.expiry < datetime.now():
                print(f"{other_token.digest} with {other_token.token_key} and {other_token.user_id} to be deleted")
                db.session.delete(other_token)
                db.session.commit()
                print('deleted')
    if auth_token.expiry is not None:
            if auth_token.expiry < datetime.now():
                print(f"The actual token is to be deleted")
                db.session.delete(auth_token)
                db.session.commit()
                print('deleted')
                print(True)
                return True    
    print(False)                   
    return False   

def validate_user(auth_token):
        owner = db.session.query(User).filter_by(id=auth_token.user_id).first()
        print(owner.username)
        if not owner.is_active:
            print('User inactive or deleted.')
            return('User inactive or deleted.')
        return (owner, auth_token)

def authenticate_credentials(token):
    #token = token.decode("utf-8")
    print(token)
    for auth_token in db.session.query(AuthToken).filter_by(
                token_key=token[:8]).all():
        print(auth_token.digest, auth_token.token_key, auth_token.user_id)
        #cleanup_token(auth_token)
        if cleanup_token(auth_token):
            print(auth_token)
            continue
        try:
            digest = hash_token(token, auth_token.salt)
            print(digest)
        except (TypeError, binascii.Error):    
            print("Invalid Token")
        if compare_digest(digest, auth_token.digest): 
            print("Correct Token")   
            return validate_user(auth_token)
    print("Invalid Token") 
    return "Invalid Token"

@app.route("/")
def index():
    result = db.session.query(User, Lawyer, Lawyerdetails).filter(User.c.id == Lawyer.c.user_id == Lawyerdetails.c.user_id).filter_by(id=30).first()
    #result = db.session.query(User).filter_by(id=30).first()
    print(result)
    return ''

@app.route("/authenticate")
def authenticate(): 
    auth = Test_token.split()
    print(auth)
    if not auth or auth[0].lower() != prefix.lower():
         print(None)
    if len(auth) == 1:
            msg = ('Invalid token header. No credentials provided.')
            print(msg)  
    elif len(auth) > 2:
            msg = ('Invalid token header.', 'Token string should not contain spaces.',)   
            print(msg)   
    user, auth_token = authenticate_credentials(auth[1])
    print(user, auth_token)             
    return ''   

@app.route("/unprotected")
def unprotected(): 
    return ''  

@app.route("/protected")
def protected():      
    return ''  