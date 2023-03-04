from flask import *
import pymongo
from flask_session import Session
import random
import smtplib
from email.message import EmailMessage
import datetime
import re
import base64
from validate_email import validate_email
from dotenv import load_dotenv
import os
import bcrypt

load_dotenv()

def generate_otp(user_email):
    new_otp = random.randint(100000, 999999)
    sender_email = os.getenv("email_id")
    sender_password = os.getenv("email_password")
    receiver_email = user_email
    message_text = f"The OTP is {new_otp}"
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)
    if validate_email(receiver_email):
        server.sendmail(sender_email, receiver_email, message_text)
        return new_otp
    else:
        return 0


def add_user(id, first_name, last_name, email, phone, password, gender):
    users_column.insert_one({'User_Id':id, "First_Name":first_name, "Last_Name":last_name, "Email":email , "Phone":phone , "Password":password, "Gender":gender, "Role":'user', "Date_Added":datetime.datetime.utcnow()})

def add_product(id, name , price, quantity, dealer, description):
    products_column.insert_one({'Product_Id':id, 'Product_Name':name, 'Product_Price':price, 'Product_Quantity':quantity, 'Product_dealer':dealer, 'Product_description':description, "Date_Added":datetime.datetime.utcnow()})

def add_to_cart(product_id, quantity):
    exist = carts_column.find_one({"$and":[{'Product_Id':product_id} , {'User_Id':session['user_id']}]})
    if exist:
        exist_cart_id = int(exist['Cart_Id'])
        exist_count = int(exist['Product_Quantity'])
        current_count = exist_count+int(quantity)
        carts_column.update_one({'Cart_Id':exist_cart_id},{"$set":{"Product_Quantity":current_count}})
    else:
        print("HI")
        latest_cart_id = carts_column.find_one(sort=[('Cart_Id', -1)])
        id = int(latest_cart_id['Cart_Id']) + 1 if latest_cart_id else 1
        carts_column.insert_one({'Cart_Id':id, 'Product_Id':int(product_id), 'Product_Quantity':int(quantity), 'User_Id':int(session['user_id'])})

project_server = pymongo.MongoClient(os.getenv("pymongo_client"))
db_users = project_server['users']
users_column = db_users['users_list']

db_products =project_server['products']
products_column = db_products['products_list']
carts_column = db_products['carts_lists']


app = Flask(__name__)
app.config['SESSION_TYPE'] = os.getenv("session_type")
app.config['SECRET_KEY'] = os.getenv("secret_key")
sess = Session()

@app.route('/',methods=['GET','POST'])
def home():
    session['name'] = None
    return render_template('home.html')

@app.route('/login',methods=['GET','POST'])
def login():
    msg = ""
    if request.method == 'POST':
        details = request.form
        name = details['username']
        password = details['password']
        user = users_column.find_one({"$or":[{'Email':name},{'Phone':name}]})
        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user['Password']):
                session['user_id'] = user['User_Id']
                session['name'] = user['First_Name']
                session['role'] = user['Role']
                session['email'] = user['Email']
                session['phone'] = user['Phone']
                return redirect('/dashboard')
            else:
                msg = "wrong Password"
        else:
            msg ="Wrong Username"
    return render_template('login.html',msg=msg)

@app.route('/signup', methods=['GET'])
def show_signup_form():
    return render_template('signup.html', msg='')

@app.route('/signup',methods=['POST'])
def signup():
    msg = ""
    if request.method == 'POST':
        details = request.form
        email = details['email_address']
        first_name = details['first_name']
        last_name = details['last_name']
        phone = details['phone']
        password = details['password']
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        gender = details['gender']
        otp=  details['otp']
        if int(otp)==session['new_otp']  :
            latest_doc = users_column.find_one(sort=[('User_Id', -1)])
            id = int(latest_doc['User_Id']) + 1 if latest_doc else 1
            b= add_user(id, first_name, last_name, email, phone, password_hash, gender)
            session['new_otp'] = None
            return redirect('/login')
        else:
            msg = "Wrong Otp"
    return render_template('signup.html',msg= msg)

@app.route('/generate_otp_email',methods=['GET','POST'])
def generate_otp_email():
    msg=""
    if request.method == 'POST':
        email=request.form.get('data')
        user = users_column.find_one({'Email':email})
        if user:
            msg = "User Email already Registered"
        else:
            msg = "OTP send to corresponding mail"
            email_otp = generate_otp(email)
            session['new_otp'] = email_otp
            if email_otp == 0:
                otp_status = 1
            else :
                otp_status = email_otp
    return jsonify ({'success':True,'otp':otp_status,'msg':msg})

@app.route('/forgot_password',methods=['GET','POST'])
def forgot_password():
    msg=" "
    if request.method == 'POST':
        email=request.form['email']
        user = users_column.find_one({'Email':email})
        if user:
            email_otp = generate_otp(email)
            session['forgot_password_email'] = email
            session['forgot_password_otp'] = email_otp
            return redirect('/forgot_password_otp')
        else :
            msg="The Email Dont Exist"
    return render_template('forgot_password.html', msg=msg)

@app.route('/forgot_password_otp',methods=['GET','POST'])
def forgot_password_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        email_otp = session['forgot_password_otp']
        session['forgot_password_otp'] = None
        if int(entered_otp) == email_otp:
            return redirect('/reset_password')
    return render_template('forgot_password_otp.html')

@app.route('/reset_password',methods=['GET','POST'])
def reset_password():
    msg = " "
    if request.method == 'POST':
        new_password = request.form['new_password']
        reenter_password = request.form['reenter_password']
        if new_password == reenter_password:
            password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            users_column.update_one({'Email':session['forgot_password_email']}, { "$set": { "Password": password_hash } })
            session['forgot_password_email']
            return redirect('/login')
        else:
            msg = "Passwords didn't match"
    return render_template('reset_password.html',msg=msg)

@app.route("/dashboard",methods=['GET','POST'])
def dashboard():
    product_details = products_column.find()
    users_details = users_column.find_one({'Email':session['email']})
    if users_details and 'Profile' in users_details:
        Profile = base64.b64encode(users_details['Profile']).decode('utf-8')
    else:
        Profile = None
    return render_template('dashboard.html',user=users_details,pic=Profile, product=product_details)

@app.route("/profile",methods=['GET','POST'])
def profile():
    users_details = users_column.find_one({'Email':session['email']})
    if users_details and 'Profile' in users_details:
        Profile = base64.b64encode(users_details['Profile']).decode('utf-8')
    else:
        Profile = None
    if request.method == 'POST':
        file = request.files["pic"]
        profile_binary = file.read()
        users_column.update_one({'Email':session['email']}, { "$set": { "Profile": profile_binary } })
    return render_template('profile.html',user=users_details,pic=Profile)

@app.route("/carts",methods=['GET','POST'])
def carts():
    your_cart = carts_column.find({'User_Id':int(session['user_id'])})
    all_products = products_column.find()
    return render_template('carts.html',products = your_cart,all_products=all_products)


@app.template_filter('b64encode')
def base64_encode(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode('utf-8')
    return value

@app.route('/add_to_cart',methods=['POST'])
def addtocart():
    if request.method == 'POST':
        product_id = request.form['id']
        quantity = request.form['count']
        a = add_to_cart(product_id, quantity)
    return jsonify({'success':True})


























@app.route('/addproduct',methods = ['GET','POST'])
def addproduct():
    latest_doc = products_column.find_one(sort=[('Product_Id', -1)])
    id = int(latest_doc['Product_Id']) + 1 if latest_doc else 1
    if request.method=='POST':
        name = request.form['product_name']
        price = request.form['product_price']
        quantity = request.form['product_quantity']
        dealer = request.form['product_dealer']
        description = request.form['product_description']
        b=add_product(id, name , price, quantity, dealer, description)
    return render_template("add_product.html")








@app.route('/logout')
def logout():
    session['name'] = None
    session['role'] = None
    session['email'] = None
    session['phone'] = None
    return redirect('/')

if __name__=='__main__':
    app.run(debug=True)
















