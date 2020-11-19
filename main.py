from dns import message
from flask import Flask, jsonify, render_template, request, session, make_response, redirect, url_for
import json
from functools import wraps
import jwt
import datetime
from pymongo import MongoClient
import pandas as pd
import logging

#configure logging file
logging.basicConfig(filename='cloudworx.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

#create flask object
app = Flask(__name__)
logging.info(f'Setting up configrations')

#read config file
with open('./config.json', 'r') as config_file:
    params = json.load(config_file)['params']

app.config['SECRET_KEY'] = params['secret_key']

#setup mongo Clint to access DB
mongo_clint = MongoClient(params['mongo_url'])
db = mongo_clint.get_database('cloudworx')
#users collection is for login verification
#csv_data collection is to load input file data
users = db.users
csv_data = db.csv_data

#validate login credentials
def validate_account(email, password):
    account = users.find_one({'email': email})

    if account == None or not account['password'] == password:
        return False
    return True

#decorator to check and validate token
def check_for_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        email = request.args.get('email')
        user = users.find_one({'email': email})

        if user == None:
            return render_template('errorpage.html', message="Invalid email id")

        token = user['token']

        if not token:
            return render_template('errorpage.html', message="Missing Token")

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])

        except:
            return render_template('errorpage.html', message="Token Expired")

        return func(*args, **kwargs)
    return wrapped

#generate token only if the login credentials are valid
@app.route('/', methods=['POST'])
def token_gen():
    email = request.form['email']
    password = request.form['password']

    account = users.find_one({'email': email})
    if account == None or not account['password'] == password:
        logging.info(f'Login failed for user with email id: {email}')
        return render_template('errorpage.html', message="Invalid user credentials")

    token = jwt.encode({"user": email, "exp": datetime.datetime.utcnow(
    ) + datetime.timedelta(seconds=60)}, app.config['SECRET_KEY'])

    users.update_one({'_id': account['_id']}, {
                     "$set": {"token": token.decode('utf-8')}})
    logging.info(
        f"User with email: {email} logged in. Generated Token = {token.decode('utf-8')}")
    return redirect(f'loadexcel?email={email}')


@app.route('/', methods=['GET'])
def login():
    return render_template('login.html')

#validate token, then allow file upload if validation successful
@app.route('/loadexcel', methods=['GET'])
@check_for_token
def loadexcel():
    logging.info(f'Token Validated')
    return render_template('upload_excel.html')

#upload read files into db and display results
@app.route('/load_database', methods=['GET'])
def load_database():
    my_file = request.args.get('my_file')
    logging.info(f'loaded file: {my_file}')
    data = []
    with open(my_file, encoding="utf-8") as file:
        df = pd.read_csv(file)

    success, fail = [], []

    for i in range(len(df)):
        temp = {}
        val = df.iloc[i, 0:].to_dict()
        for k, v in val.items():
            try:
                temp[k] = v.item()
            except:
                temp[k] = v

        try:
            inserted = csv_data.insert_one(temp)
            success.append(temp)
            logging.info(
                f'Document uploaded in DB with _id: {inserted.inserted_id}')
        except Exception as e:
            fail.append(temp)
            logging.info(
                f'Failed to upload document {temp}, Exception Deatils:\n {e}\n ')

    return render_template('load_database.html', success=pd.DataFrame(success), fail=pd.DataFrame(fail))


if __name__ == "__main__":
    logging.info(f'Server Started')
    app.run(debug=True)
