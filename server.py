#!flask/bin/python
from flask import Flask, jsonify

app = Flask(__name__)


users = [
    {
        'id': 1,
        'mail': u'test@gmail.com',
        'public_key': u'testpublicKey12312asdasdfw3'
    },
    {
        'id': 2,
        'mail': u'test2@gmail.com',
        'public_key': u'testpublicKey1234876123948ksf'
    }
]

@app.route('/')
def index():
    return "Hello, World!"

@app.route('/users')
def get_users():
    return jsonify({'users':users});

@app.route('/user/<string:user_mail>')
def get_user(user_mail):
    user = [user for user in users if user['mail'] == user_mail]
    return jsonify({'user':user});

if __name__ == '__main__':
    app.run(debug=True)