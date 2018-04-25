#!flask/bin/python
from flask import Flask, jsonify, request,abort

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

#For Testing:
#curl -i -H "Content-Type: application/json" -X POST -d '{"mail":"added_test@gmail.com", "public_key":"123key"}' http://localhost:5000/register_user
@app.route('/register_user', methods=['POST'])
def create_task():
    if not request.json :
        abort(400)
    user = {
        'id': users[-1]['id'] + 1,
        'mail': request.json['mail'],
        'public_key': request.json['public_key']
    }
    users.append(user)
    return jsonify({'user': user}), 201

if __name__ == '__main__':
    app.run(debug=True)