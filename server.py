#!flask/bin/python
from flask import Flask, jsonify, request,abort
import uuid

app = Flask(__name__)


users = [
    {
        'id': 1,
        'mail': u'test@gmail.com',
        'public_key': u'testpublicKey12312asdasdfw3',
    },
    {
        'id': 2,
        'mail': u'test2@gmail.com',
        'public_key': u'testpublicKey1234876123948ksf',
    }
]

logged_in_users = [
    {
        'id': 1,
        'mail': u'test@gmail.com',
        'sessionId' : 'asdasdas'
    }
]

saved_messages = [
    {
        'to' : 'toEmail@gmail.com',
        'message' : 'CipherMessageInHex'
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
    return jsonify(user);

@app.route('/login', methods=['POST'])
def login():
    if not request.json :
        abort(400)
    mail = request.json['mail'];
    user = get_user(mail); #TODO find mail
    sessionId = str(uuid.uuid1());
    #TODO Find in registered users
    loggedInObj = {
        'id' : 1,
        'mail' : mail,
        'sessionId' : sessionId
    };
    logged_in_users.append(loggedInObj)
    return jsonify({'sessionId':sessionId});
#For Testing:
#curl -i -H "Content-Type: application/json" -X POST -d '{"mail":"added_test@gmail.com", "public_key":"123key"}' http://localhost:5000/register_user
@app.route('/register_user', methods=['POST'])
def register_user():
    if not request.json :
        abort(400)
    id = users[-1]['id'] + 1 if len(users) > 0 else 1
    user = {
        'id': id,
        'mail': request.json['mail'],
        'public_key': request.json['public_key']
    }
    users.append(user)
    return jsonify(user), 201

#curl -i -H "Content-Type: application/json" -X POST -d '{"to":"to@gmail.com", "message":"Decriptedasda"}' http://localhost:5000/forward_message
@app.route('/forward_message', methods=['POST'])
def forward_message():
    if not request.json :
        abort(400)
    # TODO Timestamp
    message = {
        'to': request.json['to'],
        'message': request.json['message']
    }
    saved_messages.append(message);
    return jsonify(message);

@app.route('/get_messages', methods=['POST'])
def get_messages():
    sessionId = request.json['sessionId']
    #Find email for sessin id
    foundEmail = [elem for elem in logged_in_users if elem['sessionId'] == sessionId];
    foundEmail = foundEmail[0]['mail']; #TODO Handle wrong sessionId
    #Find messages for email
    messages = [elem for elem in saved_messages if elem['to'] == foundEmail];
    return jsonify(messages);

if __name__ == '__main__':
    app.run(debug=True)