#!flask/bin/python
from flask import Flask, jsonify, request,abort
import uuid
import crypto_funcs as crypto
import messages as Messages
import os

app = Flask(__name__)


users = [
    {
        'id': 1,
        'mail': u'test@gmail.com',
        'public_key': u'testpublicKey12312asdasdfw3',
    }
]

logged_in_users = [
    {
        'id': 1,
        'mail': u'test@gmail.com',
        'aes_key' : 'Test key'
    }
]

saved_messages = [
    {
        'to' : 'test@gmail.com',
        'from' : 'sender@gmail.com',
        'message' : 'CipherMessageInHex'
    }
]

key_exchange = [
    {
        'isInit' : True,
        'to' : 'toEmail@gmail.com', #Server RSA
        'message' : { #Client RSA
            'prim' : 'asd',
            'from' : 'from@gmail.com',
        },
        'macMessage' : 'TESTMAC',
        'macEgesz' : 'MACTEST'
    }
]

def authenticate_user(sessionId):
    foundEmail = [elem for elem in logged_in_users if elem['sessionId'] == sessionId];
    if len(foundEmail) == 1:
        return True, foundEmail[0]['mail']
    else :
        return False, None

def has_attribute(data, attribute):
    return attribute in data and data[attribute] is not None

key_priv_server = 0;
key_pub_server = 0;

def init():
    key_pub, key_private = crypto.create_rsa_key("server");
    key_exchange.clear();
    saved_messages.clear();
    logged_in_users.clear();
    users.clear();
    return key_pub, key_private;

@app.route('/')
def index():
    return "Hello, World!"

@app.route('/get_all')
def get_all():
    return jsonify({'users': users, 'loggedIn':logged_in_users, 'saved_messages' :saved_messages, 'key_exchange': key_exchange});

@app.route('/users')
def get_users():
    return jsonify({'users':users});

@app.route('/user/<string:user_mail>')
def get_user(user_mail):
    user = [user for user in users if user['mail'] == user_mail]
    return jsonify(user);

@app.route('/login', methods=['POST'])
def login():
    if not request.json:
        abort(400)
    mail = request.json['mail'];
    user = [user for user in users if user['mail'] == mail]
    if len(user) == 0:
        abort(404)

    for logged in logged_in_users:
        if logged['mail'] == mail:
            logged_in_users.remove(logged);
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
    if not request.json or not has_attribute(request.json, "message"):
        abort(400)


    message = request.json
    success, decrypted = Messages.Register.decryptStatic(message, key_priv_server);
    if not has_attribute(message["message"]["data"], "unsecure"): #Then it is the first step of registration
        #TODO Send email with code
        #Save random for mail
        return jsonify({});

    #TODO Drop message if timestamp is old
    #TODO Verify email code
    id = users[-1]['id'] + 1 if len(users) > 0 else 1
    decryptedData = decrypted["message"]["data"];
    userMail = decryptedData["secure_rsa"]["from"];
    random_number = os.urandom(50)
    aesKey = crypto.generateAES(crypto.string_to_byte(str(random_number)))
    client_pub_key = decryptedData["unsecure"]["public_key"];
    #TODO Only add user if email does not exists
    user = {
        'id': id,
        'mail': userMail,
        'public_key': client_pub_key,
        'aes_key' : aesKey
    }
    users.append(user)

    answerObj = Messages.SymmetricKeyAnswer.create(aesKey);
    encrypted = answerObj.encrypt(client_pub_key, key_priv_server);
    return jsonify(encrypted)

#curl -i -H "Content-Type: application/json" -X POST -d '{"to":"to@gmail.com", "message":"Decriptedasda"}' http://localhost:5000/forward_message
@app.route('/forward_message', methods=['POST'])
def forward_message():
    if not request.json :
        abort(400)
    # TODO Timestamp
    message = {
        'to': request.json['to'],
        'from': request.json['from'],
        'message': request.json['message']
    }
    saved_messages.append(message);
    return jsonify(message);


@app.route('/key_exchange_request', methods=['POST'])
def key_exchange_post():
    if not request.json :
        abort(400)
    # TODO Timestamp
    message =     {
        'isInit' : request.json['isInit'],
        'to' : request.json['to'],
        'message' : request.json['message'],
        'macMessage' : request.json['macMessage'],
        'macEgesz' : request.json['macEgesz']
    }
    key_exchange.append(message);
    return jsonify(message);

@app.route('/key_exchange_get', methods=['POST'])
def key_exchange_get():
    if not request.json :
        abort(400)
    sessionId = request.json['sessionId'];
    success, foundEmail = authenticate_user(sessionId);
    messages = [elem for elem in key_exchange if elem['to'] == foundEmail];
    for logged in key_exchange:
        if logged['to'] == foundEmail:
            key_exchange.remove(logged);
    return jsonify(messages);



@app.route('/get_messages', methods=['POST'])
def get_messages():
    sessionId = request.json['sessionId']
    #Find email for sessin id
    success, foundEmail = authenticate_user(sessionId)
    #Find messages for email
    messages = [elem for elem in saved_messages if elem['to'] == foundEmail];
    #TODO Remove these elements
    return jsonify(messages);

if __name__ == '__main__':
    key_pub_server, key_priv_server = init();
    app.run(debug=True)