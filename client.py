import requests
import crypto_funcs as crypto
import json
import hashlib

class RequestApi:
    def post(self,uri,data):
        return
    def postGet(self,uri,data):
        return;
    def get(self,uri):
        return

class TestRequest(RequestApi):
    def __init__(self,flaskTestClient):
        self.app = flaskTestClient;

    def post(self,uri,data):
        r = self.app.post(uri, content_type='application/json',
                          data=json.dumps(data));
        return r.status_code
    def postGet(self,uri,data):
        r = self.app.post(uri, content_type='application/json',
                          data=json.dumps(data));
        if r.status_code == 404:
            return {}
        return json.loads(r.data);
    def get(self,uri):
        r = self.app.get(uri)
        jsonAnswer = json.loads(r.data);
        return jsonAnswer;

class ClientRequest(RequestApi):
    def __init__(self, baseUri):
        self.baseUri = baseUri;

    def post(self,uri,data):
        r = requests.post(self.baseUri + uri, json=data)
        return r.status_code

    def postGet(self,uri,data):
        r = requests.post(self.baseUri + uri, json=data)
        if r.status_code == 404:
            return {}
        return r.json()

    def get(self,uri):
        r = requests.get(self.baseUri + uri)
        if r.status_code == 404:
            return {}
        return r.json();

class Client:
    def __init__(self,request):
        self.request = request;
        self.keys = {};

    def get_users(self):
        r = self.request.get('/users')
        return r

    def get_user(self,mail):
        uri = '/user/' + mail
        r = self.request.get(uri)
        return r

    def register_user(self,email, public_key):
        r = self.request.post('/register_user',
            {
                'mail' : email,
                'public_key' : public_key
            });
        return r;

    #TODO Add from parameter
    def send_message(self,message, to,fromMail, aeskey):
        cipher_message = crypto.encryptString(message, aeskey);
        r = self.request.post('/forward_message',
                          {
                              'to': to,
                              'from' : fromMail,
                              'message': cipher_message
                          });
        #print(r.status_code)
        return r;

    #message : prim + from
    def send_key_exchange(self, A, to,fromMail, isInit):
        #TODO Send normal SECRET request
        self.request.post('/key_exchange_request',{
            'isInit': isInit,
            'to' : to,
            'message' : {
                'from' : fromMail,
                'prim' : A
            },
            'macMessage' : 'test mac msg',
            'macEgesz' : 'test msg'
        })

    def diffie_hellman_send(self, to, fromMail):
        #TODO Need to be logged in to used because of sessionId
        #sender
        p = crypto.DHPrime
        g = crypto.DHGen
        x = crypto.randInt()

        A = pow(g, x, p)
        self.send_key_exchange(A, to,fromMail, True);
        return x;

    def diffie_hellman_send_finish(self, x, B):
        p = crypto.DHPrime

        K = pow(B, x, p)
        return K;

    def diffie_hellman_receive(self, number, toMail, fromMail):
        #receiver
        A = number
        frm = fromMail
        p = crypto.DHPrime
        g = crypto.DHGen
        y = crypto.randInt()

        B = pow(g, y, p)
        self.send_key_exchange(B, toMail, fromMail, False);
        K = pow(A, y, p)
        return K;

    def receive_key_exchanges(self, sessionId):
        r = self.request.postGet('/key_exchange_get', {'sessionId' : sessionId});
        #TODO Titkositas leszedese
        if len(r) == 0:
            return False, None
        else :
            return True, r;

    def key_exchange_request(self,toMail, fromMail):
        random = self.diffie_hellman_send(toMail,fromMail);
        self.keys[toMail] = random;

    def key_exchange_handle(self,key_exchange_request, myMail):
        if not key_exchange_request or len(key_exchange_request) == 0:
            return False, None, None

        isInit = key_exchange_request['isInit'];
        fromMail = key_exchange_request['message']['from'];
        B = int(key_exchange_request['message']['prim']);
        if not isInit:
            random = self.keys[fromMail];
            key = self.diffie_hellman_send_finish(random,B);
            return True, fromMail, key
        else :
            key = self.diffie_hellman_receive(B, fromMail, myMail);
            return True, fromMail, key

    def login(self, mail):
        r = self.request.postGet('/login', {'mail' : mail});
        self.isLoggedIn = r != {};
        if not self.isLoggedIn:
            return False, None

        self.sessionId = r['sessionId']
        return self.isLoggedIn, r['sessionId'];

    def getMessage(self):
        assert self.isLoggedIn;
        messages = self.request.postGet('/get_messages', {'sessionId': self.sessionId});
        encryptedMessages = []
        for elem in messages:
            encryptedMessages.append({'from': elem['from'], 'message':elem['message']});
        return encryptedMessages;


class RealClient():
    def __init__(self, client, rsa_key, mail):
        self.client = client;
        self.rsa_key = rsa_key;
        self.mail = mail;
        self.rsa_pub_key = self.rsa_key.publickey().exportKey(format='PEM').decode('ASCII');
        self.rsa_server_pub_key = crypto.import_key('server_pub_key.pem');
        self.isRegistered = False;
        self.isLoggedIn = False;
        self.sampleAESKEY = b'0123456789abcdef0123456789abcdef'
        self.savedKeys = {};
        #TODO Need server_pub_key to exist!!!

    def register(self):
        assert not self.isLoggedIn
        r = self.client.register_user(self.mail, self.rsa_pub_key);
        if r == 200 or r == 201:
            self.isRegistered = True;
        return self.isRegistered;

    def key_exchange_start(self, toMail):
        assert self.isLoggedIn
        self.client.key_exchange_request(toMail, self.mail);

    def login(self):
        success, sessionId = self.client.login(self.mail);
        self.isLoggedIn = success
        self.sessionId = sessionId;
        self.isRegistered = self.isLoggedIn or self.isRegistered;
        return self.isLoggedIn;

    def send_message(self,message, to):
        assert self.isLoggedIn
        if to in self.savedKeys.keys():
            key = self.savedKeys[to];
            r = self.client.send_message(message, to,self.mail, key);
            #TODO Add saved mail,aes key pairs
            return r;


    def saveExchangedKeys(self):
        isKeyExchange, key_exchange_request = self.client.receive_key_exchanges(self.sessionId);
        if isKeyExchange:
            for elem in key_exchange_request:
                success, mail, key = self.client.key_exchange_handle(elem, self.mail)
                if success:
                    self.savedKeys[mail] = crypto.generateAES(crypto.string_to_byte(str(key)));


    def decryptMessage(self,message):
        mail = message['from'];
        if mail in self.savedKeys.keys():
            key = self.savedKeys[mail];
            decrypted = crypto.decryptString(message['message'],key);
            return decrypted;

        return message['message'];


    def getMessages(self):
        assert self.isLoggedIn

        messages = self.client.getMessage();
        self.saveExchangedKeys();

        for i in range(0, len(messages)):
            messages[i] = self.decryptMessage(messages[i]);
        #TODO Save messages
        return messages;



def client_test():
    client = Client(ClientRequest('http://127.0.0.1:5000'));
    print(client.get_users())
    aeskey = b'0123456789abcdef0123456789abcdef'
    #print(crypto.encryptString(b'asd', aeskey).hex());
    RSA_key = crypto.get_rsa_key();
    RSA_public = RSA_key.publickey().exportKey(format='PEM').decode('ASCII');
    print(RSA_public)
    print(client.register_user('added_test@gmail.com', RSA_public))
    print(client.send_message(b'elkuldott uzenet wazzzeee', 'test@gmail.com', aeskey));

    print(client.get_user('added_test@gmail.com'));
    print(client.login('added_test@gmail.com'))

#client_test()
#HTTP codes -> 201 -> first created
#HTTP codes -> 200 -> already created

class ClientControl:
    def __init__(self, client):
        self.client = client;

    def login(self, mail):
        self.client.login(mail)

    def register_user(self, mail):
        self.client.register_user(mail)

    def getMessage(self):
        print(self.client.getMessages());

    def logout(self):
        self.client.logout()

    def send_message(self, message, to):
        self.client.send_message(message, to)

    def print_help(self):
        print("Register:        register <e-mail>");
        print("Login:           login <e-mail>");
        print("Send message:    send <to_e-mail> <message>");
        print("Get              get messages")
        print("Logout:          logout");

    def client_Control(self):
        command = input();
        splitted_command = command.split();

        if splitted_command[0].upper() == "GET":
            self.getMessage()
        elif splitted_command[0].upper() == "LOGOUT":
            return True;
            #TODO call logout function
        elif splitted_command[0].upper() == "SEND":
            self.send_message(splitted_command[2], splitted_command[1]);

        elif splitted_command[0].upper() == "HELP":
            self.print_help();

        else:
            print("The command is not valid!");
            self.print_help();

        return False;

    def input_loop(self):
        isQuit = self.client_Control()
        while not isQuit:
            isQuit = self.client_Control();

#TODO Normal API
def test_client_control():
    print('Enter <mail> to log in');
    mail = input();
    realClient = RealClient(Client(ClientRequest('http://127.0.0.1:5000')), crypto.get_rsa_key(), mail);
    if not realClient.login():
        realClient.register();
        realClient.login();
    print('Login succesful, session ID:' , realClient.sessionId);
    clientControl = ClientControl(realClient);
    clientControl.print_help();
    clientControl.input_loop();

#test_client_control();