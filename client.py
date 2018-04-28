import requests
import crypto_funcs as crypto
import json
import time

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
        print(r)
        if not r.json():
            return []
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
    def send_message(self,message, to, aeskey):
        cipher_message = crypto.encryptString(message, aeskey);
        r = self.request.post('/forward_message',
                          {
                              'to': to,
                              'message': cipher_message
                          });
        #print(r.status_code)
        return r;

##########################################################
    # ha már van közös szimetrikus kulcs a receiverrel, kell közös kulcs a szerverrel is ha hmac-et használunk
    def crypto_after_DH_send_message(self, message, to, server_pub_rsa, aes_with_receiver, symetric_key_with_server):
        if to == "server":
            rsa_message = crypto.encrypt_RSA(message, server_pub_rsa)
            hmac = crypto.generate_HMAC(rsa_message, symetric_key_with_server)
            req = self.request.post('/forward_message',
                                              {
                                                  'message': rsa_message,
                                                  'mac': hmac
                                              });
        else:
            aes_message = crypto.encryptString(message, aes_with_receiver)
            to_rsa = crypto.encrypt_RSA(to, server_pub_rsa)
            pair = [to_rsa, aes_message]
            hmac = crypto.generate_HMAC(pair, aes_with_receiver)
            req = self.request.post('/forward_message',
                                  {
                                      'to': to_rsa,
                                      'message': aes_message,
                                      'mac': hmac
                                  });
        return req

    # ha még nincsen közösen megegyezett kulcs
    def crypto_before_DH_send_message(self, message, to, server_pub_rsa,  aes_with_receiver, receiver_pub_rsa):
        if to == "server":
            rsa_message = crypto.encrypt_RSA(message, server_pub_rsa)
            req = self.request.post('/forward_message',
                                              {
                                                  'message': rsa_message,
                                              });
        else:
            aes_message = crypto.encryptString(message, aes_with_receiver)
            to_rsa = crypto.encrypt_RSA(to, server_pub_rsa)
            req = self.request.post('/forward_message',
                                  {
                                      'to': to_rsa,
                                      'message': aes_message,
                                  });
        return req
#############################################################
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

        #TODO Solve prime problem
        #A = g**x % p
        A = pow(g, x, p)
        self.send_key_exchange(A, to,fromMail, True);
        return x;

    def diffie_hellman_send_finish(self, x, B):
        p = crypto.DHPrime
        K = x;
        #TODO Solve prime problem
        K = pow(B, x, p)
        #K = B**x % p
        return K;

    def diffie_hellman_receive(self, number, toMail, fromMail):
        #receiver
        A = number
        frm = fromMail
        p = crypto.DHPrime
        g = crypto.DHGen
        y = crypto.randInt()

        B = pow(g, y, p)
        #TODO Solve prime
        #B = g**y % p
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
        self.isLoggedIn = True
        self.sessionId = r['sessionId'];
        return r;

    def getMessage(self):
        assert self.isLoggedIn;
        messages = self.request.postGet('/get_messages', {'sessionId': self.sessionId});
        encryptedMessages = []
        for elem in messages:
            encryptedMessages.append(elem['message']);
        return encryptedMessages;


class RealClient():
    def __init__(self, client, rsa_key, mail):
        self.client = client;
        self.rsa_key = rsa_key;
        self.mail = mail;
        self.rsa_pub_key = self.rsa_key.publickey().exportKey(format='PEM').decode('ASCII');
        self.rsa_server_pub_key = crypto.import_key('server_pub_key.pem');
        self.isRegistered = False;
        self.sampleAESKEY = b'0123456789abcdef0123456789abcdef'
        self.savedKeys = {};
        #TODO Need server_pub_key to exist!!!

    def register(self):
        r = self.client.register_user(self.mail, self.rsa_pub_key);
        if r == 200 or r == 201:
            self.isRegistered = True;
        return self.isRegistered;

    def key_exchange_start(self, toMail):
        self.client.key_exchange_request(toMail, self.mail);

    def login(self):
        r = self.client.login(self.mail);
        self.isLoggedIn = True
        self.sessionId = r['sessionId'];
        return self.isLoggedIn;

    def send_message(self,message, to):
        if to in self.savedKeys.keys():
            key = self.savedKeys[to];
            r = self.client.send_message(message, to, key);
            #TODO Add saved mail,aes key pairs
            return r;


    def saveExchangedKeys(self):
        isKeyExchange, key_exchange_request = self.client.receive_key_exchanges(self.sessionId);
        if isKeyExchange:
            for elem in key_exchange_request:
                success, mail, key = self.client.key_exchange_handle(elem, self.mail)
                if success:
                    self.savedKeys[mail] = crypto.generateAES(str(key).encode("utf-8"));

    def getMessages(self):
        messages = self.client.getMessage();
        self.saveExchangedKeys();
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
        self.request = client;

    def login(self, mail):
        self.request.login(mail)

    def register_user(self, mail):
        self.request.register_user(mail)

    def getMessage(self):
        self.request.getMessage()

    def logout(self):
        self.request.logout()

    def send_message(self, message, to):
        self.request.send_message(message, to)

    def print_help(self):
        print("Register:        register <e-mail>");
        print("Login:           login <e-mail>");
        print("Send message:    send <to_e-mail> <message>");
        print("Logout:          logout");

    def client_Control(self):
        command = input();
        splitted_command = command.split();

        if splitted_command[0].upper() == "LOGIN":
            self.login(splitted_command[1]);

        elif splitted_command[0].upper() == "REGISTER":
            self.register_user(splitted_command[1]);

        elif splitted_command[0].upper() == "GET":
            self.getMessage();

        elif splitted_command[0].upper() == "LOGOUT":
            return;
            #TODO call logout function

        elif splitted_command[0].upper() == "SEND":
            self.send_message(splitted_command[2], splitted_command[1]);

        elif splitted_command[0].upper() == "HELP":
            self.print_help();

        else:
            print("The command is not valid!");
            self.print_help();
