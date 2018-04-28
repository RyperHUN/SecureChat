import requests
import crypto_funcs as crypto
import json

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
        return r.json();

    def get(self,uri):
        r = requests.get(self.baseUri + uri)
        if r.status_code == 404:
            return {}
        return r.json();

class Client:
    def __init__(self,request):
        self.request = request;

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

    def send_message(self,message, to, aeskey):
        cipher_message = crypto.encryptString(message, aeskey);
        r = self.request.post('/forward_message',
                          {
                              'to': to,
                              'message': cipher_message
                          });
        #print(r.status_code)
        return r;

    def crypto_send_message(self, message, to, rsakey, aeskey):
        if to == "server":
            rsa_message = crypto.encrypt_RSA(message, rsakey)
            hmac = crypto.generate_HMAC(rsa_message, rsakey)
            req = self.request.post('/forward_message',
                                              {
                                                  'message': rsa_message,
                                                  'mac': hmac
                                              });
        else:
            aes_message = crypto.encryptString(message, aeskey)
            to_rsa = crypto.encrypt_RSA(to, rsakey)
            pair = [to_rsa, aes_message]
            hmac = crypto.generate_HMAC(pair, rsakey)
            req = self.request.post('/forward_message',
                                  {
                                      'to': to_rsa,
                                      'message': aes_message,
                                      'mac': hmac
                                  });
        return req

    def diffie_hellman(self, to):

        #sender
        p = crypto.DHPrime
        g = crypto.DHGen
        x = crypto.randInt()
        A = g**x % p
        self.crypto_send_message(A, to, rsakey, aeskey)
        B = receive_respond_number()
        K = B**x % p

        #receiver
        A = receive_number()
        frm = receive_sender()
        p = crypto.DHPrime
        g = crypto.DHGen
        y = crypto.randInt()
        B = g**y % p
        self.crypto_send_message(B, frm, rsakey, aeskey)
        K = A**y % p

        return K

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
        #TODO Need server_pub_key to exist!!!

    def register(self):
        r = self.client.register_user(self.mail, self.rsa_pub_key);
        if r == 200 or r == 201:
            self.isRegistered = True;
        return self.isRegistered;

    def login(self):
        r = self.client.login(self.mail);
        self.isLoggedIn = True
        self.sessionId = r['sessionId'];
        return self.isLoggedIn;

    def send_message(self,message, to):
        return;
        #TODO Add saved mail,aes key pairs
        #return r;

    def getMessages(self):
        messages = self.client.getMessage();
        #TODO Save messages



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
            #TODO call logout function

        elif splitted_command[0].upper() == "SEND":
            self.send_message(splitted_command[2], splitted_command[1]);

        elif splitted_command[0].upper() == "HELP":
            self.print_help();

        else:
            print("The command is not valid!");
            self.print_help();
