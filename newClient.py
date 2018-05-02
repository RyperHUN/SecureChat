import requests
import crypto_funcs as crypto
import json
import hashlib
import messages as Messages

def has_attribute(data, attribute):
    return attribute in data and data[attribute] is not None

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
        if r.status_code == 404 or r.status_code == 400:
            raise ValueError('Something bad happened');
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
        if r.status_code == 404 or r.status_code == 400:
            raise ValueError('Something bad happened');
        return r.json()

    def get(self,uri):
        r = requests.get(self.baseUri + uri)
        if r.status_code == 404:
            return {}
        return r.json();


class RealClient():
    def __init__(self, client, rsa_key, mail):
        self.testRequest = client;
        self.key_rsa_priv = rsa_key;
        self.mail = mail;
        self.key_rsa_pub = self.key_rsa_priv.publickey();
        self.key_aes_server = None;
        #TODO Need server_pub_key to exist!!!
        self.key_rsa_server_pub = crypto.import_key('server_pub_key.pem');
        self.isRegistered = False;
        self.isLoggedIn = False;
        self.savedKeys = {
            "mail" : {
                "aes_key": "asd",
                "rsa_pub_key": "asd",
                "random" : 123
            }
        };
        self.savedMessages = {};
        self.savedKeys = {};
        self.savedSendQueue = {};

    def add_public_key(self, mail, pub_key):
        if (type(pub_key) is str):
            pub_key = crypto.str_to_RSA(pub_key);
        if has_attribute(self.savedKeys, mail):
            self.savedKeys[mail]["rsa_pub_key"] = pub_key;
        else:
            self.savedKeys[mail] = {"aes_key": None, "rsa_pub_key": pub_key}


    def add_aes_key(self, mail, key):
        if (type(key) is str):
            key = crypto.string_to_byte(key);
        if has_attribute(self.savedKeys, mail):
            self.savedKeys[mail]["aes_key"] = key;
        else:
            self.savedKeys[mail] = {"aes_key" : key, "rsa_pub_key": None}

    def add_random(self,mail, random):
        if not has_attribute(self.savedKeys, mail):
            self.savedKeys[mail] = {"aes_key": None, "rsa_pub_key": None, "random" : random};
        self.savedKeys[mail]["random"] = random;

    def com_register(self):
        assert not self.isLoggedIn
        registerObj = Messages.Register.create(self.mail);
        registerEncrypted = registerObj.encrypt(self.key_rsa_server_pub);

        self.testRequest.post("/register_user", registerEncrypted);

        # TODO TYPE IN MAIL CODE
        code = 2000
        registerFinishObj = Messages.Register.createDone(self.mail, code, self.key_rsa_pub)
        registerFinish = registerFinishObj.encrypt(self.key_rsa_server_pub);
        # TODO Try catch
        answer = self.testRequest.postGet("/register_user", registerFinish);
        success, decrypted = Messages.SymmetricKeyAnswer.decryptStatic(answer, self.key_rsa_priv,
                                                                       self.key_rsa_server_pub);
        if not success:
            return False;

        self.key_aes_server = decrypted["message"]["data"]["secure_rsa"]["symmetric_key"];
        self.isRegistered = True;
        self.isLoggedIn = True; #TODO is logged in?

        return self.isRegistered;

    def get_rsa_key(self, mail):
        self.comm_get_public_key(mail); #Gets RSA key automatically
        if(has_attribute(self.savedKeys, mail)):
            return self.savedKeys[mail]["rsa_pub_key"];

    def get_aes_key(self, mail):
        if(has_attribute(self.savedKeys, mail)):
            return self.savedKeys[mail]["aes_key"];

    def comm_key_exchange_start(self, toMail):
        assert self.isLoggedIn
        if has_attribute(self.savedKeys, toMail) and self.savedKeys[toMail]["random"] != None:
            return; #This means that key exchange already started

        sentPow, rand = crypto.diffie_hellman_send();
        self.add_random(toMail, rand);

        obj = Messages.KeyExchangeRequest.create(self.mail, toMail, sentPow, True);
        encrypted = obj.encrypt(self.key_aes_server, self.key_rsa_server_pub, self.get_rsa_key(toMail),
                                self.key_rsa_priv);
        self.testRequest.post('/key_exchange_request', encrypted);

    def comm_save_exchanged_keys(self):
        obj = Messages.GetKeyExchangeRequest.create(self.mail);
        encrypted = obj.encrypt(self.key_aes_server, self.key_rsa_server_pub, self.key_rsa_priv);
        messages = self.testRequest.postGet('/key_exchange_get', encrypted);
        for message in messages:
            senderMail = Messages.GetKeyExchangeRequest_answer.getSenderMail(message, self.key_aes_server);
            senderRsa = self.get_rsa_key(senderMail);

            success, decrypted = Messages.GetKeyExchangeRequest_answer.decryptStatic(message,
                                                                                     self.key_aes_server,
                                                                                     self.key_rsa_server_pub,
                                                                                     senderRsa,
                                                                                     self.key_rsa_priv);
            msg = decrypted["message"]["data"]["secure_aes_server"]["secure_rsa_client"]["message"];
            sentData = msg["prime"];

            isInit = msg["isInit"];
            if(isInit):
                # Then I am the receiver
                receivedPow = sentData;
                finishPow, KEY = crypto.diffie_hellman_receive(receivedPow);
                self.add_aes_key(senderMail, crypto.generateAES(KEY));
                obj = Messages.KeyExchangeRequest.create(self.mail, senderMail, finishPow, False);
                encrypted = obj.encrypt(self.key_aes_server, self.key_rsa_server_pub, senderRsa ,
                                            self.key_rsa_priv);
                self.testRequest.post('/key_exchange_request', encrypted);
            else:
                #I am the sender, and I got back a finishPow
                finishPow = sentData;
                rand = self.savedKeys[senderMail]["random"];
                KEY = crypto.diffie_hellman_send_finish(rand, finishPow);
                self.add_aes_key(senderMail, crypto.generateAES(KEY))

            self.send_messages_from_queue(senderMail);


    def send_messages_from_queue(self,senderMail):
        if not has_attribute(self.savedSendQueue, senderMail):
            return

        for message in self.savedSendQueue[senderMail]:
            self.send_msg_finish(senderMail, message);

    def send_msg_finish(self, to, msgObj):
        key_aes_client = self.get_aes_key(to);
        encrypted = msgObj.encrypt(self.key_aes_server, self.key_rsa_server_pub, key_aes_client, self.key_rsa_priv);
        self.testRequest.post('/forward_message', encrypted);

    def comm_send_message(self, to, message):
        assert self.isLoggedIn

        obj = Messages.ForwardMessage.create(self.mail, to, message);

        key_aes_client = self.get_aes_key(to);
        if key_aes_client == None:
            self.save_msg_for_queue(to, obj);
            self.comm_key_exchange_start(to);
        else:
            self.send_msg_finish(to, obj);


    def login(self):
        success, sessionId = self.client.login(self.mail);
        self.isLoggedIn = success
        self.sessionId = sessionId;
        self.isRegistered = self.isLoggedIn or self.isRegistered;
        return self.isLoggedIn;

    def comm_get_public_key(self, mail):
        public_key_str = self.testRequest.get('/get_public_key/' + mail);
        public_key = crypto.str_to_RSA(public_key_str);
        self.add_public_key(mail, public_key);

    def save_msg_for_queue(self,to, msg):
        if not has_attribute(self.savedSendQueue,to):
            self.savedSendQueue[to] = [];

        self.savedSendQueue[to].append(msg);

    def get_msg_from_queue(self,to):
        if not has_attribute(self.savedSendQueue, to):
            return [];

        messages = self.savedSendQueue[to];

        self.savedSendQueue.pop(to); #Delete messages
        return messages;



    def save_msg(self,sender, msg):
        if not has_attribute(self.savedMessages,sender):
            self.savedMessages[sender] = [];

        self.savedMessages[sender].append(msg);

    def comm_get_message(self):
        self.comm_save_exchanged_keys();
        obj = Messages.GetMessage.create(self.mail);
        encrypted = obj.encrypt(self.key_aes_server, self.key_rsa_server_pub, self.key_rsa_priv);

        messages = self.testRequest.postGet('/get_messages', encrypted);
        for message in messages:
            sender = Messages.GetMessage_answer.getSenderMail(message, self.key_aes_server);

            clientAes = self.get_aes_key(sender);
            clientPub = self.get_rsa_key(sender);

            success, decrypted = Messages.GetMessage_answer.decryptStatic(message, self.key_aes_server, clientAes,
                                                                          self.key_rsa_server_pub,
                                                                          clientPub);

            if success:
                msg = decrypted["message"]["data"]["secure_aes_client"]["message"]["message"];
                self.save_msg(sender, msg);
        return self.savedMessages;


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
        self.client.comm_send_message(message, to)

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
        realClient.com_register();
        realClient.login();
    print('Login succesful, session ID:' , realClient.sessionId);
    clientControl = ClientControl(realClient);
    clientControl.print_help();
    clientControl.input_loop();

#test_client_control();