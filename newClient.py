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
                "rsa_pub_key": "asd"
            }
        };
        self.savedMessages = {};
        self.savedKeys = {};

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

    def register(self):
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
        #TODO if rsa_key_not exist get it from server
        if(has_attribute(self.savedKeys, mail)):
            return self.savedKeys[mail]["rsa_pub_key"];

    def get_aes_key(self, mail):
        #TODO if rsa_key_not exist get it from server
        if(has_attribute(self.savedKeys, mail)):
            return self.savedKeys[mail]["aes_key"];

    def key_exchange_start(self, toMail):
        assert self.isLoggedIn
        rand1 = 2000;

        obj = Messages.KeyExchangeRequest.create(self.mail, toMail, rand1, True);
        encrypted = obj.encrypt(self.key_aes_server, self.key_rsa_server_pub, self.get_rsa_key(toMail),
                                self.key_rsa_priv);
        self.testRequest.post('/key_exchange_request', encrypted);

    def saveExchangedKeys(self):
        obj = Messages.GetKeyExchangeRequest.create(self.mail);
        encrypted = obj.encrypt(self.key_aes_server, self.key_rsa_server_pub, self.key_rsa_priv);
        keyExchEncrypted = self.testRequest.postGet('/key_exchange_get', encrypted);
        senderMail = Messages.GetKeyExchangeRequest_answer.getSenderMail(keyExchEncrypted, self.key_aes_server);
        senderRsa = self.get_rsa_key(senderMail);

        success, decrypted = Messages.GetKeyExchangeRequest_answer.decryptStatic(keyExchEncrypted,
                                                                                 self.key_aes_server,
                                                                                 self.key_rsa_server_pub,
                                                                                 senderRsa,
                                                                                 self.key_rsa_priv);
        msg = decrypted["message"]["data"]["secure_aes_server"]["secure_rsa_client"]["message"];
        rand1 = msg["prime"];
        #TODO Diffie hellman
        rand2 = 12312;
        self.add_aes_key(senderMail, b'0123456789abcdef0123456789abcdef');


        isInit = msg["isInit"];
        if(isInit):
            obj = Messages.KeyExchangeRequest.create(self.mail, senderMail, rand2, False);
            encrypted = obj.encrypt(self.key_aes_server, self.key_rsa_server_pub, senderRsa ,
                                        self.key_rsa_priv);
            self.testRequest.post('/key_exchange_request', encrypted);



        return success;

    #TODO Login
    def login(self):
        success, sessionId = self.client.login(self.mail);
        self.isLoggedIn = success
        self.sessionId = sessionId;
        self.isRegistered = self.isLoggedIn or self.isRegistered;
        return self.isLoggedIn;

    def get_public_key(self,mail):
        public_key_str = self.testRequest.get('/get_public_key/' + mail);
        public_key = crypto.str_to_RSA(public_key_str);
        self.add_public_key(mail, public_key);

    def send_message(self,to, message):
        assert self.isLoggedIn

        obj = Messages.ForwardMessage.create(self.mail, to, message);
        key_aes_client = self.get_aes_key(to);
        encrypted = obj.encrypt(self.key_aes_server, self.key_rsa_server_pub, key_aes_client, self.key_rsa_priv);
        self.testRequest.post('/forward_message', encrypted);

    def save_msg(self,sender, msg):
        if not has_attribute(self.savedMessages,sender):
            self.savedMessages[sender] = [];

        self.savedMessages[sender].append(msg);

    #TODO get more messages at the same time
    def get_message(self):
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

    #TODO Get messages

    def getMessages(self):
        assert self.isLoggedIn

        messages = self.client.getMessage();
        self.saveExchangedKeys();

        for i in range(0, len(messages)):
            messages[i] = self.decryptMessage(messages[i]);
        #TODO Save messages
        return messages;