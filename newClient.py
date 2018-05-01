import requests
import crypto_funcs as crypto
import json
import hashlib
import messages as Messages

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
        self.savedKeys = {};

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
        self.isLoggedIn = True;

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