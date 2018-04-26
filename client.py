import requests
import crypto_funcs as crypto

class RequestApi:
    def post(self,uri,data):
        return
    def get(self,uri):
        return

class TestRequest(RequestApi):
    def __init__(self,flaskApp):
        self.app = flaskApp;

    def post(self,uri,data):
        return
    def get(self,uri):
        return

class ClientRequest(RequestApi):
    def __init__(self, baseUri):
        self.baseUri = baseUri;

    def post(self,uri,data):
        r = requests.post(self.baseUri + uri, json=data)
        return r
    def get(self,uri):
        r = requests.get(self.baseUri + uri)
        return r

class Client:
    def __init__(self,request):
        self.request = request;

    def get_users(self):
        r = self.request.get('users')
        return r.json()

    def get_user(self,mail):
        uri = 'user/' + mail
        r = self.request.get(uri)
        if r.status_code == 404:
            return 404
        return r.json()

    def register_user(self,email, public_key):
        r = self.request.post('register_user',
            {
                'mail' : email,
                'public_key' : public_key
            });
        return r.json();

    def send_message(self,message, to, aeskey):
        cipher_message = crypto.encryptString(message, aeskey);
        r = self.request.post('forward_message',
                          {
                              'to': to,
                              'message': cipher_message.hex()
                          });
        #print(r.status_code)
        return r.json();

def client_test():
    client = Client(ClientRequest('http://127.0.0.1:5000/'));
    print(client.get_users())
    aeskey = b'0123456789abcdef0123456789abcdef'
    #print(crypto.encryptString(b'asd', aeskey).hex());
    RSA_key = crypto.get_rsa_key();
    RSA_public = RSA_key.publickey().exportKey(format='PEM').decode('ASCII');
    print(RSA_public)
    print(client.register_user('added_test@gmail.com', RSA_public))
    print(client.send_message(b'elkuldott uzenet wazzzeee', 'test@gmail.com', aeskey));

    print(client.get_user('added_test@gmail.com'));

#client_test()