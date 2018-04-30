import client
import server
import unittest
import crypto_funcs as crypto
import messages as Messages;

class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        server.key_pub_server, server.key_priv_server = server.init();
        self.flaskapp = server.app;
        self.app = self.flaskapp.test_client();
        self.flaskapp.config['TESTING'] = True
        self.flaskapp.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
        self.testRequest = client.TestRequest(self.app);
        self.client = client.Client(client.TestRequest(self.app));
        self.aeskey = b'0123456789abcdef0123456789abcdef'
        self.testMessage = b'test message';

        self.key_rsa_server_priv, self.key_rsa_server_pub = crypto.create_rsa_key('server');
        self.key_rsa_client1_priv, self.key_rsa_client1_pub = crypto.create_rsa_key('client1');
        self.key_rsa_client2_priv, self.key_rsa_client2_pub = crypto.create_rsa_key('client2');

        self.client1Mail = 'real@gmail.com';
        self.client2Mail = 'client@gmail.com';
        self.realClient = client.RealClient(client.Client(client.TestRequest(self.app)), self.key_rsa_client1_priv,self.client1Mail);
        self.realClient2 = client.RealClient(client.Client(client.TestRequest(self.app)), self.key_rsa_client2_priv,self.client2Mail);

    def test_20_key_exchange_message(self):
        rnd = 123123123;
        msgObj = Messages.KeyExchangeRequest.create(self.client1Mail, self.client2Mail, rnd, True);
        encrypted = msgObj.encrypt(self.aeskey, self.key_rsa_server_pub, self.key_rsa_client2_pub, self.key_rsa_client1_priv);
        success, decripted = msgObj.decrypt(encrypted, self.aeskey, self.key_rsa_server_priv, self.key_rsa_client1_pub);
        self.assertTrue(success);
        Messages.add_rsa_decrypt(decripted["message"]["data"], "secure_rsa_client", self.key_rsa_client2_priv);
        self.assertEqual(decripted, encrypted);

    def test_21_messages(self):
        registerObj = Messages.Register.create(self.client1Mail);
        registerEncrypted = registerObj.encrypt(self.key_rsa_server_pub);

        self.testRequest.post("/register_user", registerEncrypted)
        registerFinishObj = Messages.Register.createDone(self.client1Mail, 20202, self.key_rsa_client1_pub)
        registerFinish = registerFinishObj.encrypt(self.key_rsa_server_pub);
        answer = self.testRequest.postGet("/register_user", registerFinish);

        success, decrypted = Messages.SymmetricKeyAnswer.decryptStatic(answer,self.key_rsa_client1_priv, self.key_rsa_server_pub);
        self.assertTrue(success);

        self.client1ServerAes = decrypted["message"]["data"]["secure_rsa"]["symmetric_key"];
        

    def test_22_messages_small(self):
        obj = Messages.SymmetricKeyAnswer.create(self.aeskey);
        encrypted = obj.encrypt(self.key_rsa_client1_pub, self.key_rsa_server_priv);


if __name__ == '__main__':
    unittest.main()