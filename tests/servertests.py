import client
import server
import unittest
import crypto_funcs as crypto
import messages as Messages;

class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        server.server_key = server.init();
        self.flaskapp = server.app;
        self.app = self.flaskapp.test_client();
        self.flaskapp.config['TESTING'] = True
        self.flaskapp.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
        self.testRequest = client.TestRequest(self.app);
        self.client = client.Client(client.TestRequest(self.app));
        self.aeskey = b'0123456789abcdef0123456789abcdef'
        self.testMessage = b'test message';
        server.users.clear();
        server.logged_in_users.clear();
        server.saved_messages.clear();

        self.key_rsa_server_priv, self.key_rsa_server_pub = crypto.create_rsa_key('server');
        self.key_rsa_client1_priv, self.key_rsa_client1_pub = crypto.create_rsa_key('client1');
        self.key_rsa_client2_priv, self.key_rsa_client2_pub = crypto.create_rsa_key('client2');

        self.client1Mail = 'real@gmail.com';
        self.client2Mail = 'client@gmail.com';
        self.realClient = client.RealClient(client.Client(client.TestRequest(self.app)), self.key_rsa_client1_priv,self.client1Mail);
        self.realClient2 = client.RealClient(client.Client(client.TestRequest(self.app)), self.key_rsa_client2_priv,self.client2Mail);

    def user_size_test(self, num):
        jsonAnswer = self.client.get_users();
        #print(json.dumps(jsonAnswer, indent=4));
        array = jsonAnswer["users"];
        self.assertEqual(len(array), num)

    def login_size_test(self,num):
        self.assertEqual(len(server.logged_in_users), num)

    def realClient_login_register(self,realClient):
        success = realClient.register();
        self.assertTrue(success);
        success = realClient.login();
        self.assertTrue(success);

    def two_real_client_login_test(self):
        self.realClient_login_register(self.realClient);
        self.realClient_login_register(self.realClient2);
        self.assertEqual(len(server.users), 2)  # 'User logged in, has sessionId'
        self.assertEqual(len(server.logged_in_users), 2)  # 'User logged in, has sessionId'

    def test_11_real_client_key_exchange(self):
        self.two_real_client_login_test();
        #Two clients logged in
        self.realClient.key_exchange_start(self.client2Mail);
        self.realClient2.getMessages();
        self.realClient.getMessages();
        self.assertTrue(len((self.realClient2.savedKeys)) > 0);
        self.assertTrue(len((self.realClient.savedKeys)) > 0);
        self.assertTrue(self.realClient.savedKeys[self.client2Mail] == self.realClient2.savedKeys[self.client1Mail]);
        self.realClient.send_message(self.testMessage,self.client2Mail);
        #print(json.dumps(self.testRequest.get('/get_all'),indent=4))
        self.assertEqual(len(server.saved_messages), 1);
        messages = self.realClient2.getMessages();
        self.assertEqual(len(messages), 1);
        self.assertEqual(messages[0],crypto.byte_to_string(self.testMessage))

    def test_12_login_test(self):
        self.assertFalse(self.realClient.login());
        #Login not succesful
        self.realClient.register();
        self.assertTrue(self.realClient.login())
        self.assertEqual(len(server.logged_in_users), 1);
        self.assertTrue(self.realClient.login())
        self.assertEqual(len(server.logged_in_users), 1);

    def test_20_key_exchange_message(self):
        rnd = 123123123;
        msgObj = Messages.KeyExchangeRequest.create(self.client1Mail, self.client2Mail, rnd, True);
        encrypted = msgObj.encrypt(self.aeskey, self.key_rsa_server_pub, self.key_rsa_client2_pub, self.key_rsa_client1_priv);
        success, decripted = msgObj.decrypt(encrypted, self.aeskey, self.key_rsa_server_priv, self.key_rsa_client1_pub);
        self.assertTrue(success);
        Messages.add_rsa_decrypt(decripted["message"]["data"], "secure_rsa_client", self.key_rsa_client2_priv);
        self.assertEqual(decripted, encrypted);


if __name__ == '__main__':
    unittest.main()