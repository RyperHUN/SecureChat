from flask import Flask, jsonify, request,abort
import json




import client
import server
import unittest
import crypto_funcs as crypto

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
        self.assertEqual(messages[0],self.testMessage.decode('utf-8'))

    def test_12_login_test(self):
        self.assertFalse(self.realClient.login());
        #Login not succesful
        self.realClient.register();
        self.assertTrue(self.realClient.login())
        self.assertEqual(len(server.logged_in_users), 1);
        self.assertTrue(self.realClient.login())
        self.assertEqual(len(server.logged_in_users), 1);


class CryptoTestCases(unittest.TestCase):
    def setUp(self):
        self.testMessageBin = b"alma a fa alatt";
        self.testMessageUtf = self.testMessageBin.decode('utf-8');
        self.key_AES = key = b'0123456789abcdef0123456789abcdef';

        self.key_rsa_server_priv, self.key_rsa_server_pub = crypto.create_rsa_key('server');
        self.key_rsa_client1_priv, self.key_rsa_client1_pub = crypto.create_rsa_key('client1');
        self.key_rsa_client2_priv, self.key_rsa_client2_pub = crypto.create_rsa_key('client2');
        return;

    def test_91_test(self):
        self.assertTrue(True);


    def test_91_AES(self):
        cipherText = crypto.encryptString(self.testMessageBin, self.key_AES);
        decoded = crypto.decryptString(cipherText, self.key_AES);
        self.assertEqual(decoded,self.testMessageUtf);

    def test_92_RSA(self):
        RSA_key = self.key_rsa_client1_priv;
        cipherText_RSA = crypto.encrypt_RSA(self.testMessageBin, RSA_key.publickey());
        plainText_RSA = crypto.decrypt_RSA(cipherText_RSA, RSA_key);
        self.assertEqual(plainText_RSA, self.testMessageUtf);

    def test_93_DigitalSignature(self):
        signature1 = crypto.digital_sign_message(self.testMessageBin, self.key_rsa_client1_priv);
        success = crypto.digital_sign_verify(self.testMessageBin, self.key_rsa_client1_pub, signature1);
        self.assertTrue(success);
        fail = crypto.digital_sign_verify(self.testMessageBin, self.key_rsa_server_pub, signature1);
        self.assertFalse(fail);

    #def test_94_Mac(self):
        #mackey = b'yoursecretMACkey'
        #mac = crypto.generate_HMAC(self.testMessageBin, mackey);
        #print(mac.hexdigest());
        #print(mac.digest());

        #hmac_check = crypto.check_HMAC(self.testMessageBin, mackey, mac.digest());
        #self.assertTrue(hmac_check);


if __name__ == '__main__':
    flaskTests = unittest.TestLoader().loadTestsFromTestCase(FlaskTestCase)
    cryptoTests = unittest.TestLoader().loadTestsFromTestCase(CryptoTestCases)
    #Select tests to run
    unittest.TextTestRunner(verbosity=2).run(flaskTests)
    unittest.TextTestRunner(verbosity=2).run(cryptoTests)


