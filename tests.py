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
        self.client = client.Client(client.TestRequest(self.app));
        self.aeskey = b'0123456789abcdef0123456789abcdef'
        self.testMessage = b'test message';
        server.users.clear();
        server.logged_in_users.clear();
        server.saved_messages.clear();

        self.client1Mail = 'real@gmail.com';
        self.client2Mail = 'client@gmail.com';
        self.realClient = client.RealClient(client.Client(client.TestRequest(self.app)), crypto.get_rsa_key(),self.client1Mail);
        self.realClient2 = client.RealClient(client.Client(client.TestRequest(self.app)), crypto.get_rsa_key(),self.client2Mail);

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

    def t_11_real_client_key_exchange(self):
        self.two_real_client_login_test();
        #Two clients logged in
        self.realClient.key_exchange_start(self.client2Mail);
        self.realClient2.getMessages();
        self.realClient.getMessages();
        self.assertTrue(len(json.dumps(self.realClient2.savedKeys)) > 0);
        self.assertTrue(len(json.dumps(self.realClient.savedKeys)) > 0);
        #print(self.realClient.savedKeys)
        #print(self.realClient2.savedKeys)
        self.realClient.send_message(b'Test message',self.client2Mail);
        self.assertEqual(len(server.saved_messages), 1);
        messages = self.realClient2.getMessages();
        self.assertEqual(len(messages), 1);
        print(messages)

    def test_12_login_test(self):
        self.assertFalse(self.realClient.login());
        #Login not succesful
        self.realClient.register();
        self.assertTrue(self.realClient.login())



if __name__ == '__main__':
    unittest.main()



