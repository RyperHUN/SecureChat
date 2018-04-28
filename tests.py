from flask import Flask, jsonify, request,abort
import json




import client
import server
import unittest
import crypto_funcs as crypto

class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        server.init();
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

    def user_size_test(self, num):
        jsonAnswer = self.client.get_users();
        #print(json.dumps(jsonAnswer, indent=4));
        array = jsonAnswer["users"];
        self.assertEqual(len(array), num)

    def login_size_test(self,num):
        self.assertEqual(len(server.logged_in_users), num)

    def test_00_start_test(self):
        self.user_size_test(0);

    def test_01_register(self):
        key = 'testkey1234'
        mail = 'added_mail@gmail.com'
        r = self.client.register_user(mail, key)

        #Valid answer
        self.assertEqual(True, 200 <= r and r <= 201);
        self.user_size_test(1)

    def test_02_send_message(self):
        r = self.client.send_message(self.testMessage,'added_mail@gmail.com',self.aeskey);
        self.assertEqual(True, 200 <= r and r <= 201);
        self.assertEqual(len(server.saved_messages), 1);

    #Testing login + getMessage functionality
    def test_03_login_test(self):
        self.test_02_send_message();
        self.login_size_test(0);
        r = self.client.login('added_mail@gmail.com');

        self.assertTrue(self.client.isLoggedIn);
        self.assertIn('sessionId', r);
        self.login_size_test(1);
        messages = self.client.getMessage();
        self.assertEqual(len(messages),1);
        message = messages[0];
        message = crypto.decryptString(message, self.aeskey)
        self.assertEqual(message, self.testMessage.decode('UTF-8'));


if __name__ == '__main__':
    unittest.main()



