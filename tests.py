from flask import Flask, jsonify, request,abort
import json

import client
import server
import unittest

class FlaskTestCase(unittest.TestCase):
    def setUp(self):
        self.flaskapp = server.app;
        self.app = self.flaskapp.test_client();
        self.flaskapp.config['TESTING'] = True
        self.flaskapp.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
        self.client = client.Client(client.TestRequest(self.app));
        self.aeskey = b'0123456789abcdef0123456789abcdef'
        server.users.clear();
        server.logged_in_users.clear();

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
        r = self.client.send_message(b'test message','added_mail@gmail.com',self.aeskey);
        self.assertEqual(True, 200 <= r and r <= 201);

    def test_03_login_test(self):
        self.login_size_test(0);
        r = self.client.login('test@gmail.com');

        self.assertTrue(self.client.isLoggedIn);
        self.assertIn('sessionId', r);
        self.login_size_test(1);

if __name__ == '__main__':
    unittest.main()



