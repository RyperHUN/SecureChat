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
        self.startLen = 2;
        self.client = client.Client(client.TestRequest(self.app));

    def user_size_test(self, num):
        jsonAnswer = self.client.get_users();
        #print(json.dumps(jsonAnswer, indent=4));
        array = jsonAnswer["users"];
        assert len(array) == num

    def test_00_start_test(self):
        self.user_size_test(self.startLen);

    def test_01_register(self):
        key = 'testkey1234'
        mail = 'added_mail@gmail.com'
        r = self.client.register_user(mail, key)

        self.user_size_test(self.startLen + 1)


if __name__ == '__main__':
    unittest.main()



