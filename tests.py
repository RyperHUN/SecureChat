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

    def user_size_test(self, num):
        r = self.app.get('/users')
        jsonAnswer = json.loads(r.data);
        #print(json.dumps(jsonAnswer, indent=4));
        array = jsonAnswer["users"];
        assert len(array) == num

    def test_start_test(self):
        self.user_size_test(self.startLen);

    def test_register(self):
        r = self.app.post('/register_user', json={
            'mail' : 'added_mail@gmail.com',
            'public_key' : 'testkey1234'
        });
        print(r.data)


if __name__ == '__main__':
    unittest.main()



