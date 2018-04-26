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

    def test_empty_db(self):
        r = self.app.get('/users')
        jsonAnswer = json.loads(r.data);
        #print(json.dumps(jsonAnswer, indent=4));
        array = jsonAnswer["users"];
        assert len(array) == self.startLen

if __name__ == '__main__':
    unittest.main()



