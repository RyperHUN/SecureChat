import newClient as client
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
        self.aeskey = b'0123456789abcdef0123456789abcdef'
        self.testMessage = b'test message';
        self.testMessageStr = crypto.byte_to_string(self.testMessage);

        self.key_rsa_server_priv, self.key_rsa_server_pub = crypto.create_rsa_key('server');
        self.key_rsa_client1_priv, self.key_rsa_client1_pub = crypto.create_rsa_key('client1');
        self.key_rsa_client2_priv, self.key_rsa_client2_pub = crypto.create_rsa_key('client2');

        self.client1Mail = 'FIRST@gmail.com';
        self.client2Mail = 'SECOND@gmail.com';
        self.realClient = client.RealClient(client.TestRequest(self.app), self.key_rsa_client1_priv,self.client1Mail);
        self.realClient2 = client.RealClient(client.TestRequest(self.app), self.key_rsa_client2_priv,self.client2Mail);

    def test_20_key_exchange_message(self):
        rnd = 123123123;
        msgObj = Messages.KeyExchangeRequest.create(self.client1Mail, self.client2Mail, rnd, True);
        encrypted = msgObj.encrypt(self.aeskey, self.key_rsa_server_pub, self.key_rsa_client2_pub, self.key_rsa_client1_priv);
        success, decripted = msgObj.decrypt(encrypted, self.aeskey, self.key_rsa_server_priv, self.key_rsa_client1_pub);
        self.assertTrue(success);
        Messages.add_rsa_decrypt(decripted["message"]["data"], "secure_rsa_client", self.key_rsa_client2_priv);
        self.assertEqual(decripted, encrypted);


    def test_22_messages_small(self):
        obj = Messages.SymmetricKeyAnswer.create(self.aeskey);
        encrypted = obj.encrypt(self.key_rsa_client1_pub, self.key_rsa_server_priv);

    def test_23_client(self):
        isRegistered = self.realClient.com_register();
        self.assertTrue(isRegistered);
        self.assertNotEqual(self.realClient.key_aes_server, None);

        isRegistered = self.realClient2.com_register();
        self.assertTrue(isRegistered);
        self.assertNotEqual(self.realClient2.key_aes_server, None);
        #Two clients registered

        #Not needed keys automatically queried from server
        #self.realClient.get_public_key(self.realClient2.mail)
        #self.realClient2.get_public_key(self.realClient.mail)

        sent_messages = 1;
        for i in range(0,sent_messages):
            self.realClient.comm_send_message(self.realClient2.mail, self.testMessageStr);
        self.assertEqual(len(server.key_exchange), 1);
        self.assertEqual(len(server.saved_messages), 0); #Only started key exchange
        self.realClient2.comm_get_message();
        #Client2 got the key
        self.assertTrue(crypto.has_attribute(self.realClient2.savedKeys, self.realClient.mail));
        self.realClient.comm_get_message();
        self.assertEqual(len(server.saved_messages), sent_messages);  # Only started key exchange
        self.realClient2.comm_get_message();
        self.assertEqual(len(self.realClient2.savedMessages[self.realClient.mail]), sent_messages)

        msg = self.realClient2.comm_get_message();
        self.assertEqual(len(server.saved_messages), 0);
        self.assertEqual(len(msg[self.client1Mail]), sent_messages)
        self.assertEqual(msg[self.client1Mail][0], self.testMessageStr)

if __name__ == '__main__':
    unittest.main()