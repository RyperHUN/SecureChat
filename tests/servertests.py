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
        #Testing key exchange request
        registerObj = Messages.Register.create(self.client2Mail);
        registerEncrypted = registerObj.encrypt(self.key_rsa_server_pub);

        self.testRequest.post("/register_user", registerEncrypted)
        registerFinishObj = Messages.Register.createDone(self.client2Mail, 20202, self.key_rsa_client2_pub)
        registerFinish = registerFinishObj.encrypt(self.key_rsa_server_pub);
        answer = self.testRequest.postGet("/register_user", registerFinish);

        success, decrypted = Messages.SymmetricKeyAnswer.decryptStatic(answer, self.key_rsa_client2_priv,
                                                                       self.key_rsa_server_pub);
        self.assertTrue(success);

        self.client2ServerAes = decrypted["message"]["data"]["secure_rsa"]["symmetric_key"];
        self.assertEqual(len(server.users),2);
        #Two AES keys exchanged with server
        rand1 = 2000;
        obj = Messages.KeyExchangeRequest.create(self.client1Mail,self.client2Mail,rand1,True);
        encrypted = obj.encrypt(self.client1ServerAes, self.key_rsa_server_pub, self.key_rsa_client2_pub, self.key_rsa_client1_priv);
        self.testRequest.post('/key_exchange_request', encrypted);
        self.assertEqual(len(server.key_exchange), 1);

        obj = Messages.GetKeyExchangeRequest.create(self.client2Mail);
        encrypted = obj.encrypt(self.client2ServerAes, self.key_rsa_server_pub, self.key_rsa_client2_priv);
        keyExchEncrypted = self.testRequest.postGet('/key_exchange_get', encrypted);
        mail = Messages.GetKeyExchangeRequest_answer.getSenderMail(keyExchEncrypted, self.client2ServerAes);
        self.assertEqual(mail, self.client1Mail);
        success, decrypted = Messages.GetKeyExchangeRequest_answer.decryptStatic(keyExchEncrypted, self.client2ServerAes,
                                                     self.key_rsa_server_pub, self.key_rsa_client1_pub, self.key_rsa_client2_priv);
        self.assertTrue(success)
        prime = decrypted["message"]["data"]["secure_aes_server"]["secure_rsa_client"]["message"]["prime"];
        self.assertEqual(prime, rand1);
        self.assertEqual(len(server.key_exchange), 0);
        rand2 = 5000;
        ###
        obj = Messages.KeyExchangeRequest.create(self.client2Mail, self.client1Mail, rand2, False);
        encrypted = obj.encrypt(self.client2ServerAes, self.key_rsa_server_pub, self.key_rsa_client1_pub,
                                self.key_rsa_client2_priv);
        self.testRequest.post('/key_exchange_request', encrypted);
        self.assertEqual(len(server.key_exchange), 1);

        obj = Messages.GetKeyExchangeRequest.create(self.client1Mail);
        encrypted = obj.encrypt(self.client1ServerAes, self.key_rsa_server_pub, self.key_rsa_client1_priv);
        keyExchEncrypted = self.testRequest.postGet('/key_exchange_get', encrypted);
        mail = Messages.GetKeyExchangeRequest_answer.getSenderMail(keyExchEncrypted, self.client1ServerAes);
        self.assertEqual(mail, self.client2Mail);
        success, decrypted = Messages.GetKeyExchangeRequest_answer.decryptStatic(keyExchEncrypted,
                                                                                 self.client1ServerAes,
                                                                                 self.key_rsa_server_pub,
                                                                                 self.key_rsa_client2_pub,
                                                                                 self.key_rsa_client1_priv);
        self.assertTrue(success)
        prime_2 = decrypted["message"]["data"]["secure_aes_server"]["secure_rsa_client"]["message"]["prime"];
        self.assertEqual(prime_2, rand2);
        self.assertEqual(len(server.key_exchange), 0);

        #TODO create key with DH
        #This is now self.aesKey;
        obj = Messages.ForwardMessage.create(self.client1Mail, self.client2Mail,self.testMessageStr);
        encrypted = obj.encrypt(self.client1ServerAes, self.key_rsa_server_pub, self.aeskey, self.key_rsa_client1_priv);
        self.testRequest.post('/forward_message', encrypted);

        self.assertEqual(len(server.saved_messages), 1);

        obj = Messages.GetMessage.create(self.client2Mail);
        encrypted = obj.encrypt(self.client2ServerAes,self.key_rsa_server_pub, self.key_rsa_client1_priv);
        answer = self.testRequest.postGet('/get_messages',encrypted);

        sender = Messages.GetMessage_answer.getSenderMail(answer,self.client2ServerAes);
        self.assertEqual(sender, self.client1Mail);
        success, decrypted = Messages.GetMessage_answer.decryptStatic(answer, self.client2ServerAes, self.aeskey, self.key_rsa_server_pub, self.key_rsa_client1_pub);
        self.assertTrue(success);
        msg = decrypted["message"]["data"]["secure_aes_client"]["message"]["message"];
        self.assertEqual(msg,self.testMessageStr);




    def test_22_messages_small(self):
        obj = Messages.SymmetricKeyAnswer.create(self.aeskey);
        encrypted = obj.encrypt(self.key_rsa_client1_pub, self.key_rsa_server_priv);

    def test_23_client(self):
        isRegistered = self.realClient.register();
        self.assertTrue(isRegistered);
        self.assertNotEqual(self.realClient.key_aes_server, None);

        isRegistered = self.realClient2.register();
        self.assertTrue(isRegistered);
        self.assertNotEqual(self.realClient2.key_aes_server, None);
        #Two clients registered

        #TODO get public key
        self.realClient.add_public_key(self.realClient2.mail, self.realClient2.key_rsa_pub);
        self.realClient2.add_public_key(self.realClient.mail, self.realClient.key_rsa_pub);

        self.realClient.key_exchange_start(self.realClient2.mail);
        self.assertEqual(len(server.key_exchange), 1);
        self.realClient2.saveExchangedKeys();
        self.assertEqual(len(server.key_exchange), 1); # 1 rmoved 1 added
        self.realClient.saveExchangedKeys();
        self.assertEqual(len(server.key_exchange), 0);
if __name__ == '__main__':
    unittest.main()