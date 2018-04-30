import unittest
import crypto_funcs as crypto

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
    unittest.main()