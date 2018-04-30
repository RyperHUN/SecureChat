import crypto_funcs as crypto;
import time,datetime

import json;

def print_json(item):
    parsed = item
    print(json.dumps(parsed, indent=4));

def get_time_now():
    return time.mktime(datetime.datetime.today().timetuple());

def add_rsa_encrypt(custom_part,selected_part, key_rsa_pub):
    bytes = crypto.dict_to_bytes(custom_part[selected_part]);
    custom_part[selected_part] = crypto.encrypt_RSA(bytes, key_rsa_pub);

def add_rsa_decrypt(custom_part,selected_part, key_rsa_priv):
    msg = custom_part[selected_part]
    decrypted = crypto.decrypt_RSA_toBytes(msg, key_rsa_priv);
    custom_part[selected_part] = crypto.bytes_to_dict(decrypted);

def add_aes_encrypt(custom_part,selected_part,aes_key):
    textBin = crypto.dict_to_bytes(custom_part[selected_part]);
    cipher = crypto.encryptString(textBin, aes_key);
    custom_part[selected_part] = cipher;

def add_aes_decrypt(custom_part,selected_part, aes_key):
    hex = custom_part[selected_part];
    decrypted_str = crypto.decryptString(hex, aes_key);
    custom_part[selected_part] = crypto.bytes_to_dict(crypto.string_to_byte(decrypted_str));

def add_signature_custom(custom_part, selected_part, kes_rsa_priv):
    data = custom_part[selected_part];
    bytes = crypto.dict_to_bytes(data);
    byteSignature = crypto.digital_sign_message(bytes, kes_rsa_priv)
    custom_part['signature'] = crypto.bytes_to_hex(byteSignature);
    return custom_part

def add_signature_data(message, key_rsa_priv):
    add_signature_custom(message['message'],"data", key_rsa_priv)
    return message;

def verify_signature_custom(custom_part, selected_part, key_rsa_pub):
    data = custom_part[selected_part]
    sign = custom_part['signature']
    signBytes = crypto.hex_to_bytes(sign);
    bytes = crypto.dict_to_bytes(data)
    success = crypto.digital_sign_verify(bytes, key_rsa_pub, signBytes)
    return success

def verify_signature_data(message, key_rsa_pub):
    return verify_signature_custom(message['message'], "data", key_rsa_pub)


class KeyExchangeRequest:
    def __init__(self, msg):
        self.msg = msg;

    def create(fromMail, toMail, random, isInit):
        return KeyExchangeRequest({"message": {
                    "data": {
                        "secure_rsa":{
                            "from": fromMail
                        },
                        "secure_aes_server": {
                            "to":toMail
                        },
                        "secure_rsa_client": {
                            "message": {
                                "timestamp" : get_time_now(),
                                "isInit" : isInit,
                                "prime": random
                            }
                        },
                        "signature": 0#sign_by_client1(secure_rsa_client)
                    },
                    "signature": 0#sign_by_client1(data)
                }
            })

    def encrypt(self, key_aes_server,key_server_pub,key_receiver_pub, key_sign_priv):
        message = self.msg;
        data = message["message"]["data"];
        add_aes_encrypt(data,"secure_aes_server", key_aes_server);
        add_rsa_encrypt(data,"secure_rsa", key_server_pub);
        add_rsa_encrypt(data, "secure_rsa_client", key_receiver_pub);
        add_signature_custom(data,"secure_rsa_client", key_sign_priv);
        add_signature_data(message, key_sign_priv);

        return message;
    @staticmethod
    def decryptStatic(message, key_aes_server,key_server_priv, key_sign_pub):
        data = message["message"]["data"];
        if not verify_signature_data(message, key_sign_pub):
            print("Signature error")
            return False, None

        if not verify_signature_custom(data, "secure_rsa_client", key_sign_pub):
            print("Signature error")
            return False, None

        add_aes_decrypt(data, "secure_aes_server", key_aes_server);
        add_rsa_decrypt(data, "secure_rsa", key_server_priv);

        return True, message;

    def decrypt(self, message, key_aes_server,key_server_priv, key_sign_pub):
        return self.decryptStatic( message, key_aes_server,key_server_priv, key_sign_pub);


class GetKeyExchangeRequest:
    def __init__(self, msg):
        self.msg = msg;

    def create(mail):
        return GetKeyExchangeRequest({"message": {
                    "data": {
                        "secure_rsa":{
                            "mail": mail
                        },
                        "secure_aes_server": {
                            "timestamp": get_time_now()
                        }
                    },
                    "signature": 0#sign_by_client(data)
                }
            })

    def encrypt(self, key_aes_server,key_server_pub, key_sign_priv):
        message = self.msg;
        data = message["message"]["data"];
        add_aes_encrypt(data,"secure_aes_server", key_aes_server);
        add_rsa_encrypt(data,"secure_rsa", key_server_pub);
        add_signature_custom(data,"secure_rsa_client", key_sign_priv);
        add_signature_data(message, key_sign_priv);

        return message;
    @staticmethod
    def decryptStatic(message, key_aes_server,key_server_priv, key_sign_pub):
        data = message["message"]["data"];
        if not verify_signature_data(message, key_sign_pub):
            print("Signature error")
            return False, None

        add_aes_decrypt(data, "secure_aes_server", key_aes_server);
        add_rsa_decrypt(data, "secure_rsa", key_server_priv);

        return True, message;

    def decrypt(self, message, key_aes_server,key_server_priv, key_sign_pub):
        return self.decryptStatic( message, key_aes_server,key_server_priv, key_sign_pub);

class GetKeyExchangeRequest_answer:
    def __init__(self, toMail,msg):
        self.toMail = toMail;
        self.msg = msg;

    def create(cls,secure_rsa_client, signature,toMail):
        return cls(toMail,{"message": {
                    "data": {
                        "secure_aes_server": {
                            "secure_rsa_client": secure_rsa_client,
                             "signature":signature
                        }
                    },
                    "signature": 0#sign_by_client(data)
                }
            })

    def encrypt(self, key_aes_server, key_sign_priv):
        message = self.msg;
        data = message["message"]["data"];
        add_aes_encrypt(data,"secure_aes_server", key_aes_server);
        add_signature_data(message, key_sign_priv);

        return message;
    @staticmethod
    def decryptStatic(message, key_aes_server, key_server_sign_pub, key_client_pub, key_my_priv):
        data = message["message"]["data"];
        if not verify_signature_data(message, key_server_sign_pub):
            print("Signature error")
            return False, None

        add_aes_decrypt(data, "secure_aes_server", key_aes_server);
        if not verify_signature_data(message, key_client_pub):
            print("Signature error")
            return False, None

        add_rsa_decrypt(data["secure_aes_server"], "secure_rsa_client", key_my_priv);
        return True, message;

    def decrypt(self, message, key_aes_server,key_server_priv, key_sign_pub):
        return self.decryptStatic( message, key_aes_server,key_server_priv, key_sign_pub);


class Register:
    def __init__(self, msg):
        self.msg = msg;

    def create(cls,fromMail):
        return cls({"message": {
                    "data": {
                        "secure_rsa": {
                            "timestamp:" : get_time_now(),
                            "from": fromMail
                        }
                    }
                }
            });
    def create(cls,fromMail, code, public_key):
        return cls({"message": {
                "data": {
                    "secure_rsa": {
                        "timestamp:": get_time_now(),
                        "from": fromMail,
                        "code": code
                    },
                    "unsecure": {
                        "public_key": public_key
                    }
                }
            }
        });

    def encrypt(self, key_pub_server):
        message = self.msg;
        data = message["message"]["data"];
        add_rsa_encrypt(data, "secure_rsa", key_pub_server);

        return message;
    @staticmethod
    def decryptStatic(message, key_my_priv):
        data = message["message"]["data"];

        add_rsa_decrypt(data["secure_aes_server"], "secure_rsa_client", key_my_priv);
        return True, message;

    def decrypt(self, message,  key_sign_pub):
        return self.decryptStatic( message, key_sign_pub);

class SymmetricKeyAnswer():
    def __init__(self, msg):
        self.msg = msg;

    def create(cls,aes_key):
        return cls({"message": {
                "data": {
                    "secure_rsa": {
                        "timestamp:" : get_time_now(),
                        "symmetric_key": aes_key
                    }
                },
                "signature" : 0
            }
        });

    def encrypt(self, key_pub_client,key_priv_server):
        message = self.msg;
        data = message["message"]["data"];
        add_rsa_encrypt(data, "secure_rsa", key_pub_client);
        add_signature_data(message, key_priv_server);

        return message;
    @staticmethod
    def decryptStatic(message, key_priv_client, key_pub_server):
        data = message["message"]["data"];
        if not verify_signature_data(message, key_pub_server):
            print("Signature error")
            return False, None

        add_rsa_decrypt(data, "secure_rsa", key_priv_client);
        return True, message;

    def decrypt(self, message, key_priv_client, key_pub_server):
        return self.decryptStatic( message, key_priv_client, key_pub_server );


class Login:
    def __init__(self, msg):
        self.msg = msg;

    def create(cls,fromMail):
        return cls({"message": {
                    "data": {
                        "secure_rsa": {
                            "timestamp:" : get_time_now(),
                            "from": fromMail
                        }
                    },
                    "signature" : 0
                }
            });

    def encrypt(self, key_pub_server, key_priv_client):
        message = self.msg;
        data = message["message"]["data"];
        add_rsa_encrypt(data, "secure_rsa", key_pub_server);

        add_signature_data(message, key_priv_client);

        return message;

    @staticmethod
    def decryptStatic(message, key_client_priv, key_server_priv):
        data = message["message"]["data"];
        if not verify_signature_data(message, key_client_priv):
            print("Signature error")
            return False, None

        add_rsa_decrypt(data, "secure_rsa", key_server_priv);
        return True, message;

    def decrypt(self, message,  key_client_pub, key_server_priv):
        return self.decryptStatic( message, key_client_pub, key_server_priv);

