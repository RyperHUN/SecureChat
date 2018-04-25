import requests
import crypto_funcs as crypto

server_address = 'http://127.0.0.1:5000/'
def get_users():
    r = requests.get(server_address + 'users')
    return r.json()

def get_user(mail):
    uri = server_address + 'user/' + mail
    r = requests.get(uri)
    if r.status_code == 404:
        return 404
    return r.json()

def register_user(email, public_key):
    r = requests.post(server_address + 'register_user',
        json={
            'mail' : email,
            'public_key' : public_key
        });
    return r.json();

def send_message(message, to, aeskey):
    cipher_message = crypto.encryptString(message, aeskey);
    r = requests.post(server_address + 'forward_message',
                      json={
                          'to': to,
                          'message': cipher_message.hex()
                      });
    #print(r.status_code)
    return r.json();

print(get_users())
aeskey = b'0123456789abcdef0123456789abcdef'
#print(crypto.encryptString(b'asd', aeskey).hex());
RSA_key = crypto.get_rsa_key();
RSA_public = RSA_key.publickey().exportKey(format='PEM').decode('ASCII');
#print(RSA_public)
#print(register_user('added_test@gmail.com', RSA_public))
print(send_message(b'elkuldott uzenet wazzzeee', 'test@gmail.com', aeskey));

print(get_user('added_test@gmail.com'));
