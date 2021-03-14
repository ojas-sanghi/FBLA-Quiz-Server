import rsa
import rsa.randnum
import pickle
import codecs
from Crypto.Cipher import AES

from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/get_questions/<string:encoded_pickled_pubkey>')
def get_questions(encoded_pickled_pubkey: str):
    with open("questions.json", "r") as questions:
        questions = questions.read() 
    
    # generate AES key
    aes_key = rsa.randnum.read_random_bits(128)

    # create AES instance and get nonce value
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    aes_nonce = aes_cipher.nonce

    # encrypt questions with AES instance
    encrypted_questions, aes_tag = aes_cipher.encrypt_and_digest(questions.encode("utf8"))

    # decode serialized PublicKey object into bytes
    decoded_pickle = codecs.decode(encoded_pickled_pubkey.replace("\\", "/").encode(), "base64")
    # unpickle bytes to make pubkey
    rsa_pubkey = pickle.loads(decoded_pickle)

    # encrypt AES key with RSA
    encrypted_aes_key = rsa.encrypt(aes_key, rsa_pubkey)

    # make list of all required info
    # encode them all as strings so they can be serialized and sent over the network
    list_of_data = [encrypted_questions, aes_tag, encrypted_aes_key, aes_nonce]
    for i in range(0, len(list_of_data)):
        data: bytes = list_of_data[i]
        new_data = codecs.encode(data, "base64").decode()
        list_of_data[i] = new_data
        
    # return it as JSON
    return jsonify(list_of_data)