import hashlib
import json
from time import time
from tkinter import E
from uuid import uuid4
from flask import Flask, jsonify, request, render_template, make_response, session, redirect
from textwrap import dedent
from urllib.parse import urlparse
import Crypto
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from getpass import getpass
from mysql.connector import connect, Error
import os
class blockchain():
    def __init__(self):
        self.nodes = set()
        self.NewWallets = []
        self.chain = [{
            "index": 1,
            "time": "127562.445",
            "transactions": [{"sender":"tst", "recipient":"test", "amount":5}],
            "new_wallet":[{"adress":"testWallet", "public_key":"SHA256 public key"}],
            "proof": 1,
            "key_hash": self.sha256("1")
        }]
        self.temp_transa = []
    def parallelNode(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    def createblock(self, proof):
        block = {
            "index": self.chain[-1]["index"]+1,
            "time": time(),
            "transactions": self.temp_transa,
            "new_wallet": self.NewWallets,
            "proof": proof,
            "key_hash": self.sha256(self.chain[-1])
        }
        self.chain.append(block)
        self.temp_transa = []
        self.NewWallets = []
        return block
    def createTransaction(self, sender, recipient, amount):
        self.temp_transa.append({
            "sender": sender,
            "recipient": recipient,
            "amount": amount
        })
    def NewWallet(self, sha256Adress, public_key):
        if self.MatchingWallets(sha256Adress, public_key):
            return False
        self.NewWallets.append({
            "adress":sha256Adress, 
            "public_key":public_key
            })
        return True
    def MatchingWallets(self, address, key):
        for chain in self.chain:
            for chainElements in chain["new_wallet"]:
                if chainElements["adress"] == address or chainElements["public_key"] == key:
                    return True
        for wallet in self.NewWallets:
            if wallet["adress"] == address or wallet["public_key"] == key:
                return True
        return False
    def ProofWork(self, last_proof):
        proof = 0
        while self.checkProof(last_proof, proof) is False:
            proof += 1
        proofkey = f'{last_proof}{proof}'.encode()
        proof_hash = hashlib.sha256(proofkey).hexdigest()
        print(proof_hash + " " + str(proofkey))
        return proof
    def checkProof(self, last_proof, proof):
        proofkey = f'{last_proof}{proof}'.encode()
        proof_hash = hashlib.sha256(proofkey).hexdigest()
        return proof_hash[:5] == "00000"
    def sha256(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    def checkParallerlNode(self):
        tempChain = self.chain
        for chainPraller in self.node:
            if len(self.chain) < len(request.get("http://{chainPraller}/chain")):
                self.chain = chainPraller
        if(tempChain == self.chain):
            return False
        else:
            return True
        

    def checkAllBlockchains(self):
        ElementChain = 1
        while ElementChain < len(self.chain):
            if self.chain[ElementChain]["key_hash"] != self.sha256(self.chain[ElementChain-1]):
                print("Key hash error")
                return False
            if self.checkProof(self.chain[ElementChain-1]["proof"], self.chain[ElementChain]["proof"]) is False:
                print("proofs error")
                return False
            ElementChain += 1
        return True

bc = blockchain()

app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', '')
def mine():
    if bc.checkAllBlockchains() is False:
        return "Блокчейн был изменён"
    lastBlock = bc.chain[-1]
    proof  = bc.ProofWork(lastBlock['proof'])
    bc.createTransaction("server", node_identifier, 1)
    block = bc.createblock(proof)
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'new wallets': block['new_wallet'],
        'previous_hash': block['key_hash'],
    }
    return jsonify(response), 200

def Getchain():
    return jsonify(bc.chain)
def NewWallet(values):
    if bc.NewWallet(values['wallet_adress'], values['key']):
        return jsonify({"message":"The wallet was successfully created"})
    else:
        return jsonify({"message":"A wallet with this address or key already exists"})
def AddNode(values):
    bc.nodes.add(values["url"])
def new_transaction(values):
    required = ['sender', 'recipient', 'amount']

    if not all(k in values for k in required):
        return 'Missing values', 400
    index = bc.createTransaction(values['sender'], values['recipient'], values['amount'])
 
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201
'''
@app.route('/index', methods=['POST'])
def Index():
    return render_template('index.html')
@app.route('/login', methods=['POST', "GET"])
    try:
        with connect(
            host="localhost",
            user="root",
            password="root",
            database="users"
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT password FROM users WHERE login='{}'".format(request.form.get('Login')))
                account = False
                for db in cursor:
                    print("('"+bc.sha256(request.form.get('Password'))+"',)" == str(db))
                    if "('"+bc.sha256(request.form.get('Password'))+"',)" == str(db):
                        account = True
                        print("Varible account is True")
                connection.commit()
                if account:
                    global login, public_key, private_key
                    login = request.form.get('Login')
                    private_key = ''
                    public_key = ''
                    cursor.execute("SELECT private_key FROM users WHERE login='{}'".format(request.form.get('Login')))
                    for db in cursor:
                        private_key = str(db).replace("b)", "").replace(")", " ").replace(".", "\\")
                    connection.commit()
                    cursor.execute("SELECT public_key FROM users WHERE login='{}'".format(request.form.get('Login')))
                    for db in cursor:
                        public_key = str(db).replace("b)", "").replace(")", " ").replace(".", "\\")
                    print("Log in")

    except Error as e:
        print(e)
    return render_template('login.html')
@app.route('/register', methods=["POST"])
def Reg():
    try:
        with connect(
            host="localhost",
            user="root",
            password="root",
            database="users"
        ) as connection:
            print("Install connect to mysql")
            if request.method == 'POST':
                if request.form.get('Password') == request.form.get('PasswordAgain'):
                    login = request.form.get('Login')
                    password = bc.sha256(request.form.get('Password'))
                    while True:
                        secret_key = RSA.generate(2048, os.urandom)
                        public_key = secret_key.publickey().exportKey('PEM')
                        secret_key = secret_key.exportKey('PEM')
                        newuser = "INSERT INTO users (login, password, public_key, private_key) VALUES ('{}', '{}', '{}', '{}')".format(str(login), str(password), str(public_key).replace("'", ")").replace("\\", "."), str(secret_key).replace("'", ")").replace("\\", "."))
                        with connection.cursor() as cursor:
                            cursor.execute("SELECT public_key FROM users WHERE public_key='"+str(public_key).replace("'", ")").replace("\\", ".")+"' LIMIT 0, 25")
                            prov = True
                            for db in cursor:
                                prov = False
                            connection.commit()
                                
                        if prov:
                            with connection.cursor() as cursor:
                                cursor.execute(newuser)
                                for db in cursor:
                                    print(db)
                                connection.commit()
                            print("CreateNewUser")
                            break
                                
    except Error as e:
        print(e)
    return render_template('register.html')
'''
@app.route('/function', methods=['POST', 'GET'])
def Function():
    fun = json.loads(request.get_text())
    if fun["nameFunction"] == "mine":
        return mine()
    elif fun["nameFunction"] == "getchain":
        return Getchain()
    elif fun["nameFunction"] == "newwallet":
        return NewWallet(fun)
    elif fun["nameFunction"] == "addnode":
        return Getchain(fun)
    elif fun["nameFunction"] == "newtransatction":
        return Getchain(fun)


if __name__ == '__main__':
    app.secret_key = os.urandom(24)
    app.run(host='127.0.0.2', port=5000)