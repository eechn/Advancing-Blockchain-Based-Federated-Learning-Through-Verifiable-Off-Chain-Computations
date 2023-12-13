from flask import Flask, abort
import os
import json
import sys
sys.path.append("/home/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations")

from pycrypto.zokrates_pycrypto.eddsa import PrivateKey, PublicKey
import hashlib


app = Flask(__name__)
signKey_CA = PrivateKey.from_rand()
pubKey_CA = PublicKey.from_private(signKey_CA)

@app.route("/vc/<int:pubKey_x>/<int:pubKey_y>")
def get_vc(pubKey_x, pubKey_y):

    #PubKey_device = b''

    PubKey_device = int.to_bytes(pubKey_x, 32, "big") + int.to_bytes(pubKey_y, 32, "big")
    credential_hash = hashlib.sha256(PubKey_device).digest()
    sig = signKey_CA.sign(credential_hash+credential_hash)

    output = []
    output.append({
        "pubKey_device": {
            "x": pubKey_x,
            "y": pubKey_y
        },
        "signature": {
            "r": {
                "x": str(sig[0].x),
                "y": str(sig[0].y)
            },
            "s": str(sig[1])
        },
        "pubKey_CA": {
            "x": pubKey_CA.p.x.n,
            "y": pubKey_CA.p.y.n
        },
        "deviceCertificate" : credential_hash.hex()
    })
    return {
            "vc": output
    }
    

