from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_public_key
from cryptography.hazmat.primitives.hashes import Hash, SHA224, SHA256
from cryptography.exceptions import InvalidSignature
from base64 import b64encode, b64decode

def new_key():
    return ec.generate_private_key(ec.SECP256K1, default_backend())

def prv_txt(key):
    txt = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return b''.join(txt.split(b'\n')[1:-2])

def pub_txt(pubkey):
    txt = pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return b''.join(txt.split(b'\n')[1:-2])

def txt_pub(txt):
    txt = b'-----BEGIN PUBLIC KEY-----\n' + txt[:64] + b'\n' + txt[64:64+56] + b'\n-----END PUBLIC KEY-----\n'
    return load_pem_public_key(txt, default_backend())

def address(pubkey):
    hasher = Hash(SHA224(), openssl_backend)
    hasher.update(pub_txt(pubkey))
    return b64encode(hasher.finalize())

def sign(prvkey, message):
    return b64encode(prvkey.sign(message, ec.ECDSA(SHA224())))

def verify(pubkey, signature, message):
    try:
        pubkey.verify(b64decode(signature), message, ec.ECDSA(SHA224()))
    except InvalidSignature:
        return False
    return True

def test_crypto():
    prv_key = new_key()
    pub_key = prv_key.public_key()
    txt = pub_txt(pub_key)
    #print(txt)
    #print(address(pub_key))
    txt = b'My Awesome Message for a transaction'
    signature = sign(prv_key, txt)
    print(signature)
    signature = signature[:24] + b'0' + signature[25:]
    print(verify(pub_key, signature, txt))



# -----------------------------
def get_tx(bc, txid):
    return bc[txid]
def mk_tx(txid, inputs, pubkeys, outputs):
    return {'txid': txid, 'inputs': inputs, 'pubkeys': pubkeys, 'outputs': outputs, 
            'signatures': []}
def mk_input(txid, output):
    return {'txid': txid, 'output': output}
def mk_output(address, amount):
    return {'address': address, 'amount':amount}

def tx_to_bytes(tx):
    return b''.join([str(inp).encode() for inp in tx['inputs']] +
                    tx['pubkeys'] +
                    [str(out).encode() for out in tx['outputs']])

def sign_tx(tx, privkeys):
    message = tx_to_bytes(tx)
    tx['signatures'] = [sign(p, message) for p in privkeys]

def verify_chain(bc):
    utxos = set()
    for tx in bc:
        inp_amt = 0
        for inp in tx['inputs']:
            if (inp['txid'], inp['output']) not in utxos:
                print('Error attempt to spend non-existent or spent utxo\n%s'%tx)
                return False
            inp_amt += bc[inp['txid']]['outputs'][inp['output']]['amount']

        for out in tx['outputs']: 
            if out['amount'] < 0:
                return False

        out_amt = sum(out['amount'] for out in tx['outputs'])

        if out_amt > inp_amt and tx['inputs'] != []:
            print('Error inputs < outputs in tx\n%s'%tx)
            return False

        if not verify_sig(bc, tx):
            return False

        utxos -= set((inp['txid'], inp['output']) for inp in tx['inputs'])
        utxos |= set((tx['txid'], i) for i, _ in enumerate(tx['outputs']))

    return True

def verify_sig(bc, tx):
    # Verify address corresponds to pubic key given
    pubkeys = [txt_pub(p) for p in tx['pubkeys']]
    for inp, pubkey in zip(tx['inputs'], pubkeys):
        if address(pubkey) != get_tx(bc, inp['txid'])['outputs'][inp['output']]['address']:
            print('Invalid Tx - pubkey to address mismatch\n%s'%tx)
            return False

    for sig, pubkey in zip(tx['signatures'], pubkeys):
        message = tx_to_bytes(tx)
        if not verify(pubkey, sig, message):
            print('Invalid Tx - bad signature\n%s'%tx)
            return False

    return True

def main():

    a,b,c = new_key(), new_key(), new_key()
    a_addr = address(a.public_key())
    b_addr = address(b.public_key())
    c_addr = address(c.public_key())
    bad_addr = c_addr[:5] + b'1' + c_addr[6:]

    bc = []
    bc.append(mk_tx(0, [], [], [mk_output(a_addr, 100)]))

    bc.append(mk_tx(1, [mk_input(0,0)],
                       [pub_txt(a.public_key())],
                       [mk_output(b_addr, 30), mk_output(c_addr, 70)]))
    sign_tx(bc[1], [a])

    bc.append(mk_tx(2, [mk_input(1,1), mk_input(1,0)], 
                       [pub_txt(c.public_key()), pub_txt(b.public_key())],
                       [mk_output(a_addr, 100)]))
    sign_tx(bc[2], [c, b])

    res = verify_chain(bc)
    print(res)

if __name__ == '__main__':
    main()
