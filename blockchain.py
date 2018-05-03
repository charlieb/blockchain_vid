def get_tx(bc, txid):
    return bc[txid]
def mk_tx(txid, inputs, outputs):
    return {'txid': txid, 'inputs': inputs, 'outputs': outputs}
def mk_input(txid, output):
    return {'txid': txid, 'output': output}
def mk_output(address, amount):
    return {'address': address, 'amount':amount}

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

        utxos -= set((inp['txid'], inp['output']) for inp in tx['inputs'])
        utxos |= set((tx['txid'], i) for i, _ in enumerate(tx['outputs']))

    return True

def main():

    bc = []
    bc.append(mk_tx(0, [], [mk_output('one', 100)]))

    bc.append(mk_tx(1, [mk_input(0,0)],
                       [mk_output('two', 30), mk_output('three', 70)]))

    bc.append(mk_tx(2, [mk_input(1,1), mk_input(1,0)], 
                       [mk_output('one', 100)]))

    res = verify_chain(bc)
    print(res)

if __name__ == '__main__':
    main()
