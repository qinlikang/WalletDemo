if (typeof web3 !== 'undefined') {
    web3 = new Web3(web3.currentProvider);
} else {
    // set the provider you want from Web3.providers
    web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
}

const Buffer = ethereumjs.Buffer.Buffer;;
const Wallet = ethereumjs.Wallet;
const Tx = ethereumjs.Tx;

function WalletDemo() {
    this.walletStore = []
}

WalletDemo.prototype.create = function () {
    let wlt = ethereumjs.Wallet.generate();
    this.walletStore.push(wlt);
}

WalletDemo.prototype.exportPrivateKey = function () {
    this.walletStore.forEach((wlt) => {
        console.log(wlt.getPrivateKey());
    });
}

WalletDemo.prototype.exportPrivateKeyString = function () {
    this.walletStore.forEach((wlt) => {
        console.log(wlt.getPrivateKeyString());
    });
}

// '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'
WalletDemo.prototype.importPrivateKeyString = function (priv) {
    let pk = Buffer(priv, 'hex');
    let wlt = Wallet.fromPrivateKey(pk);
    this.walletStore.push(wlt);
}

//CPU intensive work, may take 10s to generate
WalletDemo.prototype.toV3Keystore = function (password) {
    this.walletStore.forEach((wlt) => {
        wlt.toV3String(password);
    })
}

// {"version":3,"id":"859100bf-cb10-401b-badd-01611e1d55b5","address":"5cc29b545720c01927f1f631af5e43ac37fad287","Crypto":{"ciphertext":"d73a6f7fbc566205e771bb3d03ca15ae4fca06acafef89ef39b1f6191857d7cb","cipherparams":{"iv":"ce2b4c74cd0711fb8afd47e65e9ea351"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"92fd04e14f1f9d1f9fc0af5004c2001e32219f8372a5fcd6dd91ab00c357023b","n":8192,"r":8,"p":1},"mac":"a547e0798618b7f3699a216fee61a0ee57afe368c6f1870422bf9e749bb19f36"}}
// password: 123456789a
// isStrict -what's the usage?
WalletDemo.prototype.fromV3Keystore = function (v3string, password, isstrict) {
    let wlt = Wallet.fromV3(v3string, password, isstrict);
    this.walletStore.push(wlt);
}

WalletDemo.prototype.getBalance = function(address) {
    return web3.eth.getBalance(address);
}

//ganache-cli --account="0xe4c939ce393af9751836e6d21bd8a5da28144a99936fb0a6ba769c1c1399086b,100000000000000000000" -- account="0x6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1,100000000000000000000"
//we use this command to generate determinstic accounts for test purpose

WalletDemo.prototype.sendTransaction = function(toAddr, amount, gasPrice, gasLimit) {
    let acct0 = web3.eth.accounts[0];
    let acct1 = web3.eth.accounts[1];
    let to = toAddr || acct1;
    let nonce = web3.eth.getTransactionCount(acct0);
    let value = amount || 100000000;
    let gp = gasPrice || '0x09184e72a000';
    let gl = gasLimit || 21000;

    let sk = new Buffer('e4c939ce393af9751836e6d21bd8a5da28144a99936fb0a6ba769c1c1399086b', 'hex');
    let rawTx = {
        nonce: nonce,
        gasPrice: gp,
        gasLimit: gl,
        to: to,
        value: value,
    };
    let tx = new Tx(rawTx);
    tx.sign(sk);

    let serializedTx = tx.serialize();
    
    web3.eth.sendRawTransaction('0x' + serializedTx.toString('hex'), function(err, hash) {
        if (!err)
            console.log("transaction hash" + ": " + hash);
        else {
            console.log(err);
        }
    })
}



let w = new WalletDemo();
w.create();
w.create();
