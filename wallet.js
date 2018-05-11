if (typeof web3 !== 'undefined') {
    web3 = new Web3(web3.currentProvider);
} else {
    // set the provider you want from Web3.providers
    web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
}

const Buffer = ethereumjs.Buffer.Buffer;;
const Wallet = ethereumjs.Wallet;
const Tx = ethereumjs.Tx;
const Util = ethereumjs.Util;
const WalletHD = ethereumjs.WalletHD;

function WalletDemo() {
    this.walletStore = [];
    //standard Ethereum derive path (https://github.com/ethereum/EIPs/issues/84#issue-143651804)
    this.derivationPath = "m/44'/60'/0'/0";
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

WalletDemo.prototype.fromPrivateKey = function (priv) {
    if (typeof priv !== 'undefined') {
        let sk = Buffer(priv, 'hex');
        let wlt = Wallet.fromPrivateKey(sk);
        this.walletStore.push(wlt);
    } else {
        //use ganache-cli -d to generate 10 determinstic accounts and get 2 of them, test purpose
        let sk1 = '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d';
        let sk2 = '6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1';

        sk1 = Buffer(sk1, 'hex');
        sk2 = Buffer(sk2, 'hex');

        let w1 = Wallet.fromPrivateKey(sk1);
        let w2 = Wallet.fromPrivateKey(sk2);

        this.walletStore.push(w1);
        this.walletStore.push(w2);
    }
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
WalletDemo.fromV3Keystore = function (v3string, password, isstrict) {
    let wlt = Wallet.fromV3(v3string, password, isstrict);
    this.walletStore.push(wlt);
}

WalletDemo.prototype.getBalance = function(address) {
    return web3.eth.getBalance(address);
}

//ganache-cli --account="0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d,100000000000000000000" -- account="0x6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1,100000000000000000000"
//we use this command to generate determinstic accounts for test purpose
WalletDemo.prototype.sendTransaction = function(toAddr, amount, gasPrice, gasLimit) {
    let acct0 = web3.eth.accounts[0];
    let acct1 = web3.eth.accounts[1];
    let to = toAddr || acct1;
    let nonce = web3.eth.getTransactionCount(acct0);
    let value = amount || 10000000000;
    let gp = gasPrice ||  100000000;
    let gl = gasLimit || 21000;

    let sk = Buffer('4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d', 'hex');
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

// mnemonic: dry marine story expand ribbon airport ancient fire parent charge stay refuse chair meadow sock
// seed='4ffb930569fdf5614816c539634dcde6793d231ee6a1e4816a422d5f1264e6d486c34cd3c5863e411405001ccf2c3ba41fa9e9af58b4456d2c18a174efcbf044'
// m/44'/60'/0'/0/0	0x1aBBBeD56e71aFe97074d13cCF5e3fD1075a4E14
WalletDemo.prototype.fromMasterSeed = function (seed, index) {
    let seedBuf = Buffer(seed, 'hex');
    let root = WalletHD.fromMasterSeed(seedBuf);
    let path = this.derivationPath + '/' + index.toString();
    console.log(path);
    let wlt1 = root.derivePath(path);
    console.log(Util.publicToAddress(wlt1._hdkey.publicKey, true).toString('hex'));
}

WalletDemo.prototype.fromExtendedKey = function (extkey, index) {
    let extwlt = WalletHD.fromExtendedKey(extkey);
    let path = '0/' + index.toString();

    let child = extwlt.derivePath(path);
    console.log(Util.publicToAddress(child._hdkey._publicKey, true).toString('hex'));
}

WalletDemo.generateMnemonic = function (language, strength) {
    let lang = language || 'english';
    let strong = strength || 128;
    let mn = new Mnemonic(lang);
    return mn.generate(strong);
}

WalletDemo.toSeed = function (mnemonic, langage, passphrase) {
    let lang = langage || 'english';
    let mn = new Mnemonic(lang);
    return mn.toSeed(mnemonic, passphrase);
}

let w = new WalletDemo();
