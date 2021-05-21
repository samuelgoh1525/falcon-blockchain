# Simple experimental blockchain to test post-quantum signature scheme

## Blockchain
Source code adapted from [dvf/blockchain](https://github.com/dvf/blockchain). Primarily modified by adding key generation and signatures.

##### TODO:
- Add transaction identification using UTXO model
- Limit total supply of coins
- Improve node system

### Running instructions
```
python node.py
```
Note: Tested on Python 3.9.5. If you have poetry, you can use `poetry install` to install all necessary dependencies.

You will be prompted for a port number to listen for HTTP requests on, as well as whether to use [FALCON](https://falcon-sign.info/) (post-quantum signature scheme) or Ed25519 (using the PyNaCl implementation):
```
>>> Enter your port: [e.g. 5000]
>>> Use FALCON? (y/n): [e.g. y]
```

#### FALCON signature

The first time a transaction is carried out, there will be prompts for several parameter:
```
>>> Enter degree of n: [This is the ring degree of FALCON, e.g. 512]
>>> Retrieve polys from data/polys.txt? (y/n): ['n' if first time generating private key or if saved polys are in a different file location]
>>> Do you have saved polys? (y/n): ['n' to generate new polys for a new private key. Note: polys will be saved in data/polys.txt for future use]
>>> Enter file name: [Enter file name here if polys are saved in different file location]
```

#### Ed25519 (PyNaCl) signature

The first time a transaction is carried out, there will be prompts for several parameter:
```
>>> Do you have a salt? (y/n): ['n' if first time generating salt for private key. Note: salt will be saved in /data/salt.txt for future use]
>>> Is it in /data/salt.txt? (y/n/raw) ['n' if salt saved in different file location; 'raw' to type in salt directly]
>>> Enter the name of the file: [Enter file name here if salt is saved in different file location]
>>> Enter your password: [Enter password here to generate unique private key with salt]
```

#### Blockchain interactions (as of 21/5)

Send the following HTTP requests, e.g. using [Postman](https://www.postman.com/downloads/), for the following interactions. Note: the request is preceded by the HTTP address, e.g. http://localhost:5000/mine:
- [GET] /mine: Mine a new block using the POW scheme, adding all pending transactions to the block.
- [GET] /transactions/get: Get all pending transactions.
- [POST] /transactions/new: Make a new transaction. Required JSON fields: 'recipient', 'amount'.
- [GET] /chain/get: Get entire blockchain on node.
- [GET] /chain/valid: Check if blockchain is valid.
- [POST] /nodes/register: Register new list of nodes to current node. Required JSON field: 'nodes' <list>.
- [GET] /nodes/resolve: Compare blockchain with other nodes to get longest chain (consensus scheme).

## MCMC-FALCON (work in progress)
Implementing random-walk MCMC sampling based on [Symmetric Metropolis-Klein Algorithm for Lattice Gaussian Sampling](https://arxiv.org/abs/1501.05757) in the post-quantum [FALCON](https://falcon-sign.info/) signature scheme. Current Python implementation (located in subfolder /falcon_mcmc) adapted from the [original FALCON Python source code](https://github.com/tprest/falcon.py).

Main changes are made to `SecretKey.sample_preimage()` in `SecretKey.sign()`.

### Running instructions
Refer to [FALCON README.md](falcon_mcmc/README.md) for detailed instructions. Summary of basic functions listed below:
```
>>> import falcon
>>> sk = falcon.SecretKey(512)
>>> pk = falcon.PublicKey(sk)
>>> sig = sk.sign(b"Hello")
>>> pk.verify(b"Hello", sig)
True
```
Note: Tested on Python 3.9.5. If you have poetry, you can use `poetry install` to install all necessary dependencies.
