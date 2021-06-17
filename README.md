# Simple experimental blockchain to test post-quantum signature scheme

## Blockchain
Source code adapted from [dvf/blockchain](https://github.com/dvf/blockchain). Primarily modified by adding key generation and signatures.

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

Note that if FALCON is chosen, there will be an additional prompt to check if you would like to utilise MCMC sampling with either the Independent Metropolis-Hastings-Klein algorithm (i) or Symmetric Metropolis-Klein algorithm (s), or to use the original FALCON signature scheme (o):
```
>>> Use independent MHK/symmetric MK/original? (i/s/o): [e.g. o]
```

### FALCON signature

The first time a transaction is carried out, there will be prompts for several parameter:
```
>>> Enter degree of n: [This is the ring degree of FALCON, e.g. 512]
>>> Retrieve polys from data/polys.txt? (y/n): ['n' if first time generating private key or if saved polys are in a different file location]
>>> Do you have saved polys? (y/n): ['n' to generate new polys for a new private key. Note: polys will be saved in data/polys.txt for future use]
>>> Enter file name: [Enter file name here if polys are saved in different file location]
```

### Ed25519 (PyNaCl) signature

The first time a transaction is carried out, there will be prompts for several parameter:
```
>>> Do you have a salt? (y/n): ['n' if first time generating salt for private key. Note: salt will be saved in /data/salt.txt for future use]
>>> Is it in /data/salt.txt? (y/n/raw) ['n' if salt saved in different file location; 'raw' to type in salt directly]
>>> Enter the name of the file: [Enter file name here if salt is saved in different file location]
>>> Enter your password: [Enter password here to generate unique private key with salt]
```

### Blockchain interactions (as of 21/5)

Send the following HTTP requests, e.g. using [Postman](https://www.postman.com/downloads/), for the following interactions. Note: the request is preceded by the HTTP address, e.g. http://localhost:5000/mine:
- [GET] /mine: Mine a new block using the POW scheme, adding all pending transactions to the block.
- [GET] /transactions/get: Get all pending transactions.
- [POST] /transactions/new: Make a new transaction. Required JSON fields: 'recipients', 'amounts'.
- [GET] /transactions/verify: Verify a transaction. Required JSON fields: 'id', 'output_index', 'block_index', 'amount', 'signature'.
- [GET] /chain/get: Get entire blockchain on node.
- [GET] /chain/valid: Check if blockchain is valid.
- [GET] /utxo/all: Get entire UTXO set.
- [GET] /utxo/user: Get UTXOs specific to a user, i.e., how many coins a user owns. Reqruired JSON fields: 'user'.
- [GET] /utxo/unmined: Get remaining unmined coins.
- [POST] /nodes/register: Register new list of nodes to current node. Required JSON field: 'nodes' <list>.
- [GET] /nodes/resolve: Compare blockchain with other nodes to get longest chain (consensus scheme).

## MCMC-FALCON
Utilising MCMC sampling, based on the [Independent Metropolis-Hastings-Klein (IMHK) algorithm and the Symmetric Metropolis-Klein (SMK) Algorithm for Lattice Gaussian Sampling](https://arxiv.org/abs/1501.05757) in the trapdoor sampler of the post-quantum [FALCON](https://falcon-sign.info/) signature scheme. Current Python implementation (located in subfolder `/falcon_mcmc`) adapted from the [original FALCON Python source code](https://github.com/tprest/falcon.py).

Main changes are made to `SecretKey.sample_preimage()` in `SecretKey.sign()`, and `ffsampling_fft()` for the calculation of the mixing time and acceptance ratio of the MCMC sampling techniques.

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

Additionally, note that to utilise MCMC sampling, several additional parameters would have to be passed to `SecretKey.sign()`. The input (and default parameters) are as follows:
```
>>> SecretKey.sign(message, type_in='', sigma_og=None, sigma_new=30, i_mix_sym=1000, overwrite=False, randombytes=urandom)
```

The additional parameters to take note of are:
- `type_in=''`: Whether to use IMHK (`'i'`), SMK (`'s'`), or no MCMC sampling, i.e., original FALCON, (default value of `''`).
- `sigma_og=None`: The original sigma to sample with, for IMHK and SMK. Recommended parameters are 65-75 for IMHK, and 60 for SMK (n = 512).
- `sigma_new=30`: The subsequent sigma to sample with for the SMK, as part of the two-stage sampling process. Recommended parameter is the default value of 30 (n = 512).
- `i_mix_sym=1000`: Mixing time for SMK. Recommended parameter is the default value of 1000 (n = 512).

Therefore, to sign with original FALCON:
```
>>> sig = sk.sign(b"Hello")
```

To sign with IMHK:
```
>>> sig = sk.sign(b"Hello", type_in='i', sigma_og=75)
```

To sign with SMK:
```
>>> sig = sk.sign(b"Hello", type_in='s', sigma_og=60, sigma_new=30, i_mix_sym=1000)
```

Note: Tested on Python 3.9.5. If you have poetry, you can use `poetry install` to install all necessary dependencies.
