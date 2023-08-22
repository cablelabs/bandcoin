# Bandcoin

This repository contains a [Sawtooth](https://www.hyperledger.org/projects/sawtooth) Transaction Processor reference implementation for the
[Bandcoin](https://arxiv.org/abs/2104.02780) smart contract.


## Getting started

### Set up Sawtooth Network
Start up a sawtooth network. The easiest way to do this is to run a devmode single node
network using the proviced [docker-compose file](https://github.com/hyperledger/sawtooth-core/blob/main/docker/compose/sawtooth-default.yaml). 
Then expose the rest-api as well as the validator to the local host.
```
...
 validator:
    image: hyperledger/sawtooth-validator:chime
    container_name: sawtooth-validator-default
    expose:
      - 4004
    ports:
      - "4004:4004"
...
 rest-api:
    image: hyperledger/sawtooth-rest-api:chime
    container_name: sawtooth-rest-api
    ports:
      - "8008:8008"
...
```
### Install dependencies

Now install the python dependencies with:
```
pip3 install -r requirements.txt
```
### Generate provider credentials
Generate a key to issue transactions:
```
python3 aima_client.py genkey && mv aima.key provider.key
```


### Generate client credentials
```
python3 aima_client.py genkey
```

### Start Transaction processor
Start transaction processor with provider as exchange with
ability to fund accounts.
```
BANDCOIN_KEY=provider.key python3 aima_client.py getkey > provider.pub
AIMA_EXCHANGE=$(cat provider.pub) DEBUG=yes python3 aima_transaction_processor.py
```

### Create provider and client accounts
```
python3 aima_client.py create
BANDCOIN_KEY=provider.key python3 aima_client.py create
# Fund client account
BANDCOIN_KEY=provider.key python3 aima_client.py deposit $(cat aima.key) 1000
# Check client balance
python3 aima_client.py balance
```
### Create provider offer
```
# offer from_frequency to_frequency band_width price max_allocations volume_discount
BANDCOIN_KEY=provider.key python3 aima_client.py offer 1000 1200 100 1 100 10
# list blockchain states
python3 aima_client.py list
```

## Purchase allocation
```
# show offers
python3 aima_client.py offers
# allocate provider epoch price from_frequency to_frequency band_width
python3 aima_client.py allocate $(cat provider.pub) 1 1 1000 1200 100
```
## Show provider blockchain state
```
python3 aima_client.py show $(cat provider.pub)
```
## List transacttions
```
python3 aima_client.py transactions
```
