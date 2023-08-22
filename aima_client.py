#! /usr/bin/env python3

import hashlib
import base64
from base64 import b64encode
import time
import random
import requests
import yaml
import json
import os

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory

rest_api = os.getenv("RESTAPI")
if rest_api is None or rest_api == "":
  rest_api = "localhost"
DEFAULT_URL = f"http://{rest_api}:8008"

def _sha512(data):
    return hashlib.sha512(data).hexdigest()

class AimaClient:
    def __init__(self, base_url=DEFAULT_URL, keyfile=None):

        self._base_url = base_url

        if keyfile is None:
            self._signer = None
            return

        try:
            with open(keyfile) as fd:
                private_key_str = fd.read().strip()
        except OSError as err:
            raise Exception(
                'Failed to read private key {}: {}'.format(
                    keyfile, str(err)))

        try:
            private_key = Secp256k1PrivateKey.from_hex(private_key_str)
        except ParseError as e:
            raise Exception(
                'Unable to load private key: {}'.format(str(e)))

        self._signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_key)

    def get_key(self):
      return  self._signer.get_public_key().as_hex()


    def verify(self, transaction_id):
        result = requests.get("%s/transactions/%s"  % (self._base_url, transaction_id))
        transaction = json.loads(result.text)
        payload = base64.b64decode(transaction['data']['payload']).decode()
        
        data = json.loads(payload)
        provider = data.get("provider")
        action = data.get("action")
        from_freq = data.get("from_frequency")
        to_freq = data.get("to_frequency")
        bw = data.get("bandwidth")
        epoch = data.get("epoch")
        price = data.get("price")
        max_allocations = data.get("max_allocations")
        volume_discount = data.get("volume_discount")
        reservation_discount = data.get("reservation_discount")
        allocation_duration = data.get("allocation_duration")
        consumers = data.get("consumers")


        pubkey = transaction['data']['header']['signer_public_key']
        return {"action": action, "provider": provider, "epoch": epoch, "price": price, "signer": pubkey, "max_allocations": max_allocations, "volume_discount": volume_discount, "allocation_duration": allocation_duration, "reservation_discount": reservation_discount,  "consumers": consumers}

    def transactions(self):
        result = requests.get("%s/transactions"  % (self._base_url))
        t = []
        transactions = json.loads(result.text)["data"]
        for transaction in transactions:
          if not transaction["header"]["family_name"] == "aima": 
            continue
          payload = base64.b64decode(transaction['payload']).decode()
          #provider, action, from_freq, to_freq, bw, epoch, price, max_allocations = payload.split(",")
          data = json.loads(payload)
          provider = data.get("provider")
          action = data.get("action")
          from_freq = data.get("from_frequency")
          to_freq = data.get("to_frequency")
          bw = data.get("bandwidth")
          epoch = data.get("epoch")
          epoch_to = data.get("epoch_to")
          price = data.get("price")
          max_allocations = data.get("max_allocations")
          consumers = data.get("consumers")
          volume_discount = data.get("volume_discount")
          reservation_discount = data.get("reservation_discount")
          allocation_duration = data.get("allocation_duration")

          pubkey = transaction['header']['signer_public_key']
          t.append({"action": action, "from_frequency": from_freq, "to_frequency": to_freq, "band_width": bw, "volume_discount": volume_discount, "provider": provider, "epoch": epoch, "price": price, "signer": pubkey, "max_allocations": max_allocations, "allocation_duration": allocation_duration, "reservation_discount": reservation_discount, "consumers": consumers, "epoch_to": epoch_to})
        return t

    def get_transaction(self, data, max_retries=50):
        link = json.loads(data)["link"]
        status = "PENDING"
        retries = 0
        while status == "PENDING" and retries < max_retries:
          result = requests.get(link)
          data = json.loads(result.text)
          status = data["data"][0]["status"]
          if status == "PENDING":
            time.sleep(.1)
            retries += 1
            continue
        if retries == max_retries:
          return {"status": "TRANSACTION_FAILED"}
        batchid = data["data"][0]["id"]
        result = requests.get("%s/batches/%s" % (self._base_url,batchid))
        data = json.loads(result.text)
        if "data" in data and "transaction_ids" in data["data"]["header"] and len(data["data"]["header"]["transaction_ids"]) > 0:
          transaction = data["data"]["header"]["transaction_ids"][0]
          status = "OK"
        else:
          transaction = "0"
          status = "TRANSACTION_FAILED"
        return {"status": status, "transaction_id": transaction}

    def allocate(self,provider, epoch, price, from_frequency, to_frequency, band_width, consumers=None, epoch_to=-1, wait=None, auth_user=None, auth_password=None, tunnel=False, asyn=False):
        data = self._send_aima_txn(
            provider,
            "allocate",
            price,
            epoch=epoch,
            consumers=consumers,
            epoch_to=epoch_to,
            from_frequency=from_frequency,
            to_frequency=to_frequency,
            band_width=band_width,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password,
            tunnel=tunnel)
        if tunnel or asyn:
          return data
        return self.get_transaction(data)

    def deposit(self,provider, price, wait=None, auth_user=None, auth_password=None):
        data = self._send_aima_txn(
            provider,
            "deposit",
            price,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)
        return self.get_transaction(data)

    def withdraw(self,provider, price, wait=None, auth_user=None, auth_password=None):
        data = self._send_aima_txn(
            provider,
            "withdraw",
            price,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password)
        return self.get_transaction(data)

    def transfer(self, provider, price, wait=None, auth_user=None, auth_password=None, tunnel=False):
        data = self._send_aima_txn(
            provider,
            "transfer",
            price,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password,
            tunnel=tunnel)
        if tunnel:
          return data
        return self.get_transaction(data)
    def create(self, wait=None, auth_user=None, auth_password=None,tunnel=False):
        data = self._send_aima_txn(
            self._signer.get_public_key().as_hex(),
            "create",
            0,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password,
            tunnel=tunnel)
        if tunnel:
          return data
        return self.get_transaction(data)
    def offer(self, price, from_frequency, to_frequency, band_width, max_allocations, volume_discount=1.0, reservation_discount=1.0, allocation_duration=60, reservations=None, wait=None, auth_user=None, auth_password=None,tunnel=False):
        data = self._send_aima_txn(
            self._signer.get_public_key().as_hex(),
            "offer",
            price,
            from_frequency=from_frequency,
            to_frequency=to_frequency,
            band_width=band_width,
            max_allocations=max_allocations,
            volume_discount=volume_discount,
            reservation_discount=reservation_discount,
            allocation_duration=allocation_duration,
            reservations=reservations,
            wait=wait,
            auth_user=auth_user,
            auth_password=auth_password,
            tunnel=tunnel)
        if tunnel:
          return data
        return self.get_transaction(data)

    def list(self, auth_user=None, auth_password=None):
        aima_prefix = self._get_prefix()

        result = self._send_request(
            "state?address={}".format(aima_prefix),
            auth_user=auth_user,
            auth_password=auth_password)

        try:
            encoded_entries = yaml.safe_load(result)["data"]

            return [
                base64.b64decode(entry["data"]) for entry in encoded_entries
            ]

        except BaseException:
            return None

    def show(self, provider, auth_user=None, auth_password=None):
        address = self._get_address(provider)

        result = self._send_request(
            "state/{}".format(address),
            name=provider,
            auth_user=auth_user,
            auth_password=auth_password)
        try:
            return base64.b64decode(yaml.safe_load(result)["data"])

        except BaseException:
            return None

    def _get_status(self, batch_id, wait, auth_user=None, auth_password=None):
        try:
            result = self._send_request(
                'batch_statuses?id={}&wait={}'.format(batch_id, wait),
                auth_user=auth_user,
                auth_password=auth_password)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise Exception(err)

    def _get_prefix(self):
        return _sha512('aima'.encode('utf-8'))[0:6]

    def _get_address(self, name):
        aima_prefix = self._get_prefix()
        aima_address = _sha512(name.encode('utf-8'))[0:64]
        return aima_prefix + aima_address

    def _send_request(self,
                      suffix,
                      data=None,
                      content_type=None,
                      name=None,
                      auth_user=None,
                      auth_password=None):
        if self._base_url.startswith("http://"):
            url = "{}/{}".format(self._base_url, suffix)
        else:
            url = "http://{}/{}".format(self._base_url, suffix)

        headers = {}
        if auth_user is not None:
            auth_string = "{}:{}".format(auth_user, auth_password)
            b64_string = b64encode(auth_string.encode()).decode()
            auth_header = 'Basic {}'.format(b64_string)
            headers['Authorization'] = auth_header

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if result.status_code == 404:
                raise Exception("No such provider: {}".format(name))

            if not result.ok:
                raise Exception("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise Exception(
                'Failed to connect to {}: {}'.format(url, str(err)))

        except BaseException as err:
            raise Exception(err)

        return result.text

    def _send_aima_txn(self,
                     provider,
                     action,
                     price,
                     epoch=-1,
                     from_frequency=-1,
                     to_frequency=-1,
                     band_width=-1,
                     max_allocations=-1,
                     volume_discount=1.0,
                     reservation_discount=1.0,
                     allocation_duration=60,
                     reservations=None,
                     consumers=None,
                     epoch_to=-1,
                     wait=None,
                     auth_user=None,
                     auth_password=None,
                     tunnel=False):
        # Serialization is just a delimited utf-8 encoded string
        #payload = ",".join([provider, action, from_frequency, to_frequency, band_width, epoch, price, max_allocations]).encode()
       
        data = {}
        data["provider"] = provider
        if not consumers is None:
          data["consumers"] = consumers
        data["action"] = action
        data["price"] = price
        if epoch != -1:
          data["epoch"] = epoch
        if from_frequency != -1:
          data["from_frequency"] = from_frequency
        if to_frequency != -1:
          data["to_frequency"] = to_frequency
        if band_width != -1:
          data["bandwidth"] = band_width
        if max_allocations != -1:
          data["max_allocations"] = max_allocations
        if volume_discount != 1.0:
          data["volume_discount"] = volume_discount
        if allocation_duration != 60:
          data["allocation_duration"] = allocation_duration
        if reservation_discount != 1.0:
          data["reservation_discount"] = reservation_discount
        if not reservations is None:
          data["reservations"] = reservations
        if epoch_to != -1:
          data["epoch_to"] = epoch_to

        payload = json.dumps(data).encode()


        # Construct the address
        address = self._get_address(provider)
        address_me = self._get_address(self._signer.get_public_key().as_hex())

        header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name="aima",
            family_version="1.0",
            inputs=[address,address_me],
            outputs=[address,address_me],
            dependencies=[],
            payload_sha512=_sha512(payload),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            nonce=hex(random.randint(0, 2**64))
        ).SerializeToString()

        signature = self._signer.sign(header)

        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=signature
        )

        batch_list = self._create_batch_list([transaction])
        batch_id = batch_list.batches[0].header_signature

        if tunnel:
          return (batch_id, batch_list.SerializeToString())

        if wait and wait > 0:
            wait_time = 0
            start_time = time.time()
            response = self._send_request(
                "batches", batch_list.SerializeToString(),
                'application/octet-stream',
                auth_user=auth_user,
                auth_password=auth_password)
            while wait_time < wait:
                status = self._get_status(
                    batch_id,
                    wait - int(wait_time),
                    auth_user=auth_user,
                    auth_password=auth_password)
                wait_time = time.time() - start_time

                if status != 'PENDING':
                    return response

            return response


        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
            auth_user=auth_user,
            auth_password=auth_password)

    def wait_for_batch(self, batch_id, wait=10,auth_user=None,auth_password=None):
      wait_time = 0
      start_time = time.time()
      while wait_time < wait:
          status = self._get_status(
              batch_id,
              wait - int(wait_time),
              auth_user=auth_user,
              auth_password=auth_password)
          wait_time = time.time() - start_time
          if status != 'PENDING':
            return status
      return "TIMEOUT"

    def batch_payload(self, batch):
      batch_list = BatchList()
      batch_list.ParseFromString(batch)
      batch = batch_list.batches[0]
      transaction = batch.transactions[0]
      header = BatchHeader()
      header.ParseFromString(transaction.header)
      return (json.loads(transaction.payload.decode()), header.signer_public_key)

    def submit_batch(self, serialized_batch, auth_user=None,auth_password=None):
      return self._send_request(
            "batches", serialized_batch,
            'application/octet-stream',
            auth_user=auth_user,
            auth_password=auth_password)

    def _create_batch_list(self, transactions):
        transaction_signatures = [t.header_signature for t in transactions]

        header = BatchHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            transaction_ids=transaction_signatures
        ).SerializeToString()

        signature = self._signer.sign(header)

        batch = Batch(
            header=header,
            transactions=transactions,
            header_signature=signature,
            trace=True)
        return BatchList(batches=[batch])

def print_offers(offers):
  for offer in offers:
    data = json.loads(offer.decode())
    if data["price"] == 0:
      continue
    print(json.dumps(data, indent=2))
    print("\n")

def print_accounts(accounts):
  for account in accounts:
    data = json.loads(account.decode())
    if data["price"] == 0:
      print(json.dumps(data, indent=2))
      print("\n")

if __name__ == "__main__":
  import sys
  key_file = os.getenv("BANDCOIN_KEY")
  if key_file  is None:
    key_file = "aima.key"
  action = sys.argv[1]
  if action == "genkey":
      context = create_context('secp256k1')
      private_key = context.new_random_private_key()
      private_key_hex = private_key.as_hex()
      with open(key_file,'w') as f:
          f.write(private_key_hex)
      sys.exit(0)
  client = AimaClient(keyfile=key_file)
  if action == "list":
    print(client.list())
    sys.exit(0)
  if action == "offers":
    print_offers(client.list())
    sys.exit(0)
  if action == "accounts":
    print_accounts(client.list())
    sys.exit(0)
  if action == "verify":
    transaction_id = sys.argv[2]
    print(client.verify(transaction_id))
    sys.exit(0)
  if action == "show":
    provider = sys.argv[2]
    print(client.show(provider))
  elif action == "allocate":
    provider = sys.argv[2]
    epoch = int(sys.argv[3])
    price = int(sys.argv[4])
    from_frequency = int(sys.argv[5])
    to_frequency = int(sys.argv[6])
    band_width = int(sys.argv[7])
    print(client.allocate(provider,epoch,price,from_frequency, to_frequency, band_width, consumers=[client.get_key()]))
  elif action == "offer":
    from_frequency = int(sys.argv[2])
    to_frequency = int(sys.argv[3])
    band_width = int(sys.argv[4])
    price = int(sys.argv[5])
    max_allocations = int(sys.argv[6])
    if len(sys.argv) > 7:
      volume_discount = float(sys.argv[7])
    print(client.offer(price, from_frequency, to_frequency, band_width, max_allocations, volume_discount=volume_discount))
  elif action == "create":
    print(client.create())
  elif action == "transfer":
    provider = sys.argv[2]
    price = int(sys.argv[3])
    print(client.transfer(provider,price))
  elif action == "withdraw":
    provider = sys.argv[2]
    price = int(sys.argv[3])
    print(client.withdraw(provider,price))
  elif action == "deposit":
    provider = sys.argv[2]
    price = int(sys.argv[3])
    print(client.deposit(provider,price))
  elif action == "getkey":
    print(client.get_key())
  elif action == "balance":
    print(client.show(client.get_key()))
  elif action == "transactions":
    print(client.transactions())
  elif action == "payload":
    raw_batch =  base64.b64decode(sys.argv[2].encode("utf-8"))
    print(client.batch_payload(raw_batch))
  else:
    print("Invalid action %s" % action)
