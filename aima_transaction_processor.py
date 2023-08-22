#! /usr/bin/env python3

import logging

from sawtooth_sdk.processor.core import TransactionProcessor
from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.log import init_console_logging
import base64
import requests
import json
import os
import traceback
import sys

import io


import hashlib

LOGGER = logging.getLogger(__name__)

def print_trace():
  with io.StringIO() as f:
    exc_type, exc_value, exc_tb = sys.exc_info()
    traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
    _display(f.getvalue(), force=True)

def _display(msg, force=False):
    should_debug = os.getenv("DEBUG")
    if not force and (should_debug is None or should_debug == ""):
      return
    n = msg.count("\n")

    if n > 0:
        msg = msg.split("\n")
        length = max(len(line) for line in msg)
    else:
        length = len(msg)
        msg = [msg]

    # pylint: disable=logging-not-lazy
    LOGGER.debug("+" + (length + 2) * "-" + "+")
    for line in msg:
        LOGGER.debug("+ " + line.center(length) + " +")
    LOGGER.debug("+" + (length + 2) * "-" + "+")

def get_discounted_price(price, units, discount):
  discounted_price = price
  for i in range(1,units):  
    discounted_price += price * discount**i
  return discounted_price

def get_discounted_epoch_price(price, epochs, discount):
  return price * discount**epochs

def get_volume_price(price, units, discount):
  return round(get_discounted_price(price,units,discount))

def get_reservation_price(current_epoch, epoch, epoch_to, reservation_discount, reservations, units, unit_discount):
  tot_price = 0
  for e in range(epoch, epoch_to+1):
    if "%d" % e not in reservations:
      return -1
    price = get_discounted_epoch_price(reservations["%d" % e]['price'],e-current_epoch,reservation_discount)  
    tot_price += get_discounted_price(price, units, unit_discount)
  return round(tot_price)

class AimaTransactionHandler(TransactionHandler):
  def __init__(self, namespace_prefix, exchange):
    self._namespace_prefix = namespace_prefix
    _display("Starting prefix %s" % namespace_prefix)
    self.exchange = exchange

  @property
  def family_name(self):
    return 'aima'

  @property
  def family_versions(self):
    return ['1.0']

  @property
  def namespaces(self):
    return [self._namespace_prefix]

  def apply(self, transaction, context):
    header = transaction.header
    signer = header.signer_public_key
    _display("Got transaction {} from  {}".format(header,signer[:6]))
    _display("Got payload {} from  {}".format(transaction.payload,signer[:6]))
    try:
      aima_payload = AimaPayload(payload=transaction.payload)
    except Exception as inst:
      _display("Something went wrong parsing aima payload {}".format(inst))
      raise InvalidTransaction('Bad payload: {}'.format(payload))

    _display("Got action {}".format(aima_payload.action))
    aima_state = AimaState(context)
    if aima_payload.action == 'allocate':
      try:
        aima = aima_state.get_aima(aima_payload.provider)
        aima_allocator = aima_state.get_aima(signer)
        if aima is None:
          raise InvalidTransaction('Invalid offer provider')
        if aima_allocator is None:
          raise InvalidTransaction('Allocator account not found')
        allocations_left = aima.allocations_left
        
        # verify spectrum parameters
        if aima_payload.from_frequency != aima.spectrum.from_frequency:
          raise InvalidTransaction('Invalid from_frequency')
        if aima_payload.to_frequency != aima.spectrum.to_frequency:
          raise InvalidTransaction('Invalid to_frequency')
        if aima_payload.band_width != aima.spectrum.band_width:
          raise InvalidTransaction('Invalid bandwidth')

        # spot market purchase
        if aima_payload.epoch <= aima.epoch:
          if allocations_left < aima_payload.units:
            raise InvalidTransaction('No more allocations available')
          if aima.epoch != aima_payload.epoch:
            raise InvalidTransaction('Invalid epoch')
          allocations_left -= aima_payload.units
          price = get_volume_price(aima.price, aima_payload.units,aima.volume_discount)
        # reservation purchase
        else:
          allocations_left = aima.allocations_left
          price = get_reservation_price(aima.epoch, aima_payload.epoch, aima_payload.epoch_to, aima.reservation_discount, aima.reservations, aima_payload.units, aima.volume_discount)
          if price == -1:
            raise InvalidTransaction('Invalid reservation')
          for e in range(aima_payload.epoch,aima_payload.epoch_to+1):
            if 'allocated_capacity' not in aima.reservations["%d" % e]: 
              aima.reservations["%d" % e]['allocated_capacity'] = 0
            reservations_left = aima.reservations["%d" % e]['capacity'] -  aima.reservations["%d" % e]['allocated_capacity'] 
            if reservations_left < aima_payload.units: 
              raise InvalidTransaction('Insufficient reservation capacity')
            aima.reservations["%d" % e]['allocated_capacity'] +=  aima_payload.units

        if price != aima_payload.price:
          raise InvalidTransaction('Invalid price')

        if aima_allocator.balance < price:
          raise InvalidTransaction('Insufficient funds')
        aima.allocations_left = allocations_left
        aima.balance += price
        aima_allocator.balance -= price
        aima_state.set_aima(aima_payload.provider,aima)
        aima_state.set_aima(signer,aima_allocator)
        _display("Allocated band to {} from {} units {}".format(signer[:6],aima_payload.provider, aima_payload.units), force=True)
      except InvalidTransaction as it:
        _display("Invalid transaction {} {}".format(aima_payload.provider, it), force=True)
        print_trace()
        raise it
      except Exception as inst:
        _display("Something went wrong allocating band {}".format(inst), force=True)
        print_trace()
        raise InvalidTransaction('Bad payload: {}'.format(payload))
    elif aima_payload.action == 'offer' or aima_payload.action == 'create':
      try:
        old_aima = aima_state.get_aima(signer)
        spectrum = Spectrum(from_frequency=aima_payload.from_frequency,
                          to_frequency=aima_payload.to_frequency,
                          band_width=aima_payload.band_width)
        if old_aima is None:
          new_epoch = 0
          new_balance = 0
          reservations = {}
        else:
          new_epoch = old_aima.epoch + 1
          new_balance = old_aima.balance
          # update current reservations, keeping current allocations
          if not old_aima.reservations is None and not aima_payload.reservations is None:
            for e in list(aima_payload.reservations.keys()):
              if e in old_aima.reservations:
                old_aima.reservations[e].update(aima_payload.reservations[e])
              else:
                old_aima.reservations[e] = aima_payload.reservations[e]
                old_aima.reservations[e]['allocated_capacity'] = 0
          else:
            old_aima.reservations = aima_payload.reservations
          if old_aima.reservations is None:
            all_epochs = []
          else:
            all_epochs = list(old_aima.reservations.keys())
          # evict expired reservations
          for e in all_epochs:
            if int(e) <= new_epoch:
              del old_aima.reservations[e]
          reservations = old_aima.reservations
              
        aima = Aima(signer,spectrum,aima_payload.max_allocations, new_epoch, aima_payload.price, new_balance, aima_payload.volume_discount, aima_payload.reservation_discount, aima_payload.allocation_duration, reservations) 
        _display("Setting aima state {}".format(signer))
        try:
          aima_state.set_aima(aima_payload.provider,aima)
        except InvalidTransaction as it:
          _display("Invalid transaction {} {}".format(aima_payload.provider, it))
          raise it
        except Exception as inst:
          _display("Something went wrong setting aima state {} {}".format(aima_payload.provider, inst))
          raise InvalidTransaction('Unhandled action: {}'.format(aima_payload.action))
        _display("New spectrum available {} {}".format(signer[:6],aima_payload.provider))
      except InvalidTransaction as it:
        _display("Invalid transaction {} {}".format(aima_payload.provider, it))
        raise it
      except Exception as inst:
        _display("Something went wrong offering spectrum {}".format(inst))
        print_trace()
        raise InvalidTransaction('Bad payload: {}'.format(payload))
    elif aima_payload.action == 'withdraw':
      if signer != self.exchange:
        raise InvalidTransaction('Unauthorized withdrawal: {}'.format(signer))
      try:
        aima = aima_state.get_aima(aima_payload.provider)
        if aima.balance <= aima_payload.price:
          raise InvalidTransaction('Insufficient funds: {}'.format(signer))
        aima.balance -= aima_payload.price
        aima_state.set_aima(aima_payload.provider,aima)
      except InvalidTransaction as it:
        _display("Invalid transaction {} {}".format(aima_payload.provider, it))
        raise it
      except Exception as inst:
        _display("Something went wrong withdrawing funds {}".format(inst))
        print_trace()
        raise InvalidTransaction('Bad payload: {}'.format(payload))
    elif aima_payload.action == 'deposit':
      if signer != self.exchange:
        raise InvalidTransaction('Unauthorized deposit: {}'.format(signer))
      try:
        aima = aima_state.get_aima(aima_payload.provider)
        aima.balance += aima_payload.price
        aima_state.set_aima(aima_payload.provider,aima)
      except InvalidTransaction as it:
        _display("Invalid transaction {} {}".format(aima_payload.provider, it))
        raise it
      except Exception as inst:
        _display("Something went wrong depositing funds {}".format(inst))
        print_trace()
        raise InvalidTransaction('Bad payload: {}'.format(payload))
    elif aima_payload.action == 'transfer':
      try:
        from_aima = aima_state.get_aima(signer)
        to_aima = aima_state.get_aima(aima_payload.provider)
        if from_aima.balance < aima_payload.price:
          raise InvalidTransaction('Insufficient funds')
        to_aima.balance += aima_payload.price
        from_aima.balance -= aima_payload.price
        aima_state.set_aima(aima_payload.provider,to_aima)
        aima_state.set_aima(signer,from_aima)
      except InvalidTransaction as it:
        _display("Invalid transaction {} {}".format(aima_payload.provider, it))
        raise it
      except Exception as inst:
        _display("Something went wrong transferring funds {}".format(inst))
        print_trace()
        raise InvalidTransaction('Bad payload: {}'.format(payload))
    else:
      raise InvalidTransaction('Unhandled action: {}'.format(
        aima_payload.action))
      pass

class AimaPayload:
  def __init__(self, payload):
    try:
      data = json.loads(payload.decode())
      provider = data.get("provider")
      action = data.get("action")
      from_frequency = data.get("from_frequency")
      to_frequency = data.get("to_frequency")
      band_width = data.get("bandwidth")
      epoch = data.get("epoch")
      epoch_to = data.get("epoch_to")
      if epoch_to is None:
        epoch_to = epoch
      price = data.get("price")
      max_allocations = data.get("max_allocations")
      volume_discount = data.get("volume_discount")
      if volume_discount is None:
        volume_discount = 1.0 
      reservation_discount = data.get("reservation_discount")
      if reservation_discount is None:
        reservation_discount = 1.0 
      allocation_duration = data.get("allocation_duration")
      if allocation_duration is None:
        allocation_duration = 60
      consumers = data.get("consumers")
      reservations = data.get("reservations")
      units = 1
      if not consumers is None:
        units = len(consumers)

      _display("provider {} action {} from_frequency {} to_frequency {} bandwidth {} epoch {} price {} max_allocations {} volume_discount {} consumers {} units {} epoch_to {} reservation_discount {} reservations {} allocation_duration {}".format(
          provider,action,from_frequency, to_frequency, band_width, epoch, price, max_allocations, volume_discount, consumers, units, epoch_to, reservation_discount, reservations, allocation_duration))
    except ValueError:
      raise InvalidTransaction("Invalid payload serialization")

    if price is None:
        raise InvalidTransaction('price required')

    if action == "offer":
      if from_frequency is None:
        raise InvalidTransaction('from frequency required')
      if to_frequency is None:
        raise InvalidTransaction('to frequency required')
      if band_width is None:
        raise InvalidTransaction('band_width required')
      if max_allocations is None:
        raise InvalidTransaction('max_allocations required')
      try: 
        self._from_frequency = from_frequency
        self._to_frequency = to_frequency
        self._band_width = band_width
        self._max_allocations = max_allocations
        self._volume_discount = volume_discount
        self._allocation_duration = allocation_duration
        self._reservation_discount = reservation_discount
        self._reservations = reservations
      except ValueError:
        raise InvalidTransaction("Invalid spectrum definition")
    elif action == "create":
        self._from_frequency = 0
        self._to_frequency = 0
        self._band_width = 0
        self._max_allocations = 0
        self._volume_discount = volume_discount
        self._allocation_duration = allocation_duration
        self._reservation_discount = reservation_discount
        self._reservations = reservations
    elif action == "allocate":
      if from_frequency is None:
        raise InvalidTransaction('from frequency required')
      if to_frequency is None:
        raise InvalidTransaction('to frequency required')
      if band_width is None:
        raise InvalidTransaction('band_width required')
      if provider is None:
        raise InvalidTransaction('Provider is required')
      if epoch is None:
        raise InvalidTransaction('epoch required')
      if units > 0 and len(consumers) != units:
        raise InvalidTransaction('units must match consumers')
      self._from_frequency = from_frequency
      self._to_frequency = to_frequency
      self._band_width = band_width
      self._epoch = epoch 
      self._epoch_to = epoch_to 
    elif action == "withdraw" or action == "deposit" or action == "transfer":
      if provider is None:
        raise InvalidTransaction('Provider is required')
    else:
      raise InvalidTransaction('invalid action')

    self._provider = provider
    self._action = action
    self._price = price
    self._consumers = consumers
    self._units = units
    

  @staticmethod
  def from_bytes(payload, signer):
    return AimaPayload(payload=payload, signer=signer)

  @property
  def provider(self):
    return self._provider

  @property
  def units(self):
    return self._units

  @property
  def reservations(self):
    return self._reservations

  @property
  def reservation_discount(self):
    return self._reservation_discount

  @property
  def volume_discount(self):
    return self._volume_discount

  @property
  def allocation_duration(self):
    return self._allocation_duration

  @property
  def consumers(self):
    return self._consumers

  @property
  def from_frequency(self):
    return self._from_frequency

  @property
  def to_frequency(self):
    return self._to_frequency

  @property
  def max_allocations(self):
    return self._max_allocations

  @property
  def band_width(self):
    return self._band_width

  @property
  def action(self):
    return self._action

  @property
  def epoch(self):
    return self._epoch

  @property
  def epoch_to(self):
    return self._epoch_to

  @property
  def price(self):
    return self._price

AIMA_NAMESPACE = hashlib.sha512('aima'.encode("utf-8")).hexdigest()[0:6]

def _make_aima_address(name):
  return AIMA_NAMESPACE + \
    hashlib.sha512(name.encode('utf-8')).hexdigest()[:64]

class Spectrum:
  def __init__(self, from_frequency, to_frequency, band_width):
    self._from_frequency = from_frequency
    self._to_frequency = to_frequency
    self._band_width = band_width

  @property
  def from_frequency(self):
    return self._from_frequency

  @property
  def to_frequency(self):
    return self._to_frequency

  @property
  def band_width(self):
    return self._band_width

class Aima:
  def __init__(self, name, spectrum, allocations_left, epoch, price, balance, volume_discount, reservation_discount, allocation_duration, reservations):
    self.name = name
    self.spectrum = spectrum
    self.allocations_left = allocations_left
    self.epoch = epoch
    self.price = price
    self.balance = balance
    self.volume_discount = volume_discount
    self.reservation_discount = reservation_discount
    self.allocation_duration = allocation_duration
    self.reservations = reservations

class AimaState:

  TIMEOUT = 3
  
  def __init__(self, context):
    """Constructor.
    Args:
      context (sawtooth_sdk.processor.context.Context): Access to
            validator state from within the transaction processor.
    """

    self._context = context
    self._address_cache = {}

  def set_aima(self, aima_name, aima):
    aimas = self._load_aimas(aima_name=aima_name)
    aimas[aima_name] = aima
    self._store_aima(aima_name, aimas=aimas)

  def get_aima(self, aima_name):
    return self._load_aimas(aima_name=aima_name).get(aima_name)

  def _store_aima(self, aima_name, aimas):
    address = _make_aima_address(aima_name)
    state_data = self._serialize(aimas)
    self._address_cache[address] = state_data
    self._context.set_state(
            {address: state_data},
            timeout=self.TIMEOUT)

  def _load_aimas(self, aima_name):
    address = _make_aima_address(aima_name)

    if address in self._address_cache:
      if self._address_cache[address]:
        serialized_aimas = self._address_cache[address]
        aimas = self._deserialize(serialized_aimas)
      else:
        aimas = {}
    else:
      state_entries = self._context.get_state(
              [address],
              timeout=self.TIMEOUT)
      if state_entries:
        self._address_cache[address] = state_entries[0].data
        aimas = self._deserialize(data=state_entries[0].data)
      else:
        self._address_cache[address] = None
        aimas = {}
    return aimas

  def _deserialize(self, data):
    """Take bytes stored in state and deserialize them into Python
    Spex objects.
    Args:
        data (bytes): The UTF-8 encoded string stored in state.
    Returns:
        (dict): aima name (str) keys, Spex values.
    """

    aimas = {}
    try:
      for aima in data.decode().split("|"):
        data = json.loads(aima)
        name = data.get("name")
        from_frequency = data.get("from_frequency")
        to_frequency = data.get("to_frequency")
        band_width = data.get("bandwidth")
        allocations_left = data.get("allocations_left")
        epoch = data.get("epoch")
        price = data.get("price")
        balance = data.get("balance")
        volume_discount = data.get("volume_discount")
        reservation_discount = data.get("reservation_discount")
        allocation_duration = data.get("allocation_duration")
        reservations = data.get("reservations")
        spectrum = Spectrum(from_frequency, to_frequency, band_width)
        aimas[name] = Aima(name, spectrum, allocations_left, epoch, price, balance, volume_discount, reservation_discount, allocation_duration, reservations)
    except ValueError:
      raise InternalError("Failed to deserialize aima data")
    return aimas

  def _serialize(self, aimas):
    """Takes a dict of aima objects and serializes them into bytes.
    Args:
      aimas (dict): aima name (str) keys, Aima values.
    Returns:
      (bytes): The UTF-8 encoded string stored in state.
    """
    aima_strs = []
    for name, s in aimas.items():
      aima_str = json.dumps({"name":name,"from_frequency":s.spectrum.from_frequency,"to_frequency":s.spectrum.to_frequency,"bandwidth": s.spectrum.band_width,
          "allocations_left": s.allocations_left, "epoch": s.epoch, "price": s.price, "balance": s.balance, "volume_discount": s.volume_discount,
          "reservation_discount": s.reservation_discount, "allocation_duration": s.allocation_duration, "reservations": s.reservations}) 
      aima_strs.append(aima_str)
    return "|".join(sorted(aima_strs)).encode()

if __name__ == "__main__":
  validator = os.getenv("VALIDATOR")
  if validator is None or validator == "":
    validator = "localhost"
  processor = TransactionProcessor(url=f"tcp://{validator}:4004")
  init_console_logging(verbose_level=4)
  exchange = os.getenv("AIMA_EXCHANGE")
  handler = AimaTransactionHandler(AIMA_NAMESPACE, exchange)
  processor.add_handler(handler)
  processor.start()
