# Usage: Called from blockchain.py
import json

class KeyFileReader:
  def __init__(self, _filename):
    self.filename = _filename
    
  # Returns json
  def get_keys(self):
    f = open(self.filename)
    return json.load(f)
    
        
    