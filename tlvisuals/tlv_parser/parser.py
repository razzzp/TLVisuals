


from enum import Enum, IntFlag
import io
import re
from typing import Iterator


class ByteGetter:

   def __init__(self, stream: io.TextIOBase):
      self._stream = stream
      self.whitespace_regx = re.compile(r'\s')

   def next(self) -> int:
      byte = ''
      cur = self._stream.read(1)
      while cur != None and cur != '':
         if not self.whitespace_regx.match(cur):
            byte += cur
         if len(byte) == 2:
            try:
               b = bytes.fromhex(byte)
               return b[0]
            except:
               raise ValueError("Invalid hex found " + byte)
            break
         cur = self._stream.read(1)
      return None
      
      
      

class TagClass(IntFlag):
   UNIVERSAL = 0
   APPLICATION =1
   CONTEXT_SPECIFIC = 2
   PRIVATE =3

   
class TagType(IntFlag):
   PRIMITIVE = 0
   CONSTRUCTED = 1


class Tag:
   def __init__(self, cla : TagClass, type: TagType, tag_number: int) -> None:
      self.cla = cla
      self.type = type
      self.tag_number = tag_number
      self.length = 0 
      self.raw = b''

class Length:
   def __init__(self, length, len_of_length: int = 0) -> None:
      self.length = length
      self.len_of_length = len_of_length 
      self.raw = b''

class Value:
   def __init__(self, value: bytes) -> None:
      self.length = 0 
      self.value = b''


class TLV:
   def __init__(self, tag, length, value) -> None:
      self.tag = tag
      self.length = length
      self.value = value


class BERTLVParser:
   def __init__(self) -> None:
      pass
   
   def _parse_tag(self, input : ByteGetter) -> Tag:
      cur_byte = input.next()
      if cur_byte == None:
         return None
      
      cla = TagClass((cur_byte & 0b11000000) >> 6)
      val = (cur_byte & 0b00100000) >> 5
      type = TagType(int(val))
      tag_number = cur_byte & 0b00011111
      return Tag(cla,type, tag_number)



   def _parse_length(self, input : ByteGetter) -> Length:
      cur_byte = input.next()
      if cur_byte == None:
         raise EOFError("Unexpected EOF while parsing length")
      
      if cur_byte & 0b1000_0000 == 0:
         return Length(cur_byte)
      return Length(0)

   def _parse_value(self, input : ByteGetter, length: Length) -> Value:
      len = length.length
      val = bytearray()
      while len > 0:
         cur_byte = input.next()
         if cur_byte == None:
            raise EOFError("Unexpected EOF while parsing value")
         val.append(cur_byte)
         len -= 1

      return Value(val)


   def parse_tlv(self, input : ByteGetter) -> list[TLV]:
      result = []
      while True:
         try:
            tag = self._parse_tag(input)
            if tag == None:
               break
            len = self._parse_length(input)
            value = self._parse_value(input, len)
            result.append(TLV(tag,len,value))
         except Exception as e:
            raise e
      return result



def test():
   stream = io.StringIO("A20400112233")
   input = ByteGetter(stream)
   print(BERTLVParser().parse_tlv(input))

if __name__ == "__main__":
   test()
