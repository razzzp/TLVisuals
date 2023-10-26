


from enum import Enum, IntFlag
import io
import re
from typing import Iterator


class ByteGetter(Iterator[int]):

   def __init__(self, stream: io.TextIOBase):
      self._stream = stream
      self.whitespace_regx = re.compile(r'\s')

   def __iter__(self) -> Iterator[int]:
      return self

   def __next__(self) -> int:
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
         cur = self._stream.read(1)
      
      if len(byte) != 0:
         raise ValueError("Odd number of chars found")
      
      raise StopIteration()
      
      
      

class TagClass(IntFlag):
   UNIVERSAL = 0
   APPLICATION =1
   CONTEXT_SPECIFIC = 2
   PRIVATE =3

   
class TagType(IntFlag):
   PRIMITIVE = 0
   CONSTRUCTED = 1


class Tag:
   def __init__(self, cla : TagClass, type: TagType, tag_number: int, raw: bytearray) -> None:
      self.cla = cla
      self.type = type
      self.tag_number = tag_number
      self.raw = raw

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
   
   def _parse_tag(self, input :  Iterator[int]) -> Tag:
      try:
         cur_byte = input.__next__()
      except StopIteration:
         return None
      
      raw = bytearray()
      raw.append(cur_byte)

      # first bits 8-7 (LSB) is class
      # Universal/Application/Context Specific/Private
      cla = TagClass((cur_byte & 0b11000000) >> 6)
      val = (cur_byte & 0b00100000) >> 5

      # bit 6 is type
      # Primitive/Constructed
      type = TagType(int(val))
      tag_number = cur_byte & 0b00011111

      # case tag on multiple bytes
      tag_number_acc=''
      if tag_number == 31:
         while True:
            # get next bytes
            try:
               cur_tag_num_byte = input.__next__()
            except StopIteration as e:
               raise EOFError("Unexpected EOF when parsing tag")

            raw.append(cur_tag_num_byte)
            cur_tag_num = cur_tag_num_byte & 0b01111111

            if len(raw) == 2 and cur_tag_num == 0:
               # first subsequent byte cannot be 0
               raise ValueError("First subsequent tag byte cannot be 0x00")
            
            # append bits of cur tag num
            tag_number_acc+= '{0:07b}'.format(cur_tag_num)

            # if first bit 0, means last byte
            if cur_tag_num_byte & 0b10000000 == 0:
               break
         # convert bit string to int, int is unbounded
         tag_number =int(tag_number_acc, 2)

      return Tag(cla,type, tag_number, raw)



   def _parse_length(self, input :  Iterator[int]) -> Length:
      try:
         cur_byte = input.__next__()
      except StopIteration:
         raise EOFError("Unexpected EOF while parsing length")
      
      if cur_byte & 0b1000_0000 == 0:
         return Length(cur_byte)
      return Length(0)


   def _parse_value(self, input :  Iterator[int], length: Length) -> Value:
      len = length.length
      val = bytearray()
      while len > 0:
         try:
            cur_byte = input.__next__()
         except StopIteration:
            raise EOFError("Unexpected EOF while parsing value")
         val.append(cur_byte)
         len -= 1

      return Value(val)


   def parse_tlv(self, input : Iterator[int]) -> list[TLV]:
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
