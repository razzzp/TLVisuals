


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
   def __init__(self, length: int, raw: bytearray) -> None:
      self.length = length
      self.raw = raw

class Value:
   pass

class PrimitiveValue(Value):
   def __init__(self, raw: bytearray = bytearray()) -> None:
      self.raw = raw


class TLV:
   """
   value should be objects deriving Value class, or none
   none represents length of 0
   """
   def __init__(self, tag:Tag, length:Length, value: Value|None ) -> None:
      self.tag = tag
      self.length = length
      self.value = value


class ConstructedValue(Value):
   def __init__(self, children: list[TLV] = []) -> None:
      self.children = children


class DiagnosticsCollector:
   def __init__(self) -> None:
      self.diags = []
      pass

   def add_error(self, error: any):
      self.diags.append(error)

class TLVParser:
   def __init__(
         self, 
         parent_tlv : TLV | None = None, 
         diagnostic_collector: DiagnosticsCollector = DiagnosticsCollector()
         ) -> None:
      self._parent_tlv = parent_tlv
      self._bytes_taken = 0
      self._diags = diagnostic_collector
      

   def _next(self, input :  Iterator[int])->int:
      # if bytes taken exceeds parent length, raise error
      if self._parent_tlv and self._parent_tlv.length.length == self._bytes_taken:
         self._diags.add_error(f'TLV length exceeds parent length of: {self._parent_tlv.length.length}')
      
      self._bytes_taken += 1
      return input.__next__()
   
   def _parse_tag(self, input :  Iterator[int]) -> Tag:
      try:
         cur_byte = input.__next__()
      except StopIteration:
         return None
      
      raw = bytearray()
      raw.append(cur_byte)

      # first bits 8-7 (LSB) is class
      # Universal/Application/Context Specific/Private
      cla = TagClass((cur_byte & 0b1100_0000) >> 6)
      val = (cur_byte & 0b0010_0000) >> 5

      # bit 6 is type
      # Primitive/Constructed
      type = TagType(int(val))
      tag_number = cur_byte & 0b0001_1111

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
            cur_tag_num = cur_tag_num_byte & 0b0111_1111

            if len(raw) == 2 and cur_tag_num == 0:
               # first subsequent byte cannot be 0
               raise ValueError("First subsequent tag byte cannot be 0x00")
            
            # append bits of cur tag num
            tag_number_acc+= '{0:07b}'.format(cur_tag_num)

            # if first bit 0, means last byte
            if cur_tag_num_byte & 0b1000_0000 == 0:
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
         raw = bytearray()
         raw.append(cur_byte)
         return Length(cur_byte, raw)
      elif cur_byte & 0b1000_0000 == 0 and cur_byte & 0b0111_1111:
         # case using indefinite form, i.e. length byte is 0x80
         # not supported yet
         raise ValueError("Indefinite length encoding is not supported")
      else:
         length_of_length = cur_byte & 0b0111_1111
         real_length = 0
         raw = bytearray()
         raw.append(cur_byte)
         # multiple byte length
         while length_of_length>0:
            try:
               cur_byte = input.__next__()
            except StopIteration:
               raise EOFError("Unexpected EOF while parsing length")
            
            length_of_length-=1
            # shift left since there are more bytes
            real_length = real_length << 8
            real_length += cur_byte
            raw.append(cur_byte)
         
         return Length(length=real_length,raw=raw)


   def _parse_primitive(self, input :  Iterator[int], in_tlv: TLV):
      expected_len = in_tlv.length.length
      val = bytearray()
      while expected_len > 0:
         try:
            cur_byte = input.__next__()
         except StopIteration:
            raise EOFError("Unexpected EOF while parsing value")
         val.append(cur_byte)
         expected_len -= 1
      return PrimitiveValue(val)

   """ recursively parse children TLV """
   def _parse_constructed(self, input :  Iterator[int],  in_tlv: TLV):
      expected_len = in_tlv.length.length
      children = self.parse_tlv(input)
      return ConstructedValue(children)


   def _parse_value(self, input :  Iterator[int],  in_tlv: TLV) -> Value:
      if in_tlv.length.length == 0:
         return None
      
      if in_tlv.tag.type == TagType.PRIMITIVE:
         return self._parse_primitive(input, in_tlv)
      else:
         return self._parse_constructed(input, in_tlv)


   def parse_tlv(self, input : Iterator[int]) -> list[TLV]:
      result = []
      while True:
         try:
            tag = self._parse_tag(input)
            if tag == None:
               break
            len = self._parse_length(input)

            tlv= TLV(tag, len, None)

            value = self._parse_value(input, tlv)

            tlv.value = value
            result.append(tlv)
         except Exception as e:
            raise e
      return result
