

from enum import IntFlag


class TagClass(IntFlag):
   UNIVERSAL = 0
   APPLICATION =1
   CONTEXT_SPECIFIC = 2
   PRIVATE =3

   
class TagType(IntFlag):
   PRIMITIVE = 0
   CONSTRUCTED = 1


class PrimitiveType(IntFlag):
   UNKNOWN = 0
   BOOLEAN = 1



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
   def get_raw(self) -> bytes:
      raise NotImplementedError()

class PrimitiveValue(Value):
   def __init__(self, raw: bytearray|None) -> None:
      self.raw = bytearray() if raw is None  else raw

   def get_raw(self) -> bytes:
      return self.raw


class TLV:
   """
   value should be objects deriving Value class, or none
   none represents length of 0
   """
   def __init__(self, tag:Tag, length:Length, value: Value|None = None) -> None:
      self.tag = tag
      self.length = length
      self.value = value


class ConstructedValue(Value):
   def __init__(self, children: list[TLV]|None=None) -> None:
      self.children = [] if children is None  else children
