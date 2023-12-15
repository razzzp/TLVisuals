
import unittest
from tlvisuals.output_builder.raw_format import *
from tlvisuals.tlv import *

class RawFormatOutputBuilderTest(unittest.TestCase):

   def create_primitive_tag(self)->Tag:
      return Tag(TagClass.CONTEXT_SPECIFIC,TagType.PRIMITIVE,1, bytearray(b'\x81'))
      
   def create_constructed_tag(self)->Tag:
      return Tag(TagClass.CONTEXT_SPECIFIC,TagType.CONSTRUCTED,1, bytearray(b'\xA1'))
   
   def create_universal_primitive_tlv(self, tag_number: int, length: int, value: bytes):
      return TLV(
         tag= Tag(cla=TagClass.UNIVERSAL,type=TagType.PRIMITIVE,tag_number=tag_number,raw=tag_number.to_bytes(1,"big")),
         length= Length(length=length,raw=length.to_bytes(1,"big")),
         value= PrimitiveValue(raw=value)
      )

   def create_universal_constructed_tlv(self, tag_number: int, length: int, children: list[TLV]):
      return TLV(
         tag= Tag(cla=TagClass.UNIVERSAL,type=TagType.CONSTRUCTED,tag_number=tag_number,raw=(tag_number | 0b0010_0000).to_bytes(1,"big")),
         length= Length(length=length,raw=length.to_bytes(1,"big")),
         value= ConstructedValue(children=children)
      )
   
   def setUp(self) -> None:
      self.builder = RawFormatBuilder()

   def test_one_primitive_tlv(self):
      input = [self.create_universal_primitive_tlv(1,1,b'\xff')]
      expected = """01 01 FF\n"""

      self.builder._inline_interpretation = False
      result = self.builder.build(input)
      self.assertEqual(result, expected)

   def test_multiple_primitive_tlv(self):
      input = []
      for i in range(1, 9):
         input.append(self.create_universal_primitive_tlv(i,1,b'\xff'))
      io = StringIO()
      for i in range(1, 9):
         io.write(f'{i.to_bytes(1,"big").hex().upper()} 01 FF\n')
      expected = io.getvalue()

      self.builder._inline_interpretation = False
      result = self.builder.build(input)
      self.assertEqual(result, expected)

   def test_constructed(self):
      children = []
      for i in range(1, 9):
         children.append(self.create_universal_primitive_tlv(i,1,b'\xff'))
      input = [self.create_universal_constructed_tlv(1, 0, children)]

      io = StringIO()
      io.write("21 00\n")
      for i in range(1, 9):
         io.write(f'   {i.to_bytes(1, "big").hex().upper()} 01 FF\n')
      # io.write('\n')
      expected = io.getvalue()

      self.builder._inline_interpretation = False
      result = self.builder.build(input)
      # print(result)
      # print('\n')
      # print(expected)
      self.assertEqual(result, expected)

if __name__ == '__main__':
   unittest.main()