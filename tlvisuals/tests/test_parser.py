from typing import cast
import unittest

from tlvisuals.parser import TLVParser, TagClass, TagType
from tlvisuals.tlv import TLV, ConstructedValue, Length, PrimitiveValue, Tag

class TestTLVParser(unittest.TestCase):
   def setUp(self) -> None:
      self.parser = TLVParser()
      
   def create_primitive_tag(self)->Tag:
      return Tag(TagClass.CONTEXT_SPECIFIC,TagType.PRIMITIVE,1, bytearray(b'\x81'))
      
   def create_constructed_tag(self)->Tag:
      return Tag(TagClass.CONTEXT_SPECIFIC,TagType.CONSTRUCTED,1, bytearray(b'\xA1'))
   
   def create_length(self,length: int)->Tag:
      if length <= 127:
         return Length(length, length.to_bytes(1,'big'))
      else:
         length_bytes = length.to_bytes(126, 'big')
         bytes = bytearray((len(length_bytes) | 0x80).to_bytes(1,'big'))
         bytes.extend(length_bytes)
         return Length(length, bytes)

   
   def test_tag_classes(self):
      input = b'\x00\x40\x80\xC0'.__iter__()
      self.assertEqual(self.parser._parse_tag(input).cla, TagClass.UNIVERSAL)
      self.assertEqual(self.parser._parse_tag(input).cla, TagClass.APPLICATION)
      self.assertEqual(self.parser._parse_tag(input).cla, TagClass.CONTEXT_SPECIFIC)
      self.assertEqual(self.parser._parse_tag(input).cla, TagClass.PRIVATE)

   def test_tag_type(self):
      input = b'\x00\x20'.__iter__()
      self.assertEqual(self.parser._parse_tag(input).type, TagType.PRIMITIVE)
      self.assertEqual(self.parser._parse_tag(input).type, TagType.CONSTRUCTED)

   def test_tag_number_30(self):
      bytes = bytearray()
      for i in range(0,30):
         bytes.append(i)
      iter = bytes.__iter__()
      for i in range(0,30):
         tag = self.parser._parse_tag(iter)
         self.assertEqual(tag.tag_number, i)
         self.assertEqual(tag.raw, i.to_bytes(1,'big'))

   def test_tag_number_2_bytes(self):
      bytes = b'\x1f\x81\x00'
      iter = bytes.__iter__()
      tag = self.parser._parse_tag(iter)
      self.assertEqual(tag.tag_number, 128)
      self.assertEqual(tag.raw, b'\x1f\x81\x00')

   def test_tag_number_3_bytes(self):
      bytes = b'\x1f\xff\x80\x01'
      iter = bytes.__iter__()
      tag = self.parser._parse_tag(iter)
      self.assertEqual(tag.tag_number, 2_080_769)
      self.assertEqual(tag.raw, b'\x1f\xff\x80\x01')

   def test_first_subs_tag_byte_0(self):
      bytes = b'\x1f\x80'
      iter = bytes.__iter__()
      self.assertRaises(ValueError, self.parser._parse_tag, iter)

   def test_tag_multiple_eof(self):
      bytes = b'\x1f\x81'
      iter = bytes.__iter__()
      self.assertRaises(EOFError, self.parser._parse_tag, iter)

   def test_length_1byte(self):
      bytes = bytearray()
      for i in range(0,127):
         bytes.append(i)
      iter = bytes.__iter__()
      for i in range(0,127):
         length = self.parser._parse_length(iter)
         self.assertEqual(length.length, i)
         self.assertEqual(length.raw, i.to_bytes(1,'big'))

   def test_length_2bytes(self):
      bytes = b'\x81\xFF'
      iter = bytes.__iter__()
      
      length = self.parser._parse_length(iter)
      self.assertEqual(length.length, 255)
      self.assertEqual(length.raw, bytes)

   def test_length_4bytes(self):
      bytes = b'\x84\x01\x01\x01\x01'
      iter = bytes.__iter__()
      
      length = self.parser._parse_length(iter)
      self.assertEqual(length.length, 16_843_009)
      self.assertEqual(length.raw, bytes)

   def test_length_eof(self):
      bytes = b'\x84\x01\x01\x01'
      iter = bytes.__iter__()
      self.assertRaises(EOFError,  self.parser._parse_length, iter)

   def test_value_primitive(self):
      bytes = b'\x01\x02\x03\x04'
      input = bytes.__iter__()
      test_tlv = TLV(
         self.create_primitive_tag(),
         self.create_length(4),
      )
      value = self.parser._parse_value(input, test_tlv)
      self.assertTrue(type(value) is PrimitiveValue)
      self.assertEqual(value.raw, bytes)

   def test_value_primitive_too_short(self):
      bytes = b'\x01\x02\x03'
      input = bytes.__iter__()
      test_tlv = TLV(
         self.create_primitive_tag(),
         self.create_length(4),
      )
      self.assertRaises(EOFError, self.parser._parse_value, input, test_tlv)

   def test_value_constructed(self):
      bytes = b'\x81\x04\x00\x01\x02\x03\x82\x04\x00\x00\x00\x00'
      input = bytes.__iter__()
      test_tlv = TLV(
         self.create_constructed_tag(),
         self.create_length(12),
      )
      value =  self.parser._parse_value(input, test_tlv)
      self.assertTrue(type(value) is ConstructedValue)
      self.assertEqual(len(cast(ConstructedValue, value).children), 2)
      self.assertEqual(cast(ConstructedValue, value).children[0].tag.raw, b'\x81')
      self.assertEqual(cast(ConstructedValue, value).children[1].tag.raw, b'\x82')

   
   def test_value_constructed_nested(self):
      bytes = b'\xA1\x04\xA2\x02\xA3\x00'
      input = bytes.__iter__()
      test_tlv = TLV(
         self.create_constructed_tag(),
         self.create_length(12),
      )
      value =  self.parser._parse_value(input, test_tlv)
      self.assertTrue(type(value) is ConstructedValue)
      self.assertEqual(len(cast(ConstructedValue, value).children), 1)
      self.assertEqual(cast(ConstructedValue, value).children[0].tag.raw, b'\xA1')
      self.assertEqual(cast(ConstructedValue, value)
                       .children[0].value
                       .children[0].tag.raw, b'\xA2')
      self.assertEqual(cast(ConstructedValue, value)
                       .children[0].value
                       .children[0].value
                       .children[0].tag.raw, b'\xA3')
      self.assertEqual(cast(ConstructedValue, value)
                       .children[0].value
                       .children[0].value
                       .children[0].value, None)
      
   
   def test_value_constructed_value_too_long(self):
      bytes = b'\x81\x04\x00\x01\x02\x03'
      input = bytes.__iter__()
      test_tlv = TLV(
         self.create_constructed_tag(),
         self.create_length(4),
      )
      value =  self.parser._parse_value(input, test_tlv)
      self.assertTrue(type(value) is ConstructedValue)
      self.assertEqual(len(cast(ConstructedValue, value).children), 1)
      self.assertEqual(cast(ConstructedValue, value).children[0].tag.raw, b'\x81')
      self.assertEqual(len(self.parser.diagnostic_collector.get_diagnostics()), 1)


if __name__ == "__main__":
   unittest.main()
