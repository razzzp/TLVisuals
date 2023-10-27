import unittest

from tlvisuals.tlv_parser.parser import TLVParser, TagClass, TagType

class TestTLVParser(unittest.TestCase):
   def setUp(self) -> None:
      self.parser = TLVParser()
      
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

if __name__ == "__main__":
   unittest.main()
