import unittest

from tlvisuals.tlv_parser.parser import BERTLVParser, TagClass, TagType

class TestTLVParser(unittest.TestCase):
   def setUp(self) -> None:
      self.parser = BERTLVParser()
      
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
         self.assertEqual(self.parser._parse_tag(iter).tag_number, i)

   def test_tag_number_2_bytes(self):
      bytes = b'\x1f\x81\x00'
      iter = bytes.__iter__()
      self.assertEqual(self.parser._parse_tag(iter).tag_number, 128)

   def test_tag_number_3_bytes(self):
      bytes = b'\x1f\xff\x80\x01'
      iter = bytes.__iter__()
      self.assertEqual(self.parser._parse_tag(iter).tag_number, 2_080_769)

   def test_first_subs_tag_byte_0(self):
      bytes = b'\x1f\x80'
      iter = bytes.__iter__()
      self.assertRaises(ValueError, self.parser._parse_tag, iter)

   def test_tag_multiple_eof(self):
      bytes = b'\x1f\x81'
      iter = bytes.__iter__()
      self.assertRaises(EOFError, self.parser._parse_tag, iter)

if __name__ == "__main__":
   unittest.main()
