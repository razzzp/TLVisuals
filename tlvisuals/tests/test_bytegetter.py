
import io
import unittest
from tlvisuals.tlv_parser.parser import ByteGetter

class TestByteGetter(unittest.TestCase):

   def test_all_chars(self):
      input = "00112233445566778899AABBCCDDEEFF"
      stream = io.StringIO("00112233445566778899AABBCCDDEEFF")
      byte_getter = ByteGetter(stream)
      count = 0
      while True:
         try:
            cur = byte_getter.__next__()
         except StopIteration:
            break         

         self.assertEqual("0x%0.2X" % cur, "0x%s" % input[count*2:count*2+2])
         count +=1

   def test_all_chars_with_space(self):
      input = "00 11 22 33   44   55 6 6 7 7 8899AABBCCDDEE   F F  "
      stream = io.StringIO("00112233445566778899AABBCCDDEEFF")
      byte_getter = ByteGetter(stream)
      count = 0
      while True:
         try:
            cur = byte_getter.__next__()
         except StopIteration:
            break   
         
         self.assertEqual(cur, (count << 4) +count)
         count +=1


   def test_invalid_chars(self):
      input = "AA BB CX DD"
      stream = io.StringIO("00112233445566778899AABBCCDDEEFF")
      byte_getter = ByteGetter(stream)
      count = 0
      while True:
         try:
            cur = byte_getter.__next__()
         except ValueError as e:
            self.assertEqual(count, 2)
         except StopIteration:
            break
         
         count +=1


   def test_odd_number(self):
      input = "00112"
      stream = io.StringIO("00112233445566778899AABBCCDDEEFF")
      byte_getter = ByteGetter(stream)
      count = 0
      while True:
         try:
            cur = byte_getter.__next__()
         except ValueError as e:
            self.assertEqual(count, 2)
         except StopIteration:
            break

         count +=1


if __name__ == '__main__':
    unittest.main()