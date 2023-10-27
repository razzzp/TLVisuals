


from io import StringIO
from tlvisuals.tlv import *


class RawFormatBuilder:
   def __init__(self, indent_size:int = 3,  indent:int = 0) -> None:
      self._indent_size = indent_size
      self._indent_str = ' ' * indent_size
      self._indent = indent

   def _add_indent(self, output: StringIO):
      for _ in range(0, self._indent):
         output.write(self._indent_str)


   def _build_primitive(self, tlv: TLV, output:StringIO):
      output.write(' ')
      output.write(tlv.value.get_raw().hex().upper())


   def _build_constructed(self, tlv: TLV, output:StringIO):
      output.write('\n')
      new_builder = RawFormatBuilder(self._indent_size, self._indent+1)
      new_builder.build_on_output(tlv.value.children, output)


   def _build_tlv(self, tlv: TLV, output:StringIO):
      self._add_indent(output)
      output.write(tlv.tag.raw.hex().upper())
      output.write(' ')
      output.write(tlv.length.raw.hex().upper())
      if not tlv.value is None:
         if tlv.tag.type == TagType.PRIMITIVE:
            self._build_primitive(tlv, output)
         else:
            self._build_constructed(tlv, output)
      output.write('\n')

   def build_on_output(self, input: list[TLV], output: StringIO):
      for tlv in input:
         self._build_tlv(tlv, output)

   def build(self, input: list[TLV]) -> str:
      output = StringIO()
      self.build_on_output(input, output)
      return output.getvalue()



   