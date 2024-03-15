import argparse
import sys
import json
from tlvisuals.tlv_parser import ByteGetter, TLVParser, DiagnosticsCollector, DerByteGetter
from tlvisuals.output_builder.raw_format import RawFormatBuilder

def main():
   parser = argparse.ArgumentParser(
      prog='TLVisuals',
      description='Prints TLV in a readable format. \
      Without options, app will read from standard input and assume the format is Hex in ASCII form, and output will be to standard output',
      )
   parser.add_argument('-f', '--file')           # positional argument
   parser.add_argument('-o', '--out')      # option that takes a value
   parser.add_argument('-v', '--verbose',action='store_true')  # on/off flag
   parser.add_argument('--input-format')  # inform formats: 'der', 'hextext'
   args = parser.parse_args()
   # print(args.file, args.out, args.verbose)

   # construct byte getter
   if args.file:
      if args.input_format and args.input_format == 'der':
         input_stream = open(args.file, 'rb')
      else:
         input_stream = open(args.file, 'r')
   else:
      input_stream = sys.stdin
   
   if args.input_format and args.input_format == 'der':
      byte_getter = DerByteGetter(input_stream)
   else:
      byte_getter = ByteGetter(input_stream)
  

   # construct parser
   diags = DiagnosticsCollector()
   parser = TLVParser(diagnostic_collector=diags)
   parsed_tlvs = parser.parse_tlv(byte_getter)
   # for tlv in parsed_tlvs:
   #    print(json.dumps(tlv, indent=1))

   # build output
   output_builder = RawFormatBuilder()
   out_str = output_builder.build(parsed_tlvs)

   # write to stream
   if args.out:
      with open(args.out, 'wt') as f:
         f.write(out_str)
   else:
      sys.stdout.write(out_str)
   
   return 0


if __name__ == '__main__':
   main()