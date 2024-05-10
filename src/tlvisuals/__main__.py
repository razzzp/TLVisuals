import argparse
from argparse import RawTextHelpFormatter
import sys
import json
from tlvisuals.tlv_parser import ByteGetter, TLVParser, DiagnosticsCollector, DerByteGetter
from tlvisuals.output_builder.raw_format import RawFormatBuilder

def main():
   parser = argparse.ArgumentParser(
      prog='TLVisuals',
      description='Prints TLV in a readable format. \
      Without options, app will read from standard input and assume the format is Hex in ASCII form, and output will be to standard output',
      formatter_class=RawTextHelpFormatter
      )
   parser.add_argument('-f', '--file', help="Parses input from specified FILE")
   parser.add_argument('-o', '--out', help="Writes output to specified OUT file")
   parser.add_argument('-v', '--verbose',action='store_true', help="Outputs more logs")  # on/off flag
   parser.add_argument('--input-format', help="Specifies input format:\n -der: input is raw hex\notherwise assumed to be ascii hex")  # inform formats: 'der', 'hextext'
   parser.add_argument('--output-format', help="Specifies output format:\n -interpretation: shows basic TLV flag interpretation")
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
   output_builder = RawFormatBuilder(inline_interpretation = True if args.output_format == "interpretation" else False)
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