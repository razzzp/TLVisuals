import argparse
from argparse import RawTextHelpFormatter
import sys
import json
from tlvisuals.tlv_parser import ByteGetter, TLVParser, DiagnosticsCollector, DerByteGetter
from tlvisuals.output_builder.raw_format import RawFormatBuilder


def main():
   parser = argparse.ArgumentParser(
      prog="tlvisuals",
      description="Utilities for parsing and printing TLV in a more user friendly format",
      formatter_class=RawTextHelpFormatter
      )
   parser.add_argument('-v', '--verbose',action='store_true', help="Outputs more logs")  # on/off flag
   subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")

   tlvparse_parser = subparsers.add_parser(name="tlvparse", description="Without options, app will read from standard input and assume the format is Hex in ASCII form, and output will be to standard output")
   tlvparse_parser.add_argument('-f', '--file', help="Parses input from specified FILE")
   tlvparse_parser.add_argument('-o', '--out', help="Writes output to specified OUT file")
   tlvparse_parser.add_argument('--input-format', help="Specifies input format:\n -der: input is raw hex\notherwise assumed to be ascii hex")  # inform formats: 'der', 'hextext'
   tlvparse_parser.add_argument('--output-format', help="Specifies output format:\n -interpretation: shows basic TLV flag interpretation")

   hextoraw_parser = subparsers.add_parser(name="hextoraw",description="Converts ASCII hex input to raw bytes, ignoring whitespaces")
   hextoraw_parser.add_argument('-f', '--file', help="Reads input from specified FILE")
   hextoraw_parser.add_argument('-o', '--out', help="Writes output to specified OUT file")
   args = parser.parse_args()

   
   match(args.subcommand):
      case "tlvparse":
         sys.exit(tlvparse(args=args))
      case "hextoraw":
         sys.exit(hextoraw(args=args))
      case _:
         print("Unknown command")
         parser.print_help()
         sys.exit(1)
   

def tlvparse(args):
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


def hextoraw(args):
   # construct byte getter
   if args.file:
      input_stream = open(args.file, 'r')
   else:
      input_stream = sys.stdin
   byte_getter = ByteGetter(input_stream)
   out_bytes = bytes(byte_getter)
    # write to stream
   if args.out:
      with open(args.out, 'wtb') as f:
         f.write(out_bytes)
   else:
      sys.stdout.buffer.write(out_bytes)

   return 0


if __name__ == '__main__':
   main()