# TLVisuals

Takes TLV in the form of UTF8 hex values, interprets the Tags, Lengths and Values, and outputs the interpretation in a more readable format.

2 Commands available:
- tlvparse
- hextoraw

## tlvparse
usage: TLVisuals [-h] [-f FILE] [-o OUT] [-v] [--input-format INPUT_FORMAT] [--output-format OUTPUT_FORMAT]

Prints TLV in a readable format.       Without options, app will read from standard input and assume the format is Hex in ASCII form, and output will be to standard output

options:  
  -h, --help               show this help message and exit  
  -f FILE, --file FILE     Parses input from specified FILE  
  -o OUT, --out OUT        Writes output to specified OUT file  
  -v, --verbose            Outputs more logs
  --input-format INPUT_FORMAT  
                        Specifies input format:
                         -der: input is raw hex
                        otherwise assumed to be ascii hex  
  --output-format OUTPUT_FORMAT  
                        Specifies output format:
                         -interpretation: shows basic TLV flag interpretation  

## hextoraw
usage: tlvisuals hextoraw [-h] [-f FILE] [-o OUT]

Converts ASCII hex input to raw bytes, ignoring whitespaces

options:  
  -h, --help            show this help message and exit  
  -f FILE, --file FILE  Reads input from specified FILE  
  -o OUT, --out OUT     Writes output to specified OUT file  