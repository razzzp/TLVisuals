import sys
from tlvisuals.tlv_parser import TLVParser, ByteGetter
from tlvisuals.output_builder.raw_format import RawFormatBuilder


class ProgramOptions:
    def __init__(self) -> None:
        self.input_file = None
        self.output_file = None
        pass


def _parse_arguments(argv: list[str]) -> ProgramOptions:
    options = ProgramOptions()
    if len(argv) == 0: return options

    iter = argv.__iter__()
    try:
        while True:
            try:
                cur_arg = iter.__next__()
            except StopIteration:
                break
            if cur_arg == '--file-in':
                file_name = iter.__next__()
                options.file = file_name
            if cur_arg == '--file-out':
                file_name = iter.__next__()
                options.output_file = file_name

    except StopIteration:
        raise Exception(f'Expected value after argument {cur_arg}')
    
    return options
        


def main():
    options = _parse_arguments(sys.argv)
    input = ByteGetter(sys.stdin)
    tlv_parser = TLVParser()
    tlvs = tlv_parser.parse_tlv(input=input)
    output = RawFormatBuilder().build(tlvs)
    print(output)



if __name__ == '__main__':
    main()