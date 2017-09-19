import sys

from peanalysis.parse import  PEParser
import json
if __name__ == '__main__':
    pe = PEParser(sys.argv[1])
    pe.load()
    pe.dump_sections()
    pe.dump_imports()
    print(json.dumps(pe.dict_pe))
