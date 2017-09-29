import sys

from peanalysis.parse import  PEParser
import json
if __name__ == '__main__':
    pe = PEParser(sys.argv[1])
    pe.load()
    pe.dump_sections()
    pe.dump_imports()
    pe.dump_exports()
    pe.dump_resources()
    pe.dump_tls()
    print(json.dumps(pe.dict_pe))
