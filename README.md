PEtoJSON
==========

the goal of this project based on pe-parse, it's to serialize pe to json with metadata informations


Installation
=============

* Install python 3.5


* Install pe-parse https://github.com/sebdraven/pe-parse 


* ` pip install -r requirements.txt `


* `python3.5 setup.py install`

Usage
=======

petojson.py <path_file> 

or

    from peanalysis.parse import PEParser 
        p = <path_of_my_file>
        pe = PEParser(p)
        pe.load()
        pe.dump_sections()
        pe.dump_imports()
        pe.dump_exports()
        pe.dump_resources()
        pe.dump_tls() 
        json.dumps(pe.dict_pe)

Todo
=======

Support:

* PE 64bits format
* PEHash
* Assembly and Graph flow
