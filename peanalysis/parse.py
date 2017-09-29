import datetime
import os
import pepy

import binascii

from peanalysis import resources
from peanalysis.utils import Utils
import magic


class PEParser:

    def __init__(self, path):
        self.path = path
        self.pe = None
        self.data = None
        self.sections =  None
        self.dict_pe = {

        }

    def load(self):
        self.pe = pepy.parse(self.path)
        self.data = bytes(self.pe.get_data())
        self.sections = self.pe.get_sections()

        is_exe, is_dll, is_driver = Utils.get_characteristics(self.pe.characteristics)

        self.dict_pe = {
            'type': 'PE',
            'sections': [],
            'address_entrypoint': hex(self.pe.get_entry_point()),
            'section_entrypoint': '',
            'path': self.path,
            'hashes': {

            },
            'assembly': '',
            'exports': [],
            'imports': {},
            'tls': [],
            'strings': [],
            'is_dll': is_dll,
            'is_driver': is_driver,
            'is_exe': is_exe,
            'x86': self.pe.machine == 0x14c,
            'x86_64': self.pe.machine == 0x8664 or self.pe.machine == 0x0200,
            'size': os.stat(self.path).st_size,
            'number_sections': len(self.sections),
            'resources': [],
            'Date Compilation': datetime.datetime.fromtimestamp(int(self.pe.timedatestamp)
                                                                ).strftime('%Y-%m-%d %H:%M:%S')
        }

        self.dict_pe['hashes']['md5'], self.dict_pe['hashes']['sha1'], self.dict_pe['hashes']['sha256'], self.dict_pe['hashes']['ssdeep'] = Utils.get_hashes(
            open(self.path,'rb').read())

    def dump_sections(self):

        for sec in self.sections:
            md5_sec = None
            sha1_sec = None
            sha256_sec = None
            ssdeep_sec = None
            entropy = 0.0

            charac_sections = {}
            section_name = sec.name
            data = sec.data

            if data:
                md5_sec, sha1_sec, sha256_sec, ssdeep_sec = Utils.get_hashes(data)
                entropy = Utils.get_entropy(data, sec.length)
            char = sec.characteristics
            if char:
                charac_sections = Utils.get_char_sections(char)

            section = {
                'name': section_name,
                'md5': md5_sec,
                'sha1': sha1_sec,
                'sha256': sha256_sec,
                'ssdeep': ssdeep_sec,
                'characteristics': charac_sections,
                'virtual_size': hex(sec.virtsize),
                'size': hex(sec.length),
                'virtual_address': hex(sec.virtaddr),
                'entropy': entropy
            }

            self.dict_pe['sections'].append(section)

    def dump_imports(self):
        imports_win = self.pe.get_imports()
        self.dict_pe['imports'] = Utils.get_imports(imports_win)
        imphash, impfuzzy = Utils.get_hashes_imports(self.dict_pe['imports'])
        self.dict_pe['hashes']['imphash'] = imphash
        self.dict_pe['hashes']['impfuzzy'] = impfuzzy

    def dump_exports(self):
        exports_win = self.pe.get_exports()
        self.dict_pe['exports'] = Utils.get_exports(exports_win)

    def dump_resources(self):

        for res in self.pe.get_resources():

            res_dict = {}

            res_dict['type'] = res.type_str.replace('\x00', '')
            res_dict['file_type'] = magic.from_buffer(bytes(res.data))
            res_dict['size'] = len(res.data)
            res_dict['lang'] = resources.LANG.get(res.lang, 'UNKNOWN')
            res_dict['code_page'] = res.codepage
            res_dict['data'] = binascii.hexlify(res.data).decode()

            res_dict['md5'], res_dict['sha1'], res_dict['sha256'], res_dict['ssdeep'] = Utils.get_hashes(res.data)

            self.dict_pe['resources'].append(res_dict)

    def dump_tls(self):
        tls_va, tls_size = self.pe.get_datadirectories()[pepy.DIR_TLS]
        if tls_size > 0:
            tls_data_struct = Utils.get_tls(self.pe.get_bytes(tls_va+self.pe.imagebase, tls_size))
            offset = Utils.get_offset_from_rva(tls_data_struct['AddressOfCallBacks'] - self.pe.imagebase, len(self.data)
                                               , self.sections, self.pe.sectionalignement, self.pe.filealingment)

            while Utils.get_dword_from_offset(offset, self.data):
                cb = Utils.get_dword_from_offset(offset, self.data) - self.pe.imagebase
                section = Utils.get_section_from_rva(cb, self.sections, self.pe.sectionalignement, self.pe.filealingment
                                                     , len(self.data))
                section_name = ''
                if section:
                    section_name = section.name

                elem = {}

                elem['call_back'] = "    0x%08x" % cb

                elem['section_name'] = section_name

                self.dict_pe['tls'].append(elem)

                offset += 4
