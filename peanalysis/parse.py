import datetime
import os
import pepy
from peanalysis.utils import Utils

class PEParser:

    def __init__(self, path):
        self.path = path
        self.pe = None
        self.dict_pe = {

        }

    def load(self):
        self.pe = pepy.parse(self.path
                             )
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
            'is_dll': False,
            'is_driver': False,
            'is_exe': False,
            'x86': self.pe.machine == 0x14c,
            'x86_64': self.pe.machine == 0x8664 or self.pe.machine == 0x0200,
            'size': os.stat(self.path).st_size,
            'number_sections': 0,
            'ressources': {},
            'Date Compilation': datetime.datetime.fromtimestamp(int(self.pe.timedatestamp)
                                                                ).strftime('%Y-%m-%d %H:%M:%S')
        }

    def dump_sections(self):

        for sec in self.pe.get_sections():
            md5_sec = None
            sha1_sec = None
            sha256_sec = None
            ssdeep_sec = None
            entropy = 0.0

            charac_sections = {}
            section_name = sec.name
            data = sec.data

            if data:
                md5_sec, sha1_sec, sha256_sec, ssdeep_sec = Utils.get_hashes_section(data)
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