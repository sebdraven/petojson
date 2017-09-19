import math
from collections import Counter

import ssdeep
import hashlib
import pepy

class Utils:

    @staticmethod
    def get_hashes_section(data):
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        ssdeep_hash = ssdeep.Hash()

        md5_hash.update(data)
        sha1_hash.update(data)
        sha256_hash.update(data)
        ssdeep_hash.update(bytes(data))

        return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest(), ssdeep_hash.digest()

    @staticmethod
    def get_char_sections(char):
        all_characteristics = {

            'IMAGE_SCN_TYPE_NO_PAD': 0x00000008,
            'IMAGE_SCN_CNT_CODE': 0x00000020,
            'IMAGE_SCN_CNT_INITIALIZED_DATA':0x00000040,
            'IMAGE_SCN_CNT_UNINITIALIZED_DATA': 0x00000080,
            'IMAGE_SCN_LNK_OTHER': 0x00000100,
            'IMAGE_SCN_LNK_INFO':0x00000200,
            'IMAGE_SCN_LNK_REMOVE':0x00000800,
            'IMAGE_SCN_LNK_COMDAT':0x00001000,
            'IMAGE_SCN_NO_DEFER_SPEC_EXC':0x00004000,
            'IMAGE_SCN_GPREL': 0x00008000,
            'IMAGE_SCN_MEM_PURGEABLE': 0x00020000,
            'IMAGE_SCN_MEM_LOCKED': 0x00040000,
            'IMAGE_SCN_MEM_PRELOAD': 0x00080000,
            'IMAGE_SCN_ALIGN_1BYTES': 0x00100000,
            'IMAGE_SCN_ALIGN_2BYTES': 0x00200000,
            'IMAGE_SCN_ALIGN_4BYTES': 0x00300000,
            'IMAGE_SCN_ALIGN_8BYTES': 0x00400000,
            'IMAGE_SCN_ALIGN_16BYTES': 0x00500000,
            'IMAGE_SCN_ALIGN_32BYTES': 0x00600000,
            'IMAGE_SCN_ALIGN_64BYTES': 0x00700000,
            'IMAGE_SCN_ALIGN_128BYTES': 0x00800000,
            'IMAGE_SCN_ALIGN_256BYTES':0x00900000,
            'IMAGE_SCN_ALIGN_512BYTES': 0x00A00000,
            'IMAGE_SCN_ALIGN_1024BYTES': 0x00B00000,
            'IMAGE_SCN_ALIGN_2048BYTES': 0x00C00000,
            'IMAGE_SCN_ALIGN_4096BYTES': 0x00D00000,
            'IMAGE_SCN_ALIGN_8192BYTES': 0x00E00000,
            'IMAGE_SCN_LNK_NRELOC_OVFL': 0x01000000,
            'IMAGE_SCN_MEM_DISCARDABLE': 0x02000000,
            'IMAGE_SCN_MEM_NOT_CACHED': 0x04000000,
            'IMAGE_SCN_MEM_NOT_PAGED': 0x08000000,
            'IMAGE_SCN_MEM_SHARED': 0x10000000,
            'IMAGE_SCN_MEM_EXECUTE': 0x20000000,
            'IMAGE_SCN_MEM_READ': 0x40000000,
            'IMAGE_SCN_MEM_WRITE': 0x80000000

        }

        char_sections = [k for k, v in all_characteristics.items() if char & v]

        return {'read':  'IMAGE_SCN_MEM_READ' in char_sections, 'write': 'IMAGE_SCN_MEM_WRITE' in char_sections,
                'execute': 'IMAGE_SCN_MEM_EXECUTE' in char_sections
                 }

    @staticmethod
    def get_entropy(data, size):

        if len(data) == 0:
            return 0.0

        occurences = Counter(data)

        entropy = 0
        for x in occurences.values():
            p_x = float(x) / size
            entropy -= p_x * math.log(p_x, 2)
        return entropy
