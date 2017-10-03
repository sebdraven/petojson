import math
import struct
from collections import Counter, OrderedDict

import ssdeep
import hashlib
import pepy
from peanalysis.ordinal import ord_translate

class Utils:

    FILE_ALIGNMENT_HARDCODED_VALUE = 0x200
    FileAlignment_Warning = False  # We only want to print the warning once
    SectionAlignment_Warning = False  # We only want to print the warning once

    @staticmethod
    def get_hashes(data):
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
    def get_dword_from_offset(offset, data):
        if offset + 4 > len(data) and (offset+1)*4 > len(data):
            return None

        return struct.unpack('<I', data[offset:(offset+4)])[0]


    @staticmethod
    def get_characteristics(characteristics):
        is_dll = bool(characteristics & 0x2000)
        is_driver = bool(characteristics & 0x1000)
        is_exe = bool(characteristics & 0x0002)
        return is_exe, is_dll, is_driver

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

    @staticmethod
    def get_imports(imports_win):
        imps = OrderedDict()
        for imp in imports_win:
            dll, sym = imp.name, imp.sym
            if 'ORDINAL' in sym:
                try:
                    tokens = sym.split('_')
                    number_entry = tokens[len(tokens) - 1]
                    sym = ord_translate[dll][int(number_entry)].decode()
                except KeyError:
                    print('ordinal not found %s %s' % (dll, number_entry))
                    sym = 'ordinal_%s' % number_entry
            try:
                imps[dll].append(sym)

            except KeyError:
                imps[dll] = [sym]

        return imps

    @staticmethod
    def get_hashes_imports(imports_win):
        imphash=0
        impfuzzy = 0
        imps = ['%s.%s' % (dll.lower().split('.')[0], s.lower()) for dll, symbols in imports_win.items() for s in symbols]
        impfuzzy = ssdeep.hash(','.join(sorted(imps)))
        imphash = hashlib.md5(','.join(imps).encode()).hexdigest()
        return imphash, impfuzzy

    @staticmethod
    def get_exports(exports_win):
        exps = OrderedDict()
        for exp in exports_win:
            dll, sym = exp.mod, exp.func
            if 'ORDINAL' in sym:
                tokens = sym.split('_')
                number_entry = tokens[len(tokens) - 1]
                sym = ord_translate[dll][int(number_entry)].decode()
            try:
                exps[dll].append(sym)

            except KeyError:
                exps[dll] = [sym]

        return exps

    @staticmethod
    def get_tls(tlsData):
        tls_data_dict = {}
        startAddressOfRawData,endAddressOfRawData,addressOfIndex,addressOfCallBacks,sizeOfZeroFill,characteristics\
            = struct.unpack('<IIIIII', tlsData)
        tls_data_dict['StartAddressOfRawData'] = startAddressOfRawData
        tls_data_dict['EndAddressOfRawData'] = endAddressOfRawData
        tls_data_dict['AddressOfIndex'] = addressOfIndex
        tls_data_dict['AddressOfCallBacks'] = addressOfCallBacks
        tls_data_dict['SizeOfZeroFill'] = sizeOfZeroFill
        tls_data_dict['Characteristics'] = characteristics
        return tls_data_dict

    @staticmethod
    def adjust_SectionAlignment(val, section_alignment, file_alignment):
        global SectionAlignment_Warning
        if file_alignment < Utils.FILE_ALIGNMENT_HARDCODED_VALUE:
            if file_alignment != section_alignment and SectionAlignment_Warning is False:
                SectionAlignment_Warning = True

        if section_alignment < 0x1000:  # page size
            section_alignment = file_alignment

        # 0x200 is the minimum valid FileAlignment according to the documentation
        # although ntoskrnl.exe has an alignment of 0x80 in some Windows versions
        #
        # elif section_alignment < 0x80:
        #    section_alignment = 0x80

        if section_alignment and val % section_alignment:
            return section_alignment * (int(val / section_alignment))
        return val

    @staticmethod
    def power_of_two(val):
        return val != 0 and (val & (val - 1)) == 0

    @staticmethod
    def adjust_FileAlignment(val, file_alignment):
        global FileAlignment_Warning
        if file_alignment > Utils.FILE_ALIGNMENT_HARDCODED_VALUE:
            # If it's not a power of two, report it:
            if not Utils.power_of_two(file_alignment) and FileAlignment_Warning is False:
                FileAlignment_Warning = True

        if file_alignment < Utils.FILE_ALIGNMENT_HARDCODED_VALUE:
            return val
        return (int(val / 0x200)) * 0x200

    @staticmethod
    def get_next_addr_of_section(sections,index):
        if index < len(sections) - 1:
            return sections[index + 1].virtaddr
        return None

    @staticmethod
    def get_section_from_rva(rva, sections, section_alignement, file_alignement, size_of_file):
        sect_found = []
        for index,s in enumerate(sections):
            next_section_virtual_address = Utils.get_next_addr_of_section(sections, index)
            if Utils.contains_rva(rva, s, section_alignement, file_alignement, next_section_virtual_address,size_of_file):
                sect_found.append(s)

            if sect_found:
                return sect_found[0]

        return None

    @staticmethod
    def contains_rva(rva, section, file_alignment, section_alignment, next_section_virtual_address, size_of_file):
        # Check if the SizeOfRawData is realistic. If it's bigger than the size of
        # the whole PE file minus the start address of the section it could be
        # either truncated or the SizeOfRawData contain a misleading value.
        # In either of those cases we take the VirtualSize
        #
        if size_of_file - Utils.adjust_FileAlignment(section.pointerrawdata,
                                                     file_alignment) < section.length:
            # PECOFF documentation v8 says:
            # VirtualSize: The total size of the section when loaded into memory.
            # If this value is greater than SizeOfRawData, the section is zero-padded.
            # This field is valid only for executable images and should be set to zero
            # for object files.
            #
            size = section.virtsize
        else:
            size = max(section.length, section.virtsize)

        VirtualAddress_adj = Utils.adjust_SectionAlignment(section.virtaddr,
                                                           section_alignment,
                                                           file_alignment)

        # Check whether there's any section after the current one that starts before the
        # calculated end for the current one, if so, cut the current section's size
        # to fit in the range up to where the next section starts.
        if (next_section_virtual_address is not None and next_section_virtual_address > section.virtaddr
            and VirtualAddress_adj + size > next_section_virtual_address):

            size = next_section_virtual_address - VirtualAddress_adj

        return VirtualAddress_adj <= rva < VirtualAddress_adj + size

    @staticmethod
    def get_offset_from_rva_by_section(rva, section, sectionAlignment, fileAlignment):
        return (rva -
                Utils.adjust_SectionAlignment(
                    section.virtaddr,
                    sectionAlignment,
                    fileAlignment)
                ) + Utils.adjust_FileAlignment(
            section.pointerrawdata,
            fileAlignment)

    @staticmethod
    def get_offset_from_rva(rva, size_of_file,sections, section_alignment, file_alignment):
        section = Utils.get_section_from_rva(rva, sections, section_alignment, file_alignment,size_of_file)
        if not section:
            if rva < size_of_file:
                return rva

        return Utils.get_offset_from_rva_by_section(rva, section, section_alignment, file_alignment)
