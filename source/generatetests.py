import distorm3
import pathlib
import json
import subprocess
import time
import gzip
import base64
import collections
import re
import itertools
import math
from collections import OrderedDict
from os import path
import pathlib

DEFAULT_HEAP_SIZE = 0x0
CURRENT_OUT_FILE_INDEX = 0
TEMP_DIR = 'temp'
TEST_WRITER_COUNTER = 0
OUT_DIR = 'x86-tests'

BSS_ADDRESS  = 0x7ff00000
DATA_ADDRESS = 0x70000000
TEXT_ADDRESS = 0x60000080 #0x08048080 #0x60000000
HEAP_ADDRESS = 0x80000000

EREGS = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']


####
# overall script
#  generating the various kinds of tests
#  helpers to collect
#  creating arguments
#  modrm/sib
#  generating asm
#  compiling/running/
#  

#should this be a class?
#def new_output_file(name)
#def add_test(name, code)
#def close_output_file()
#class output_file():
#

        

def generate_tests():
    global TEST_WRITER_COUNTER; TEST_WRITER_COUNTER = 0
    gen_base()
    #gen_test('0o0[1239]0 /mr'
    #gen_opcode()
    #gen_mod_rm()
    #gen_c_jmp8()
    #gen_mod_op()
    #gen_op_i08()
    #gen_op_i32()


#### test helpers  ################################################################################
# TODO function to create code to set registers, flags, memory
# further - given sets of values, flags, memory/reg, yield objects that only need to have instructions appended
#
# for (op1, op2), add_function in setup_tests(Values, reg/mem-offsets, flag-values):
#   add_function('and {op1} {op2}')


# base tests - ensuring 
def gen_base():
    w = TestWriter('base')
    
    # stack/int3
    w.add_instructions('', 'int3')
    
    # nop
    w.add_instructions('nop')
    w.add_instructions('nop\nnop')
    
    # push imm32
    for v in mov_values:
        w.add_instructions(f'push strict dword 0x{v:08X}', f'push_imm32_{hex(v)}')
    
    # flag push
    w.add_instructions('pushfd')
    
    # flag push/pop
    w.add_instructions('pushfd\npopfd')
    
    # push imm/pop->flags
    for status in all_status_and_direction_flags():
        w.add_instructions(f'push strict dword 0x{status:08X}\npopfd', f'push_imm32_{hex(status)}-popfd')
    
    # move imm32
    for reg in EREGS:
        for v in mov_values:
            w.add_instructions(f'mov {reg}, strict dword 0x{v:08X}', f'mov_imm32_{reg}_'+hex(v))
    
    # move eax->[imm32] (A3)
    # mov [0x4030201], eax
    for v in mov_values:
        for offset in memory_offsets:
            w.add_instructions(f'mov eax, strict dword 0x{v:08X}\nmov [0x{offset + HEAP_ADDRESS:08X}], eax',
                               f'mov-0x{v:08X}->[0x{offset+HEAP_ADDRESS:08X}]',
                               heapsize=offset)
        
    w.close()


    
#### code helpers  ################################################################################
def bytes_to_code(bytestring):
    instructions = [
        '    db  ' + ', '.join('0x%02x' % c for c in bytestring[i:i+w])
        + ' '*(18 - len(opcodes)*3) + ' ; ' + instr
        for i, w, instr, opcodes
        in distorm3.Decode(0, bytestring, distorm3.Decode32Bits)
    ]
    return "\n".join(instructions)


def code_for_opcodes(bytestring, heapsize=DEFAULT_HEAP_SIZE,
                     initialize_stack=True, append_int3=True):
    return code_for_instructions(
        bytes_to_code(bytestring),
        heapsize = heapsize,
        initialize_stack = initialize_stack,
        append_int3 = append_int3
    )


def code_for_instructions(instructions, heapsize=DEFAULT_HEAP_SIZE,
                          initialize_stack=True, append_int3=True):
    instructions = (
        ''.join('    ' + instr.strip() + '\n' for instr in instructions.split('\n')
                if len(instr.strip()) > 0)
        + ('    int3\n' if append_int3 else '')
    )
    code = (
        code_header(heapsize=heapsize, initialize_stack=initialize_stack)
        + instructions
    )
    return code


def code_header(heapsize=DEFAULT_HEAP_SIZE, initialize_stack=True):
    HEAP_SIZE_PAD = 16
    heapsize = math.ceil(heapsize/HEAP_SIZE_PAD)*HEAP_SIZE_PAD + HEAP_SIZE_PAD
    stack_initializer = ('    mov esp, strict dword 0x7ffff000 ; init stack\n'
                         if initialize_stack else
                         '')
    return f"""
; ===== export ======
global _start
global _memory_start
global _memory_end
global _heap
global _stack

; ===== data ========
section .data

; ===== memory ======
section .bss        ; 
    resb 0xfe000    ; @ 0x7ff00000 (padding)
_memory_start:
    resb 0x1000     ; @ 0x7fffe000
_stack:
    resb 0x1000     ; @ 0x7ffff000
_heap:              ; @ 0x80000000
    resb {heapsize} ; @ 0x80000000
_memory_end:
    resb 1          ; @ 0x80000000 + heapsize


; ===== code ========
section .text

_start:
{stack_initializer}"""


#### flag helpers ################################################################################
def all_status_flags():
    all_flags = STATUS_FLAGS.keys()
    flag_sets = list(itertools.chain.from_iterable(itertools.combinations(all_flags, r)
                                                   for r in range(len(all_flags)+1)))
    for flag_set in flag_sets:
        status = FLAG_MASK
        for flag in flag_set:
            status |= STATUS_FLAGS[flag]
        yield status

def all_status_and_direction_flags():
    for status in all_status_flags():
        yield status
        yield status | CONTROL_FLAGS['DF']
        

FLAG_MASK = 0x202 # always set
STATUS_FLAGS = collections.OrderedDict([
    ('CF', 0x0001), # Carry flag  StatusCY(Carry) - NC(No Carry)
    ('PF', 0x0004), # Parity flag - Status - PE(Parity Even) - PO(Parity Odd)
    ('AF', 0x0010), # Adjust flag - Status - AC(Auxiliary Carry) - NA(No Auxiliary Carry)
    ('ZF', 0x0040), # Zero flag - Status - ZR(Zero) - NZ(Not Zero)
    ('SF', 0x0080), # Sign flag - Status - NG(Negative) - PL(Positive)
    ('OF', 0x0800), # Overflow flag - Status - OV(Overflow) - NV(Not Overflow)
])
CONTROL_FLAGS = collections.OrderedDict([
    ('TF', 0x0100), # Trap flag (single step) - Control
    ('IF', 0x0200), # Interrupt enable flag - Control - EI(Enable Interrupt) - DI(Disable Interrupt)
    ('DF', 0x0400), # Direction flag - Control - DN(Down) - UP(Up)
])




#### argument/value helpers #######################################################################
class ValueSet:
    def __init__(self, *args, kind = 'values'):
        self.kind = kind
        if kind == 'values':   
            self._values = list(args)
        else:
            [self.left, self.right] = args
            
    def __repr__(self):
        if self.kind == 'values':
            return ValueSet.repr_numbers(self._values)
        elif self.kind == '*':
            return '%s*%s' % (self.left, self.right)
        elif self.kind == '+':
            return '%s + %s' % (self.left, self.right)
    
    def __add__(self, other):
        if self.kind == 'values' and other.kind == 'values':
            return ValueSet(*ValueSet.union(self._values, other._values))
        else:
            return ValueSet(self, other, kind='+')
    
    def __mul__(self, other):
        assert self.kind == 'values' and other.kind == 'values'
        return ValueSet(self, other, kind='*')
    
    def values(self):
        if self.kind == 'values':
            return self._values
        else:
            return ValueSet.union(self.left.values(), self.right.values())

    def __iter__(self):
        return iter(self.values())
        
    def tuples(self):
        if self.kind == 'values':
            return sorted(set((v1, v2) for v1 in self._values for v2 in self._values))
        elif self.kind == '+':
            return ValueSet.union(self.left.tuples(), self.right.tuples())
        elif self.kind == '*':
            return sorted(set(
                (v1, v2)[::d]
                for v1 in self.left.values()
                for v2 in self.right.values()
                for d in [-1, 1]
            ))

                                  
    def union(a, b):
        #d = OrderedDict((v, None) for v in a)
        #d.update((v, None) for v in b)
        #return list(d.keys())
        return sorted(set(a) | set(b))

    def repr_numbers(values):
        return "{" + ",".join(hex(v) if v > 16 else str(v) for v in values) + "}"
        

basic = ValueSet(
    0x00_00_00_00,
    0x00_00_00_01,
    0xFF_FF_FF_FF,
    0x78_9A_BC_DE, # odd parity, bytes are recognizable
)
one = ValueSet(1)
numbers = ValueSet( # basic numbers
    0,
    1,
    2,
)
ext_numbers = ValueSet( # more numbers
    0x00_00_00_03,
    0x00_00_00_09, 
    0x00_00_00_0A, # 10
    0x00_00_00_0B, # 11
    0x00_00_00_0F, # 15
)
negative32 = ValueSet(
    0xFF_FF_FF_FF, #-1 (negative numbers)
#    0xFF_FF_FF_FE, #-2
)
negative16 = ValueSet(
    0x00_00_FF_FF, # -1 - 16 bit
#    0x00_00_FF_FE, # -2 - 16 bit
)
negative8 = ValueSet(
    0x00_00_00_FF, # -1 -  8 bit
#    0x00_00_00_FE, # -2 -  8 bit
)
bit_patterns = ValueSet(
    0xAA_AA_AA_AA, # 1010 bit patterns
    0x55_55_55_55, # 0101
    0xFF_FF_FF_FF,
    0x00_00_00_00,
    0x78_9A_BC_DE, # odd parity, bytes are recognizable
)
carry_overflow32 = ValueSet(
    0xFF_FF_FF_FF, # dword carry/overflow
    0x7F_FF_FF_FF,
    0x80_00_00_00,
    0x80_00_00_01,
)
carry_overflow16 = ValueSet(
    0x00_00_FF_FF, # word carry/overflow
    0x00_00_7F_FF,
    0x00_00_80_00,
    0x00_00_80_01,
)
carry_overflow8 = ValueSet(
    0x00_00_00_FF, # byte carry/overflow
    0x00_00_00_7F,
    0x00_00_00_80,
    0x00_00_00_81,
)
carry_overflow4 = ValueSet(
    0x00_00_00_0F, # nibble carry/overflow
    0x00_00_00_07,
    0x00_00_00_08,
    0x00_00_00_09,
)
mask = ValueSet(
    0xFF_FF_00_00, # word mask
    0x00_00_FF_FF,
    0xFF_FF_FF_00, # byte mask
    0x00_00_00_FF,
    0xFF_FF_FF_F0, # nibble mask
    0x00_00_00_0F,
)
memory_offsets = ValueSet(
    0x00_00_03_F4, # 32-bit aligned
    0x00_00_00_C5, # prime 197
)

# (basic,)
# basic
arithmetic_values = (
    (basic*basic)
    + (one + negative32)*(numbers + ext_numbers + carry_overflow32 + carry_overflow8)
    + (bit_patterns)
)
bit_values = bit_patterns
mov_values = basic


def get_addressing_modes():
    opcode = b'\x03'
    result = []
    # for all modrm possibilities
    for modrm in range(256):
        # get all address_code possibitilities, including sib if applicable
        has_sib = ((modrm & 0b111 == 4) and ((modrm>>6) & 0b11 != 0b11))
        if has_sib:
            address_codes = [bytes([modrm, sib]) for sib in range(256)]
        else:
            address_codes = [bytes([modrm])]
        # for all the resulting address codes
        for address_code in address_codes:
            # create dummy instruction and dissassembly to find ops
            bytestring = opcode + address_code + (15*b'\0')
            _, num_bytes, instr, _ = distorm3.Decode(0, bytestring, distorm3.Decode32Bits)[0]
            op1, op2 = instr[3:].strip().split(', ')
            # extract / parse info
            disp_num_bytes = num_bytes - 2 - has_sib
            if op2[0] == '[':
                groups = re.match(r'\[(?P<b>...)(\+(?P<i>...))?(\*(?P<s>[248]))?(\+0x0)?\]',
                                  op2).groupdict()
                op2_dict = {
                    'type':  'mem',
                    'base':  groups['b'].lower(),
                    'index': groups['i'].lower() if groups['i'] is not None else None,
                    'scale': int(groups['s'] or '1'),
                    'disp':  disp_num_bytes*8,
                }
            else:
                op2_dict = {
                    'type': 'reg',
                    'reg': op2.lower(),
                }
            info = {
                'address_code': address_code,
                'has_sib': has_sib,
                'op1': op1.lower(),
                'op2': op2_dict,

            }
            result.append(info)
            print('ops', op1, ':', op2, 'res', info)
    return result

            


#### writing out tests #############################################################################
class TestWriter:
    def __init__(self, name):
        global TEST_WRITER_COUNTER
        self.name = filename = '%04d-%s' % (TEST_WRITER_COUNTER, name)
        self.results = []
        TEST_WRITER_COUNTER += 1

    def add_opcodes(self, bytestring, testname=None, heapsize=DEFAULT_HEAP_SIZE,
                    initialize_stack=True, append_int3=True):
        self.code_instructions(bytes_to_code(bytestring),
                               testname=testname,
                               heapsize=heapsize,
                               initialize_stack=initialize_stack,
                               append_int3=append_int3)
        
    def add_instructions(self, instructions, testname=None, heapsize=DEFAULT_HEAP_SIZE,
                         initialize_stack=True, append_int3=True):
        if testname is None:
            testname = "-".join(instr[ :instr.find(';') ].strip() # remove comment
                                for instr in instructions.split("\n"))
        self.add_code(
            code_for_instructions(instructions,
                                  heapsize=heapsize,
                                  initialize_stack=initialize_stack,
                                  append_int3=append_int3
            ),
            testname=testname
        )
    
    
    def add_code(self, code, testname=''):
        self.results.append(
            run_code(code, self.name + ("-%04d-%s" % (len(self.results), testname)))
        )
    
    
    def close(self):
        pathlib.Path(OUT_DIR).mkdir(exist_ok=True) # ensure outdir exists
        result = collections.OrderedDict()
        result['name'] = self.name
        result['tests'] = self.results
        filename = path.join(OUT_DIR, self.name + '.json')
        with open(filename, 'w') as f:
            json.dump(result, f, indent=2)
        num_tests = len(result['tests'])
        print(f'wrote out {num_tests} tests in file {filename}')


#### assemble/run/record ###########################################################################
#assemble, link and run the given assembly code, return result object
def run_code(code, test_name = "n/a", test_code=None, verbose=True):
    result = OrderedDict()
    result['test_name'] = test_name
    result['test_code'] = ''
    result['elf_gzip_base64'] = ''

    if verbose: print("test:", test_name)
    
    # ensure temp directory exists
    pathlib.Path(f'{TEMP_DIR}').mkdir(parents=True, exist_ok=True) 
    
    # output code file
    with open(f'{TEMP_DIR}/test.s', 'w') as f:
        f.write(code)
    
    # compile, link
    def run(cmd):
        if verbose: print(cmd)
        result = subprocess.run(cmd, shell=True, capture_output=True)
        try:
            result.check_returncode()
        except subprocess.CalledProcessError as e:
            print(result.stdout)
            print(result.stderr)
            raise e
        return result
    run(f'nasm {TEMP_DIR}/test.s -f elf -o {TEMP_DIR}/test.o')
    run(f'ld   {TEMP_DIR}/test.o -S -Os -o {TEMP_DIR}/test --verbose \
                -Tbss 0x{BSS_ADDRESS:x}  -Tdata 0x{DATA_ADDRESS:x} -Ttext 0x{TEXT_ADDRESS:x}')
    #print(run(f'objdump -D {TEMP_DIR}/test').stdout.decode('utf-8'))
    # execute with gdb, collect data
    gdb_result = run(f'source/gdb-generate-test-output.sh {TEMP_DIR}/test').stdout.decode('utf-8')
    result.update(json.loads(gdb_result, object_pairs_hook=OrderedDict))    
    
    # remove empty registers
    registers = result['result_registers']
    for k, v in list(registers.items()):
        if int(v, 16) == 0:
            del registers[k]
    
    # strip, read and compress executable
    run(f'strip {TEMP_DIR}/test')
    with open(f'{TEMP_DIR}/test', 'rb') as f:
        exe = f.read()
    compressed_exe = gzip.compress(exe)
    result['elf_gzip_base64'] = base64.b64encode(compressed_exe).decode('utf-8')

    # read the memory
    with open(f'{TEMP_DIR}/memory.bin', 'rb') as f:
        memory = f.read()
    print('result memory', result['result_memory'])
    result['result_memory']['nonzeros'] = get_hex_dump(
        memory, int(result['result_memory']['start'], 16))
    
    # get instructions
    if test_code is not None:
        result['test_code'] = test_code
    else:
        instructions = code.split("; init stack")[1].strip()
        result['test_code'] = ';'.join(instr.strip() for instr in instructions.split('\n'))
    
    result_string = (json.dumps(result, indent=2))
    if verbose:
        print(result_string)
        print("length of result:", len(result_string))
        print()
    return result



def get_hex_dump(bytestring, offset=0):
    LINE_SIZE = 8
    assert offset % LINE_SIZE == 0
    result = collections.OrderedDict()
    for i in range(0, len(bytestring), LINE_SIZE):
        line = bytestring[i : i+8]
        if any(line):
            address = offset + i
            result['0x%08x' % address] = ' '.join('%02x' % c for c in line)
    return result


##### MAIN #########################################################################################
if __name__ == "__main__":
    generate_tests()




    
