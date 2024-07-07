import subprocess
from argparse import ArgumentParser
import sys
import os

def check_dependencies():
    """Ensure objdump is available"""
    return subprocess.getoutput("which objdump") != ''

def get_opcodes(filename, arch='elf'):
    """Extract opcodes from a binary file"""
    result = subprocess.getoutput(f"objdump -d {filename}")
    opcodes = ''
    for line in result.split('\n')[7:]:
        parts = line.split(':', 1)
        if len(parts) > 1:
            parts = parts[1].split('\t')
            if len(parts) > 1:
                code = parts[1].strip().replace(' ', '')
                if '<' not in code:
                    opcodes += code
    return opcodes

def format_shellcode(opcodes, width=8):
    """Format opcodes into shellcode"""
    formatted_bytes = ''.join([f"\\x{opcodes[i:i+2]}" for i in range(0, len(opcodes), 2)])
    return '\\x' + '\\x'.join([formatted_bytes[i:i+width*4] for i in range(0, len(formatted_bytes), width*4)])

def run(options):
    """Generate and print shellcode"""
    if options.inf:
        opcodes = get_opcodes(options.inf, options.arch)
        shellcode = format_shellcode(opcodes)
        print('[+] Encoded:\n', shellcode)
        if options.output:
            with open(options.output, 'w') as f:
                f.write(shellcode)

def parse_arguments():
    """Parse command line arguments"""
    parser = ArgumentParser()
    parser.add_argument('-f', help='Binary file', metavar='FILE', action='store', dest='inf')
    parser.add_argument('-o', help='Output file', action='store', dest='output')
    parser.add_argument('-a', help='Architecture [elf/elf64]', action='store', dest='arch', default='elf')

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()

if __name__ == "__main__":
    if not check_dependencies():
        print('[-] objdump is required')
        sys.exit(1)
    run(parse_arguments())
