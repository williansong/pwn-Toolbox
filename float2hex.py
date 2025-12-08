#!/usr/bin/env python3
import struct
import sys

def main():
    if len(sys.argv) != 2:
        print("Usage: python float2hex.py <float_value>")
        print("Example: python float2hex.py 0.1")
        return

    try:
        f = float(sys.argv[1])
    except ValueError:
        print(f"Error: '{sys.argv[1]}' is not a valid floating-point number.")
        return

    # 小端 (little-endian) - x86/x64 栈布局常用
    little_bytes = struct.pack('<d', f)
    little_hex = '0x' + little_bytes.hex().upper()

    # 大端 (big-endian)
    big_bytes = struct.pack('>d', f)
    big_hex = '0x' + big_bytes.hex().upper()

    def bytes_to_escaped(b):
        return ''.join(f'\\x{byte:02x}' for byte in b)

    print(f"\nFloat value: {f}")
    print("=" * 60)
    print("Little-endian (x86/x64 stack layout, commonly used in CTF):")
    print(f"  Hex integer: {little_hex}")
    print(f"  Raw bytes  : {little_bytes!r}")
    print(f"  \\x format   : {bytes_to_escaped(little_bytes)}")

    print("\nBig-endian (network order / some embedded systems):")
    print(f"  Hex integer: {big_hex}")
    print(f"  Raw bytes  : {big_bytes!r}")
    print(f"  \\x format   : {bytes_to_escaped(big_bytes)}")
    print("=" * 60)

if __name__ == '__main__':
    main()