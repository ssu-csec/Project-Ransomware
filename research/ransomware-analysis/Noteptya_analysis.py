import argparse
import struct
import udmp_parser
import logging
import sys
import pathlib
from typing import Optional
from binascii import hexlify

logging.getLogger().setLevel(logging.INFO)


def p32(a) -> bytes:
    return struct.pack("<I", a)


def u32(a) -> int:
    return struct.unpack("<I", a)[0]


def read_memory(dmp: udmp_parser.UserDumpParser, addr: int, size: int) -> bytearray:
    data = dmp.ReadMemory(addr, size)
    assert data
    return bytearray(data)


def previous_frame(dmp: udmp_parser.UserDumpParser, current_ebp: int, depth: int):
    while depth > 0:
        previous_ebp_addr = read_memory(
            dmp, addr=current_ebp, size=4
        )  # change to right size
        previous_ebp = u32(previous_ebp_addr[0:4])
        current_ebp = previous_ebp
        depth -= 1
    return previous_ebp


def parse_dump(minidumpfile: str, thread_id: int) -> Optional[bytearray]:
    dmp = udmp_parser.UserDumpParser()
    assert dmp.Parse(minidumpfile)

    #
    # Find the right thread
    #
    threads: list[udmp_parser.Thread_t] = dmp.Threads()
    thread: Optional[udmp_parser.Thread_t] = None
    if thread_id not in threads:
        logging.error(f"Cannot find thread {thread_id}")
        return

    thread = threads[thread_id]
    assert thread is not None
    logging.info(f"Found {thread=}")

    #
    # Go to previous frame
    #
    ebp = previous_frame(dmp, current_ebp=thread.Context.Rbp, depth=2)

    #
    # Retrieve the session context
    #
    custom_struct_addr = read_memory(dmp, addr=ebp + 3 * 4, size=4)
    custom_struct_addr = u32(custom_struct_addr[0:4])
    custom_struct = read_memory(dmp, addr=custom_struct_addr, size=0x20)
    logging.info(f"session context is at {custom_struct_addr:#x}")

    #
    # Get the `hcryptkey` at offset 0x14
    #
    hcryptkey_struct_addr = u32(custom_struct[0x14:0x18])
    hcryptkey_struct = read_memory(dmp, addr=hcryptkey_struct_addr, size=128)
    logging.info(f"hCryptContext is at {hcryptkey_struct_addr:#x}")

    #
    # Decode the AES structure pointer
    #
    magic_s_addr = u32(hcryptkey_struct[0x2C:0x30]) ^ 0xE35A172C
    magic_s_struct = read_memory(dmp, addr=magic_s_addr, size=128)

    key_data_s_struct_addr = u32(magic_s_struct[0x00:0x04])
    key_data_s_struct = read_memory(dmp, addr=key_data_s_struct_addr, size=128)
    logging.info(f"AES structure is at {key_data_s_struct_addr:#x}")

    #
    # Finally extract the AES-CBC key
    #
    aes_key_addr = u32(key_data_s_struct[0x10:0x14])
    aes_key = read_memory(dmp, addr=aes_key_addr, size=16)
    return aes_key


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NotPetya dump extractor/decryptor based on minidumps (onweek POC)"
    )
    parser.add_argument(
        "minidumpfile", help="path to the minidump file", type=pathlib.Path
    )
    parser.add_argument(
        "--thread-id",
        dest="thread_id",
        help="Thread ID that triggered the alert",
        type=lambda x: int(x, 0),
    )

    args = parser.parse_args()
    aes_key = parse_dump(args.minidumpfile, args.thread_id)
    if not aes_key:
        logging.error("Failed to retrieve the key")
        sys.exit(1)

    logging.info(f"AES key: {hexlify(aes_key).decode()}")
