#!/usr/bin/env python3

import os, argparse, re, random, struct
from tqdm import tqdm
from aes import *

def validate_key(key):
    if re.fullmatch(r"[0-9a-fA-F]{32}", key):
        return key
    raise argparse.ArgumentTypeError("AES key must be a 32-character hexadecimal string")

parser = argparse.ArgumentParser(prog="simaes", description="simulate AES encryption for SIFA")
parser.add_argument("output", help="output file to store ineffective faults")
parser.add_argument("-s", "--samples", type=int, default=1000, help="number of samples to collect")
parser.add_argument("-k", "--key", type=validate_key, default="cafebabe01020304feeeeeedfaaaaace", help="default aes key is cafebabe01020304feeeeeedfaaaaace")
parser.add_argument("-r", "--round", type=int, default=9, choices=[2, 9, 10], help="round to inject fault into")
parser.add_argument("-i", "--index", type=int, default=0, choices=range(0, 16), help="which byte in the AES state to inject fault into")
parser.add_argument("-t", "--type", type=str, default="and", choices=["rand", "flip", "and", "zero", "one"], help="type of fault: random, bit flip, random and, stuck at zero, stuck at one. paper section 3.1, FDT needs to produce bias")
parser.add_argument("-b", "--bits", type=int, default=4, choices=range(1, 9), help="bit width for fault, starts from lsb")
parser.add_argument("-v", "--verbose", action="store_true")
args = parser.parse_args()

testkey = bytes.fromhex(args.key)

def inject_fault(state):
    i = args.index // 4
    j = args.index % 4
    r = random.randint(0, (1 << args.bits) - 1)
    if args.type == "rand":
        state[i][j] = r
    elif args.type == "flip":
        state[i][j] ^= r
    elif args.type == "and":
        state[i][j] &= r
    elif args.type == "zero":
        state[i][j] &= ~((1 << args.bits) - 1)
    elif args.type == "one":
        state[i][j] |= (1 << args.bits) - 1

def aes_forward(roundkeys, plaintext, fault=False, round=9):
    state = []
    for i in range(keywords):
        state.append([plaintext[(i * 4) + 0], plaintext[(i * 4) + 1], plaintext[(i * 4) + 2], plaintext[(i * 4) + 3]])
    
    add_round_key(state, roundkeys[0])

    for i in range(1, numrounds):
        if fault and i == round:
            inject_fault(state)
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, roundkeys[i])

    # this is not like the paper, but reduces search space
    if fault and round == 10:
        inject_fault(state)

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, roundkeys[-1])

    ciphertext = b""
    for i in range(keywords):
        for j in range(4):
            ciphertext += state[i][j].to_bytes()

    return ciphertext

def aes_backward(roundkeys, ciphertext):
    state = []
    for i in range(keywords):
        state.append([ciphertext[(i * 4) + 0], ciphertext[(i * 4) + 1], ciphertext[(i * 4) + 2], ciphertext[(i * 4) + 3]])

    add_round_key(state, roundkeys[-1])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    for i in range(numrounds - 1, 0, -1):
        add_round_key(state, roundkeys[i])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    add_round_key(state, roundkeys[0])

    plaintext = b""
    for i in range(keywords):
        for j in range(4):
            plaintext += state[i][j].to_bytes()

    return plaintext

# test cipher
# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
tv_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
assert aes_forward(key_schedule(tv_key), bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")) == bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
assert aes_backward(key_schedule(tv_key), bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")) == bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

def generate_bias_ciphertexts(key, number_samples):
    roundkeys = key_schedule(key)

    if args.verbose:
        print("round keys")
        for roundkey in roundkeys:
            for i in range(4): print(bytes(roundkey[i]).hex(), end="")
            print()

    plaintexts, ciphertexts = [], []
    ineffective = 0

    for i in tqdm(range(number_samples)):
        plaintext = os.urandom(16)
        ctext = aes_forward(roundkeys, plaintext)
        ftext = aes_forward(roundkeys, plaintext, fault=True, round=args.round)
        if ctext == ftext:
            plaintexts.append(plaintext)
            ciphertexts.append(ftext)
            ineffective += 1

    return plaintexts, ciphertexts, ineffective

if args.verbose:
    print(f"injecting faults into {args.round}th round")
    print(f"index '{args.index}' type '{args.type}' bits '{args.bits}'")

plaintexts, ciphertexts, ineffective = generate_bias_ciphertexts(testkey, args.samples)

if args.verbose:
    print(f"{ineffective} ineffective faults")
    print(f"{ineffective / args.samples * 100:0.2f}% hit rate")

# TODO: maybe document this format?
with open(args.output, "wb") as fp:
    fp.write(struct.pack("<L", ineffective))
    for i in range(ineffective):
        fp.write(plaintexts[i])
        fp.write(ciphertexts[i])
