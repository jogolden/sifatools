#!/usr/bin/env python3

import argparse, random, struct
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
from tqdm import tqdm
from aes import add_round_key, inv_mix_columns, inv_shift_rows, inv_sub_bytes

parser = argparse.ArgumentParser(prog="sifa", description="attack AES using SIFA")
parser.add_argument("input", help="input file for ineffective faults")
parser.add_argument("-s", "--samples", default=-1, help="how many samples to use from the input, default '-1' will use them all")
parser.add_argument("-a", "--attack", default=9, choices=[2, 9, 10], help="what round are you attacking? 9, 10 done from output. 10 is single byte. 2 is from input. 9 and 10 are 4 bytes (slow).")
parser.add_argument("-k", "--k", default=0, choices=range(4), help="what key byte group are you going after? see README")
parser.add_argument("-v", "--verbose", action="store_true")
args = parser.parse_args()

# TODO: maybe load one by one later instead of all into memory at the same time
plaintexts, ciphertexts, ineffective = [], [], 0
with open(args.input, "rb") as fp:
    ineffective = struct.unpack("<L", fp.read(4))[0]
    if args.verbose: print(f"loading {ineffective} ineffective faults")
    for i in range(ineffective):
        plaintexts.append(fp.read(16))
        ciphertexts.append(fp.read(16))

def partial_decrypt_10(ciphertext, keyguess):
    ps10 = []
    for i in range(4):
        ps10.append(list(ciphertext[i * 4:i * 4 + 4]))
    add_round_key(ps10, keyguess)
    inv_shift_rows(ps10)
    inv_sub_bytes(ps10)
    return ps10

def partial_decrypt_9(ciphertext, keyguess):
    ps9 = []
    for i in range(4):
        ps9.append(list(ciphertext[i * 4:i * 4 + 4]))
    add_round_key(ps9, keyguess)
    inv_shift_rows(ps9)
    inv_sub_bytes(ps9)
    inv_mix_columns(ps9)
    return ps9

def compute_sei(counts):
    p = counts / np.sum(counts)
    expected = 1.0 / 256.0 # expected uniform probability distribution
    sei = np.sum((p - expected) ** 2)
    return sei

# r10 key 8d8f26a0 b3a457c3 8d9b485e 392a9ca3

# round 9 state[0][0] <- faulted # looking at state[0][0]
# round 9 state[1][1] <- faulted # looking at state[0][1]
# round 9 state[2][2] <- faulted # looking at state[0][2]
# round 9 state[3][3] <- faulted # looking at state[0][3]
# [[0x8D, 0, 0, 0], [0, 0, 0, 0xC3], [0, 0, 0x48, 0], [0, 0x2A, 0, 0]]

# round 9 state[0][3] <- faulted # looking at state[1][3]
# round 9 state[1][0] <- faulted # looking at state[1][0]
# round 9 state[2][1] <- faulted # looking at state[1][1]
# round 9 state[3][2] <- faulted # looking at state[1][2]
# [[0, 0x8F, 0, 0], [0xB3, 0, 0, 0], [0, 0, 0, 0x5E], [0, 0, 0x9C, 0]]

# round 9 state[0][2] <- faulted # looking at state[2][2]
# round 9 state[1][3] <- faulted # looking at state[2][3]
# round 9 state[2][0] <- faulted # looking at state[2][0]
# round 9 state[3][1] <- faulted # looking at state[2][1]
# [[0, 0, 0x26, 0], [0, 0xA4, 0, 0], [0x8D, 0, 0, 0], [0, 0, 0, 0xA3]]

# round 9 state[0][1] <- faulted # looking at state[3][1]
# round 9 state[1][2] <- faulted # looking at state[3][2]
# round 9 state[2][3] <- faulted # looking at state[3][3]
# round 9 state[3][0] <- faulted # looking at state[3][0]
# [[0, 0, 0, 0xA0], [0, 0, 0x57, 0], [0, 0x9B, 0, 0], [0x39, 0, 0, 0]]

sei = np.zeros(256, dtype=np.float32)
test = np.zeros((256, ineffective), dtype=np.uint8)
for k in range(256):
    for i in range(ineffective):
        ps9 = partial_decrypt_9(ciphertexts[i], [[k, 0, 0, 0], [0, 0, 0, 0xC3], [0, 0, 0x48, 0], [0, 0x2A, 0, 0]])
        test[k][i] = ps9[0][0]
    sei[k] = compute_sei(np.bincount(test[k], minlength=256))
maxsei = np.argmax(sei)
print(hex(maxsei))

def print_matrix(matrix):
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            print(f"{matrix[i][j]:02X} ", end="")
        print()
    print()

# state = [[0xAA, 0, 0, 0],
#          [0, 0xBB, 0, 0],
#          [0, 0, 0xCC, 0],
#          [0, 0, 0, 0xDD]]
# state = [[0, 0, 0, 0xAA],
#          [0xBB, 0, 0, 0],
#          [0, 0xCC, 0, 0],
#          [0, 0, 0xDD, 0]]
# state = [[0, 0, 0xAA, 0],
#          [0, 0, 0, 0xBB],
#          [0xCC, 0, 0, 0],
#          [0, 0xDD, 0, 0]]
# state = [[0, 0xAA, 0, 0],
#          [0, 0, 0xBB, 0],
#          [0, 0, 0, 0xCC],
#          [0xDD, 0, 0, 0]]
# print_matrix(state)

# inv_shift_rows(state)
# # inv_sub_bytes(state)
# inv_mix_columns(state)
# print_matrix(state)

# plt.title(f"{ineffective} ineffective faults")
# plt.plot(sei)
# plt.show()

# fig, axs = plt.subplots(2, 5, figsize=(15, 6))

# keys_to_plot = [0x8F, 0x8D, np.argmax(sei), 234, 252, 182, 70, 100, 91, 26]

# for ax, key in zip(axs.flat, keys_to_plot):
#     ax.hist(test[key], bins=256, edgecolor="black", range=(0, 256))
#     ax.set_title(f"Distribution 0x{key:02X}")
#     ax.set_xlim(0, 256)

# plt.suptitle(f"Key Candidate Internal State Distributions")
# plt.tight_layout()
# plt.show()

# 367efe8b95575ee41dfe23f6da4e50ad
# 367efe8b95575ee41dfe23f6da4e50ad

# Now lets calculate backwards
# intermediate_candidates = np.zeros((256, ineffective), dtype=np.uint8)
# for key_candidate in range(256):
#     for i in range(ineffective):
#         C = ciphertexts[i][0]
#         I = (C ^ key_candidate) & 0xFF # add round key
#         # ignore inverse shift rows because our fault is focused on state[0][0], only columns 1, 2, 3 are impacted by SR
#         I = inv_sbox[I]
#         intermediate_candidates[key_candidate][i] = I

# counts = np.zeros((256, 256), dtype=np.float32)
# for key_candidate in range(256):
#     counts[key_candidate] = np.bincount(intermediate_candidates[key_candidate], minlength=256)

#     #hist, bin_edges = np.histogram(intermediate_candidates[key_candidate], bins=256, density=True)
#     #counts[key_candidate] = hist

# values = np.zeros(256, dtype=np.float32)
# for i in range(256):
#     values[i] = compute_sei(counts[i])

# plt.title(f"{ineffective} faults")
# plt.plot(values)
# plt.show()

# fig, axs = plt.subplots(2, 5, figsize=(15, 6))

# # need 10
# # 0x8D is the correct 10th round key 1st byte
# keys_to_plot = [0x8D]
# for i in range(10 - len(keys_to_plot)):
#     keys_to_plot += [random.randbytes(1)[0]]

# for ax, key in zip(axs.flat, keys_to_plot):
#     #counts = np.bincount(intermediate_candidates[key], minlength=256)
#     #ax.plot(counts)
#     ax.hist(intermediate_candidates[key], bins=256, edgecolor="black", range=(0, 256))
#     ax.set_title(f"Distribution 0x{key:02X}")
#     ax.set_xlim(0, 256)

# plt.suptitle(f"{ineffective} ineffective faults")
# plt.tight_layout()
# plt.show()

# candidates_sum = np.zeros(256)
# for i in range(256):
#     hist, bin_edges = np.histogram(intermediate_candidates[i], bins=256, density=True)
#     candidates_sum[i] = np.sum(hist)

# print(np.argmax(candidates_sum))
