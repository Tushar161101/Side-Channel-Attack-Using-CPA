import numpy as np
import sys
import os
import itertools


# CONSTANTS
SBOX = np.array([
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
], dtype=np.uint8)

PBOX = [
    0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
    4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
    8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
    12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63
]

HW = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)


# BYTE-WISE CPA (Top-2 Candidates Per Byte)
def recover_round_key_candidates(pt, traces):

    N = pt.shape[0]

    traces = traces.astype(np.float64)
    traces_centered = traces - np.mean(traces, axis=0)
    traces_std = np.std(traces, axis=0) + 1e-12

    byte_candidates = []

    for byte_index in range(8):

        plaintext_byte = pt[:, byte_index]
        scores = []

        for key_guess in range(256):

            x = plaintext_byte ^ key_guess

            # PRESENT SBOX nibble-wise
            high = SBOX[(x >> 4) & 0xF]
            low  = SBOX[x & 0xF]
            sbox_out = (high << 4) | low

            leakage = HW[sbox_out]

            leakage_centered = leakage - np.mean(leakage)
            leakage_std = np.std(leakage)

            if leakage_std < 1e-12:
                continue

            numerator = leakage_centered @ traces_centered
            denominator = N * leakage_std * traces_std
            corr = numerator / denominator

            score = np.max(np.abs(corr))
            scores.append((key_guess, score))

        scores.sort(key=lambda x: -x[1])

        # Store top-2 candidates
        byte_candidates.append([scores[0][0], scores[1][0]])

    return byte_candidates


# PRESENT ENCRYPTION (80-bit)
def sbox_layer(state):
    result = 0
    for i in range(16):
        nib = (state >> (4*i)) & 0xF
        result |= int(SBOX[nib]) << (4*i)
    return result

def pbox_layer(state):
    result = 0
    for i in range(64):
        if (state >> i) & 1:
            result |= 1 << PBOX[i]
    return result

def generate_round_keys(master_key):
    keys = []
    mask = (1 << 80) - 1
    K = master_key & mask

    for r in range(1, 33):
        keys.append(K >> 16)

        # rotate left by 61
        K = ((K << 61) | (K >> 19)) & mask

        # SBOX on MSB nibble
        msb = (K >> 76) & 0xF
        K &= ~(0xF << 76)
        K |= int(SBOX[msb]) << 76

        # XOR round counter
        K ^= (r & 0x1F) << 15

    return keys

def present_encrypt(plaintext, master_key):
    state = plaintext
    round_keys = generate_round_keys(master_key)

    for i in range(31):
        state ^= round_keys[i]
        state = sbox_layer(state)
        state = pbox_layer(state)

    state ^= round_keys[31]
    return state


# MASTER KEY RECOVERY
def recover_master_key(round_key_bytes, pt, ct):

    round_key_int = int.from_bytes(round_key_bytes, byteorder='big')

    num_checks = min(3, len(pt))
    plaintexts = [int.from_bytes(bytes(pt[i]), 'big') for i in range(num_checks)]
    ciphertexts = [int.from_bytes(bytes(ct[i]), 'big') for i in range(num_checks)]

    for last16 in range(1 << 16):

        master_key = (round_key_int << 16) | last16

        valid = True
        for i in range(num_checks):
            if present_encrypt(plaintexts[i], master_key) != ciphertexts[i]:
                valid = False
                break

        if valid:
            return master_key

    return None


# MINIMAL SWAP SEARCH (Rank-2 Only)
def find_master_with_swaps(byte_candidates, pt, ct, max_swaps=2):

    # Base key: all rank-1 guesses
    base = [c[0] for c in byte_candidates]

    # Try base first
    round_key = bytes(base)
    master_key = recover_master_key(round_key, pt, ct)
    if master_key is not None:
        return round_key, master_key

    # Try swaps
    for swaps in range(1, max_swaps + 1):

        for positions in itertools.combinations(range(8), swaps):

            candidate = base.copy()

            for pos in positions:
                candidate[pos] = byte_candidates[pos][1]  # rank-2 guess

            round_key = bytes(candidate)
            master_key = recover_master_key(round_key, pt, ct)

            if master_key is not None:
                return round_key, master_key

    return None, None


# MAIN
def main():

    if len(sys.argv) != 4:
        print("Usage: python CS25M052.py plaintexts.npy traces.npy ciphertexts.npy")
        sys.exit(1)

    pt_file = sys.argv[1]
    traces_file = sys.argv[2]
    ct_file = sys.argv[3]

    if not (os.path.exists(pt_file) and os.path.exists(traces_file) and os.path.exists(ct_file)):
        print("One or more input files not found.")
        sys.exit(1)

    pt = np.load(pt_file).astype(np.uint8)
    traces = np.load(traces_file)
    ct = np.load(ct_file).astype(np.uint8)

    if pt.shape[0] != traces.shape[0] or pt.shape != ct.shape:
        print("Input files have mismatched shapes.")
        sys.exit(1)

    byte_candidates = recover_round_key_candidates(pt, traces)
    round_key, master_key = find_master_with_swaps(byte_candidates, pt, ct, max_swaps=2)

    if master_key is None:
        print("Master key not found.")
        sys.exit(1)

    print("\n===== FINAL RESULT =====")
    print("Round Key :", round_key.hex().upper())
    print("Master Key:", format(master_key, "020X"))

if __name__ == "__main__":
    main()