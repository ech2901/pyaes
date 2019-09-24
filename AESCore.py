from Field import GF, sbox, invsbox, modulus

# TODO comment code
# TODO create docstrings
# TODO format according to PEP 8

def encrypt_128(state, key):

    state = addroundkey(state, next(key))

    for _ in range(9):
        state = subbytes(state)
        state = shiftrows(state)
        state = mixcolumns(state)
        state = addroundkey(state, next(key))

    state = subbytes(state)
    state = shiftrows(state)
    state = addroundkey(state, next(key))

    return state

def decrypt_128(state, key):

    state = addroundkey(state, next(key))
    state = invshiftrows(state)
    state = invsubbytes(state)

    for _ in range(9):
        state = addroundkey(state, next(key))
        state = invmixcolumns(state)
        state = invshiftrows(state)
        state = invsubbytes(state)

    state = addroundkey(state, next(key))

    return state

def encrypt_192(state, key):

    state = addroundkey(state, next(key))

    for _ in range(11):
        state = subbytes(state)
        state = shiftrows(state)
        state = mixcolumns(state)
        state = addroundkey(state, next(key))

    state = subbytes(state)
    state = shiftrows(state)
    state = addroundkey(state, next(key))

    return state

def decrypt_192(state, key):

    state = addroundkey(state, next(key))
    state = invshiftrows(state)
    state = invsubbytes(state)

    for _ in range(11):
        state = addroundkey(state, next(key))
        state = invmixcolumns(state)
        state = invshiftrows(state)
        state = invsubbytes(state)

    state = addroundkey(state, next(key))

    return state

def encrypt_256(state, key):

    state = addroundkey(state, next(key))

    for _ in range(13):
        state = subbytes(state)
        state = shiftrows(state)
        state = mixcolumns(state)
        state = addroundkey(state, next(key))

    state = subbytes(state)
    state = shiftrows(state)
    state = addroundkey(state, next(key))

    return state

def decrypt_256(state, key):

    state = addroundkey(state, next(key))
    state = invshiftrows(state)
    state = invsubbytes(state)

    for _ in range(13):
        state = addroundkey(state, next(key))
        state = invmixcolumns(state)
        state = invshiftrows(state)
        state = invsubbytes(state)

    state = addroundkey(state, next(key))

    return state


def addroundkey(state, roundKey):
    out = []
    for s_item, k_item in zip(state, roundKey):
        out.append(s_item ^ k_item)
    return out


def subbytes(state):
    out = []
    for item in state:
        out.append(sbox(item))
    return out


def invsubbytes(state):
    out = []
    for item in state:
        out.append(invsbox(item))
    return out


def shiftrows(state):
    out = []
    for i in range(0, 13, 4):
        for j in range(0, 16, 5):
            out.append(state[(j+i) % 16])
    return out


def invshiftrows(state):
    out = []
    for i in [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]:
        out.append(state[i])
    return out


def mixcolumns(state):
    def mul_round(vals, arr):
        round_out = GF(0)
        for val, item in zip(vals, arr):
            round_out = val.mul(item, modulus) ^ round_out
        arr.insert(0, arr.pop())
        return round_out, arr

    out = []
    arr = [GF(2), GF(3), GF(1), GF(1)]

    for i in range(0, 16, 4):
        for _ in range(4):
            round_out, arr = mul_round(state[i:i+4], arr)
            out.append(round_out)
    return out

def invmixcolumns(state):
    def mul_round(vals, arr):
        round_out = GF(0)
        for val, item in zip(vals, arr):
            round_out = val.mul(item, modulus) ^ round_out
        arr.insert(0, arr.pop())
        return round_out, arr

    out = []
    arr = [GF(14), GF(11), GF(13), GF(9)]

    for i in range(0, 16, 4):
        for _ in range(4):
            round_out, arr = mul_round(state[i:i+4], arr)
            out.append(round_out)
    return out



