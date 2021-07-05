from SHAConstants import IV
from SHAConstants import K
from SHAConstants import ex1, ex2, ex3

# function to convert a string to hex
def str_to_hex(some_string):
    string_hex = []
    for c in some_string:
        string_hex.append(hex(ord(c))[2:])
    return string_hex

#function to xor binary
def xor(b1, b2):
    b1_int = int('0b' + b1, 2)
    b2_int = int('0b' + b2, 2)
    
    res_int = b1_int ^ b2_int
    res = bin(res_int)[2:].zfill(32)
    return res

def xor_int(b1, b2):
    res_int = b1 ^ b2
    res = bin(res_int)[2:].zfill(32)
    return res

# converts a hex string to an integer
def hex_to_int(s_string):
    hex_val = "0x" + s_string
    an_integer = int(hex_val, 16)
    return an_integer

def bin_to_hex(w_bin):
    # split word into 8 bit blocks
    w_bin_list = slice_p(w_bin, 8)
    # convert to hex 
    for i in range(len(w_bin_list)):
        temp = int(('0b' + w_bin_list[i]), 2)
        w_bin_list[i] = hex(temp)[2:]
        if (len(hex(temp)[2:]) == 1):
            w_bin_list[i] = '0' + hex(temp)[2:]
    return w_bin_list



#bitwise rotation right function
def rotation_right(word):
    rotated = list(word)
    temp = rotated [len(rotated) - 1]
    for x in reversed(range (len(rotated))):
        if (x == 0):
            rotated[x] = temp
        else:
            rotated[x] = rotated[x - 1] 
    return (''.join([str(elem) for elem in rotated]))

# right rotation
def rotate_word(word, degree):
    for _ in range(degree):
        word = rotation_right(word) 
    return word

# right shift 
def shift_word(word, degree):
    word_int = int('0b' + word, 2)
    return bin(word_int>>degree)[2:].zfill(32)

# convert string to binary
def str_to_bin(some_string):
    byte_array = bytearray(some_string, "utf8")
    str_bin = ""
    
    for byte in byte_array:
        binary_representation = format(byte, '08b')
        str_bin += binary_representation
    
    return str_bin


def pad(plain_bin):
    # get length of p
    L = len(plain_bin)

    # add 1 bit
    plain_bin += '1'

    # calculate multiple of 512 so that 
    # this multiple is our padded plaintext message
    L_temp = L + 1 + 64
    L_pad = L_temp // 512
    mult512 = (L_pad + 1) * 512
    
    # calculate k from the obtained multiple
    k = mult512 - L_temp
    # add k 0s
    for _ in range(k):
        plain_bin += '0'

    # add length of plaintext L as a 64 bit integer
    # convert length to 64bit binary value
    L_bin = bin(L)[2:].zfill(64)
    plain_bin += L_bin

    return plain_bin

# split plaintext into blocks of block_size
def slice_p(p_bin, block_size):
    p_blocks = []
    block = ''
    count = 0
    for i in range (len(p_bin)):
        # add bit to blocks until block_size bits have been added
        block += p_bin[i]
        count += 1
        if (count == block_size):
            p_blocks.append(block)
            # reset block
            block = ''
            # reset count
            count = 0
    return p_blocks

def mod32_add(x1, x2):
    # convert x1 and x2 to integer
    x1_int = int('0b' + x1, 2)
    x2_int = int('0b' + x2, 2)

    # modulo 2^32 addition
    res = (x1_int + x2_int) % (2**32)
    res_bin = bin(res)[2:].zfill(32)
    return res_bin

def bin_to_int(binary_txt):
    return int('0b' + binary_txt, 2)

def SHA_box(h, block):
    # split the plaintext block into 32 bit words
    l_words = slice_p(block, 32)

    # obtain the rest of the 64 words
    for i in range(16, 64):
        # obtain s0 and s1
        s0 = xor(rotate_word(l_words[i - 15], 7), rotate_word(l_words[i - 15], 18))
        s0 = xor(s0, shift_word(l_words[i - 15], 3))
        s1 = xor(rotate_word(l_words[i - 2], 17), rotate_word(l_words[i - 2], 19))
        s1 = xor(s1, shift_word(l_words[i - 2], 10))

        z1 = mod32_add(l_words[i - 16], s0)
        z2 = mod32_add(l_words[i - 7], s1)
        wi = mod32_add(z1, z2)
        l_words.append(wi)

    # initialize h from IV or previous h 
    h_list = []
    for el in h:
        h_list.append(bin(el)[2:].zfill(32))

    # compression function
    # a, b, c, d, e, f, g, h
    # 0, 1, 2, 3, 4, 5, 6, 7
    alph_list = []
    for el in h:
        alph_list.append(bin(el)[2:].zfill(32))

    # initialize K from file
    K_list = []
    for el in K:
        K_list.append(bin(el)[2:].zfill(32))
    

    for i in range(64):
        X11 = xor(rotate_word(alph_list[4], 6), rotate_word(alph_list[4], 11))
        # X1
        X1 = xor(X11, rotate_word(alph_list[4], 25))
        # CH
        CH = xor_int(bin_to_int(alph_list[4]) & bin_to_int(alph_list[5]), ~(bin_to_int(alph_list[4])) & bin_to_int(alph_list[6]))
        # X2
        X2 = xor(xor(rotate_word(alph_list[0], 2), rotate_word(alph_list[0], 13)), rotate_word(alph_list[0], 22))
        # MAJ = (a and b) xor (a and c) xor (b and c)
        MAJ1 = xor_int((bin_to_int(alph_list[0]) & bin_to_int(alph_list[1])), (bin_to_int(alph_list[0]) & bin_to_int(alph_list[2])))
        MAJ1 = int('0b' + MAJ1, 2)
        MAJ = xor_int(MAJ1, (bin_to_int(alph_list[1]) & bin_to_int(alph_list[2])))
        # temp1 :=h + X1 + CH + Ki + Wi
        z1 = mod32_add(alph_list[7], X1)
        z2 = mod32_add(z1, CH)
        z3 = mod32_add(z2, K_list[i])
        temp1 = mod32_add(z3, l_words[i])
        temp2 = mod32_add(X2, MAJ)
        # h = g
        alph_list[7] = alph_list[6]
        # g = f
        alph_list[6] = alph_list[5]
        # f = e
        alph_list[5] = alph_list[4]
        # e = d + temp1
        alph_list[4] = mod32_add(alph_list[3], temp1)
        # d = c
        alph_list[3] = alph_list[2]
        # c = b
        alph_list[2] = alph_list[1]
        # b = a
        alph_list[1] = alph_list[0]
        # a = temp1 + temp2
        alph_list[0] = mod32_add(temp1, temp2)

    # obtain new_h values
    new_h = []
    for i in range (len(alph_list)):
        new_h.append(mod32_add(h_list[i], alph_list[i]))
    
    return new_h  
        
def SHA256(plaintext):
    # convert plaintext to binary
    p_bin = str_to_bin(plaintext)
    # Step 1: padding
    p_pad = pad(p_bin)

    # Step 2: Merkle - Damgard
    # slice the plaintext into 512 bit blocks
    p_blocks = slice_p(p_pad, 512)

    # use SHA_box to obtain cipher
    # initial h
    h = SHA_box(IV, p_blocks[0])
    # go through all other plaintext blocks
    for i in range(1, len(p_blocks)):
        for k in range(len(h)):
            h[k] = int('0b' + h[k], 2)
        h = SHA_box(h, p_blocks[i])

    h_string = ''
    for item in h:
        h_string += item

    hash_list = bin_to_hex(h_string)

    hashstring = ''
    for item in hash_list:
        hashstring += item

    return hashstring


# copied from the pdf for test purposes
# For the empty string ””, you should obtain the following hash
pdf1 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
# ”Welcome to Wrestlemania!”
pdf2 = '70eeb26f0052ebe0041e58d221e954c575f32a979cefdae7b761969e33b7934f'
# ”Fight for your dreams, and your dreams will fight for you!”
pdf3 = '31bba5997ae84193407798293636745b88d0126146fd105aa96e599c5f197714'

print(SHA256(ex1))
if (SHA256(ex1) == pdf1):
    print('hashstrings are equal')
else:
    print('hashstrings are not equal')

print(SHA256(ex2))
if (SHA256(ex2) == pdf2):
    print('hashstrings are equal')
else:
    print('hashstrings are not equal')

print(SHA256(ex3))
if (SHA256(ex3) == pdf3):
    print('hashstrings are equal')
else:
    print('hashstrings are not equal')


