#include "SimpleTinyAes.h"

#include <string.h> // CBC mode, for memset


const uint8_t SimpleTinyAes::rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


const uint8_t SimpleTinyAes::rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };


const uint8_t SimpleTinyAes::sbox[256] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };



SimpleTinyAes::SimpleTinyAes(AES_TYPE type)
{
    this->aesType = type;
    switch (type)
    {
    case AES_TYPE::AES128:
        nk = 4; nr = 10;
        keyLength = 16;
        keyExpSize = 176;
        break;
    case AES_TYPE::AES192:
        nk = 6; nr = 12;
        keyLength = 24;
        keyExpSize = 208;
        break;
    case AES_TYPE::AES256:
    default:
        nk = 8; nr = 14;
        keyLength = 32;
        keyExpSize = 240;
        break;
    }
}

void SimpleTinyAes::initCtx(const uint8_t *key)
{
    ctx.roundKey.resize(keyExpSize);
    keyExpansion(ctx.roundKey.data(), key);
}

void SimpleTinyAes::initCtxIv(const uint8_t *key, const uint8_t *iv)
{
    ctx.roundKey.resize(keyExpSize);
    keyExpansion(ctx.roundKey.data(), key);
    ctx.iv.resize(BLOCK_LENGTH);
    memcpy (ctx.iv.data(), iv, BLOCK_LENGTH);
}

bool SimpleTinyAes::initCtx(const std::vector<uint8_t> &key)
{
    if(key.size() != keyLength)
    {
        return false;
    }

    initCtx(key.data());
    return true;
}

bool SimpleTinyAes::initCtxIv(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    if(key.size() != keyLength || iv.size() != BLOCK_LENGTH)
    {
        return false;
    }

    initCtx(key.data());
    ctx.iv = iv;
    return true;
}

void SimpleTinyAes::ecbEncrypt(uint8_t *buf)
{
    // The next function call encrypts the PlainText with the Key using AES algorithm.
    cipher((tiny_aes_state_t*)buf, ctx.roundKey.data());
}

void SimpleTinyAes::ecbDecrypt(uint8_t *buf)
{
    // The next function call decrypts the PlainText with the Key using AES algorithm.
    invCipher((tiny_aes_state_t*)buf, ctx.roundKey.data());
}

void SimpleTinyAes::cbcEncryptBuffer(uint8_t *buf, size_t length)
{
    size_t i;
    uint8_t *Iv = ctx.iv.data();
    for (i = 0; i < length; i += BLOCK_LENGTH)
    {
        xorWithIv(buf, Iv);
        cipher((tiny_aes_state_t*)buf, ctx.roundKey.data());
        Iv = buf;
        buf += BLOCK_LENGTH;
    }
    /* store Iv in ctx for next call */
    memcpy(ctx.iv.data(), Iv, BLOCK_LENGTH);
}

void SimpleTinyAes::cbcDecryptBuffer(uint8_t *buf, size_t length)
{
    size_t i;
    uint8_t storeNextIv[BLOCK_LENGTH];
    for (i = 0; i < length; i += BLOCK_LENGTH)
    {
        memcpy(storeNextIv, buf, BLOCK_LENGTH);
        invCipher((tiny_aes_state_t*)buf, ctx.roundKey.data());
        xorWithIv(buf, ctx.iv.data());
        memcpy(ctx.iv.data(), storeNextIv, BLOCK_LENGTH);
        buf += BLOCK_LENGTH;
    }
}

void SimpleTinyAes::ctrXcryptBuffer(uint8_t *buf, size_t length)
{
    uint8_t buffer[BLOCK_LENGTH];

    size_t i;
    int bi;
    for (i = 0, bi = BLOCK_LENGTH; i < length; ++i, ++bi)
    {
        if (bi == static_cast<int>(BLOCK_LENGTH)) /* we need to regen xor compliment in buffer */
        {
            memcpy(buffer, ctx.iv.data(), BLOCK_LENGTH);
            cipher((tiny_aes_state_t*)buffer,ctx.roundKey.data());

            /* Increment Iv and handle overflow */
            for (bi = (BLOCK_LENGTH - 1); bi >= 0; --bi)
            {
                /* inc will overflow */
                if (ctx.iv[bi] == 255)
                {
                    ctx.iv[bi] = 0;
                    continue;
                }
                ctx.iv[bi] += 1;
                break;
            }
            bi = 0;
        }

        buf[i] = (buf[i] ^ buffer[bi]);
    }
}

void SimpleTinyAes::xorWithIv(uint8_t *buf, const uint8_t *iv)
{
    uint8_t i;
    for (i = 0; i < BLOCK_LENGTH; ++i) // The block in AES is always 128bit no matter the key size
    {
        buf[i] ^= iv[i];
    }
}

void SimpleTinyAes::invCipher(tiny_aes_state_t *state, const uint8_t *roundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    addRoundKey(nr, state, roundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr rounds are executed in the loop below.
    // Last one without InvMixColumn()
    for (round = (nr - 1); ; --round)
    {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(round, state, roundKey);
        if (round == 0) {
            break;
        }
        invMixColumns(state);
    }
}

void SimpleTinyAes::cipher(tiny_aes_state_t *state, const uint8_t *roundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    addRoundKey(0, state, roundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr rounds are executed in the loop below.
    // Last one without MixColumns()
    for (round = 1; ; ++round)
    {
        subBytes(state);
        shiftRows(state);
        if (round == nr) {
            break;
        }
        mixColumns(state);
        addRoundKey(round, state, roundKey);
    }
    // Add round key to last round
    addRoundKey(nr, state, roundKey);
}

void SimpleTinyAes::invShiftRows(tiny_aes_state_t *state)
{
    uint8_t temp;

    // Rotate first row 1 columns to right
    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    // Rotate second row 2 columns to right
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}

void SimpleTinyAes::invSubBytes(tiny_aes_state_t *state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = rsbox[((*state)[j][i])];
        }
    }
}

void SimpleTinyAes::invMixColumns(tiny_aes_state_t *state)
{
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i)
    {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        (*state)[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        (*state)[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        (*state)[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

uint8_t SimpleTinyAes::multiply(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^
            ((y>>1 & 1) * xtime(x)) ^
            ((y>>2 & 1) * xtime(xtime(x))) ^
            ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
}

void SimpleTinyAes::mixColumns(tiny_aes_state_t *state)
{
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        t   = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
        Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
    }
}

uint8_t SimpleTinyAes::xtime(uint8_t x)
{
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

void SimpleTinyAes::shiftRows(tiny_aes_state_t *state)
{
    uint8_t temp;

    // Rotate first row 1 columns to left
    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left
    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

void SimpleTinyAes::subBytes(tiny_aes_state_t *state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = sbox[((*state)[j][i])];
        }
    }
}

void SimpleTinyAes::addRoundKey(uint8_t round, tiny_aes_state_t *state, const uint8_t *roundKey)
{
    uint8_t i,j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[i][j] ^= roundKey[(round * NB * 4) + (i * NB) + j];
        }
    }
}

void SimpleTinyAes::keyExpansion(uint8_t *roundKey, const uint8_t *key)
{
    if(nk == 0) return;

    unsigned i, j, k;
    uint8_t tempa[4]; // Used for the column/row operations

    // The first round key is the key itself.
    for (i = 0; i < nk; ++i)
    {
        roundKey[(i * 4) + 0] = key[(i * 4) + 0];
        roundKey[(i * 4) + 1] = key[(i * 4) + 1];
        roundKey[(i * 4) + 2] = key[(i * 4) + 2];
        roundKey[(i * 4) + 3] = key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = nk; i < NB * (nr + 1); ++i)
    {
        {
            k = (i - 1) * 4;
            tempa[0]=roundKey[k + 0];
            tempa[1]=roundKey[k + 1];
            tempa[2]=roundKey[k + 2];
            tempa[3]=roundKey[k + 3];
        }

        if (i % nk == 0)
        {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            {
                const uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
            }

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            {
                tempa[0] = sbox[tempa[0]];
                tempa[1] = sbox[tempa[1]];
                tempa[2] = sbox[tempa[2]];
                tempa[3] = sbox[tempa[3]];
            }

            tempa[0] = tempa[0] ^ rcon[i/nk];
        }

        if(aesType == AES_TYPE::AES256 && (i % nk == 4))
        {
            tempa[0] = sbox[tempa[0]];
            tempa[1] = sbox[tempa[1]];
            tempa[2] = sbox[tempa[2]];
            tempa[3] = sbox[tempa[3]];
        }

        j = i * 4; k=(i - nk) * 4;
        roundKey[j + 0] = roundKey[k + 0] ^ tempa[0];
        roundKey[j + 1] = roundKey[k + 1] ^ tempa[1];
        roundKey[j + 2] = roundKey[k + 2] ^ tempa[2];
        roundKey[j + 3] = roundKey[k + 3] ^ tempa[3];
    }
}
