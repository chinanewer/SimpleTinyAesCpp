#ifndef SIMPLETINYAES_H
#define SIMPLETINYAES_H

#include <cstdint>
#include <vector>

using tiny_aes_state_t = uint8_t[4][4];

class SimpleTinyAes
{
public:
    enum class AES_TYPE
    {
        AES128,
        AES192,
        AES256
    };

    struct AES_ctx
    {
        std::vector<uint8_t> roundKey;
        std::vector<uint8_t> iv;
    };

public:
    SimpleTinyAes(AES_TYPE type);

    void initCtx(const uint8_t* key);
    void initCtxIv(const uint8_t* key, const uint8_t* iv);

    bool initCtx(const std::vector<uint8_t>& key);
    bool initCtxIv(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

    void ecbEncrypt(uint8_t* buf);
    void ecbDecrypt(uint8_t* buf);

    void cbcEncryptBuffer(uint8_t* buf, size_t length);
    void cbcDecryptBuffer(uint8_t* buf, size_t length);

    void ctrXcryptBuffer(uint8_t* buf, size_t length);

private:
    void xorWithIv(uint8_t* buf, const uint8_t* iv);
    void invCipher(tiny_aes_state_t* state, const uint8_t* roundKey);
    void cipher(tiny_aes_state_t* state, const uint8_t* roundKey);
    void invShiftRows(tiny_aes_state_t* state);
    void invSubBytes(tiny_aes_state_t* state);
    void invMixColumns(tiny_aes_state_t* state);
    uint8_t multiply(uint8_t x, uint8_t y);
    void mixColumns(tiny_aes_state_t* state);
    uint8_t xtime(uint8_t x);
    void shiftRows(tiny_aes_state_t* state);
    void subBytes(tiny_aes_state_t* state);
    void addRoundKey(uint8_t round, tiny_aes_state_t* state, const uint8_t* roundKey);
    void keyExpansion(uint8_t* roundKey, const uint8_t* key);

private:
    size_t keyLength = 32;
    size_t keyExpSize = 240;
    const size_t BLOCK_LENGTH = 16;
    const size_t NB = 4;
    size_t nk = 8;
    size_t nr = 14;
    AES_TYPE aesType = AES_TYPE::AES256;
    static const uint8_t rcon[11];
    static const uint8_t rsbox[256];
    static const uint8_t sbox[256];
    AES_ctx ctx;
};

#endif // SIMPLETINYAES_H
