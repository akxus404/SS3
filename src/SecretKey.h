#pragma once

#include <sodium.h>

#include <cstddef>
#include <cstdlib>

// Clave de 32 bytes en memoria protegida (sodium_malloc: páginas con guardas, se borra al liberar).
// Requiere haber llamado antes a sodium_init() (Vault::initCrypto()).
class SecretKey {
public:
    static constexpr std::size_t kSize = 32;
    SecretKey() : p_(static_cast<unsigned char*>(sodium_malloc(kSize))) {
        if (!p_) std::abort();
        sodium_memzero(p_, kSize);
    }
    ~SecretKey() { sodium_free(p_); }
    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    unsigned char* data() { return p_; }
    const unsigned char* data() const { return p_; }
    void clear() { sodium_memzero(p_, kSize); }
    void randomize() { randombytes_buf(p_, kSize); }

private:
    unsigned char* p_;
};
