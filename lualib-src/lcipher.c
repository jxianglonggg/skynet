#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h> 
#include <stdatomic.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <lua.h>
#include <lauxlib.h>
static bool CIPHER_IS_INIT = false;

struct evp_cipher_ctx{
    EVP_CIPHER_CTX* ctx; 
    const EVP_CIPHER* cipher;
    int key_size;
    int iv_size;
    int block_size;
    bool initialized;
};

static struct evp_cipher_ctx *
_check_cipherctx(lua_State* L, int idx) {
    struct evp_cipher_ctx* ctx_p = (struct evp_cipher_ctx*)lua_touserdata(L, idx);
    if(!ctx_p) {
        luaL_error(L, "need evp_cipher_ctx");
    }
    return ctx_p;
}

static int
_lctx_gc(lua_State* L) {
    struct evp_cipher_ctx* ctx_p = _check_cipherctx(L, 1);
    if(ctx_p->ctx) {
        EVP_CIPHER_CTX_free(ctx_p->ctx);
        ctx_p->ctx = NULL;
    }
    return 0;
}

static void init(lua_State* L, struct evp_cipher_ctx* ctx_p, const unsigned char* key,
 int keylen, const unsigned char* iv, int ivlen, bool no_padding, bool is_encrypt){
    if (key == NULL || keylen != ctx_p->key_size)
    {
        luaL_error(L, "cipher:init: incorrect key size, expect %d", ctx_p->key_size);
    }
    if (iv == NULL || ivlen > 16)
    {
        luaL_error(L, "cipher:init: incorrect iv size, default size %d", ctx_p->iv_size);
    }
    if(EVP_CipherInit_ex(ctx_p->ctx, ctx_p->cipher, NULL, key, iv, is_encrypt) == 0) {
        luaL_error(L, "cipher:init EVP_CipherInit_ex fail");
    }
    
    if ( (ctx_p->iv_size != ivlen) && 
        ((EVP_CIPHER_CTX_ctrl(ctx_p->ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL) != 1)
        || EVP_CipherInit_ex(ctx_p->ctx, NULL, NULL, key, iv, is_encrypt) == 0) ) {
        luaL_error(L, "cipher:init set ev fail");
    }
    ctx_p->iv_size = ivlen;
    if(no_padding) EVP_CIPHER_CTX_set_padding(ctx_p->ctx, 0);
    ctx_p->initialized = true;
}

static void update_aead_aad(lua_State* L, struct evp_cipher_ctx* ctx_p, const unsigned char* aad, int len){
    int outlen;
    if (!ctx_p->initialized){
        luaL_error(L, "cipher:update_aead_aad: cipher not initalized, call cipher:init first");
    }
    if (EVP_CipherUpdate(ctx_p->ctx, NULL, &outlen, aad, len) != 1){
        luaL_error(L, "cipher:update_aead_aad");
    }
}

static bool update(lua_State* L, struct evp_cipher_ctx* ctx_p, const unsigned char* in, int in_len, unsigned char* out){
    if (!ctx_p->initialized){
        luaL_error(L, "cipher:update: cipher not initalized, call cipher:init first");
    }
    int out_len = 0;
    if(EVP_CipherUpdate(ctx_p->ctx, out, &out_len, in, in_len) != 1){
        luaL_error(L, "cipher:update:CipherUpdate");
    }
    return true;
}

static bool finial(lua_State* L, struct evp_cipher_ctx* ctx_p, const unsigned char* in, int in_len, unsigned char* out){
    if(in){
        update(L, ctx_p, in, in_len, out);
    }
    int outlen = 0;
    if(EVP_CipherFinal_ex(ctx_p->ctx, out, &outlen) != 1) {
        luaL_error(L, "cipher:final: EVP_CipherFinal_ex fail");
    }
    return true;
}

static bool set_aead_tag(lua_State* L, struct evp_cipher_ctx* ctx_p, const unsigned char* tag, int len)
{
    if (!ctx_p->initialized){
        luaL_error(L, "cipher:update: cipher not initalized, call cipher:init first");
    }
    if(EVP_CIPHER_CTX_ctrl(ctx_p->ctx, EVP_CTRL_AEAD_SET_TAG, len, (void*)tag) != 1){
        luaL_error(L, "cipher:set_aead_tag fail");
    }
    return true;
}

static int
_lctx_encrypt(lua_State* L) {
    struct evp_cipher_ctx* ctx_p = _check_cipherctx(L, 1);
    size_t key_len = 0;
    const unsigned char* key = (const unsigned char*)lua_tolstring(L, 2, &key_len);
    size_t iv_len = 0;
    const unsigned char* iv = (const unsigned char*)lua_tolstring(L, 3, &iv_len);
    size_t slen = 0;
    const unsigned char* unencrypted_data = (const unsigned char*)lua_tolstring(L, 4, &slen);
    bool no_padding = lua_toboolean(L, 5);
    size_t alen = 0;
    const unsigned char* aead_aad = (const unsigned char*)lua_tolstring(L, 6, &alen);
    init(L, ctx_p, key, (int)key_len, iv, (int)iv_len, no_padding, true);
    if(aead_aad) update_aead_aad(L, ctx_p, aead_aad, (int)alen);
    int outlen = slen;
    unsigned char out[outlen];
    finial(L, ctx_p, unencrypted_data, (int)slen, out);
    lua_pushlstring(L, (const char*)out, outlen);
    return 1;
}

static int
_lctx_decrypt(lua_State* L) {
    struct evp_cipher_ctx* ctx_p = _check_cipherctx(L, 1);
    size_t key_len = 0;
    const unsigned char* key = (const unsigned char*)lua_tolstring(L, 2, &key_len);
    size_t iv_len = 0;
    const unsigned char* iv = (const unsigned char*)lua_tolstring(L, 3, &iv_len);
    size_t slen = 0;
    const unsigned char* encrypted_data = (const unsigned char*)lua_tolstring(L, 4, &slen);
    bool no_padding = lua_toboolean(L, 5);
    size_t aad_len = 0;
    const unsigned char* aead_aad = (const unsigned char*)lua_tolstring(L, 6, &aad_len);
    size_t tag_len = 0;
    const unsigned char* aead_tag = (const unsigned char*)lua_tolstring(L, 7, &tag_len);
    init(L, ctx_p, key, (int)key_len, iv, (int)iv_len, no_padding, false);
    if(aead_aad) update_aead_aad(L, ctx_p, aead_aad, (int)aad_len);
    if(aead_tag) set_aead_tag(L, ctx_p, aead_tag, tag_len);
    int outlen = slen;
    unsigned char out[outlen];
    finial(L, ctx_p, encrypted_data, (int)outlen, out);
    lua_pushlstring(L, (const char*)out, outlen);
    return 1;
}

static int
_lctx_set_aead_tag(lua_State* L) {
    struct evp_cipher_ctx* ctx_p = _check_cipherctx(L, 1);
    if (!ctx_p->initialized){
        luaL_error(L, "cipher:set_aead_tag: cipher not initalized, call cipher:init first");
    }
    size_t len = 0;
    const unsigned char* tag = (const unsigned char*)lua_tolstring(L, 2, &len);
    if(EVP_CIPHER_CTX_ctrl(ctx_p->ctx, EVP_CTRL_AEAD_SET_TAG, (int)len, (void*)tag) != 1)
    luaL_error(L, "cipher:get_aead_tag fail");
    return 0;
}

static int
_lctx_get_aead_tag(lua_State* L) {
    struct evp_cipher_ctx* ctx_p = _check_cipherctx(L, 1);
    if (!ctx_p->initialized){
        luaL_error(L, "cipher:get_aead_tag: cipher not initalized, call cipher:init first");
    }
    int size = luaL_optinteger(L, 2, ctx_p->key_size / 2);
    if (size > ctx_p->key_size) luaL_error(L, "tag size %d is too large", size);
    char out[size];
    if(EVP_CIPHER_CTX_ctrl(ctx_p->ctx, EVP_CTRL_AEAD_GET_TAG, size, (void*)out) != 1) 
    luaL_error(L, "cipher:get_aead_tag fail");
    lua_pushlstring(L, out, size);
    return 1;
}

static int
lnew(lua_State* L) {
    const char* name = lua_tostring(L, 1);
    if(!name){
        luaL_error(L, "cipher.new: expect type to be defined");
    }
    struct evp_cipher_ctx* ctx_p = (struct evp_cipher_ctx*)lua_newuserdatauv(L, sizeof(*ctx_p), 0);
    ctx_p->ctx = EVP_CIPHER_CTX_new();
    if(!ctx_p->ctx) {
        unsigned int err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        luaL_error(L, "EVP_CIPHER_CTX_new faild. %s\n", buf);
    }
    ctx_p->cipher = EVP_get_cipherbyname(name);
    if (!ctx_p->cipher){
        luaL_error(L, "need get cipher by name fail.%s", name);
    }
    int code = EVP_CipherInit_ex(ctx_p->ctx, ctx_p->cipher, NULL, NULL, NULL, -1);
    if (code != 1){
        luaL_error(L, "evp cipher init fail");
    }
    ctx_p->block_size = EVP_CIPHER_CTX_block_size(ctx_p->ctx);
    ctx_p->key_size = EVP_CIPHER_CTX_key_length(ctx_p->ctx);
    ctx_p->iv_size = EVP_CIPHER_CTX_iv_length(ctx_p->ctx);
    if(luaL_newmetatable(L, "_EVP_CIPHER_CTX_METATABLE_")) {
        luaL_Reg l[] = {
            {"encrypt", _lctx_encrypt},
            {"decrypt", _lctx_decrypt},
            {"set_aead_tag", _lctx_set_aead_tag},
            {"get_aead_tag", _lctx_get_aead_tag},
            {NULL, NULL},
        };

        luaL_newlib(L, l);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, _lctx_gc);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);
    return 1;
}

int
luaopen_lcipher_c(lua_State* L) {
    if(!CIPHER_IS_INIT) {
        luaL_error(L, "lcipher need init, Put enablecipher = true in you config file.");
    }
    luaL_Reg l[] = {
        {"new", lnew},
        {NULL, NULL},
    };
    luaL_checkversion(L);
    luaL_newlib(L, l);
    return 1;
}

// for lcipher init
static int
lcipher_init_constructor(lua_State* L) {
#ifndef OPENSSL_EXTERNAL_INITIALIZATION
    if(!CIPHER_IS_INIT) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }
#endif
    CIPHER_IS_INIT = true;
    return 0;
}

static int
lcipher_init_destructor(lua_State* L) {
#ifndef OPENSSL_EXTERNAL_INITIALIZATION
    if(CIPHER_IS_INIT) {
        ENGINE_cleanup();
        CONF_modules_unload(1);
        ERR_free_strings();
        EVP_cleanup();
        sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
        CRYPTO_cleanup_all_ex_data();
    }
#endif
    CIPHER_IS_INIT = false;
    return 0;
}

int
luaopen_lcipher_init_c(lua_State* L) {
    luaL_Reg l[] = {
        {"constructor", lcipher_init_constructor},
        {"destructor", lcipher_init_destructor},
        {NULL, NULL},
    };
    luaL_checkversion(L);
    luaL_newlib(L, l);
    return 1;
}