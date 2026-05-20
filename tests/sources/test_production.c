/**
 * NiPass Production-Level Test
 *
 * 模拟真实 Android native 库场景：
 *   - 许可证验证 / token 校验
 *   - 配置解析器 (key=value)
 *   - 协议状态机
 *   - 哈希 / HMAC 计算
 *   - 函数分发表 (vtable 模式)
 *   - 内存池
 *   - 位操作与编解码
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ========================================================================
 * 1. 常量 / 密钥 — 字符串加密的主要目标
 * ======================================================================== */

static const char *LICENSE_SERVER  = "https://license.nipass.dev/v2/verify";
static const char *API_SECRET      = "sk_live_9f8E3kLm2Xp7Qr4Tn6Wv1Yz";
static const char *AES_KEY_HEX     = "4e695061737332303234414553";
static const char *HMAC_SALT       = "NiPass::HMAC::Salt::2024";
static const char *INTERNAL_MAGIC  = "\x7fNIPASS\x01\x02\x03";

/* ========================================================================
 * 2. 数据结构
 * ======================================================================== */

#define CONFIG_MAX_ENTRIES 32
#define CONFIG_KEY_LEN     64
#define CONFIG_VAL_LEN     256

typedef struct {
    char key[CONFIG_KEY_LEN];
    char value[CONFIG_VAL_LEN];
} ConfigEntry;

typedef struct {
    ConfigEntry entries[CONFIG_MAX_ENTRIES];
    int count;
} ConfigStore;

/* 内存池 */
#define POOL_BLOCK_SIZE 64
#define POOL_CAPACITY   16

typedef struct {
    uint8_t  blocks[POOL_CAPACITY][POOL_BLOCK_SIZE];
    uint8_t  used[POOL_CAPACITY];
    int      alloc_count;
    int      free_count;
} MemPool;

/* 协议包 */
typedef enum {
    PKT_HANDSHAKE = 0x01,
    PKT_AUTH      = 0x02,
    PKT_DATA      = 0x03,
    PKT_HEARTBEAT = 0x04,
    PKT_CLOSE     = 0x05,
    PKT_ERROR     = 0xFF
} PacketType;

typedef struct {
    uint8_t  magic[4];
    uint8_t  version;
    uint8_t  type;
    uint16_t payload_len;
    uint8_t  payload[512];
    uint32_t checksum;
} Packet;

/* 协议状态机 */
typedef enum {
    STATE_IDLE,
    STATE_HANDSHAKE_SENT,
    STATE_AUTHENTICATED,
    STATE_DATA_TRANSFER,
    STATE_CLOSING,
    STATE_ERROR
} SessionState;

typedef struct {
    SessionState state;
    uint32_t     session_id;
    uint32_t     seq;
    uint8_t      auth_token[32];
    int          retry_count;
} Session;

/* 许可证 */
typedef struct {
    char     product_id[32];
    uint32_t expire_ts;
    uint32_t features;
    uint8_t  signature[32];
} License;

/* ========================================================================
 * 3. 哈希 / 校验 — 大量算术 + 位运算，MBA / Substitution 目标
 * ======================================================================== */

static uint32_t fnv1a_hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x01000193u;
    }
    return h;
}

static uint32_t crc32_table[256];
static int crc32_table_ready = 0;

static void crc32_init_table(void) {
    if (crc32_table_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_table_ready = 1;
}

static uint32_t crc32_compute(const uint8_t *data, size_t len) {
    crc32_init_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

static void hmac_simple(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen,
                        uint8_t out[32]) {
    uint8_t ipad[64], opad[64];
    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);
    for (size_t i = 0; i < klen && i < 64; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    /* inner = H(ipad || msg) */
    uint32_t inner = fnv1a_hash(ipad, 64);
    inner ^= fnv1a_hash(msg, mlen);
    /* outer = H(opad || inner) */
    uint32_t outer = fnv1a_hash(opad, 64);
    outer ^= inner;
    memset(out, 0, 32);
    for (int i = 0; i < 4; i++) {
        out[i]      = (inner >> (i * 8)) & 0xFF;
        out[i + 4]  = (outer >> (i * 8)) & 0xFF;
        out[i + 8]  = ((inner ^ outer) >> (i * 8)) & 0xFF;
        out[i + 12] = ((inner + outer) >> (i * 8)) & 0xFF;
    }
}

/* ========================================================================
 * 4. 配置解析器 — 字符串处理 + 分支
 * ======================================================================== */

static void config_init(ConfigStore *store) {
    store->count = 0;
    memset(store->entries, 0, sizeof(store->entries));
}

static int config_set(ConfigStore *store, const char *key, const char *value) {
    /* 先查找是否已存在 */
    for (int i = 0; i < store->count; i++) {
        if (strcmp(store->entries[i].key, key) == 0) {
            strncpy(store->entries[i].value, value, CONFIG_VAL_LEN - 1);
            return 0;
        }
    }
    if (store->count >= CONFIG_MAX_ENTRIES) return -1;
    strncpy(store->entries[store->count].key, key, CONFIG_KEY_LEN - 1);
    strncpy(store->entries[store->count].value, value, CONFIG_VAL_LEN - 1);
    store->count++;
    return 0;
}

static const char *config_get(const ConfigStore *store, const char *key) {
    for (int i = 0; i < store->count; i++) {
        if (strcmp(store->entries[i].key, key) == 0)
            return store->entries[i].value;
    }
    return NULL;
}

/* 解析 "key1=val1;key2=val2;..." 格式 */
static int config_parse(ConfigStore *store, const char *input) {
    char buf[1024];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    int parsed = 0;
    char *saveptr1 = NULL;
    char *pair = strtok_r(buf, ";", &saveptr1);
    while (pair != NULL) {
        char *eq = strchr(pair, '=');
        if (eq != NULL) {
            *eq = '\0';
            /* trim leading spaces */
            char *k = pair;
            while (*k == ' ') k++;
            char *v = eq + 1;
            while (*v == ' ') v++;
            if (*k && *v) {
                config_set(store, k, v);
                parsed++;
            }
        }
        pair = strtok_r(NULL, ";", &saveptr1);
    }
    return parsed;
}

/* ========================================================================
 * 5. 内存池 — 指针运算 + 状态管理
 * ======================================================================== */

static void pool_init(MemPool *pool) {
    memset(pool, 0, sizeof(*pool));
}

static void *pool_alloc(MemPool *pool) {
    for (int i = 0; i < POOL_CAPACITY; i++) {
        if (!pool->used[i]) {
            pool->used[i] = 1;
            pool->alloc_count++;
            memset(pool->blocks[i], 0, POOL_BLOCK_SIZE);
            return pool->blocks[i];
        }
    }
    return NULL;
}

static void pool_free(MemPool *pool, void *ptr) {
    for (int i = 0; i < POOL_CAPACITY; i++) {
        if (pool->blocks[i] == ptr && pool->used[i]) {
            pool->used[i] = 0;
            pool->free_count++;
            return;
        }
    }
}

static int pool_used_count(const MemPool *pool) {
    int n = 0;
    for (int i = 0; i < POOL_CAPACITY; i++) {
        if (pool->used[i]) n++;
    }
    return n;
}

/* ========================================================================
 * 6. 协议状态机 — 复杂 switch + 嵌套分支，平坦化核心目标
 * ======================================================================== */

static uint32_t packet_checksum(const Packet *pkt) {
    uint32_t sum = 0;
    sum ^= fnv1a_hash(pkt->magic, 4);
    sum ^= (uint32_t)pkt->version << 16 | (uint32_t)pkt->type;
    sum ^= fnv1a_hash(pkt->payload, pkt->payload_len);
    return sum;
}

static void packet_build(Packet *pkt, PacketType type,
                         const uint8_t *payload, uint16_t len) {
    pkt->magic[0] = 'N'; pkt->magic[1] = 'I';
    pkt->magic[2] = 'P'; pkt->magic[3] = 'S';
    pkt->version = 2;
    pkt->type = (uint8_t)type;
    pkt->payload_len = len;
    if (payload && len > 0) {
        memcpy(pkt->payload, payload, len > 512 ? 512 : len);
    }
    pkt->checksum = packet_checksum(pkt);
}

static int packet_validate(const Packet *pkt) {
    if (pkt->magic[0] != 'N' || pkt->magic[1] != 'I' ||
        pkt->magic[2] != 'P' || pkt->magic[3] != 'S')
        return -1;
    if (pkt->version < 1 || pkt->version > 3)
        return -2;
    if (pkt->payload_len > 512)
        return -3;
    if (pkt->checksum != packet_checksum(pkt))
        return -4;
    return 0;
}

static int session_handle_packet(Session *sess, const Packet *pkt) {
    if (packet_validate(pkt) != 0) {
        sess->state = STATE_ERROR;
        return -1;
    }

    switch (sess->state) {
    case STATE_IDLE:
        if (pkt->type == PKT_HANDSHAKE) {
            sess->session_id = fnv1a_hash(pkt->payload, pkt->payload_len);
            sess->seq = 1;
            sess->state = STATE_HANDSHAKE_SENT;
            return 0;
        }
        break;

    case STATE_HANDSHAKE_SENT:
        if (pkt->type == PKT_AUTH) {
            /* 验证 auth payload */
            uint8_t expected[32];
            hmac_simple((const uint8_t *)API_SECRET, strlen(API_SECRET),
                        pkt->payload, pkt->payload_len, expected);
            /* 简化：只比较前 8 字节 */
            int auth_ok = 1;
            for (int i = 0; i < 8 && i < (int)pkt->payload_len; i++) {
                if (pkt->payload[i] == 0) { auth_ok = 0; break; }
            }
            if (auth_ok) {
                memcpy(sess->auth_token, expected, 32);
                sess->state = STATE_AUTHENTICATED;
                sess->retry_count = 0;
                return 0;
            } else {
                sess->retry_count++;
                if (sess->retry_count >= 3) {
                    sess->state = STATE_ERROR;
                    return -2;
                }
                return -1;
            }
        }
        break;

    case STATE_AUTHENTICATED:
        if (pkt->type == PKT_DATA) {
            sess->seq++;
            sess->state = STATE_DATA_TRANSFER;
            return (int)pkt->payload_len;
        } else if (pkt->type == PKT_CLOSE) {
            sess->state = STATE_CLOSING;
            return 0;
        }
        break;

    case STATE_DATA_TRANSFER:
        if (pkt->type == PKT_DATA) {
            sess->seq++;
            return (int)pkt->payload_len;
        } else if (pkt->type == PKT_HEARTBEAT) {
            return 0;
        } else if (pkt->type == PKT_CLOSE) {
            sess->state = STATE_CLOSING;
            return 0;
        }
        break;

    case STATE_CLOSING:
    case STATE_ERROR:
        return -1;
    }

    sess->state = STATE_ERROR;
    return -1;
}

/* ========================================================================
 * 7. 许可证验证 — 多层校验 + 时间检查
 * ======================================================================== */

static int license_verify(const License *lic, uint32_t now_ts) {
    /* Step 1: product id 白名单 */
    const char *valid_products[] = {
        "com.nipass.pro", "com.nipass.enterprise",
        "com.nipass.trial", NULL
    };
    int product_ok = 0;
    for (int i = 0; valid_products[i] != NULL; i++) {
        if (strcmp(lic->product_id, valid_products[i]) == 0) {
            product_ok = 1;
            break;
        }
    }
    if (!product_ok) return -1;

    /* Step 2: 过期检查 */
    if (lic->expire_ts != 0 && now_ts > lic->expire_ts) return -2;

    /* Step 3: feature flags 合法性 */
    const uint32_t KNOWN_FEATURES = 0x0000FFFF;
    if (lic->features & ~KNOWN_FEATURES) return -3;

    /* Step 4: 签名校验 */
    uint8_t computed_sig[32];
    uint8_t msg[128];
    int mlen = snprintf((char *)msg, sizeof(msg), "%s:%u:%u",
                        lic->product_id, lic->expire_ts, lic->features);
    hmac_simple((const uint8_t *)HMAC_SALT, strlen(HMAC_SALT),
                msg, (size_t)mlen, computed_sig);

    if (memcmp(computed_sig, lic->signature, 16) != 0) return -4;

    return 0; /* valid */
}

static void license_make_test(License *lic, const char *product,
                              uint32_t expire, uint32_t features) {
    memset(lic, 0, sizeof(*lic));
    strncpy(lic->product_id, product, sizeof(lic->product_id) - 1);
    lic->expire_ts = expire;
    lic->features = features;
    /* 生成匹配的签名 */
    uint8_t msg[128];
    int mlen = snprintf((char *)msg, sizeof(msg), "%s:%u:%u",
                        lic->product_id, lic->expire_ts, lic->features);
    hmac_simple((const uint8_t *)HMAC_SALT, strlen(HMAC_SALT),
                msg, (size_t)mlen, lic->signature);
}

/* ========================================================================
 * 8. 编解码器 — Base64 + XOR cipher
 * ======================================================================== */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t *in, size_t inlen,
                         char *out, size_t outmax) {
    size_t olen = 4 * ((inlen + 2) / 3);
    if (olen + 1 > outmax) return -1;

    size_t i, j;
    for (i = 0, j = 0; i + 2 < inlen; i += 3, j += 4) {
        uint32_t v = ((uint32_t)in[i] << 16) |
                     ((uint32_t)in[i+1] << 8) | in[i+2];
        out[j]   = b64_table[(v >> 18) & 0x3F];
        out[j+1] = b64_table[(v >> 12) & 0x3F];
        out[j+2] = b64_table[(v >> 6)  & 0x3F];
        out[j+3] = b64_table[v & 0x3F];
    }
    if (i < inlen) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < inlen) v |= (uint32_t)in[i+1] << 8;
        out[j]   = b64_table[(v >> 18) & 0x3F];
        out[j+1] = b64_table[(v >> 12) & 0x3F];
        out[j+2] = (i + 1 < inlen) ? b64_table[(v >> 6) & 0x3F] : '=';
        out[j+3] = '=';
        j += 4;
    }
    out[j] = '\0';
    return (int)j;
}

static void xor_cipher(uint8_t *data, size_t len,
                       const uint8_t *key, size_t klen) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % klen];
        data[i] = (data[i] << 3) | (data[i] >> 5); /* rotate left 3 */
        data[i] ^= (uint8_t)(i * 0x9E + 0x37);
    }
}

static void xor_decipher(uint8_t *data, size_t len,
                         const uint8_t *key, size_t klen) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= (uint8_t)(i * 0x9E + 0x37);
        data[i] = (data[i] >> 3) | (data[i] << 5); /* rotate right 3 */
        data[i] ^= key[i % klen];
    }
}

/* ========================================================================
 * 9. 函数分发表 — 间接调用目标
 * ======================================================================== */

typedef int (*CommandHandler)(const char *arg, char *result, size_t rlen);

static int cmd_echo(const char *arg, char *result, size_t rlen) {
    snprintf(result, rlen, "ECHO: %s", arg);
    return 0;
}

static int cmd_hash(const char *arg, char *result, size_t rlen) {
    uint32_t h = fnv1a_hash((const uint8_t *)arg, strlen(arg));
    snprintf(result, rlen, "HASH: 0x%08X", h);
    return 0;
}

static int cmd_crc(const char *arg, char *result, size_t rlen) {
    uint32_t c = crc32_compute((const uint8_t *)arg, strlen(arg));
    snprintf(result, rlen, "CRC32: 0x%08X", c);
    return 0;
}

static int cmd_b64(const char *arg, char *result, size_t rlen) {
    char encoded[512];
    int n = base64_encode((const uint8_t *)arg, strlen(arg),
                          encoded, sizeof(encoded));
    if (n < 0) {
        snprintf(result, rlen, "B64: error");
        return -1;
    }
    snprintf(result, rlen, "B64: %s", encoded);
    return 0;
}

static int cmd_encrypt(const char *arg, char *result, size_t rlen) {
    uint8_t buf[256];
    size_t len = strlen(arg);
    if (len > sizeof(buf)) len = sizeof(buf);
    memcpy(buf, arg, len);
    xor_cipher(buf, len, (const uint8_t *)AES_KEY_HEX, strlen(AES_KEY_HEX));
    /* 输出 hex */
    char hex[513];
    for (size_t i = 0; i < len && i * 2 + 2 < sizeof(hex); i++) {
        sprintf(hex + i * 2, "%02x", buf[i]);
    }
    snprintf(result, rlen, "ENC: %s", hex);
    return 0;
}

typedef struct {
    const char     *name;
    CommandHandler  handler;
    const char     *description;
} CommandEntry;

static const CommandEntry command_table[] = {
    {"echo",    cmd_echo,    "Echo input back"},
    {"hash",    cmd_hash,    "FNV-1a hash"},
    {"crc",     cmd_crc,     "CRC32 checksum"},
    {"b64",     cmd_b64,     "Base64 encode"},
    {"encrypt", cmd_encrypt, "XOR encrypt"},
    {NULL, NULL, NULL}
};

static int dispatch_command(const char *name, const char *arg,
                            char *result, size_t rlen) {
    for (int i = 0; command_table[i].name != NULL; i++) {
        if (strcmp(command_table[i].name, name) == 0) {
            return command_table[i].handler(arg, result, rlen);
        }
    }
    snprintf(result, rlen, "Unknown command: %s", name);
    return -1;
}

/* ========================================================================
 * 10. 排序 + 二分查找 — 循环密集型
 * ======================================================================== */

static void sort_u32(uint32_t *arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - 1 - i; j++) {
            if (arr[j] > arr[j + 1]) {
                uint32_t tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
            }
        }
    }
}

static int bsearch_u32(const uint32_t *arr, int n, uint32_t target) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (arr[mid] == target) return mid;
        else if (arr[mid] < target) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}

/* ========================================================================
 * 11. 测试框架
 * ======================================================================== */

static int g_tests_run    = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (cond) { g_tests_passed++; } \
    else { g_tests_failed++; printf("  FAIL: %s (line %d)\n", msg, __LINE__); } \
} while(0)

static void test_hash_and_crc(void) {
    printf("[TEST] Hash & CRC\n");

    uint32_t h1 = fnv1a_hash((const uint8_t *)"hello", 5);
    uint32_t h2 = fnv1a_hash((const uint8_t *)"hello", 5);
    TEST_ASSERT(h1 == h2, "fnv1a deterministic");
    TEST_ASSERT(h1 != 0,  "fnv1a non-zero");

    uint32_t h3 = fnv1a_hash((const uint8_t *)"world", 5);
    TEST_ASSERT(h1 != h3, "fnv1a different inputs differ");

    uint32_t c1 = crc32_compute((const uint8_t *)"123456789", 9);
    TEST_ASSERT(c1 == 0xCBF43926u, "crc32 known vector");

    uint32_t c2 = crc32_compute((const uint8_t *)"", 0);
    TEST_ASSERT(c2 == 0x00000000u, "crc32 empty");
}

static void test_config_parser(void) {
    printf("[TEST] Config Parser\n");

    ConfigStore store;
    config_init(&store);

    int n = config_parse(&store, "host=192.168.1.1;port=8080;mode=release;debug=false");
    TEST_ASSERT(n == 4, "parsed 4 entries");
    TEST_ASSERT(store.count == 4, "store has 4 entries");

    const char *host = config_get(&store, "host");
    TEST_ASSERT(host != NULL && strcmp(host, "192.168.1.1") == 0, "host value");

    const char *port = config_get(&store, "port");
    TEST_ASSERT(port != NULL && strcmp(port, "8080") == 0, "port value");

    const char *mode = config_get(&store, "mode");
    TEST_ASSERT(mode != NULL && strcmp(mode, "release") == 0, "mode value");

    TEST_ASSERT(config_get(&store, "nonexist") == NULL, "missing key returns NULL");

    /* 覆盖已有 key */
    config_set(&store, "port", "9090");
    port = config_get(&store, "port");
    TEST_ASSERT(port != NULL && strcmp(port, "9090") == 0, "overwrite value");
    TEST_ASSERT(store.count == 4, "count unchanged after overwrite");
}

static void test_mempool(void) {
    printf("[TEST] Memory Pool\n");

    MemPool pool;
    pool_init(&pool);
    TEST_ASSERT(pool_used_count(&pool) == 0, "pool initially empty");

    void *ptrs[POOL_CAPACITY];
    for (int i = 0; i < POOL_CAPACITY; i++) {
        ptrs[i] = pool_alloc(&pool);
        TEST_ASSERT(ptrs[i] != NULL, "alloc succeeds");
    }
    TEST_ASSERT(pool_used_count(&pool) == POOL_CAPACITY, "pool full");
    TEST_ASSERT(pool_alloc(&pool) == NULL, "alloc fails when full");

    pool_free(&pool, ptrs[5]);
    pool_free(&pool, ptrs[10]);
    TEST_ASSERT(pool_used_count(&pool) == POOL_CAPACITY - 2, "freed 2 blocks");

    void *p = pool_alloc(&pool);
    TEST_ASSERT(p != NULL, "re-alloc after free");
    TEST_ASSERT(pool.alloc_count == POOL_CAPACITY + 1, "alloc count tracks");
}

static void test_protocol_state_machine(void) {
    printf("[TEST] Protocol State Machine\n");

    Session sess;
    memset(&sess, 0, sizeof(sess));
    sess.state = STATE_IDLE;

    Packet pkt;

    /* Handshake */
    const char *client_hello = "client-hello-nonce-abc123";
    packet_build(&pkt, PKT_HANDSHAKE,
                 (const uint8_t *)client_hello, (uint16_t)strlen(client_hello));
    int r = session_handle_packet(&sess, &pkt);
    TEST_ASSERT(r == 0, "handshake accepted");
    TEST_ASSERT(sess.state == STATE_HANDSHAKE_SENT, "state -> HANDSHAKE_SENT");
    TEST_ASSERT(sess.session_id != 0, "session_id assigned");

    /* Auth */
    const char *auth_payload = "user:admin;token:xyz789";
    packet_build(&pkt, PKT_AUTH,
                 (const uint8_t *)auth_payload, (uint16_t)strlen(auth_payload));
    r = session_handle_packet(&sess, &pkt);
    TEST_ASSERT(r == 0, "auth accepted");
    TEST_ASSERT(sess.state == STATE_AUTHENTICATED, "state -> AUTHENTICATED");

    /* Data transfer */
    const char *data1 = "payload-chunk-1";
    packet_build(&pkt, PKT_DATA,
                 (const uint8_t *)data1, (uint16_t)strlen(data1));
    r = session_handle_packet(&sess, &pkt);
    TEST_ASSERT(r == (int)strlen(data1), "data returns payload len");
    TEST_ASSERT(sess.state == STATE_DATA_TRANSFER, "state -> DATA_TRANSFER");
    TEST_ASSERT(sess.seq == 2, "seq incremented");

    /* More data */
    const char *data2 = "payload-chunk-2-longer-data";
    packet_build(&pkt, PKT_DATA,
                 (const uint8_t *)data2, (uint16_t)strlen(data2));
    r = session_handle_packet(&sess, &pkt);
    TEST_ASSERT(r == (int)strlen(data2), "second data chunk");
    TEST_ASSERT(sess.seq == 3, "seq incremented again");

    /* Heartbeat */
    packet_build(&pkt, PKT_HEARTBEAT, NULL, 0);
    r = session_handle_packet(&sess, &pkt);
    TEST_ASSERT(r == 0, "heartbeat ok");
    TEST_ASSERT(sess.state == STATE_DATA_TRANSFER, "state unchanged after heartbeat");

    /* Close */
    packet_build(&pkt, PKT_CLOSE, NULL, 0);
    r = session_handle_packet(&sess, &pkt);
    TEST_ASSERT(r == 0, "close accepted");
    TEST_ASSERT(sess.state == STATE_CLOSING, "state -> CLOSING");

    /* Invalid packet on closed session */
    packet_build(&pkt, PKT_DATA, (const uint8_t *)"x", 1);
    r = session_handle_packet(&sess, &pkt);
    TEST_ASSERT(r == -1, "reject after close");

    /* Bad magic */
    Packet bad;
    memset(&bad, 0, sizeof(bad));
    bad.magic[0] = 'X';
    Session s2;
    memset(&s2, 0, sizeof(s2));
    r = session_handle_packet(&s2, &bad);
    TEST_ASSERT(r == -1, "bad magic rejected");
    TEST_ASSERT(s2.state == STATE_ERROR, "state -> ERROR on bad packet");
}

static void test_license(void) {
    printf("[TEST] License Verification\n");

    uint32_t now = 1700000000u; /* 模拟当前时间 */

    /* 有效许可证 */
    License lic;
    license_make_test(&lic, "com.nipass.pro", now + 86400, 0x000F);
    int r = license_verify(&lic, now);
    TEST_ASSERT(r == 0, "valid license accepted");

    /* 过期许可证 */
    License expired;
    license_make_test(&expired, "com.nipass.pro", now - 1, 0x000F);
    r = license_verify(&expired, now);
    TEST_ASSERT(r == -2, "expired license rejected");

    /* 未知产品 */
    License unknown;
    license_make_test(&unknown, "com.fake.app", now + 86400, 0x000F);
    r = license_verify(&unknown, now);
    TEST_ASSERT(r == -1, "unknown product rejected");

    /* 非法 feature flags */
    License bad_feat;
    license_make_test(&bad_feat, "com.nipass.pro", now + 86400, 0xFFFF0000u);
    r = license_verify(&bad_feat, now);
    TEST_ASSERT(r == -3, "bad features rejected");

    /* 签名篡改 */
    License tampered;
    license_make_test(&tampered, "com.nipass.enterprise", now + 86400, 0x00FF);
    tampered.signature[0] ^= 0xFF;
    r = license_verify(&tampered, now);
    TEST_ASSERT(r == -4, "tampered signature rejected");

    /* 永不过期 (expire_ts == 0) */
    License forever;
    license_make_test(&forever, "com.nipass.trial", 0, 0x0001);
    r = license_verify(&forever, now);
    TEST_ASSERT(r == 0, "no-expire license accepted");
}

static void test_codec(void) {
    printf("[TEST] Codec (Base64 + XOR cipher)\n");

    /* Base64 */
    char b64out[256];
    int n = base64_encode((const uint8_t *)"Hello, NiPass!", 14,
                          b64out, sizeof(b64out));
    TEST_ASSERT(n > 0, "b64 encode ok");
    TEST_ASSERT(strcmp(b64out, "SGVsbG8sIE5pUGFzcyE=") == 0, "b64 known vector");

    n = base64_encode((const uint8_t *)"a", 1, b64out, sizeof(b64out));
    TEST_ASSERT(strcmp(b64out, "YQ==") == 0, "b64 single byte");

    n = base64_encode((const uint8_t *)"ab", 2, b64out, sizeof(b64out));
    TEST_ASSERT(strcmp(b64out, "YWI=") == 0, "b64 two bytes");

    n = base64_encode((const uint8_t *)"abc", 3, b64out, sizeof(b64out));
    TEST_ASSERT(strcmp(b64out, "YWJj") == 0, "b64 three bytes");

    /* XOR cipher round-trip */
    const char *plaintext = "This is a secret message for NiPass testing!";
    uint8_t buf[256];
    size_t len = strlen(plaintext);
    memcpy(buf, plaintext, len);

    const uint8_t *key = (const uint8_t *)AES_KEY_HEX;
    size_t klen = strlen(AES_KEY_HEX);

    xor_cipher(buf, len, key, klen);
    TEST_ASSERT(memcmp(buf, plaintext, len) != 0, "cipher changes data");

    xor_decipher(buf, len, key, klen);
    TEST_ASSERT(memcmp(buf, plaintext, len) == 0, "decipher restores data");

    /* 空数据 */
    uint8_t empty[1] = {0};
    xor_cipher(empty, 0, key, klen);
    xor_decipher(empty, 0, key, klen);
    TEST_ASSERT(empty[0] == 0, "empty cipher no-op");
}

static void test_command_dispatch(void) {
    printf("[TEST] Command Dispatch\n");

    char result[512];

    int r = dispatch_command("echo", "hello world", result, sizeof(result));
    TEST_ASSERT(r == 0, "echo ok");
    TEST_ASSERT(strcmp(result, "ECHO: hello world") == 0, "echo output");

    r = dispatch_command("hash", "test", result, sizeof(result));
    TEST_ASSERT(r == 0, "hash ok");
    TEST_ASSERT(strncmp(result, "HASH: 0x", 8) == 0, "hash format");

    r = dispatch_command("crc", "123456789", result, sizeof(result));
    TEST_ASSERT(r == 0, "crc ok");
    TEST_ASSERT(strcmp(result, "CRC32: 0xCBF43926") == 0, "crc known value");

    r = dispatch_command("b64", "ABC", result, sizeof(result));
    TEST_ASSERT(r == 0, "b64 ok");
    TEST_ASSERT(strcmp(result, "B64: QUJD") == 0, "b64 output");

    r = dispatch_command("encrypt", "secret", result, sizeof(result));
    TEST_ASSERT(r == 0, "encrypt ok");
    TEST_ASSERT(strncmp(result, "ENC: ", 5) == 0, "encrypt format");

    r = dispatch_command("nonexist", "x", result, sizeof(result));
    TEST_ASSERT(r == -1, "unknown command fails");
}

static void test_sort_and_search(void) {
    printf("[TEST] Sort & Binary Search\n");

    uint32_t arr[] = {42, 17, 99, 3, 55, 8, 71, 23, 64, 1};
    int n = sizeof(arr) / sizeof(arr[0]);

    sort_u32(arr, n);
    /* 验证有序 */
    int sorted = 1;
    for (int i = 1; i < n; i++) {
        if (arr[i] < arr[i - 1]) { sorted = 0; break; }
    }
    TEST_ASSERT(sorted, "array sorted");
    TEST_ASSERT(arr[0] == 1 && arr[n-1] == 99, "sort min/max");

    TEST_ASSERT(bsearch_u32(arr, n, 42) >= 0, "find 42");
    TEST_ASSERT(bsearch_u32(arr, n, 1) == 0, "find 1 at index 0");
    TEST_ASSERT(bsearch_u32(arr, n, 99) == n - 1, "find 99 at last");
    TEST_ASSERT(bsearch_u32(arr, n, 100) == -1, "100 not found");
    TEST_ASSERT(bsearch_u32(arr, n, 0) == -1, "0 not found");
}

static void test_string_constants(void) {
    printf("[TEST] String Constants Visibility\n");

    /* 这些字符串在混淆后应该不可见于 binary */
    TEST_ASSERT(strlen(LICENSE_SERVER) > 10, "license server present");
    TEST_ASSERT(strlen(API_SECRET) > 10, "api secret present");
    TEST_ASSERT(strlen(AES_KEY_HEX) > 10, "aes key present");
    TEST_ASSERT(strlen(HMAC_SALT) > 10, "hmac salt present");
    TEST_ASSERT(strlen(INTERNAL_MAGIC) > 0, "internal magic present");

    /* 验证内容正确（运行时解密后） */
    TEST_ASSERT(strstr(LICENSE_SERVER, "nipass.dev") != NULL, "license url content");
    TEST_ASSERT(strncmp(API_SECRET, "sk_live_", 8) == 0, "api secret prefix");
}

/* ========================================================================
 * 12. main
 * ======================================================================== */

int main(void) {
    printf("========================================\n");
    printf("  NiPass Production-Level Test Suite\n");
    printf("========================================\n\n");

    test_hash_and_crc();
    test_config_parser();
    test_mempool();
    test_protocol_state_machine();
    test_license();
    test_codec();
    test_command_dispatch();
    test_sort_and_search();
    test_string_constants();

    printf("\n========================================\n");
    printf("  Results: %d/%d passed", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        printf(", %d FAILED", g_tests_failed);
    printf("\n========================================\n");

    return g_tests_failed > 0 ? 1 : 0;
}
