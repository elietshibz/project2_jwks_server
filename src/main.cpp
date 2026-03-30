/*
 * CSCE 3550 – Project 2: JWKS Server with SQLite Backend
 *
 * Extends Project 1 by persisting RSA private keys in a SQLite database
 * (totally_not_my_privateKeys.db) so they survive restarts.
 *
 * Endpoints:
 *   GET  /.well-known/jwks.json  – all non-expired public keys as JWKS
 *   POST /auth                   – JWT signed with a valid key
 *   POST /auth?expired           – JWT signed with an expired key
 *
 * All SQL INSERT statements use parameterized queries (? placeholders)
 * to prevent SQL injection.
 */

#include "httplib.h"
#include "json.hpp"
#include "sqlite3_minimal.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;

// ── Filename for the SQLite database ─────────────────────────────────────────
static const char* DB_FILE = "totally_not_my_privateKeys.db";

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Returns the current UNIX timestamp in seconds.
static std::int64_t now_unix() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

/// Base64url-encodes raw bytes (no padding).
static std::string b64url_encode(const unsigned char* data, std::size_t len) {
    std::string b64;
    b64.resize(((len + 2) / 3) * 4);
    int outlen = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&b64[0]), data, static_cast<int>(len));
    b64.resize(outlen);
    for (char& c : b64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!b64.empty() && b64.back() == '=') b64.pop_back();
    return b64;
}

static std::string b64url_encode_str(const std::string& s) {
    return b64url_encode(
        reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

/// Encodes an OpenSSL BIGNUM as base64url (used for RSA n and e).
static std::string bn_to_b64url(const BIGNUM* bn) {
    int nbytes = BN_num_bytes(bn);
    std::vector<unsigned char> buf(static_cast<std::size_t>(nbytes));
    BN_bn2bin(bn, buf.data());
    return b64url_encode(buf.data(), buf.size());
}

// ── RSA key helpers ───────────────────────────────────────────────────────────

/// Generates a fresh 2048-bit RSA private key. Caller owns the returned EVP_PKEY*.
static EVP_PKEY* generate_rsa_2048() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) return nullptr;

    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    if (!rsa || !e) {
        if (e)   BN_free(e);
        if (rsa) RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    BN_set_word(e, RSA_F4); // exponent 65537
    if (RSA_generate_key_ex(rsa, 2048, e, nullptr) != 1) {
        BN_free(e); RSA_free(rsa); EVP_PKEY_free(pkey);
        return nullptr;
    }
    BN_free(e);

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa); EVP_PKEY_free(pkey);
        return nullptr;
    }
    return pkey; // pkey now owns rsa
}

/**
 * Serializes an RSA private key to PEM format (PKCS#1).
 * PEM is stored as a BLOB in SQLite so it can be deserialized on read.
 */
static std::string pkey_to_pem(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    // Write traditional (PKCS#1) PEM — no encryption
    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, static_cast<std::size_t>(len));
    BIO_free(bio);
    return pem;
}

/// Deserializes a PEM string back into an EVP_PKEY*. Caller owns the result.
static EVP_PKEY* pem_to_pkey(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return nullptr;
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

// ── JWT signing ───────────────────────────────────────────────────────────────

/// Signs message with RSASSA-PKCS1-v1_5 / SHA-256 and returns base64url signature.
static std::string sign_rs256(EVP_PKEY* pkey, const std::string& message) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    std::string sig;
    size_t siglen = 0;

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1 ||
        EVP_DigestSignUpdate(ctx, message.data(), message.size()) != 1 ||
        EVP_DigestSignFinal(ctx, nullptr, &siglen) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    sig.resize(siglen);
    if (EVP_DigestSignFinal(
            ctx, reinterpret_cast<unsigned char*>(&sig[0]), &siglen) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    sig.resize(siglen);
    EVP_MD_CTX_free(ctx);

    return b64url_encode(
        reinterpret_cast<const unsigned char*>(sig.data()), sig.size());
}

/**
 * Builds a signed RS256 JWT with the given key ID, issued-at, and expiry.
 * The kid in the header lets verifiers look up the matching public key in JWKS.
 */
static std::string make_jwt(
        EVP_PKEY* pkey,
        const std::string& kid,
        std::int64_t iat,
        std::int64_t exp) {

    json header  = {{"alg","RS256"}, {"typ","JWT"}, {"kid", kid}};
    json payload = {{"sub","userABC"}, {"iss","jwks-server"}, {"iat", iat}, {"exp", exp}};

    std::string h = b64url_encode_str(header.dump());
    std::string p = b64url_encode_str(payload.dump());
    std::string signing_input = h + "." + p;
    std::string sig = sign_rs256(pkey, signing_input);
    return signing_input + "." + sig;
}

// ── Public JWK builder ────────────────────────────────────────────────────────

/// Extracts the public components (n, e) from an RSA key and formats them as JWK.
static json public_jwk(EVP_PKEY* pkey, const std::string& kid) {
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) return json::object();

    const BIGNUM *n = nullptr, *e = nullptr;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    RSA_get0_key(rsa, &n, &e, nullptr);
#else
    n = rsa->n; e = rsa->e;
#endif

    json jwk;
    jwk["kty"] = "RSA";
    jwk["use"] = "sig";
    jwk["alg"] = "RS256";
    jwk["kid"] = kid;
    jwk["n"]   = bn_to_b64url(n);
    jwk["e"]   = bn_to_b64url(e);

    RSA_free(rsa);
    return jwk;
}

// ── SQLite database layer ─────────────────────────────────────────────────────

/**
 * KeyDatabase manages all interactions with the SQLite DB.
 *
 * Table schema (exactly as required by the project spec):
 *   CREATE TABLE IF NOT EXISTS keys(
 *       kid INTEGER PRIMARY KEY AUTOINCREMENT,
 *       key BLOB NOT NULL,
 *       exp INTEGER NOT NULL
 *   )
 *
 * Private keys are stored as PEM-encoded BLOBs so they can be
 * deserialized on read. All INSERT statements use ? placeholders
 * to prevent SQL injection.
 */
class KeyDatabase {
public:
    explicit KeyDatabase(const char* path) : db_(nullptr) {
        if (sqlite3_open(path, &db_) != SQLITE_OK) {
            std::string err = sqlite3_errmsg(db_);
            sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("Cannot open DB: " + err);
        }
        create_table();
    }

    ~KeyDatabase() {
        if (db_) sqlite3_close(db_);
    }

    // Non-copyable
    KeyDatabase(const KeyDatabase&) = delete;
    KeyDatabase& operator=(const KeyDatabase&) = delete;

    /**
     * Inserts a PEM-encoded private key with its expiry timestamp.
     * Uses parameterized INSERT to prevent SQL injection.
     */
    void insert_key(const std::string& pem, std::int64_t exp) {
        const char* sql =
            "INSERT INTO keys (key, exp) VALUES (?, ?)";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db_));
        }

        // Bind PEM as BLOB (raw bytes, length explicit)
        sqlite3_bind_blob(stmt, 1, pem.data(), static_cast<int>(pem.size()),
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, exp);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    struct Row {
        std::int64_t kid;
        std::string  pem;
        std::int64_t exp;
    };

    /// Returns one valid (non-expired) key row, or an empty optional.
    std::vector<Row> fetch_valid_keys() {
        return fetch_where(false);
    }

    /// Returns one expired key row, or an empty optional.
    std::vector<Row> fetch_expired_keys() {
        return fetch_where(true);
    }

private:
    sqlite3* db_;

    /// Creates the keys table if it doesn't already exist.
    void create_table() {
        const char* sql =
            "CREATE TABLE IF NOT EXISTS keys("
            "    kid INTEGER PRIMARY KEY AUTOINCREMENT,"
            "    key BLOB NOT NULL,"
            "    exp INTEGER NOT NULL"
            ")";

        char* errmsg = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
            std::string err = errmsg;
            sqlite3_free(errmsg);
            throw std::runtime_error("Cannot create table: " + err);
        }
    }

    /**
     * Fetches rows from the keys table.
     * If expired=true, fetches rows where exp <= now (expired keys).
     * If expired=false, fetches rows where exp >  now (valid keys).
     * Uses parameterized queries to prevent SQL injection.
     */
    std::vector<Row> fetch_where(bool expired) {
        std::int64_t now = now_unix();
        const char* sql = expired
            ? "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1"
            : "SELECT kid, key, exp FROM keys WHERE exp >  ? LIMIT 1";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(db_));
        }

        sqlite3_bind_int64(stmt, 1, now);

        std::vector<Row> rows;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Row r;
            r.kid = sqlite3_column_int64(stmt, 0);

            // Read PEM blob
            const void* blob = sqlite3_column_blob(stmt, 1);
            int blen         = sqlite3_column_bytes(stmt, 1);
            r.pem            = std::string(static_cast<const char*>(blob),
                                           static_cast<std::size_t>(blen));
            r.exp            = sqlite3_column_int64(stmt, 2);
            rows.push_back(std::move(r));
        }
        sqlite3_finalize(stmt);
        return rows;
    }
};

// ── HTTP response helpers ─────────────────────────────────────────────────────

static void method_not_allowed(httplib::Response& res) {
    res.status = 405;
    res.set_content("Method Not Allowed", "text/plain");
}

static void internal_error(httplib::Response& res, const std::string& msg) {
    res.status = 500;
    json body = {{"error", msg}};
    res.set_content(body.dump(), "application/json");
}

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    // Open / create the SQLite database
    KeyDatabase db(DB_FILE);

    // Seed two keys on startup:
    //   1. A key that expires in 1 hour  (valid)
    //   2. A key that expired 1 hour ago (expired)
    // Keys are regenerated each run; the DB accumulates rows across restarts,
    // so there will always be at least one valid and one expired row.
    {
        std::int64_t now = now_unix();

        EVP_PKEY* valid_pkey = generate_rsa_2048();
        if (valid_pkey) {
            db.insert_key(pkey_to_pem(valid_pkey), now + 3600);
            EVP_PKEY_free(valid_pkey);
        }

        EVP_PKEY* expired_pkey = generate_rsa_2048();
        if (expired_pkey) {
            db.insert_key(pkey_to_pem(expired_pkey), now - 3600);
            EVP_PKEY_free(expired_pkey);
        }
    }

    httplib::Server svr;

    // ── GET /.well-known/jwks.json ────────────────────────────────────────────
    // Returns all non-expired public keys as a JWKS JSON object.
    svr.Get("/.well-known/jwks.json",
        [&](const httplib::Request&, httplib::Response& res) {
            try {
                auto rows = db.fetch_valid_keys();

                json out;
                out["keys"] = json::array();

                for (auto& row : rows) {
                    EVP_PKEY* pkey = pem_to_pkey(row.pem);
                    if (!pkey) continue;

                    std::string kid_str = std::to_string(row.kid);
                    out["keys"].push_back(public_jwk(pkey, kid_str));
                    EVP_PKEY_free(pkey);
                }

                res.status = 200;
                res.set_content(out.dump(), "application/json");
            } catch (const std::exception& ex) {
                internal_error(res, ex.what());
            }
        });

    // Disallow non-GET on JWKS
    svr.Post("/.well-known/jwks.json",
        [](const httplib::Request&, httplib::Response& res) {
            method_not_allowed(res); });
    svr.Put("/.well-known/jwks.json",
        [](const httplib::Request&, httplib::Response& res) {
            method_not_allowed(res); });
    svr.Delete("/.well-known/jwks.json",
        [](const httplib::Request&, httplib::Response& res) {
            method_not_allowed(res); });
    svr.Patch("/.well-known/jwks.json",
        [](const httplib::Request&, httplib::Response& res) {
            method_not_allowed(res); });

    // ── POST /auth ────────────────────────────────────────────────────────────
    // Issues a JWT. If ?expired is present, uses an expired key and sets
    // exp in the past so the token is verifiably expired.
    svr.Post("/auth",
        [&](const httplib::Request& req, httplib::Response& res) {
            try {
                bool want_expired = req.has_param("expired");

                auto rows = want_expired
                    ? db.fetch_expired_keys()
                    : db.fetch_valid_keys();

                if (rows.empty()) {
                    internal_error(res, "No suitable key found in database");
                    return;
                }

                auto& row = rows[0];
                EVP_PKEY* pkey = pem_to_pkey(row.pem);
                if (!pkey) {
                    internal_error(res, "Failed to deserialize key");
                    return;
                }

                std::int64_t now = now_unix();
                std::int64_t exp = want_expired ? (now - 3600) : (now + 3600);
                std::string  kid = std::to_string(row.kid);

                std::string token = make_jwt(pkey, kid, now, exp);
                EVP_PKEY_free(pkey);

                json body = {{"token", token}};
                res.status = 200;
                res.set_content(body.dump(), "application/json");
            } catch (const std::exception& ex) {
                internal_error(res, ex.what());
            }
        });

    // Disallow non-POST on /auth
    svr.Get("/auth",
        [](const httplib::Request&, httplib::Response& res) {
            method_not_allowed(res); });
    svr.Put("/auth",
        [](const httplib::Request&, httplib::Response& res) {
            method_not_allowed(res); });
    svr.Delete("/auth",
        [](const httplib::Request&, httplib::Response& res) {
            method_not_allowed(res); });
    svr.Patch("/auth",
        [](const httplib::Request&, httplib::Response& res) {
            method_not_allowed(res); });

    std::cout << "JWKS server listening on http://localhost:8080\n";
    std::cout << "  GET  /.well-known/jwks.json\n";
    std::cout << "  POST /auth\n";
    std::cout << "  POST /auth?expired\n";
    std::cout << "  DB:  " << DB_FILE << "\n";

    svr.listen("0.0.0.0", 8080);
    return 0;
}
