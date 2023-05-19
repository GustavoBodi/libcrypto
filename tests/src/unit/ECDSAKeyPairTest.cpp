#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/ECDSAKeyPair.h>
#include <libcryptosec/KeyPair.h>
#include <libcryptosec/ByteArray.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <sstream>
#include <gtest/gtest.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>

class ECDSAKeyPairTest: public ::testing::Test {
  protected:
    virtual void SetUp() {

    }

    virtual void TearDown() {

    }

    //ECDSAKeyPair genKeysFromCurve() {
    //  EllipticCurve curve = EllipticCurve();
    //  ECDSAKeyPair chave (curve);
    //  return chave;
    //}

    ECDSAKeyPair genKeysFromNamedCurve() {
      ECDSAKeyPair chave (AsymmetricKey::BRAINPOOL_P256R1);
      return chave;
    }


    void getAlgoTest(ECDSAKeyPair pair) {
      ASSERT_EQ(pair.getAlgorithm(), AsymmetricKey::ECDSA);
    }

    void testValidGen(ECDSAKeyPair pair) {
      std::string private_key { pair.getPrivateKey()->getPemEncoded() };
      BIO *bo = BIO_new( BIO_s_mem() );
      BIO_write(bo, private_key.c_str(), private_key.length());
      EC_KEY *priv_key { EC_KEY_new() };
      PEM_read_bio_ECPrivateKey(bo, &priv_key, nullptr, nullptr);

      // Now for the public key
      std::string public_key { pair.getPublicKey()->getPemEncoded() };
      BIO *bo_pub { BIO_new( BIO_s_mem() ) };
      BIO_write(bo_pub, public_key.c_str(), public_key.length());
      EC_KEY *pub_key { EC_KEY_new() };
      PEM_read_bio_EC_PUBKEY(bo_pub, &pub_key, nullptr, nullptr);
      // Checking if the generated key is valid

      
      //ASSERT_TRUE( BN_cmp(n_pub, n_priv) == 0 );
    }

    void testSizeBits(ECDSAKeyPair keys) {
      ASSERT_EQ(keys.getPrivateKey()->getSizeBits(), size);
      ASSERT_EQ(keys.getPublicKey()->getSizeBits(), size);
    }

    void testSizeBytes(ECDSAKeyPair keys) {
      ASSERT_EQ(keys.getPrivateKey()->getSize(), 72);
      ASSERT_EQ(keys.getPublicKey()->getSize(), 72);
    }

    void pemSanityTest(ECDSAKeyPair pair) {
      std::string priv_key = pair.getPemEncoded();
      ASSERT_EQ(priv_key, pair.getPrivateKey()->getPemEncoded());
    }

    void derSanityTest(ECDSAKeyPair pair) {
      ByteArray priv_key = pair.getDerEncoded();
      ASSERT_EQ(priv_key, pair.getPrivateKey()->getDerEncoded());
    }

    void evpSanityTest(ECDSAKeyPair pair) {
      EVP_PKEY *key = pair.getEvpPkey();
      ASSERT_EQ(key, pair.getPrivateKey()->getEvpPkey());
    }

    static int size;
    static std::string pem_key;
    static std::string pem_key_pass;
    static ByteArray pass;
};

int ECDSAKeyPairTest::size {256};

ByteArray ECDSAKeyPairTest::pass { "12345" };

std::string ECDSAKeyPairTest::pem_key {"-----BEGIN PRIVATE KEY-----\n" \
"MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgJzF+xTug88/hzy2coPRh\n" \
"tA9t4XZjzWGc3eBW5PtaYAmhRANCAATA/DHmG44GnELQGrNYaqyFewUJzJpU/9mT\n" \
"5uUgpJSMx3q4IdzbYhF8ZVNdnLwEJ7TQdayE4hoFNPh2rmsva1FJ\n" \
"-----END PRIVATE KEY-----\n" };
//std::string ECDSAKeyPairTest::pem_key_pass { "-----BEGIN EC PRIVATE KEY-----\n" \
//"Proc-Type: 4,ENCRYPTED\n" \
//"DEK-Info: AES-256-CBC,4065373A17B5C0AD827303D726753DB2\n" \
//"\n" \
//"Y4lsqUhsAESA5BZ6UFRD6NMqj3qs6gh7mUcIL4ofItk/Ubl9bKx1hYWTAoAUk9fm\n" \
//"Zzn8IhNSBusx3pILYJpdwlXGPmz/4kKGTLk+XSwBCAH8dianCFlr1W0bp7CZWwYf\n" \
//"/jcBx7tP4SEvdXR8MNJv2TBrDleC6QmMGM4i8Eir1CQ=\n" \
//"-----END EC PRIVATE KEY-----\n" };

TEST_F(ECDSAKeyPairTest, GenKey) {
  genKeysFromNamedCurve();
}

TEST_F(ECDSAKeyPairTest, GeneratedKeyTest) {
  testValidGen(genKeysFromNamedCurve());
}

TEST_F(ECDSAKeyPairTest, AlgorithmTest) {
  getAlgoTest(genKeysFromNamedCurve());
}

TEST_F(ECDSAKeyPairTest, EvpSanityTest) {
  evpSanityTest( genKeysFromNamedCurve() );
}

TEST_F(ECDSAKeyPairTest, genKeyFromNamedCurveTest) {
  genKeysFromNamedCurve();
}

TEST_F(ECDSAKeyPairTest, DerSanityTest) {
  derSanityTest( genKeysFromNamedCurve() );
}

TEST_F(ECDSAKeyPairTest, PemSanityTest) {
  pemSanityTest( genKeysFromNamedCurve() );
}

TEST_F(ECDSAKeyPairTest, SizeTestBitsEq) {
  testSizeBits( genKeysFromNamedCurve() );
}

TEST_F(ECDSAKeyPairTest, SizeTestBytesEq) {
  testSizeBytes( genKeysFromNamedCurve() );
}

