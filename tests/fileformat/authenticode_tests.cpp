/**
* @file tests/fileformat/authenticode_tests.cpp
* @brief Tests for the bundled authenticode-parser library.
* @copyright (c) 2024 Avast Software, licensed under the MIT license
*
* The signatures are generated here with OpenSSL, so the tests need no binary
* fixtures. They cover the places where the parser reads ASN.1 strings, which
* became opaque types in OpenSSL 4.
*/

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <authenticode-parser/authenticode.h>

using namespace ::testing;

namespace retdec {
namespace fileformat {
namespace tests {

namespace {

using Bytes = std::vector<unsigned char>;

const char* SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4";
const char* SPC_SP_OPUS_INFO_OID = "1.3.6.1.4.1.311.2.1.12";
const int64_t COUNTERSIGNATURE_TIME = 1700000000;

template <typename T, void (*Free)(T*)>
struct Freer
{
	void operator()(T* p) const { Free(p); }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, Freer<EVP_PKEY, EVP_PKEY_free>>;
using X509Ptr = std::unique_ptr<X509, Freer<X509, X509_free>>;
using Pkcs7Ptr = std::unique_ptr<PKCS7, Freer<PKCS7, PKCS7_free>>;
using AuthPtr = std::unique_ptr<AuthenticodeArray, Freer<AuthenticodeArray, authenticode_array_free>>;

Bytes der(unsigned char tag, const Bytes& body)
{
	Bytes out{tag};
	if (body.size() < 0x80)
	{
		out.push_back(static_cast<unsigned char>(body.size()));
	}
	else
	{
		out.push_back(0x82);
		out.push_back(static_cast<unsigned char>(body.size() >> 8));
		out.push_back(static_cast<unsigned char>(body.size() & 0xff));
	}
	out.insert(out.end(), body.begin(), body.end());
	return out;
}

Bytes concat(std::initializer_list<Bytes> parts)
{
	Bytes out;
	for (const auto& p : parts)
	{
		out.insert(out.end(), p.begin(), p.end());
	}
	return out;
}

Bytes sha256(const unsigned char* data, size_t len)
{
	Bytes out(EVP_MAX_MD_SIZE);
	unsigned int outLen = 0;
	EVP_Digest(data, len, out.data(), &outLen, EVP_sha256(), nullptr);
	out.resize(outLen);
	return out;
}

Bytes toBytes(const ByteArray& a)
{
	return a.data ? Bytes(a.data, a.data + a.len) : Bytes{};
}

PkeyPtr generateKey()
{
	std::unique_ptr<EVP_PKEY_CTX, Freer<EVP_PKEY_CTX, EVP_PKEY_CTX_free>> ctx(
			EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
	EVP_PKEY* key = nullptr;
	if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0
			|| EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0
			|| EVP_PKEY_keygen(ctx.get(), &key) <= 0)
	{
		return nullptr;
	}
	return PkeyPtr(key);
}

X509Ptr generateCertificate(EVP_PKEY* key)
{
	X509Ptr cert(X509_new());
	X509_set_version(cert.get(), 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 0x1234);
	X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60 * 60 * 24 * 365);
	X509_set_pubkey(cert.get(), key);

	std::unique_ptr<X509_NAME, Freer<X509_NAME, X509_NAME_free>> name(X509_NAME_new());
	auto add = [&](const char* field, const char* value) {
		X509_NAME_add_entry_by_txt(name.get(), field, MBSTRING_ASC,
				reinterpret_cast<const unsigned char*>(value), -1, -1, 0);
	};
	add("C", "CZ");
	add("O", "RetDec Test Org");
	add("CN", "RetDec Test Signer");
	add("serialNumber", "SN-42");
	X509_set_subject_name(cert.get(), name.get());
	X509_set_issuer_name(cert.get(), name.get());

	X509_sign(cert.get(), key, EVP_sha256());
	return cert;
}

/**
 * Everything needed to inspect a generated signature.
 */
struct TestSignature
{
	Bytes blob;            // DER of the PKCS7 structure.
	Bytes fileDigest;      // Digest stored in SpcIndirectDataContent.
	Bytes signerDigest;    // Expected messageDigest of the signer.
	bool ok = false;
};

/**
 * Builds a PKCS7 signature shaped like the ones found in signed PE files.
 */
TestSignature buildSignature(bool withCountersignature)
{
	TestSignature result;

	initialize_authenticode_parser();

	auto key = generateKey();
	if (!key)
	{
		return result;
	}
	auto cert = generateCertificate(key.get());

	// SpcIndirectDataContent: { SpcAttributeTypeAndOptionalValue, DigestInfo }.
	result.fileDigest = Bytes(32);
	for (size_t i = 0; i < result.fileDigest.size(); ++i)
	{
		result.fileDigest[i] = static_cast<unsigned char>(0xA0 + i);
	}
	const Bytes spcPeImageDataOid = {0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F};
	const Bytes sha256Oid = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
	const Bytes inner = concat({
		der(0x30, concat({spcPeImageDataOid, der(0x30, {})})),
		der(0x30, concat({
			der(0x30, concat({sha256Oid, Bytes{0x05, 0x00}})),
			der(0x04, result.fileDigest)
		}))
	});
	const Bytes content = der(0x30, inner);
	result.signerDigest = sha256(inner.data(), inner.size());

	Pkcs7Ptr p7(PKCS7_new());
	PKCS7_set_type(p7.get(), NID_pkcs7_signed);
	PKCS7_content_new(p7.get(), NID_pkcs7_data);
	PKCS7_set_detached(p7.get(), 1);
	PKCS7_add_certificate(p7.get(), cert.get());

	PKCS7_SIGNER_INFO* si = PKCS7_add_signature(p7.get(), cert.get(), key.get(), EVP_sha256());
	if (!si)
	{
		return result;
	}
	PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,
			OBJ_txt2obj(SPC_INDIRECT_DATA_OID, 1));

	// SpcSpOpusInfo with programName "Test" (UTF-16BE).
	const Bytes opus = der(0x30, der(0xA0, der(0x80, {0x00, 'T', 0x00, 'e', 0x00, 's', 0x00, 't'})));
	ASN1_STRING* opusStr = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
	ASN1_STRING_set(opusStr, opus.data(), static_cast<int>(opus.size()));
	PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_SP_OPUS_INFO_OID), V_ASN1_SEQUENCE, opusStr);

	// The signer digest is computed over the content without its outer header.
	BIO* contentBio = BIO_new_mem_buf(inner.data(), static_cast<int>(inner.size()));
	BIO* p7bio = PKCS7_dataInit(p7.get(), contentBio);
	if (!p7bio)
	{
		BIO_free(contentBio);
		return result;
	}
	char buf[512];
	while (BIO_read(p7bio, buf, sizeof(buf)) > 0)
	{
	}
	const bool finalized = PKCS7_dataFinal(p7.get(), p7bio) == 1;
	BIO_free_all(p7bio);
	if (!finalized)
	{
		return result;
	}

	if (withCountersignature)
	{
		PKCS7_SIGNER_INFO* cs = PKCS7_SIGNER_INFO_new();
		PKCS7_SIGNER_INFO_set(cs, cert.get(), key.get(), EVP_sha256());

		PKCS7_add_signed_attribute(cs, NID_pkcs9_contentType, V_ASN1_OBJECT,
				OBJ_nid2obj(NID_pkcs7_data));
		ASN1_UTCTIME* time = ASN1_UTCTIME_set(nullptr, COUNTERSIGNATURE_TIME);
		PKCS7_add_signed_attribute(cs, NID_pkcs9_signingTime, V_ASN1_UTCTIME, time);

		const Bytes sigDigest = sha256(ASN1_STRING_get0_data(si->enc_digest),
				ASN1_STRING_length(si->enc_digest));
		ASN1_OCTET_STRING* md = ASN1_OCTET_STRING_new();
		ASN1_OCTET_STRING_set(md, sigDigest.data(), static_cast<int>(sigDigest.size()));
		PKCS7_add_signed_attribute(cs, NID_pkcs9_messageDigest, V_ASN1_OCTET_STRING, md);

		if (PKCS7_SIGNER_INFO_sign(cs) != 1)
		{
			PKCS7_SIGNER_INFO_free(cs);
			return result;
		}

		unsigned char* csDer = nullptr;
		const int csLen = i2d_PKCS7_SIGNER_INFO(cs, &csDer);
		PKCS7_SIGNER_INFO_free(cs);
		if (csLen <= 0)
		{
			return result;
		}
		ASN1_STRING* csStr = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
		ASN1_STRING_set(csStr, csDer, csLen);
		OPENSSL_free(csDer);
		PKCS7_add_attribute(si, NID_pkcs9_countersignature, V_ASN1_SEQUENCE, csStr);
	}

	// Replace the detached data content with the Authenticode one.
	PKCS7* contents = p7->d.sign->contents;
	contents->type = OBJ_txt2obj(SPC_INDIRECT_DATA_OID, 1);
	contents->d.other = ASN1_TYPE_new();
	ASN1_STRING* contentStr = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
	ASN1_STRING_set(contentStr, content.data(), static_cast<int>(content.size()));
	ASN1_TYPE_set(contents->d.other, V_ASN1_SEQUENCE, contentStr);

	const int len = i2d_PKCS7(p7.get(), nullptr);
	if (len <= 0)
	{
		return result;
	}
	result.blob.resize(len);
	unsigned char* out = result.blob.data();
	i2d_PKCS7(p7.get(), &out);
	result.ok = true;
	return result;
}

AuthPtr parse(const Bytes& blob)
{
	return AuthPtr(authenticode_new(blob.data(), static_cast<int32_t>(blob.size())));
}

} // anonymous namespace

/**
 * Tests for the @c authenticode-parser library.
 */
class AuthenticodeTests : public Test {};

TEST_F(AuthenticodeTests, ParsesSignatureContentAndSignerDigests)
{
	auto sig = buildSignature(false);
	ASSERT_TRUE(sig.ok);

	auto result = parse(sig.blob);
	ASSERT_NE(result, nullptr);
	ASSERT_EQ(1u, result->count);
	const Authenticode* auth = result->signatures[0];

	// A valid signature means the signed content bytes were read correctly.
	EXPECT_EQ(0, auth->verify_flags);

	ASSERT_NE(auth->digest_alg, nullptr);
	EXPECT_EQ("sha256", std::string(auth->digest_alg));
	EXPECT_EQ(sig.fileDigest, toBytes(auth->digest));

	ASSERT_NE(auth->signer, nullptr);
	ASSERT_NE(auth->signer->digest_alg, nullptr);
	EXPECT_EQ("sha256", std::string(auth->signer->digest_alg));
	EXPECT_EQ(sig.signerDigest, toBytes(auth->signer->digest));
}

TEST_F(AuthenticodeTests, ParsesProgramName)
{
	auto sig = buildSignature(false);
	ASSERT_TRUE(sig.ok);

	auto result = parse(sig.blob);
	ASSERT_NE(result, nullptr);
	ASSERT_EQ(1u, result->count);
	const Authenticode* auth = result->signatures[0];

	ASSERT_NE(auth->signer, nullptr);
	ASSERT_NE(auth->signer->program_name, nullptr);
	EXPECT_EQ("Test", std::string(auth->signer->program_name));
}

TEST_F(AuthenticodeTests, ParsesCertificateNameAttributes)
{
	auto sig = buildSignature(false);
	ASSERT_TRUE(sig.ok);

	auto result = parse(sig.blob);
	ASSERT_NE(result, nullptr);
	ASSERT_EQ(1u, result->count);
	const Authenticode* auth = result->signatures[0];

	ASSERT_NE(auth->certs, nullptr);
	ASSERT_EQ(1u, auth->certs->count);
	const Attributes& subject = auth->certs->certs[0]->subject_attrs;

	EXPECT_EQ(Bytes({'C', 'Z'}), toBytes(subject.country));
	EXPECT_EQ(Bytes({'R', 'e', 't', 'D', 'e', 'c', ' ', 'T', 'e', 's', 't', ' ', 'O', 'r', 'g'}),
			toBytes(subject.organization));
	const std::string cn = "RetDec Test Signer";
	EXPECT_EQ(Bytes(cn.begin(), cn.end()), toBytes(subject.commonName));
	const std::string serial = "SN-42";
	EXPECT_EQ(Bytes(serial.begin(), serial.end()), toBytes(subject.serialNumber));
}

TEST_F(AuthenticodeTests, DetectsModifiedFileDigest)
{
	auto sig = buildSignature(false);
	ASSERT_TRUE(sig.ok);

	// Corrupt the stored file digest, which the signature covers.
	auto it = std::search(sig.blob.begin(), sig.blob.end(),
			sig.fileDigest.begin(), sig.fileDigest.end());
	ASSERT_NE(sig.blob.end(), it);
	*it ^= 0xFF;

	auto result = parse(sig.blob);
	ASSERT_NE(result, nullptr);
	ASSERT_EQ(1u, result->count);
	EXPECT_EQ(AUTHENTICODE_VFY_INVALID, result->signatures[0]->verify_flags);
}

TEST_F(AuthenticodeTests, ParsesAndVerifiesPkcs9Countersignature)
{
	auto sig = buildSignature(true);
	ASSERT_TRUE(sig.ok);

	auto result = parse(sig.blob);
	ASSERT_NE(result, nullptr);
	ASSERT_EQ(1u, result->count);
	const Authenticode* auth = result->signatures[0];

	ASSERT_NE(auth->countersigs, nullptr);
	ASSERT_EQ(1u, auth->countersigs->count);
	const Countersignature* cs = auth->countersigs->counters[0];

	EXPECT_EQ(0, cs->verify_flags);
	EXPECT_EQ(COUNTERSIGNATURE_TIME, cs->sign_time);
	ASSERT_NE(cs->digest_alg, nullptr);
	EXPECT_EQ("sha256", std::string(cs->digest_alg));
	EXPECT_EQ(32, cs->digest.len);
}

TEST_F(AuthenticodeTests, RejectsGarbageInput)
{
	const Bytes garbage = {0x01, 0x02, 0x03, 0x04};

	auto result = parse(garbage);
	ASSERT_NE(result, nullptr);
	ASSERT_EQ(1u, result->count);
	EXPECT_EQ(AUTHENTICODE_VFY_CANT_PARSE, result->signatures[0]->verify_flags);
}

} // namespace tests
} // namespace fileformat
} // namespace retdec
