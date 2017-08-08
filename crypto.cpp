#include <QDebug>
#include <QFile>
extern "C" {
	#include <openssl/pem.h>
	#include <openssl/evp.h>
	#include <openssl/rand.h>
	#include <openssl/ecdsa.h>
}
#include "crypto.h"

Crypto::Crypto(QObject *parent):
    QObject(parent)
{
    qDebug() << "Crypto::Crypto";
	init();
}

Crypto::~Crypto() {
    qDebug() << "Crypto::~Crypto()";
	EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
	EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
	EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
	EVP_CIPHER_CTX_cleanup(aesDecryptCtx);

	free(rsaEncryptCtx);
	free(aesEncryptCtx);
	free(rsaDecryptCtx);
	free(aesDecryptCtx);

}

const QByteArray Crypto::iterativeHash(const QByteArray &input, const QByteArray &salt, const int iterations, const Crypto::HashType hashType) {
	unsigned char *out;
	const EVP_MD *md = getMD(hashType);
	int md_len = EVP_MD_size(md);
	static const char default_salt_value[] = "QtSimpleCrypto";
	QByteArray used_salt;
	if (salt.isEmpty())
        used_salt = QByteArray::fromRawData(default_salt_value, sizeof(default_salt_value));
	else
		used_salt = salt;

	out = (unsigned char *) malloc(sizeof(unsigned char) * md_len);

	/* qDebug() << "ITERATION:" << iterations;
	QDebug dbg(QtDebugMsg);
	dbg << "salt: ";
	for(i=0;i<sizeof(salt_value);i++) {
		dbg << qDebug("%02x", salt_value[i]);
	}
	dbg << '\n';*/
	if( PKCS5_PBKDF2_HMAC(input.constData(), input.length(), (const unsigned char*)used_salt.constData(), used_salt.length(), iterations, md, md_len, out) != 1 ) {
		qCritical() << "PKCS5_PBKDF2_HMAC_SHA1 failed";
		free(out);
		return QByteArray();
	}
	//printf("out: "); for(i=0;i<md_len;i++) { printf("%02x", out[i]); } printf("\n");
	QByteArray ret((const char *)out, md_len);
	free(out);
	return ret;
}

const QByteArray Crypto::asymmetricEncrypt(const QByteArray &input, const ASymmetricKey &key, const SymmetricKey::KeyType &symmetricKeyType) {
	unsigned char *encMsg;
	size_t encMsgLen = 0;
	size_t blockLen  = 0;
	unsigned char *ek;
	int ekl;
	unsigned char *iv;
	int ivl;
	if (key.ecdsaCryptCheck())
		return QByteArray();

	const EVP_CIPHER *cipher = SymmetricKey::getCipherS(symmetricKeyType);

	ekl=EVP_PKEY_size(key.getKey());
	//qDebug() << "ekl: " << ekl;
	ek = (unsigned char*)malloc(ekl);
	ivl = cipher->iv_len;
	//qDebug() << "ivl: " << ivl;
	iv = (unsigned char*)malloc(ivl);

	if(ek == NULL || iv == NULL)
		return QByteArray();

	encMsg = (unsigned char*)malloc(input.length() + cipher->iv_len);
	if(encMsg == NULL)
		return QByteArray();
	EVP_PKEY *pkey = key.getKey();
	if(!EVP_SealInit(rsaEncryptCtx, cipher, &ek, &ekl, iv, &pkey, 1)) {
		return QByteArray();
	}

	if(!EVP_SealUpdate(rsaEncryptCtx, encMsg + encMsgLen, (int*)&blockLen, (const unsigned char*)input.data(), input.length())) {
		return QByteArray();
	}
	encMsgLen += blockLen;

	if(!EVP_SealFinal(rsaEncryptCtx, encMsg + encMsgLen, (int*)&blockLen)) {
		return QByteArray();
	}
	encMsgLen += blockLen;

	EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);

	//Format: IV, EK, DATA
	QByteArray ret = QByteArray((const char *)iv, ivl) + QByteArray((const char *)ek, ekl) + QByteArray((const char *)encMsg, encMsgLen);
	free(iv);
	free(ek);
	free(encMsg);
	return ret;
}

const QByteArray Crypto::symmetricEncrypt(
		const QByteArray &input,
		const SymmetricKey &key) {
	size_t blockLen  = 0;
	size_t encMsgLen = 0;
	unsigned char *encMsg;
	qDebug() << "input: " << input.length();

	encMsg = (unsigned char*)malloc(input.length() + AES_BLOCK_SIZE);
	if(encMsg == NULL) return QByteArray();

	if(!EVP_EncryptInit_ex(aesEncryptCtx, key.getCipher(), NULL, key.getKey_c(), key.getIV_c())) {
		qCritical() << "EVP_EncryptInit_ex fail";
		return QByteArray();
	}

	if(!EVP_EncryptUpdate(aesEncryptCtx, encMsg, (int*)&blockLen, (unsigned char*)input.data(), input.length())) {
		qCritical() << "EVP_EncryptUpdate fail";
		return QByteArray();
	}
	encMsgLen += blockLen;

	if(!EVP_EncryptFinal_ex(aesEncryptCtx, encMsg + encMsgLen, (int*)&blockLen)) {
		qCritical() << "EVP_EncryptFinal_ex fail";
		return QByteArray();
	}
	encMsgLen += blockLen;

	EVP_CIPHER_CTX_cleanup(aesEncryptCtx);

	QByteArray ret((const char *)encMsg, encMsgLen);
	free(encMsg);
	return ret;
}

void Crypto::printSslErrors(QString message) {
	long err = ERR_get_error();
	ERR_load_ERR_strings();
	ERR_load_ECDSA_strings();
	ERR_load_ECDSA_strings();
	ERR_load_EVP_strings();

	qCritical() << "openssl error: " << message << ": " << ERR_error_string(err, NULL);
}

const QByteArray Crypto::asymmetricDecrypt(const QByteArray &encrypted, const ASymmetricKey &key, const SymmetricKey::KeyType &symmetricKeyType) {
	unsigned char *decMsg;
	size_t ekl, ivl, blockLen = 0, decLen = 0;
	const EVP_CIPHER *cipher;
	if (key.ecdsaCryptCheck())
		return QByteArray();
	if (encrypted.length() < 1) {
		qWarning() << "no data to decrypt";
		return QByteArray();
	}
	cipher = SymmetricKey::getCipherS(symmetricKeyType);
	//qDebug() << "decrypt";
	ekl = EVP_PKEY_size(key.getKey());
	//qDebug() << "asymmetric key length (ekl): " << ekl;
	ivl = cipher->iv_len;
	//qDebug() << "symmetric IV length (ivl): " << ivl;

	//Format: IV, EK, DATA
	//We must know the key type, so we know IV and EK length before opening encrypted blobs.
	QByteArray iv(encrypted.mid(0, ivl));
	QByteArray ek(encrypted.mid(ivl, ekl));
	QByteArray data(encrypted.mid(ivl + ekl));

	decMsg = (unsigned char*)malloc(data.length() + ivl);
	if(decMsg == NULL) return QByteArray();

	if(!EVP_OpenInit(rsaDecryptCtx, cipher, (unsigned char *)ek.data(), ekl, (unsigned char *)iv.data(), key.getKey())) {
		printSslErrors("EVP_OpenInit");
		return QByteArray();
	}

	if(!EVP_OpenUpdate(rsaDecryptCtx, (unsigned char*)decMsg + decLen, (int*)&blockLen, (const unsigned char *)data.data(), data.length())) {
		printSslErrors("EVP_OpenUpdate");
		return QByteArray();
	}
	decLen += blockLen;

	if(!EVP_OpenFinal(rsaDecryptCtx, (unsigned char*)decMsg + decLen, (int*)&blockLen)) {
		printSslErrors("EVP_OpenFinal");
		return QByteArray();
	}
	decLen += blockLen;

	EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
	QByteArray ret((const char *)decMsg, decLen);
	free(decMsg);
	return ret;
}

const QByteArray Crypto::symmetricDecrypt(const QByteArray &input, const SymmetricKey &key) {
	size_t decLen   = 0;
	size_t blockLen = 0;
	unsigned char *decMsg;
	QByteArray ret;

	decMsg = (unsigned char*)malloc(input.length());
	if(decMsg == NULL) return QByteArray();

	if(!EVP_DecryptInit_ex(aesDecryptCtx, key.getCipher(), NULL, key.getKey_c(), key.getIV_c())) {
		qWarning() << "EVP_DecryptInit_ex failed";
		goto error;
	}

	if(!EVP_DecryptUpdate(aesDecryptCtx, (unsigned char*)decMsg, (int*)&blockLen, (const unsigned char *)input.data(), input.length())) {
		qWarning() << "EVP_DecryptUpdate failed";
		goto error;
	}
	decLen += blockLen;

	if(!EVP_DecryptFinal_ex(aesDecryptCtx, (unsigned char*)decMsg + decLen, (int*)&blockLen)) {
		qWarning() << "EVP_DecryptFinal_ex failed";
		goto error;
	}
	decLen += blockLen;

	EVP_CIPHER_CTX_cleanup(aesDecryptCtx);
	ret = QByteArray((const char *)decMsg, decLen);
	free(decMsg);
	return ret;

error:
	free(decMsg);
	return ret;
}

const EVP_MD *Crypto::getMD(const Crypto::HashType &hashType) {
	if (hashType == Crypto::SHA160) {
		return EVP_sha1();
	} else if (hashType == Crypto::SHA256) {
		return EVP_sha256();
	} else if (hashType == Crypto::SHA512) {
		return EVP_sha512();
	} else {
		return NULL;
	}
}

const QByteArray Crypto::sign(const QByteArray &input, const ASymmetricKey &key, const Crypto::HashType &hashType)
{
	EVP_MD_CTX *mdctx = NULL;
	unsigned char *sig = NULL;
	const EVP_MD *md = NULL;
	bool success = false;
	size_t siglen;

	if (!key.hasPrivateKey()) {
		qCritical() << "Supplied ASymmetricKey doesn't have a private part, can't sign data with a public key.";
		return QByteArray();
	}

	try {
		if(!(mdctx = EVP_MD_CTX_create())) {
			qCritical() << "Failed to create message digest context";
			return QByteArray();
		}

		md = getMD(hashType);

		if(1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, key.getKey()))
			throw std::exception();
		if(1 != EVP_DigestSignUpdate(mdctx, (unsigned char *)input.constData(), input.length()))
			throw std::exception();

		/* Finalise the DigestSign operation */
		/* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
		 * signature. Length is returned in slen */
		if(1 != EVP_DigestSignFinal(mdctx, NULL, &siglen))
			throw std::exception();

		/* Allocate memory for the signature based on size in slen */
		if(!(sig = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char) * siglen)))
			throw std::exception();

		/* Obtain the signature */
		if(1 != EVP_DigestSignFinal(mdctx, sig, &siglen))
			throw std::exception();

		success = true;
	}
	catch (const std::exception &e) {

	}

	if(mdctx)
		EVP_MD_CTX_destroy(mdctx);
	QByteArray ret;
	if (success) {
		ret = QByteArray((const char *)sig, siglen);
	} else {
		qWarning() << "sign() failed";
	}
	OPENSSL_free(sig);

	return ret;
}

bool Crypto::verify(const QByteArray &data, const QByteArray &signature, const ASymmetricKey &key, const Crypto::HashType hashType)
{
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *md = NULL;
	bool success = false;

	if (!key.hasPublicKey()) {
		qCritical() << "Supplied ASymmetricKey doesn't have a public part (??? shouldn't be possible with openssl'), can't verify signature";
		return false;
	}

	try {
		if(!(mdctx = EVP_MD_CTX_create())) {
			qCritical() << "Failed to create message digest context";
			throw std::exception();
		}

		md = getMD(hashType);

		if(1 != EVP_DigestVerifyInit(mdctx, NULL, md, NULL, key.getKey()))
			throw std::exception();
		if(1 != EVP_DigestVerifyUpdate(mdctx, (unsigned char*)data.constData(), data.length()))
			throw std::exception();
		if(1 != EVP_DigestVerifyFinal(mdctx, (unsigned char*)signature.constData(), signature.length()))
			throw std::exception();
		qDebug() << "signature verified OK";
		success=true;
	} catch (const std::exception &e) {
		qDebug() << "signature verify fail";
	}

	if(mdctx)
		EVP_MD_CTX_destroy(mdctx);

	return success;
}

ASymmetricKey *Crypto::generateKeyPair(const ASymmetricKey::KeyType type)
{
	EVP_PKEY_CTX *ctx = NULL, *pctx = NULL;
	EVP_PKEY *params = NULL;
	ASymmetricKey *keyPair = NULL;
	qDebug() << "type=" << type;
	try {
		int nid = -1;
		if (type == ASymmetricKey::ECDSA384) {
			qDebug() << "ECDSA384";
			nid = NID_secp384r1;
		} else if (type == ASymmetricKey::ECDSA521) {
			qDebug() << "ECDSA521";
			nid = NID_secp521r1;
		}

		if (nid > 0) {
			qDebug() << "Generate parameters";
			pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
			if (!pctx) {
				qCritical() << "EVP_PKEY_CTX_new_id failed";
				throw(std::exception());
			}
			if (!EVP_PKEY_paramgen_init(pctx)) {
				qCritical() << "EVP_PKEY_paramgen_init failed";
				throw(std::exception());
			}


			if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) < 1) {
				qCritical() << "Problem with EVP_PKEY_CTX_set_ec_paramgen_curve_nid";
				throw(std::exception());
			}
			if (!EVP_PKEY_paramgen(pctx, &params)) {
				qCritical() << "Problem with EVP_PKEY_paramgen";
				throw(std::exception());
			}
		} else {
			qDebug() << "Parameter generation not required";
		}

		if (type == ASymmetricKey::RSA2048
				|| type == ASymmetricKey::RSA4096) {
			ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
		} else if (type == ASymmetricKey::ECDSA384
				   || type == ASymmetricKey::ECDSA521) {
			ctx = EVP_PKEY_CTX_new(params, NULL);
		} else {
			qCritical() << "Invalid crypto type";
			throw(std::exception());
		}

		if (!ctx) {
			qCritical() << "ctx is null";
			throw(std::exception());
		}

		if(EVP_PKEY_keygen_init(ctx) <= 0) {
			qCritical() << "keygen init failed";
			throw(std::exception());
		}

		if (type==ASymmetricKey::RSA2048 || type == ASymmetricKey::RSA4096) {
			int keyLen = ASymmetricKey::getAsyncKeyLengthBits(type);
			qDebug() << "Set RSA length to " << keyLen;
			if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keyLen) <= 0) {
				qCritical() << "set RSA length failed";
				throw(std::exception());
			}
		}

		EVP_PKEY *pkey = NULL;
		if(EVP_PKEY_keygen(ctx, &pkey) <= 0) {
			qCritical() << "keygen failed";
			throw(std::exception());
		}

		qDebug() << "Key pair generation successful";

		keyPair = new ASymmetricKey(pkey, type, true, true);
	}
	catch (const std::exception &e) {
	}

	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	if (pctx)
		EVP_PKEY_CTX_free(pctx);
	if (params)
		EVP_PKEY_free(params);
	return keyPair;
}

int Crypto::init() {
	// Initalize contexts
	rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	aesEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));

	rsaDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	aesDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));

	// Always a good idea to check if malloc failed
	if(rsaEncryptCtx == NULL || aesEncryptCtx == NULL || rsaDecryptCtx == NULL || aesDecryptCtx == NULL) {
		return FAILURE;
	}

	// Init these here to make valgrind happy
	EVP_CIPHER_CTX_init(rsaEncryptCtx);
	EVP_CIPHER_CTX_init(aesEncryptCtx);

	EVP_CIPHER_CTX_init(rsaDecryptCtx);
	EVP_CIPHER_CTX_init(aesDecryptCtx);

	return SUCCESS;
}

