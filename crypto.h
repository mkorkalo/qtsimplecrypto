#ifndef CRYPTO_H
#define CRYPTO_H

#include <QObject>
extern "C" {
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
}
#include "symmetrickey.h"
#include "asymmetrickey.h"
#include "qtsimplecrypto_global.h"

#define SUCCESS 0
#define FAILURE -1

class QTSIMPLECRYPTOSHARED_EXPORT Crypto : public QObject {
	Q_OBJECT
	Q_ENUMS(HashType)

public:
	enum HashType {
		SHA160,
		SHA256,
		SHA512
	};

	Crypto(QObject *parent = 0);
	~Crypto();

	const QByteArray myPublicKey(const QByteArray hash);
	//const QByteArray myPrivateKey(const QByteArray hash);

	/*! \brief Encrypts data using recipients public key, such as RSA, and a random generated symmetric key.*/
	const QByteArray asymmetricEncrypt(const QByteArray &input, const ASymmetricKey &key, const SymmetricKey::KeyType &symmetricKeyType);

	/*! \brief Decrypts data using recipients private key, such as RSA, and the temporary symmetric key included in data.*/
	const QByteArray asymmetricDecrypt(const QByteArray &encrypted, const ASymmetricKey &key, const SymmetricKey::KeyType &symmetricKeyType);

	/*! \brief Encrypts data using a symmetric key such as AES. Could be a key generated from password.*/
	const QByteArray symmetricEncrypt(const QByteArray &input, const SymmetricKey &key);

	/*! \brief Decrypts data using a symmetric key such as AES. Could be a key generated from password.*/
	const QByteArray symmetricDecrypt(const QByteArray &input, const SymmetricKey &key);

	/*! \brief Signs data using asymmetric key such as RSA.
	*
	* Data will be hashed, hash will be encrypted using signer's *private key*.
	*/
	const QByteArray sign(const QByteArray &input, const ASymmetricKey &key, const HashType &hashType);

	/*! \brief Verifies signature using asymmetric key such as RSA.
	*
	* Data will be hashed, signature will be decrypted using signer's *public key*.
	* After this hashes are compared; if they match, return true, otherwise false.
	*/
	bool verify(const QByteArray &data, const QByteArray &signature, const ASymmetricKey &key, const HashType hashType);

	/*! \brief Generates an asymmetric keypair, such as RSA.*/
	static ASymmetricKey *generateKeyPair(const ASymmetricKey::KeyType type);

	/*! \brief Hashes input data using OpenSSL PKCS5_PBKDF2_HMAC method. Salt can be left empty, in which case default salt is used.*/
	const QByteArray iterativeHash(const QByteArray &input, const QByteArray &salt, const int iterations, const Crypto::HashType hashType);

private:
	static const EVP_MD *getMD(const Crypto::HashType &hashType);
	EVP_PKEY *remotePubKey;

	EVP_CIPHER_CTX *rsaEncryptCtx;
	EVP_CIPHER_CTX *aesEncryptCtx;

	EVP_CIPHER_CTX *rsaDecryptCtx;
	EVP_CIPHER_CTX *aesDecryptCtx;

	int init();

	void printSslErrors(QString message);
};

#endif
