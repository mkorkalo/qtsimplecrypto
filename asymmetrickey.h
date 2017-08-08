#ifndef ASYMMETRICENCRYPTIONKEY_H
#define ASYMMETRICENCRYPTIONKEY_H

#include <QObject>
#include <QIODevice>
extern "C" {
	#include <openssl/pem.h>
	#include <openssl/rand.h>
}
#include "qtsimplecrypto_global.h"
#include "symmetrickey.h"

#define QTSIMPLECRYPTO_DEFAULT_PRIVATE_KEY_HASH_ITERATIONS 12

/*! \brief Represents ASymmetric Cryptography object used to encrypt/decrypt data.
 *
 *  Can do encryption/decryption using a combination of i.e. RSA and AES.
 */
class QTSIMPLECRYPTOSHARED_EXPORT ASymmetricKey : public QObject
{
	Q_OBJECT
	Q_ENUMS(KeyType)
public:
	enum KeyType {
        RSA2048 = 0,
		RSA4096 = 1,	//recommended for messaging
		ECDSA384 = 2,	//only for sign/verify
		ECDSA521 = 3	//only for sign/verify
	};

	/*! \brief Create a new ASymmetricKey from EVP_PKEY object.*/
	ASymmetricKey(EVP_PKEY *key, const KeyType &type, bool hasPrivateKey, bool hasPublicKey, QObject *parent = 0);

	/*! \brief Create a blank ASymmetricKey.*/
	ASymmetricKey(QObject *parent = 0);

	/*! \brief Destructor. Will zero out any private keys securely. */
	~ASymmetricKey();

	/*! \brief Is the object valid, i.e. is the key usable.*/
	bool isValid() const;

	/*! \brief Does the object contain a public key. */
	bool hasPublicKey() const;

	/*! \brief Does the object contain a private key. */
	bool hasPrivateKey() const;

	/*! \brief change the default symmetric key type used for public/private key encryption */
	void setSymmetricKeyType(const SymmetricKey::KeyType &type);

	/*! \brief Gets the OpenSSL EVP_PKEY pointer.*/
	EVP_PKEY *getKey() const;

	/*! \brief Loads encrypted private key from file.*/
	static ASymmetricKey *fromPrivateKeyFile(const QString &path, const KeyType &type, const QByteArray &hash, void *crypto, const int iterations);

	/*! \brief Decrypts an encrypted private key from byte array.*/
	static ASymmetricKey *decryptPrivateKey(const QByteArray &encrypted, const QByteArray &password, void *crypto, const KeyType type, const int iterations);

	/*! \brief Loads plain private key from byte array.*/
	static ASymmetricKey *fromPrivateKeyBytes(const QByteArray &privateKey, const KeyType &type);

	/*! \brief Loads plain public key from file.*/
	static ASymmetricKey *fromPublicKeyFile(const QString &path, const KeyType &type);

	/*! \brief Loads plain public key from byte array.*/
	static ASymmetricKey *fromPublicKeyBytes(const QByteArray &pubkey, const KeyType &type);
    static int getAsyncKeyLength(const KeyType &type);
	static int getAsyncKeyLengthBits(const KeyType &type);

	/*! \brief Saves the private key in file in encrypted format.*/
	bool savePrivateKeyFile(const QString &destinationPath, const QByteArray &password, void *crypto, const int iterations) const;

    /*! \brief Saves the public key in file.*/
    bool savePublicKeyFile(const QString &destinationPath) const;

	/*! \brief Encrypts the private key into byte array.*/
	const QByteArray encryptPrivateKey(const QByteArray &password, void *crypto, const int iterations) const;

	/*! \brief Gets the private key as byte array. This is unencrypted, so
				be careful when saving the bytearray.*/
	const QByteArray getPrivateKeyBytes() const;

	/*! \brief Gets the public key as byte array.*/
	const QByteArray getPublicKeyBytes() const;

	/*! \brief Gets the key type, i.e. AES256.*/
	KeyType getType() const;

	/*! \brief Checks if the keytype is ECDSA, and prints out a warning that ECDSA cannot be used to encrypt/decrypt. Only to sign and verify. */
	bool ecdsaCryptCheck() const;
signals:

public slots:
private:
	class Private;
	Private *d;
};

#endif // ASYMMETRICENCRYPTIONKEY_H
