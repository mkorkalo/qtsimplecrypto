/*
 * Represents a symmetric encryption key such as AES.
 * Can create keys from passwords.
 * Author: Mikko Korkalo
 */

#ifndef SYMMETRICENCRYPTIONKEY_H
#define SYMMETRICENCRYPTIONKEY_H

#include <QObject>
extern "C" {
	#include <openssl/pem.h>
	#include <openssl/rand.h>
}
#include "qtsimplecrypto_global.h"

/*! \brief Used to encrypt/decrypt data usign AES or alike.
 *
 *  Used to derive symmetric key from a shared password, and then to decrypt
 *  or encrypt data.
 */
class QTSIMPLECRYPTOSHARED_EXPORT SymmetricKey : public QObject
{
	Q_OBJECT
	Q_ENUMS(KeyType)

public:
	enum KeyType {
		AES128 = 0,		//combined with SHA1 when derived from password
		AES256 = 1		//combined with SHA256 when derived from password
	};

	/*! \brief Creates a new SymmetricKey from string password.*/
	SymmetricKey(
			const QString &fromPassword,
			const KeyType &type,
			QObject *parent = 0);

	/*! \brief Creates a new SymmetricKey from byte array, i.e. precalculated hash.*/
	SymmetricKey(const QByteArray &fromPasswordBytes,
				 const KeyType &type,
				 QObject *parent = 0);

	/*! \brief Destructor. Will zero out any private keys securely. */
	~SymmetricKey();

	/*! \brief Gets the encryption key IV as byte array.*/
	const QByteArray getIV();

	/*! \brief Gets the encryption key as byte array.*/
	const QByteArray getKey();
	const unsigned char *getIV_c() const;
	const unsigned char *getKey_c() const;

	/*! \brief Gets the OpenSSL EVP_CIPHER.*/
	const EVP_CIPHER *getCipher() const;

	/*! \brief Gets the OpenSSL EVP_CIPHER based on key type.*/
	static const EVP_CIPHER *getCipherS(const KeyType &type);
signals:

public slots:
private:
	class Private;
	Private *d;
	int setFromPassword(
			const QString &fromPassword,
			const KeyType type);
	int setFromPasswordBytes(const QByteArray &fromPassword, const KeyType type);
	static int passwordToAESKey(const QByteArray &password,
			const KeyType &type,
			unsigned char **key,
			int *keyl,
			unsigned char **iv,
			int *ivl);


};

#endif // SYMMETRICENCRYPTIONKEY_H
