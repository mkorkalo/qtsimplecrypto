#include "symmetrickey.h"
#include <QByteArray>
#include <QDebug>

class SymmetricKey::Private {
public:
	QByteArray key;
	QByteArray iv;
	SymmetricKey::KeyType type;
};

SymmetricKey::SymmetricKey(
		const QString &fromPassword,
		const KeyType &type,
		QObject *parent):
	QObject(parent)
{
	d=new Private;
	setFromPassword(fromPassword, type);
}
SymmetricKey::SymmetricKey(
		const QByteArray &fromPasswordBytes,
		const KeyType &type,
		QObject *parent):
	QObject(parent)
{
	d=new Private;
	setFromPasswordBytes(fromPasswordBytes, type);
}

SymmetricKey::~SymmetricKey()
{
	//we're going to zero the private data, just in case.
	//we don't trust Qt is going to do that for us.

	if (d->key.length()) {
		//qDebug() << "zero key";
		ZERO_BYTEARRAY(d->key);
	}
	if (d->iv.length()) {
		//qDebug() << "zero iv";
		ZERO_BYTEARRAY(d->iv);
	}
	delete d;
}

const unsigned char *SymmetricKey::getIV_c() const
{
	if (d->iv.length() < 1)
		return NULL;
	return (const unsigned char *) d->iv.constData();
}

const unsigned char *SymmetricKey::getKey_c() const
{
	if (d->key.length() < 1)
		return NULL;
	return (const unsigned char *) d->key.constData();
}

const EVP_CIPHER *SymmetricKey::getCipher() const
{
	return getCipherS(d->type);
}

const EVP_CIPHER *SymmetricKey::getCipherS(const SymmetricKey::KeyType &type)
{
	if (type == AES128)
		return EVP_aes_128_cbc();
	else if (type == AES256)
		return EVP_aes_256_cbc();
	else
		return NULL;
}

int SymmetricKey::setFromPasswordBytes(
		const QByteArray &fromPassword,
		const KeyType type) {
	unsigned char *key, *iv;
	int keyl, ivl;
	qDebug() << "passwordToAESKey using"<<fromPassword.length() << " byte password";
	if (passwordToAESKey(fromPassword, type, &key, &keyl, &iv, &ivl) != 0) {
		qCritical() << "passwordToAESKey failed";
		return 1;
	}
	d->key = QByteArray((const char *)key, keyl);
	d->iv = QByteArray((const char *)iv, ivl);
	d->type = type;
	free(iv);
	free(key);
	return 0;
}

int SymmetricKey::setFromPassword(
		const QString &fromPassword,
		const KeyType type) {
	if (fromPassword.length() < 1) {
		qCritical() << "Missing password";
		return -1;
	}
	return setFromPasswordBytes(fromPassword.toLocal8Bit(), type);
}

int SymmetricKey::passwordToAESKey(
		const QByteArray &password, const KeyType &type,
		unsigned char **key, int *keyl, unsigned char **iv, int *ivl)
{
	const EVP_CIPHER *cipher;
	const EVP_MD *dgst = NULL;
	const unsigned char *salt = NULL;
	qDebug() << "SymmetricEncryptionKey::passwordToAESKey";

	OpenSSL_add_all_algorithms();

	if (type == AES128)
		cipher = EVP_aes_128_cbc();
	else if (type == AES256)
		cipher = EVP_aes_256_cbc();
	else {
		qCritical() << "UNSUPPORTED SYMMETRIC CIPHER";
		return -1;
	}
	if(!cipher) {
		qCritical() << "Crypto::passwordToAESKey: no such cipher";
		return 1;
	}

	if (type == AES128)
		dgst=EVP_get_digestbyname("SHA1");
	else if (type == AES256)
		dgst=EVP_get_digestbyname("SHA256");
	else {
		qCritical() << "UNSUPPORTED HASH ALGORITHM";
		return -1;
	}

	if(!dgst) {
		qCritical() << "Crypto::passwordToAESKey: no such digest";
		return 1;
	}

	*ivl = cipher->iv_len;
	*keyl = cipher->key_len;
	//qDebug() << "keyl=" << (*keyl);
	//qDebug() << "ivl=" << (*ivl);

	*iv = (unsigned char*)malloc(*ivl);
	*key = (unsigned char*)malloc(*keyl);

	if (password.length() > (*keyl)) {
		qCritical() << "Too long password of "<<password.length()<< " bytes, key length "<<(*keyl) << " bytes. It doesn't make sense to use long passwords for this cipher, either use bigger cipher or shorted passwords.";
		return -1;
	}

	int i = EVP_BytesToKey(cipher, dgst, salt,
		(unsigned char *) password.constData(),
		password.length(), 1, *key, *iv);

	if (i != (*keyl)) {
		qCritical() << "Crypto::passwordToAESKey: EVP_BytesToKey failed: got "<<i << "expected" << (*keyl);
		return 1;
	}

	return 0;
}

