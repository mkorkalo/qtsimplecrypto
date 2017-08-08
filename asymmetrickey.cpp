#include <QDebug>
#include <QFile>
extern "C" {
	#include <openssl/err.h>
	#include <openssl/pem.h>
}
#include "asymmetrickey.h"
#include "crypto.h"

class ASymmetricKey::Private {
public:
	EVP_PKEY *key;
	ASymmetricKey::KeyType type;
	bool hasPrivateKey;
	bool hasPublicKey;
};

ASymmetricKey::ASymmetricKey(EVP_PKEY *key, const KeyType &type, bool hasPrivateKey, bool hasPublicKey, QObject *parent) :
	QObject(parent)
{
	d = new Private;
	d->key = key;
	d->type = type;
	d->hasPrivateKey = hasPrivateKey;
	d->hasPublicKey = hasPublicKey;
}
ASymmetricKey::ASymmetricKey(QObject *parent) :
	QObject(parent)
{
	d = new Private;
	d->key = NULL;
	d->hasPrivateKey=false;
	d->hasPublicKey=false;
}

ASymmetricKey::~ASymmetricKey()
{
	if (d->key) {
		EVP_PKEY_free(d->key);
	}
	delete d;
	qDebug() << "ASymmetricKey object was deleted successfully";
}

bool ASymmetricKey::isValid() const
{
	return d->key != NULL;
}

bool ASymmetricKey::hasPublicKey() const
{
	return d->hasPublicKey;
}

bool ASymmetricKey::hasPrivateKey() const
{
	return d->hasPrivateKey;
}

EVP_PKEY *ASymmetricKey::getKey() const
{
	return d->key;
}

bool ASymmetricKey::ecdsaCryptCheck() const {
	if (d->type == ASymmetricKey::ECDSA384 || d->type == ASymmetricKey::ECDSA521) {
		qCritical() << "ECDSA cannot be used to encrypt";
		return true;
	}
	return false;
}

const QByteArray ASymmetricKey::encryptPrivateKey(const QByteArray &password, void *crypto, const int iterations) const {
	if (!crypto || password.length() < 1) {
		qCritical() << "Missing arguments";
		return QByteArray();
	}
	Crypto *c = (Crypto*) crypto;
	int use_iterations;
	if (iterations > 1)
		use_iterations = iterations;
	else
		use_iterations = QTSIMPLECRYPTO_DEFAULT_PRIVATE_KEY_HASH_ITERATIONS;

	const QByteArray newpassword = c->iterativeHash(password, QByteArray(), use_iterations, Crypto::SHA256);
	if (newpassword.isEmpty()) {
		qCritical() << "hashing password failed";
		return QByteArray();
	}
	SymmetricKey key(newpassword, SymmetricKey::AES256);
	qDebug() << "create a key from " << newpassword.length() << " size password";
	const QByteArray priv = getPrivateKeyBytes();
	const QByteArray encrypted = c->symmetricEncrypt(priv, key);
	qDebug() << "encrypted" << encrypted.length() << "bytes";
	if (encrypted.length() < 1) {
		qCritical() << "private key encrypt error";
		return QByteArray();
	}

	qDebug() << "Private key encrypt success: " << encrypted.length() << " bytes";

	return encrypted;
}
ASymmetricKey *ASymmetricKey::decryptPrivateKey(const QByteArray &encrypted, const QByteArray &password, void *crypto, const KeyType type, const int iterations) {
	Crypto *c = (Crypto *) crypto;

	int use_iterations;
	if (iterations > 1)
		use_iterations = iterations;
	else
		use_iterations = QTSIMPLECRYPTO_DEFAULT_PRIVATE_KEY_HASH_ITERATIONS;

	const QByteArray hash = c->iterativeHash(password, QByteArray(), use_iterations, Crypto::SHA256);
	SymmetricKey key(hash, SymmetricKey::AES256);
	const QByteArray decrypted = c->symmetricDecrypt(encrypted, key);
	if (decrypted.length() < 1) {
		qWarning() << "decryption failed";
		return NULL;
	}
	return ASymmetricKey::fromPrivateKeyBytes(decrypted, type);
}

ASymmetricKey *ASymmetricKey::fromPrivateKeyFile(const QString &path, const KeyType &type, const QByteArray &password, void *crypto, const int iterations) {
	QFile file(path);
	if (!file.open(QIODevice::ReadOnly)) {
		qWarning() << "couldn't open file for read access";
		return NULL;
	}

	QByteArray ba = file.readAll();
	file.close();
	qDebug() << "decrypting private key from " << ba.length() << " bytes";
	ASymmetricKey *key = ASymmetricKey::decryptPrivateKey(ba, password, crypto, type, iterations);
	return key;
}

ASymmetricKey *ASymmetricKey::fromPublicKeyFile(const QString &path, const KeyType &type)
{
	FILE *key_file;
	EVP_PKEY *key;
	key_file = fopen(path.toLocal8Bit(), "r");
	if (!key_file) {
		qCritical() << "ASymmetricKey::fromPublicKeyFile: Couldn't open public key file";
		return NULL;
	}

	if ((key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL)) == NULL) {
		qCritical() << "ASymmetricKey::fromPublicKeyFile: Couldn't read private key";
		fclose(key_file);
		return NULL;
	}

	fclose(key_file);

	return new ASymmetricKey(key, type, false, true);	//TODO: read key type from file
}

ASymmetricKey::KeyType ASymmetricKey::getType() const
{
	return d->type;
}

ASymmetricKey *ASymmetricKey::fromPublicKeyBytes(const QByteArray &pubkey, const KeyType &type)
{
	BIO *bmem;
	EVP_PKEY *key;

	bmem = BIO_new(BIO_s_mem());

	BIO_write(bmem, pubkey.data(), pubkey.length());

	if ((key = PEM_read_bio_PUBKEY(bmem, NULL, NULL, NULL)) == NULL) {
		qCritical() << "ASymmetricKey::fromPublicKeyData: Error reading public key";
		BIO_free_all(bmem);
		return NULL;
	}

	BIO_free_all(bmem);

	//TODO: read key type from file
	return new ASymmetricKey(key, type, false, true);
}

ASymmetricKey *ASymmetricKey::fromPrivateKeyBytes(const QByteArray &privateKey, const KeyType &type)
{
	BIO *bmem, *b;
	EVP_PKEY *key;

	b = BIO_new(BIO_f_buffer());
	bmem = BIO_new(BIO_s_mem());
	b = BIO_push(b, bmem);

	BIO_write(bmem, privateKey.data(), privateKey.length());

	if ((key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL)) == NULL) {
		qCritical() << "ASymmetricKey::fromPrivateKeyBytes: Error reading private key";
		BIO_free_all(b);
		return NULL;
	}

	BIO_free_all(b);

	//TODO: read key type from file
	return new ASymmetricKey(key, type, true, true);
}

bool ASymmetricKey::savePrivateKeyFile(const QString &destinationPath, const QByteArray &password, void *crypto, const int iterations) const {
	if (!crypto || destinationPath.isEmpty() || password.isEmpty()) {
		qCritical() << "missing arguments";
		return false;
	}
	const QByteArray ba = encryptPrivateKey(password, crypto, iterations);
	if (ba.length() < 1) {
		qCritical() << "encrypting private key failed";
		return false;
	}
	QFile file(destinationPath);
	bool ret = false;
	if (!file.open(QIODevice::WriteOnly)) {
		qCritical() << "failed to open file for write access";
		return false;
	}
	qDebug() << "Writing " << ba.length() << " bytes";

	if (!file.write(ba)) {
		qCritical() << "failed to write to file";
		goto out;
	}
	ret=true;

out:
	file.close();
	return ret;
}

bool ASymmetricKey::savePublicKeyFile(const QString &destinationPath) const {
	if (destinationPath.isEmpty() ) {
		qCritical() << "missing arguments";
		return false;
	}

	const QByteArray ba = getPublicKeyBytes();

	QFile file(destinationPath);
	bool ret = false;
	if (!file.open(QIODevice::WriteOnly)) {
		qCritical() << "failed to open file for write access";
		return false;
	}
	qDebug() << "Writing " << ba.length() << " bytes";

	if (!file.write(ba)) {
		qCritical() << "failed to write to file";
		goto out;
	}
	ret=true;

out:
	file.close();
	return ret;
}

const QByteArray ASymmetricKey::getPrivateKeyBytes() const
{
	QByteArray ba;
	BIO *bmem = NULL;
	int len, t;
	char *p;
	bmem = BIO_new(BIO_s_mem());

	if (!PEM_write_bio_PrivateKey(bmem, d->key, NULL, NULL, 0, NULL, NULL)) {
		qCritical() << "PEM_write_bio_PrivateKey failed: " << ERR_get_error();
		goto out;
	}

	t = BIO_flush(bmem);
	(void) t;

	len = BIO_get_mem_data(bmem,&p);
	if (len < 1) {
		qCritical() << "error reading";
		goto out;
	}
	qDebug() << "read " << len << " bytes";
	ba.append(p, len);
	qDebug() << "copied " << len << " bytes";

out:
	if (bmem)
		BIO_free_all(bmem);
	return ba;
}

const QByteArray ASymmetricKey::getPublicKeyBytes() const
{
	QByteArray ba;
	BIO *bmem = NULL;
	int len, t;
	char *p;
	qDebug("Key=%p", d->key);

	bmem = BIO_new(BIO_s_mem());

	if (!PEM_write_bio_PUBKEY(bmem, d->key)) {
		qCritical() << "PEM_write_bio_PUBKEY failed: " << ERR_get_error();
		goto out;
	}
	t = BIO_flush(bmem);
	(void) t;

	len = BIO_get_mem_data(bmem,&p);
	if (len < 1) {
		qCritical() << "error reading";
		goto out;
	}
	qDebug() << "read " << len << " bytes";
	ba.append(p, len);
	qDebug() << "copied " << len << " bytes";

out:
	if (bmem)
		BIO_free_all(bmem);
	return ba;
}

int ASymmetricKey::getAsyncKeyLength(const ASymmetricKey::KeyType &type)
{
	if (type == RSA2048) {
		return 2048/8;
	} else if (type == RSA4096) {
		return 4096/8;
	} else if (type == ECDSA384) {
		return 384/8;
	} else if (type == ECDSA521) {
		return 521/8+1;	//XXX
	} else {
		return -1;
	}
}

int ASymmetricKey::getAsyncKeyLengthBits(const ASymmetricKey::KeyType &type)
{
	if (type == RSA2048) {
		return 2048;
	} else if (type == RSA4096) {
		return 4096;
	} else if (type == ECDSA384) {
		return 384;
	} else if (type == ECDSA521) {
		return 521;
	} else {
		return -1;
	}
}
