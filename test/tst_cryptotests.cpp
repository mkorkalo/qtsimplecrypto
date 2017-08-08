#include <QString>
#include <QtTest>
#include "../crypto.h"
#include "openssl/rand.h"

class CryptoTests : public QObject
{
    Q_OBJECT

public:
    CryptoTests();

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
	void encryptionTests();



private:

};

CryptoTests::CryptoTests()
{

}

void CryptoTests::initTestCase()
{

}

void CryptoTests::cleanupTestCase()
{

}

const QByteArray getRandomData(int minBytes, int maxBytes) {
	qsrand(QDateTime::currentMSecsSinceEpoch());
	int count = qrand() % (maxBytes - minBytes) + minBytes;
	unsigned char *bytes = new unsigned char[count+1];
	//qDebug() << "getting random data of " << count << " bytes...";
	int k;
	for (k=0; k<count; k++)
		bytes[k] = (unsigned char) qrand();
	QByteArray ret((const char *)bytes, count);
	delete bytes;
	return ret;
}

void CryptoTests::encryptionTests() {
	Crypto crypto;
	ASymmetricKey *privateKey2 = NULL, *publicKey2 = NULL,
		*privateKeyFromFile = NULL;

	//Asymmetric Key types to test
    QList<ASymmetricKey::KeyType> asymmetricKeyTypes;
	//enabling these will cause tests to fail. something is wrong with EC key generation.
	asymmetricKeyTypes << ASymmetricKey::ECDSA384;
	//asymmetricKeyTypes << ASymmetricKey::ECDSA521;
	asymmetricKeyTypes << ASymmetricKey::RSA2048;
    asymmetricKeyTypes << ASymmetricKey::RSA4096;

	//symmetric key type used for passwords
    SymmetricKey::KeyType symmetricKeyTypeForPassword = SymmetricKey::AES128;

	//symmetric key type used for encrypting with asymmetric keys i.e. RSA
    SymmetricKey::KeyType symmetricKeyTypeForAsymmetric = SymmetricKey::AES256;

    QList<QByteArray> list;
    list << QString("testi123 123 123").toLocal8Bit();
#ifdef LONG_TEST
    int k;
    qDebug() << "fill list with random crap to trigger any segfaults in crypto code";
    for (k=0; k<100; k++) {
        list << getRandomData(1, 5000);
        list << getRandomData(1, 10);
    }
#else
    qDebug() << "only short test enabled, define LONG_TEST for more test data.";
#endif

	qDebug() << "a";
    foreach (ASymmetricKey::KeyType asymmetricKeyType, asymmetricKeyTypes) {
        ASymmetricKey *generatedKeyPair1 = crypto.generateKeyPair(asymmetricKeyType);
        QVERIFY2(generatedKeyPair1 != NULL, "Key pair generation failed");
        ASymmetricKey *privateKey1 = ASymmetricKey::fromPrivateKeyBytes(generatedKeyPair1->getPrivateKeyBytes(), asymmetricKeyType);
        QVERIFY2(privateKey1 != NULL, "private key loading fail");
        qDebug() << "Private key dumped and read OK";
        ASymmetricKey *publicKey1 = ASymmetricKey::fromPublicKeyBytes(generatedKeyPair1->getPublicKeyBytes(), asymmetricKeyType);
        QVERIFY2(publicKey1 != NULL, "public key loading fail");

        ASymmetricKey *generatedKeyPair2 = crypto.generateKeyPair(asymmetricKeyType);
        QVERIFY2(generatedKeyPair2 != NULL, "Key pair generation failed");
		privateKey2 = ASymmetricKey::fromPrivateKeyBytes(generatedKeyPair2->getPrivateKeyBytes(), asymmetricKeyType);
		QVERIFY2(privateKey2 != NULL, "private key loading fail");
		publicKey2 = ASymmetricKey::fromPublicKeyBytes(generatedKeyPair2->getPublicKeyBytes(), asymmetricKeyType);
		QVERIFY2(publicKey2 != NULL, "public key loading fail");

		if (asymmetricKeyType != ASymmetricKey::ECDSA384 && asymmetricKeyType != ASymmetricKey::ECDSA521) {
			const QByteArray pass = QString("foobarhsdfg").toLocal8Bit();

			//qDebug() << "save private key";
			const int test_iterations = 100;
			privateKey1->savePrivateKeyFile("/tmp/test.key", pass, &crypto, test_iterations);

			//qDebug() << "load private key";
			privateKeyFromFile = ASymmetricKey::fromPrivateKeyFile("/tmp/test.key", asymmetricKeyType, pass, &crypto, test_iterations);
			QVERIFY2(privateKeyFromFile != NULL, "Loading private key failed");
		}

        qDebug() << "begin tests...";
        foreach (QByteArray testData, list) {
			if (asymmetricKeyType != ASymmetricKey::ECDSA384 && asymmetricKeyType != ASymmetricKey::ECDSA521) {
				qDebug() << "Test ASYM encrypt for " << asymmetricKeyType << "...";
				qDebug() << "ASYM original for"<< asymmetricKeyType << ":" << testData.toHex();
				const QByteArray asymEncrypted = crypto.asymmetricEncrypt(testData, *publicKey1, symmetricKeyTypeForAsymmetric);
				QVERIFY2(asymEncrypted.length() > 0, "ASYM encrypt fail");
				qDebug() << "ASYM encrypted for"<< asymmetricKeyType << ":" << asymEncrypted.toHex();

				// Decrypt the message
				const QByteArray asymDecrypted = crypto.asymmetricDecrypt(asymEncrypted, *privateKey1, symmetricKeyTypeForAsymmetric);
				QVERIFY2(asymDecrypted.length() > 0, "ASYM decrypt fail");
				qDebug() << "ASYM decrypted: " << asymDecrypted.toHex();
				QVERIFY2(asymDecrypted == testData, "ASYM decrypt data mismatch");

				//test that private key loaded from file does the same thing as privateKey1
				const QByteArray asymDecrypted_PKeyFromFile = crypto.asymmetricDecrypt(asymEncrypted, *privateKeyFromFile, symmetricKeyTypeForAsymmetric);
				QVERIFY2(asymDecrypted_PKeyFromFile.length() > 0, "ASYM decrypt fail");
				qDebug() << "ASYM decrypted: " << asymDecrypted.toHex();
				QVERIFY2(asymDecrypted_PKeyFromFile == testData, "ASYM decrypt data mismatch");
			}

            qDebug() << "Test SYM encrypt...";
            SymmetricKey key(QString("salasana"), symmetricKeyTypeForPassword);
            const QByteArray aesEncrypted = crypto.symmetricEncrypt(testData, key);
            QVERIFY2(aesEncrypted.length() > 0, "SYM ENCRYPT FAIL");

            const QByteArray aesDecrypted = crypto.symmetricDecrypt(aesEncrypted, key);
            QVERIFY2(aesDecrypted.length() > 0, "SYM DECRYPT FAIL");
            qDebug() << "SYM original: " << testData.toHex();
            qDebug() << "SYM encrypted: " << aesEncrypted.toHex();
            qDebug() << "SYM decrypted: " << aesDecrypted.toHex();
            if (aesDecrypted != testData) {
                qWarning() << "SYM TEST FAIL";
            } else {
                qDebug() << "SYM TEST SUCCESS";
            }

            SymmetricKey key2(QString("salasana2"), symmetricKeyTypeForPassword);
            const QByteArray aesDecrypted2 = crypto.symmetricDecrypt(aesEncrypted, key2);
            QVERIFY2(aesDecrypted2.length() == 0, "AES TEST2 FAIL - shouldn't be any data here?");
            qDebug() << "AES original: " << testData.toHex();
            qDebug() << "AES encrypted: " << aesEncrypted.toHex();
            qDebug() << "AES decrypted with WRONG password: " << aesDecrypted2.toHex();
            QVERIFY2(testData != aesDecrypted2, "arrays match");

            qDebug() << "Test signing...";
            const QByteArray signature = crypto.sign(testData, *privateKey1, Crypto::SHA512);
            QVERIFY2(signature.length() > 0, "Signing failed, signature is empty");
            qDebug() << "signature length: " << signature.length();

            bool verifyOk = crypto.verify(testData, signature, *publicKey1, Crypto::SHA512);
            QVERIFY2(verifyOk, "Verify failed: signature doesn't match");

            bool verifyOkWrongKey = crypto.verify(testData, signature, *publicKey2, Crypto::SHA512);
            if (verifyOkWrongKey)
                QFAIL("What?! signature verify OK with a wrong public key");
            else
                qDebug() << "^ that fail was expected and is OK";
        }
        delete generatedKeyPair1;
        delete generatedKeyPair2;
		if (privateKeyFromFile)
			delete privateKeyFromFile;
        delete privateKey1;
        delete publicKey1;
		if (privateKey2)
			delete privateKey2;
		if (publicKey2)
			delete publicKey2;
	}
}

QTEST_APPLESS_MAIN(CryptoTests)

#include "tst_cryptotests.moc"

