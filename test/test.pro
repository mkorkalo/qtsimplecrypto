# A hacky project to do command line unit testing

QT       += testlib
QT       -= gui

TARGET = tst_cryptotests
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

INCLUDEPATH += ../

# testing
#LIBS += -L/usr/local/Cellar/openssl/1.0.2j/lib/
#INCLUDEPATH += /usr/local/Cellar/openssl/1.0.2j/include/

SOURCES += tst_cryptotests.cpp
DEFINES += SRCDIR=\\\"$$PWD/\\\"
LIBS += -lcrypto -lssl
LIBS += -L../../qtsimplecrypto-build-Desktop-Debug -lqtsimplecrypto
