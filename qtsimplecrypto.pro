TEMPLATE = lib
QT       += core
QT       -= gui

TARGET = qtsimplecrypto
CONFIG   -= app_bundle

CONFIG(debug, debug|release) {
    CONFIG += declarative_debug
    CONFIG += qml_debug
    QMAKE_CXXFLAGS_DEBUG += -g3 -O0
    message("DEBUG!")
} else {
    DEFINES += QT_NO_DEBUG_OUTPUT
    message("RELEASE!")
}

LIBS += -lcrypto

# testing
#LIBS += -L/usr/local/Cellar/openssl/1.0.2j/lib/
#INCLUDEPATH += /usr/local/Cellar/openssl/1.0.2j/include/

DEFINES += QTSIMPLECRYPTO_LIBRARY
SOURCES += \
    crypto.cpp \
    symmetrickey.cpp \
    asymmetrickey.cpp

HEADERS += \
    crypto.h \
    qtsimplecrypto_global.h \
    symmetrickey.h \
    asymmetrickey.h

unix:!symbian {
    target.path = /usr/lib
    INSTALLS += target
}
