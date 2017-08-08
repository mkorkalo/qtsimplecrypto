#ifndef QTSIMPLECRYPTO_GLOBAL_H
#define QTSIMPLECRYPTO_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(QTSIMPLECRYPTO_LIBRARY)
#  define QTSIMPLECRYPTOSHARED_EXPORT Q_DECL_EXPORT
#else
#  define QTSIMPLECRYPTOSHARED_EXPORT Q_DECL_IMPORT
#endif

#define ZERO_BYTEARRAY(b) if ((b).length() > 0) memset((b).data(), 0, (b).length());

#endif // QTSIMPLECRYPTO_GLOBAL_H
