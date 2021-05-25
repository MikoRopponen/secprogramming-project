TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
PKGCONFIG += libssl
LIBS+=-lssl -lcrypto
SOURCES += main.cpp \
    multitool_evp.c \
    multitool_c_util.c

HEADERS += \
    multitool_evp.h \
    multitool_c_util.h
