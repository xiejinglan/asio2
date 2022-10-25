cmake_minimum_required(VERSION 3.16)
project(asio2)
set(CMAKE_CXX_STANDARD 17)

IF (CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(OPENSSL_LIBS libssl.a libcrypto.a)
    set(GENERAL_LIBS -lpthread -lrt -ldl stdc++fs)
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(OPENSSL_LIBS "libssl.lib;libcrypto.lib;Crypt32.lib;")
    set(GENERAL_LIBS "ws2_32;mswsock;")
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    set(OPENSSL_LIBS libssl.a libcrypto.a)
    set(GENERAL_LIBS -lpthread -lrt -ldl stdc++fs)
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set(OPENSSL_LIBS libssl.a libcrypto.a)
    set(GENERAL_LIBS -lpthread -ldl)
ELSE ()
    set(OPENSSL_LIBS libssl.a libcrypto.a)
    set(GENERAL_LIBS -lpthread -lrt -ldl stdc++fs)
ENDIF (CMAKE_SYSTEM_NAME MATCHES "Linux")


add_library(asio2 STATIC
        include/asio2/udp/component/fec.cpp
        include/asio2/udp/component/galois.cpp
        include/asio2/udp/component/galois_noasm.cpp
        include/asio2/udp/component/galois_table.c
        include/asio2/udp/component/inversion_tree.cpp
        include/asio2/udp/component/matrix.cpp
        include/asio2/udp/component/reedsolomon.cpp
        )
target_link_libraries(asio2 ${GENERAL_LIBS})
