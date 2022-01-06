cmake_minimum_required(VERSION 2.4)
project(license)

include_directories(
    ${THIRD_PARTY}/http_parser/include
    ${THIRD_PARTY}/json_parser/include
    ${THIRD_PARTY}/mbedtls/include
    ${UTILITY})

link_directories(${THIRD_PARTY}/mbedtls/lib/${MACHINE})
link_directories(${THIRD_PARTY}/http_parser/lib/${MACHINE})

add_executable(license_activator license_activator.c)
target_link_libraries(license_activator http_parser libmbedtls.a libmbedx509.a libmbedcrypto.a)

add_executable(license_query license_query.c)
target_link_libraries(license_query http_parser libmbedtls.a libmbedx509.a libmbedcrypto.a)
