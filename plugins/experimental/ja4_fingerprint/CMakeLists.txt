add_executable(test_ja4 test_ja4.cc ja4.cc tls_summary.cc)
target_link_libraries(test_ja4 PRIVATE catch2::catch2)

add_test(test_ja4 test_ja4)
