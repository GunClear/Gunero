SET(GCC_COVERAGE_COMPILE_FLAGS "-fpermissive")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
#set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})

include_directories(.)

add_executable(
  main

  main.cpp
  sparse_merkle_tree_check_read_gadget.tcc
  sparse_merkle_tree_check_update_gadget.tcc
  crypto/sha256.cpp
  uint256.cpp
  utilstrencodings.cpp
)
target_link_libraries(
  main

  snark
)
target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)