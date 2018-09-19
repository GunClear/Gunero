include_directories(.)

add_executable(
  main

  main.cpp
  sparse_merkle_tree_check_read_gadget.tcc
  sparse_merkle_tree_check_update_gadget.tcc
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