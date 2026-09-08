add_executable(aethon_benchmark benchmark.cpp)
target_link_libraries(aethon_benchmark PRIVATE aethon::aethon CLI11::CLI11 pthread)
target_compile_options(aethon_benchmark PRIVATE -Wall -Wextra -pthread -D_GLIBCXX_ASSERTIONS -Wno-interference-size -Wno-unused-but-set-variable)

