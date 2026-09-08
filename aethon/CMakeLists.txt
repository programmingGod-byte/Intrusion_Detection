# Facebook Folly-Style Library CMake Configuration

set(AETHON_HEADERS
    aethon.h
    function.h
    spsc_queue.h
    mpmc_queue.h
    fast_vector.h
    fast_hash_map.h
)

set(AETHON_SOURCES
    function.cpp
)

add_library(aethon_lib ${AETHON_SOURCES} ${AETHON_HEADERS}) # default static 
add_library(aethon::aethon ALIAS aethon_lib)

target_include_directories(aethon_lib PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
    $<INSTALL_INTERFACE:include>
)

target_compile_options(aethon_lib PRIVATE -Wall -Wextra -Wpedantic -pthread -Wno-interference-size)
target_link_libraries(aethon_lib PRIVATE pthread)
