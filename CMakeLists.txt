cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include(CTest)
find_package(Threads REQUIRED)

set(PROJECT_HEADERS_DIR ${CMAKE_SOURCE_DIR}/include)

set(DPI_CORE_SOURCES
    src/dpi_engine.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/sni_extractor.cpp
    src/types.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)

# Official application target: the full DPI engine.
# Other main files in src/ are kept as older demos/reference entrypoints.
set(DPI_ENGINE_SOURCES
    src/main_dpi.cpp
    ${DPI_CORE_SOURCES}
)

add_executable(dpi_engine ${DPI_ENGINE_SOURCES})
target_include_directories(dpi_engine PRIVATE ${PROJECT_HEADERS_DIR})
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

if (MSVC)
    target_compile_options(dpi_engine PRIVATE /W4)
else()
    target_compile_options(dpi_engine PRIVATE -Wall -Wextra -pedantic)
endif()

if (BUILD_TESTING)
    add_executable(packet_component_tests
        tests/test_packet_components.cpp
        src/rule_manager.cpp
        src/sni_extractor.cpp
        src/types.cpp
        src/pcap_reader.cpp
        src/packet_parser.cpp
    )
    target_include_directories(packet_component_tests PRIVATE ${PROJECT_HEADERS_DIR})
    target_link_libraries(packet_component_tests PRIVATE Threads::Threads)

    if (MSVC)
        target_compile_options(packet_component_tests PRIVATE /W4)
    else()
        target_compile_options(packet_component_tests PRIVATE -Wall -Wextra -pedantic)
    endif()

    add_test(NAME packet_component_tests COMMAND packet_component_tests)
endif()
