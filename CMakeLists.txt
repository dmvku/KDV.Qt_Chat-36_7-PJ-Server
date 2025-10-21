cmake_minimum_required(VERSION 3.16)

project(Qt_Chat_Server VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

if ( CMAKE_COMPILER_IS_GNUCC )
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif()
if ( MSVC )
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /W4")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network Sql)

file(GLOB_RECURSE SRC_FILES *.cpp)
file(GLOB_RECURSE HEADER_FILES *.h)
file(GLOB_RECURSE RC_FILES *.qrc)
file(GLOB_RECURSE UI_FILES *.ui)

# set(CMAKE_AUTOUIC ON)
# set(CMAKE_AUTOMOC ON)
# set(CMAKE_AUTORCC ON)

# qt6_wrap_ui(UI_SOURCES ${UI_FILES})
# qt6_add_resources(RESOURCE_SOURCES ${RC_FILES})

qt_standard_project_setup()

add_executable(Qt_Chat_Server
    ${SRC_FILES}
    ${HEADER_FILES}
    ${RC_FILES}
    ${UI_FILES}
)

target_link_libraries(Qt_Chat_Server
    PUBLIC
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::Sql)
