cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(fugue-idapro CXX)

set(CMAKE_POLICY_DEFAULT_CMP0063 NEW)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(FLATBUFFERS_BUILD_TESTS OFF CACHE INTERNAL "Disable FlatBuffers tests")

add_subdirectory(third-party EXCLUDE_FROM_ALL)

set(IdaSdk_ROOT_DIR ${PROJECT_SOURCE_DIR}/third-party)
find_package(IdaSdk REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${IdaSdk_INCLUDE_DIRS})

flatbuffers_generate_headers(
  TARGET schema
  SCHEMAS ${fugueschema_SOURCE_DIR}/fugue.fbs
)

add_ida_plugin(fugue
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core.cc
)

if (WIN32)
  target_link_libraries(fugue${_so} flatbuffers schema shlwapi.lib)
  target_link_libraries(fugue${_so64} flatbuffers schema shlwapi.lib)
else()
  target_link_libraries(fugue${_so} flatbuffers schema)
  target_link_libraries(fugue${_so64} flatbuffers schema)
endif()