cmake_minimum_required(VERSION 3.20)
if(APPLE)
  set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING "Minimum supported macOS version")
endif()
project(mkckks_bridge LANGUAGES C)

find_program(GO_EXECUTABLE go REQUIRED)
execute_process(
  COMMAND "${GO_EXECUTABLE}" env CGO_ENABLED
  OUTPUT_VARIABLE MKCKKS_CGO_ENABLED
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE MKCKKS_GO_ENV_RESULT
)
if(NOT MKCKKS_GO_ENV_RESULT EQUAL 0 OR NOT MKCKKS_CGO_ENABLED STREQUAL "1")
  message(FATAL_ERROR
    "MKCKKS source builds require Go with cgo enabled. Install Go and a C compiler, then set CGO_ENABLED=1.")
endif()

if(APPLE)
  set(MKCKKS_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/libmkckks.dylib")
  set(MKCKKS_GO_ENV
      "MACOSX_DEPLOYMENT_TARGET=12.0"
      "CGO_CFLAGS=-mmacosx-version-min=12.0"
      "CGO_LDFLAGS=-mmacosx-version-min=12.0")
elseif(UNIX)
  set(MKCKKS_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/libmkckks.so")
  set(MKCKKS_GO_ENV)
else()
  message(FATAL_ERROR "This release supports macOS and Linux source builds only")
endif()

file(GLOB_RECURSE BRIDGE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/bridge/*.go")
file(GLOB_RECURSE UPSTREAM_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/mkckks/*.go"
  "${CMAKE_CURRENT_SOURCE_DIR}/mkrlwe/*.go"
)

add_custom_command(
  OUTPUT "${MKCKKS_LIBRARY}" "${CMAKE_CURRENT_BINARY_DIR}/libmkckks.h"
  COMMAND "${CMAKE_COMMAND}" -E env
          "GOCACHE=${CMAKE_CURRENT_BINARY_DIR}/go-cache"
          ${MKCKKS_GO_ENV}
          "${GO_EXECUTABLE}" build -trimpath -buildvcs=false -buildmode=c-shared
          -ldflags=-buildid=
          -o "${MKCKKS_LIBRARY}" ./bridge
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  DEPENDS ${BRIDGE_SOURCES} ${UPSTREAM_SOURCES} go.mod go.sum
  COMMENT "Building the MKCKKS Go bridge"
  VERBATIM
)

add_custom_target(mkckks_native ALL DEPENDS "${MKCKKS_LIBRARY}")
install(FILES "${MKCKKS_LIBRARY}" "${CMAKE_CURRENT_BINARY_DIR}/libmkckks.h"
        DESTINATION mkckks/_native)
