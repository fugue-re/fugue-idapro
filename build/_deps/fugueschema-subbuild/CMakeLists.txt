# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.21.0)

# We name the project and the target for the ExternalProject_Add() call
# to something that will highlight to the user what we are working on if
# something goes wrong and an error message is produced.

project(fugueschema-populate NONE)



include(ExternalProject)
ExternalProject_Add(fugueschema-populate
                     "UPDATE_DISCONNECTED" "False" "URL" "https://github.com/fugue-re/fugue-db-schema/archive/master.zip"
                    SOURCE_DIR          "/Users/slt/Projects/fugue-idapro/build/_deps/fugueschema-src"
                    BINARY_DIR          "/Users/slt/Projects/fugue-idapro/build/_deps/fugueschema-build"
                    CONFIGURE_COMMAND   ""
                    BUILD_COMMAND       ""
                    INSTALL_COMMAND     ""
                    TEST_COMMAND        ""
                    USES_TERMINAL_DOWNLOAD  YES
                    USES_TERMINAL_UPDATE    YES
)


