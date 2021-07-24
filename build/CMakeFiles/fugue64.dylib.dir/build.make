# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.21

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/homebrew/Cellar/cmake/3.21.0/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/Cellar/cmake/3.21.0/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/slt/Projects/fugue-idapro

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/slt/Projects/fugue-idapro/build

# Include any dependencies generated for this target.
include CMakeFiles/fugue64.dylib.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/fugue64.dylib.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/fugue64.dylib.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/fugue64.dylib.dir/flags.make

schema/fugue_generated.h: _deps/flatbuffers-build/flatc
schema/fugue_generated.h: _deps/fugueschema-src/fugue.fbs
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/Users/slt/Projects/fugue-idapro/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating schema/fugue_generated.h"
	cd /Users/slt/Projects/fugue-idapro && /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build/flatc -o /Users/slt/Projects/fugue-idapro/build/schema -c /Users/slt/Projects/fugue-idapro/build/_deps/fugueschema-src/fugue.fbs

CMakeFiles/fugue64.dylib.dir/src/core.cc.o: CMakeFiles/fugue64.dylib.dir/flags.make
CMakeFiles/fugue64.dylib.dir/src/core.cc.o: ../src/core.cc
CMakeFiles/fugue64.dylib.dir/src/core.cc.o: CMakeFiles/fugue64.dylib.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/slt/Projects/fugue-idapro/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/fugue64.dylib.dir/src/core.cc.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/fugue64.dylib.dir/src/core.cc.o -MF CMakeFiles/fugue64.dylib.dir/src/core.cc.o.d -o CMakeFiles/fugue64.dylib.dir/src/core.cc.o -c /Users/slt/Projects/fugue-idapro/src/core.cc

CMakeFiles/fugue64.dylib.dir/src/core.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/fugue64.dylib.dir/src/core.cc.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/slt/Projects/fugue-idapro/src/core.cc > CMakeFiles/fugue64.dylib.dir/src/core.cc.i

CMakeFiles/fugue64.dylib.dir/src/core.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/fugue64.dylib.dir/src/core.cc.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/slt/Projects/fugue-idapro/src/core.cc -o CMakeFiles/fugue64.dylib.dir/src/core.cc.s

# Object files for target fugue64.dylib
fugue64_dylib_OBJECTS = \
"CMakeFiles/fugue64.dylib.dir/src/core.cc.o"

# External object files for target fugue64.dylib
fugue64_dylib_EXTERNAL_OBJECTS =

fugue64.dylib: CMakeFiles/fugue64.dylib.dir/src/core.cc.o
fugue64.dylib: CMakeFiles/fugue64.dylib.dir/build.make
fugue64.dylib: _deps/flatbuffers-build/libflatbuffers.a
fugue64.dylib: CMakeFiles/fugue64.dylib.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/slt/Projects/fugue-idapro/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX shared module fugue64.dylib"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/fugue64.dylib.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/fugue64.dylib.dir/build: fugue64.dylib
.PHONY : CMakeFiles/fugue64.dylib.dir/build

CMakeFiles/fugue64.dylib.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/fugue64.dylib.dir/cmake_clean.cmake
.PHONY : CMakeFiles/fugue64.dylib.dir/clean

CMakeFiles/fugue64.dylib.dir/depend: schema/fugue_generated.h
	cd /Users/slt/Projects/fugue-idapro/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/slt/Projects/fugue-idapro /Users/slt/Projects/fugue-idapro /Users/slt/Projects/fugue-idapro/build /Users/slt/Projects/fugue-idapro/build /Users/slt/Projects/fugue-idapro/build/CMakeFiles/fugue64.dylib.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/fugue64.dylib.dir/depend

