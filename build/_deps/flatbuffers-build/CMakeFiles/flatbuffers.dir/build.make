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
include _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/compiler_depend.make

# Include the progress variables for this target.
include _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/progress.make

# Include the compile flags for this target's objects.
include _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/flags.make

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.o: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/flags.make
_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.o: _deps/flatbuffers-src/src/idl_parser.cpp
_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.o: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/slt/Projects/fugue-idapro/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.o"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.o -MF CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.o.d -o CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.o -c /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/idl_parser.cpp

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.i"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/idl_parser.cpp > CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.i

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.s"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/idl_parser.cpp -o CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.s

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.o: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/flags.make
_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.o: _deps/flatbuffers-src/src/idl_gen_text.cpp
_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.o: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/slt/Projects/fugue-idapro/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.o"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.o -MF CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.o.d -o CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.o -c /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/idl_gen_text.cpp

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.i"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/idl_gen_text.cpp > CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.i

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.s"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/idl_gen_text.cpp -o CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.s

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/reflection.cpp.o: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/flags.make
_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/reflection.cpp.o: _deps/flatbuffers-src/src/reflection.cpp
_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/reflection.cpp.o: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/slt/Projects/fugue-idapro/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/reflection.cpp.o"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/reflection.cpp.o -MF CMakeFiles/flatbuffers.dir/src/reflection.cpp.o.d -o CMakeFiles/flatbuffers.dir/src/reflection.cpp.o -c /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/reflection.cpp

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/reflection.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/flatbuffers.dir/src/reflection.cpp.i"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/reflection.cpp > CMakeFiles/flatbuffers.dir/src/reflection.cpp.i

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/reflection.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/flatbuffers.dir/src/reflection.cpp.s"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/reflection.cpp -o CMakeFiles/flatbuffers.dir/src/reflection.cpp.s

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/util.cpp.o: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/flags.make
_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/util.cpp.o: _deps/flatbuffers-src/src/util.cpp
_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/util.cpp.o: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/slt/Projects/fugue-idapro/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/util.cpp.o"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/util.cpp.o -MF CMakeFiles/flatbuffers.dir/src/util.cpp.o.d -o CMakeFiles/flatbuffers.dir/src/util.cpp.o -c /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/util.cpp

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/util.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/flatbuffers.dir/src/util.cpp.i"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/util.cpp > CMakeFiles/flatbuffers.dir/src/util.cpp.i

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/util.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/flatbuffers.dir/src/util.cpp.s"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src/src/util.cpp -o CMakeFiles/flatbuffers.dir/src/util.cpp.s

# Object files for target flatbuffers
flatbuffers_OBJECTS = \
"CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.o" \
"CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.o" \
"CMakeFiles/flatbuffers.dir/src/reflection.cpp.o" \
"CMakeFiles/flatbuffers.dir/src/util.cpp.o"

# External object files for target flatbuffers
flatbuffers_EXTERNAL_OBJECTS =

_deps/flatbuffers-build/libflatbuffers.a: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_parser.cpp.o
_deps/flatbuffers-build/libflatbuffers.a: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/idl_gen_text.cpp.o
_deps/flatbuffers-build/libflatbuffers.a: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/reflection.cpp.o
_deps/flatbuffers-build/libflatbuffers.a: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/src/util.cpp.o
_deps/flatbuffers-build/libflatbuffers.a: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/build.make
_deps/flatbuffers-build/libflatbuffers.a: _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/slt/Projects/fugue-idapro/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX static library libflatbuffers.a"
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && $(CMAKE_COMMAND) -P CMakeFiles/flatbuffers.dir/cmake_clean_target.cmake
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/flatbuffers.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/build: _deps/flatbuffers-build/libflatbuffers.a
.PHONY : _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/build

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/clean:
	cd /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build && $(CMAKE_COMMAND) -P CMakeFiles/flatbuffers.dir/cmake_clean.cmake
.PHONY : _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/clean

_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/depend:
	cd /Users/slt/Projects/fugue-idapro/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/slt/Projects/fugue-idapro /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-src /Users/slt/Projects/fugue-idapro/build /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build /Users/slt/Projects/fugue-idapro/build/_deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : _deps/flatbuffers-build/CMakeFiles/flatbuffers.dir/depend

