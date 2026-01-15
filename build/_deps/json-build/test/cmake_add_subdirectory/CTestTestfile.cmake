# CMake generated Testfile for 
# Source directory: /home/vagrant/blacksmith/build/_deps/json-src/test/cmake_add_subdirectory
# Build directory: /home/vagrant/blacksmith/build/_deps/json-build/test/cmake_add_subdirectory
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(cmake_add_subdirectory_configure "/usr/bin/cmake" "-G" "Unix Makefiles" "-DCMAKE_CXX_COMPILER=/usr/bin/c++" "-Dnlohmann_json_source=/home/vagrant/blacksmith/build/_deps/json-src" "/home/vagrant/blacksmith/build/_deps/json-src/test/cmake_add_subdirectory/project")
set_tests_properties(cmake_add_subdirectory_configure PROPERTIES  FIXTURES_SETUP "cmake_add_subdirectory" _BACKTRACE_TRIPLES "/home/vagrant/blacksmith/build/_deps/json-src/test/cmake_add_subdirectory/CMakeLists.txt;1;add_test;/home/vagrant/blacksmith/build/_deps/json-src/test/cmake_add_subdirectory/CMakeLists.txt;0;")
add_test(cmake_add_subdirectory_build "/usr/bin/cmake" "--build" ".")
set_tests_properties(cmake_add_subdirectory_build PROPERTIES  FIXTURES_REQUIRED "cmake_add_subdirectory" _BACKTRACE_TRIPLES "/home/vagrant/blacksmith/build/_deps/json-src/test/cmake_add_subdirectory/CMakeLists.txt;8;add_test;/home/vagrant/blacksmith/build/_deps/json-src/test/cmake_add_subdirectory/CMakeLists.txt;0;")
