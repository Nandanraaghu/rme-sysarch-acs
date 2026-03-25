## @file
# Copyright (c) 2025-2026, Arm Limited or its affiliates. All rights reserved.
 # SPDX-License-Identifier : Apache-2.0
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #  http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
 ##

# Compile all the platform specific source files under pal_baremetal.
file(GLOB PAL_SRC
 "${PAL_DIR}/${TARGET}/src/*.c"
 "${PAL_DIR}/src/AArch64/*.S"
 "${PAL_DIR}/src/*.c"
)
# Remove pal_rng.c from the compile list, pal_rng.c is build separately as a library.
list(FILTER PAL_SRC EXCLUDE REGEX ".*/pal_rng\\.c$")

#Create compile list files
list(APPEND COMPILE_LIST ${PAL_SRC})
set(COMPILE_LIST ${COMPILE_LIST} PARENT_SCOPE)

# Create PAL library
add_library(${PAL_LIB} STATIC ${PAL_SRC})

target_include_directories(${PAL_LIB} PRIVATE
 ${CMAKE_CURRENT_BINARY_DIR}
 ${ROOT_DIR}/
 ${ROOT_DIR}/pal_el3/
 ${ROOT_DIR}/baremetal_app/
 ${PAL_DIR}/
 ${PAL_DIR}/include/
 ${PAL_DIR}/${TARGET}/
 ${PAL_DIR}/${TARGET}/include/
 ${ROOT_DIR}/tools/configs/

)

# Share SPDM enablement with PAL sources for conditional compilation.
target_compile_definitions(${PAL_LIB} PRIVATE ENABLE_SPDM=$<IF:$<BOOL:${ENABLE_SPDM}>,1,0>)

# Propagate ACS print verbosity to PAL sources (for UART/prefix helpers).
target_compile_definitions(${PAL_LIB} PRIVATE "ACS_PRINT_LEVEL=${ACS_PRINT_LEVEL}")

unset(PAL_SRC)
