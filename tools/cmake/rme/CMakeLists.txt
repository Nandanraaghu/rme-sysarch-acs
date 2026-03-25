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

project(rme LANGUAGES C ASM)

set(EXE_NAME ${PROJECT_NAME})

set(VAL_LIB ${EXE_NAME}_val_lib)
set(PAL_LIB ${EXE_NAME}_pal_lib)

# Bare-metal print verbosity (1..5). Default 3: TEST/ALWAYS/ERR/WARN.
# Users can pass -DACS_PRINT_LEVEL=2 to include DEBUG, or 1 to include INFO.
if(NOT DEFINED ACS_PRINT_LEVEL)
  set(ACS_PRINT_LEVEL 3 CACHE STRING "ACS print verbosity level (1..5)" FORCE)
else()
  set(ACS_PRINT_LEVEL ${ACS_PRINT_LEVEL} CACHE STRING "ACS print verbosity level (1..5)" FORCE)
endif()


if(ENABLE_SPDM)
  include(${ROOT_DIR}/tools/cmake/rme/libspdm.cmake)
else()
  set(LIBSPDM_INCLUDE_DIR "" CACHE INTERNAL "libspdm public headers" FORCE)
  set(LIBSPDM_OS_STUB_INCLUDE_DIR "" CACHE INTERNAL "libspdm os_stub headers" FORCE)
  set(SPDM_EMU_INCLUDE_DIR "" CACHE INTERNAL "spdm-emu public headers" FORCE)
endif()
include(${ROOT_DIR}/platform/pal_baremetal/pal_rme.cmake)
include(${ROOT_DIR}/val/val_rme.cmake)
include(${ROOT_DIR}/test_pool/test.cmake)
