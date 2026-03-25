/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#ifndef LIBSPDM_EDK2_DEBUG_LIB_H
#define LIBSPDM_EDK2_DEBUG_LIB_H

#include <Library/DebugLib.h>

#define LIBSPDM_DEBUG_INFO     DEBUG_INFO
#define LIBSPDM_DEBUG_VERBOSE  DEBUG_VERBOSE
#define LIBSPDM_DEBUG_ERROR    DEBUG_ERROR

#define LIBSPDM_DEBUG                DEBUG
#define LIBSPDM_ASSERT               ASSERT
#define LIBSPDM_ASSERT_RETURN_ERROR  ASSERT_RETURN_ERROR

#define LIBSPDM_DEBUG_CODE_BEGIN     DEBUG_CODE_BEGIN
#define LIBSPDM_DEBUG_CODE_END       DEBUG_CODE_END
#define LIBSPDM_DEBUG_CODE(expr)     DEBUG_CODE(expr)

#endif /* LIBSPDM_EDK2_DEBUG_LIB_H */
