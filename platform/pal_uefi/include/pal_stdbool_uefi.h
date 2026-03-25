/** @file
 * Copyright (c) 2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
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

#ifndef PAL_STDBOOL_UEFI_H_
#define PAL_STDBOOL_UEFI_H_

#include <Base.h>

#ifndef __bool_true_false_are_defined
typedef BOOLEAN bool;
#define true  TRUE
#define false FALSE
#define __bool_true_false_are_defined 1
#endif

#endif /* PAL_STDBOOL_UEFI_H_ */
