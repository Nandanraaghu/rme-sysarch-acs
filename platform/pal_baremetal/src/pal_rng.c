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

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "library/rnglib.h"

static uint64_t
pal_rng_read_counter(void)
{
#if defined(__aarch64__)
  uint64_t counter;
  __asm__ volatile("mrs %0, cntpct_el0" : "=r"(counter));
  return counter;
#else
  static uint64_t fallback = 0x6c8e9cf570932bd5ULL;
  fallback ^= fallback << 13;
  fallback ^= fallback >> 7;
  fallback ^= fallback << 17;
  return fallback;
#endif
}

bool
libspdm_get_random_number_64(uint64_t *rand_data)
{
  static uint64_t state = 0x9e3779b97f4a7c15ULL;
  uint64_t entropy;

  if (rand_data == NULL)
    return false;

  entropy = pal_rng_read_counter();
  if (state == 0u)
    state = 0x123456789abcdef0ULL;

  state ^= entropy;
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;

  *rand_data = state;
  return true;
}
