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
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

extern void *pal_mem_alloc(uint32_t size);
extern void *pal_mem_calloc(uint32_t num, uint32_t size);
extern void pal_mem_free(void *buffer);
extern void pal_mem_set(void *buf, uint32_t size, uint8_t value);
extern void *pal_memcpy(void *dest, const void *src, uint32_t length);
extern int32_t pal_mem_compare(void *src, void *dest, uint32_t len);

void *
memcpy(void *dest, const void *src, size_t n)
{
  return pal_memcpy(dest, src, (uint32_t)n);
}

void *
memmove(void *dest, const void *src, size_t n)
{
  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;

  if (d == s || n == 0)
    return dest;

  if (d < s) {
    for (size_t i = 0; i < n; ++i)
      d[i] = s[i];
  } else {
    for (size_t i = n; i != 0; --i)
      d[i - 1] = s[i - 1];
  }

  return dest;
}

int
memcmp(const void *s1, const void *s2, size_t n)
{
  return (int)pal_mem_compare((void *)s2, (void *)s1, (uint32_t)n);
}

void *
memset(void *s, int c, size_t n)
{
  pal_mem_set(s, (uint32_t)n, (uint8_t)c);
  return s;
}

size_t
strlen(const char *s)
{
  size_t len = 0;

  while (s[len] != '\0')
    ++len;

  return len;
}

int
strncmp(const char *s1, const char *s2, size_t n)
{
  const unsigned char *p1 = (const unsigned char *)s1;
  const unsigned char *p2 = (const unsigned char *)s2;

  while (n-- != 0) {
    if (*p1 != *p2 || *p1 == '\0' || *p2 == '\0')
      return (int)(*p1 - *p2);
    ++p1;
    ++p2;
  }

  return 0;
}

int
strcmp(const char *s1, const char *s2)
{
  const unsigned char *p1 = (const unsigned char *)s1;
  const unsigned char *p2 = (const unsigned char *)s2;

  while ((*p1 != '\0') && (*p1 == *p2)) {
    ++p1;
    ++p2;
  }

  return (int)(*p1 - *p2);
}

char *
strchr(const char *s, int c)
{
  char ch = (char)c;

  while (*s != '\0') {
    if (*s == ch)
      return (char *)s;
    ++s;
  }

  return (ch == '\0') ? (char *)s : NULL;
}

char *
strstr(const char *haystack, const char *needle)
{
  const char *h;
  size_t needle_len;

  if (*needle == '\0')
    return (char *)haystack;

  needle_len = strlen(needle);
  h = haystack;

  while (*h != '\0') {
    if ((*h == *needle) && (strncmp(h, needle, needle_len) == 0))
      return (char *)h;
    ++h;
  }

  return NULL;
}

void *
malloc(size_t size)
{
  return pal_mem_alloc((uint32_t)size);
}

void
free(void *ptr)
{
  if (ptr != NULL)
    pal_mem_free(ptr);
}

void *
calloc(size_t nmemb, size_t size)
{
  return pal_mem_calloc((uint32_t)nmemb, (uint32_t)size);
}

void *
realloc(void *ptr, size_t size)
{
  if (ptr == NULL)
    return malloc(size);

  if (size == 0) {
    free(ptr);
    return NULL;
  }

  void *new_ptr = malloc(size);

  if (new_ptr == NULL)
    return NULL;

  pal_memcpy(new_ptr, ptr, (uint32_t)size);
  free(ptr);
  return new_ptr;
}
