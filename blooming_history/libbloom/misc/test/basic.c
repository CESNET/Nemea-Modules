/*
 *  Copyright (c) 2016-2017, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "bloom.h"

#ifdef __linux
#include <sys/time.h>
#include <time.h>
#endif


/** ***************************************************************************
 * A few simple tests to check if it works at all.
 *
 * These are covered in the main test, repeated here just to create a test
 * executable using the static libbloom library to exercise it as well.
 *
 */
int main(int argc, char **argv)
{
  struct bloom bloom;
  struct bloom bloom2;
  uint8_t* serialization_buffer;
  int32_t serialization_buffer_size;
  int32_t bad_size1 = htonl(5);
  int32_t bad_size2 = htonl(616);

  printf("----- Basic tests with static library -----\n");
  assert(bloom_init(&bloom, 0, 1.0) == 1);
  assert(bloom_init(&bloom, 10, 0) == 1);
  assert(bloom.ready == 0);
  assert(bloom_add(&bloom, "hello world", 11) == -1);
  assert(bloom_check(&bloom, "hello world", 11) == -1);
  bloom_free(&bloom);

  assert(bloom_init(&bloom, 1002, 0.1) == 0);
  assert(bloom.ready == 1);
  bloom_print(&bloom);

  assert(bloom_check(&bloom, "hello world", 11) == 0);
  assert(bloom_add(&bloom, "hello world", 11) == 0);
  assert(bloom_check(&bloom, "hello world", 11) == 1);
  assert(bloom_add(&bloom, "hello world", 11) > 0);
  assert(bloom_add(&bloom, "hello", 5) == 0);
  assert(bloom_add(&bloom, "hello", 5) > 0);
  assert(bloom_check(&bloom, "hello", 5) == 1);
  bloom_free(&bloom);

  printf("----- Basic tests with static library - merge -----\n");
  assert(bloom_init(&bloom, 1002, 0.1) == 0);
  assert(bloom.ready == 1);

  assert(bloom2.ready != 1);
  assert(bloom_merge(&bloom, &bloom2) == -1);

  assert(bloom_init(&bloom2, 1003, 0.1) == 0);
  assert(bloom2.ready == 1);
  assert(bloom_merge(&bloom, &bloom2) == -2);
  bloom_free(&bloom2);

  assert(bloom_init(&bloom2, 1002, 0.2) == 0);
  assert(bloom2.ready == 1);
  assert(bloom_merge(&bloom, &bloom2) == -3);
  bloom_free(&bloom2);

  assert(bloom_init(&bloom2, 1002, 0.1) == 0);
  assert(bloom2.ready == 1);
  assert(bloom_add(&bloom, "hello world", 11) == 0);
  assert(bloom_add(&bloom, "hello", 5) == 0);
  assert(bloom_add(&bloom2, "hello world 2", 13) == 0);
  assert(bloom_add(&bloom2, "hello 2", 7) == 0);
  assert(bloom_merge(&bloom, &bloom2) == 0);
  assert(bloom_check(&bloom2, "hello world", 11) == 0);
  assert(bloom_check(&bloom2, "hello", 5) == 0);
  assert(bloom_check(&bloom2, "hello world 2", 13) == 1);
  assert(bloom_check(&bloom2, "hello 2", 7) == 1);
  assert(bloom_check(&bloom, "hello world", 11) == 1);
  assert(bloom_check(&bloom, "hello", 5) == 1);
  assert(bloom_check(&bloom, "hello world 2", 13) == 1);
  assert(bloom_check(&bloom, "hello 2", 7) == 1);
  bloom_print(&bloom);
  bloom_print(&bloom2);

  bloom_free(&bloom);
  bloom_free(&bloom2);

  printf("----- Basic tests with static library - serialization -----\n");

  assert(bloom_serialize(&bloom, &serialization_buffer, &serialization_buffer_size) == -1);

  assert(bloom_init(&bloom, 1002, 0.1) == 0);
  assert(bloom.ready == 1);

  assert(bloom_serialize(&bloom, &serialization_buffer, &serialization_buffer_size) == 0);
  assert(serialization_buffer_size == 617);
  memcpy(serialization_buffer, &bad_size1, sizeof(int32_t));
  assert(bloom_deserialize(&bloom2, serialization_buffer) == -2);
  memcpy(serialization_buffer, &bad_size2, sizeof(int32_t));
  assert(bloom_deserialize(&bloom2, serialization_buffer) == -2);
  memcpy(serialization_buffer, &serialization_buffer_size, sizeof(int32_t));
  bloom_free_serialized_buffer(&serialization_buffer);

  assert(bloom_serialize(&bloom, &serialization_buffer, &serialization_buffer_size) == 0);
  assert(serialization_buffer_size == 617);
  assert(bloom_deserialize(&bloom2, serialization_buffer) == 0);
  bloom_print(&bloom);
  bloom_print(&bloom2);
  assert(bloom.entries == bloom2.entries);
  assert(bloom.error == bloom2.error);
  assert(bloom.bits == bloom2.bits);
  assert(bloom.bytes == bloom2.bytes);
  assert(bloom.hashes == bloom2.hashes);
  assert(bloom.bpe == bloom2.bpe);

  bloom_free_serialized_buffer(&serialization_buffer);
  assert(serialization_buffer == NULL);
  bloom_free(&bloom);
  bloom_free(&bloom2);

  printf("----- Basic tests with static library - serialization to file -----\n");

  assert(bloom_file_write(&bloom, "/tmp/test.bloom") == -3);
  assert(bloom_file_read(&bloom, "/dev/zero") == -3);
  assert(bloom_file_read(&bloom, "/tmp/test_nonexistent.bloom") == -1);

  assert(bloom_init(&bloom, 1002, 0.1) == 0);
  assert(bloom.ready == 1);
  assert(bloom_file_write(&bloom, "/tmp/test.bloom") == 0);
  assert(bloom_file_read(&bloom2, "/tmp/test.bloom") == 0);
  assert(bloom2.ready == 1);
  assert(bloom.entries == bloom2.entries);
  assert(bloom.error == bloom2.error);
  assert(bloom.bits == bloom2.bits);
  assert(bloom.bytes == bloom2.bytes);
  assert(bloom.hashes == bloom2.hashes);
  assert(bloom.bpe == bloom2.bpe);
  bloom_free(&bloom);
  bloom_free(&bloom2);

  printf("----- DONE Basic tests with static library -----\n");
}

