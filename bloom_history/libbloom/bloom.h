/*
 *  Copyright (c) 2012-2017, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

#ifndef _BLOOM_H
#define _BLOOM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** ***************************************************************************
 * Structure to keep track of one bloom filter.  Caller needs to
 * allocate this and pass it to the functions below. First call for
 * every struct must be to bloom_init().
 *
 */
struct bloom
{
  // These fields are part of the public interface of this structure.
  // Client code may read these values if desired. Client code MUST NOT
  // modify any of these.
  int32_t entries;
  double error;
  int32_t bits;
  int32_t bytes;
  int32_t hashes;

  // Fields below are private to the implementation. These may go away or
  // change incompatibly at any moment. Client code MUST NOT access or rely
  // on these.
  double bpe;
  uint8_t * bf;
  int ready;
};


/** ***************************************************************************
 * Initialize the bloom filter for use.
 *
 * The filter is initialized with a bit field and number of hash functions
 * according to the computations from the wikipedia entry:
 *     http://en.wikipedia.org/wiki/Bloom_filter
 *
 * Optimal number of bits is:
 *     bits = (entries * ln(error)) / ln(2)^2
 *
 * Optimal number of hash functions is:
 *     hashes = bpe * ln(2)
 *
 * Parameters:
 * -----------
 *     bloom   - Pointer to an allocated struct bloom (see above).
 *     entries - The expected number of entries which will be inserted.
 *               Must be at least 1000 (in practice, likely much larger).
 *     error   - Probability of collision (as long as entries are not
 *               exceeded).
 *
 * Return:
 * -------
 *     0 - on success
 *     1 - on failure
 *
 */
int bloom_init(struct bloom * bloom, int32_t entries, double error);


/** ***************************************************************************
 * Deprecated, use bloom_init()
 *
 */
int bloom_init_size(struct bloom * bloom, int32_t entries, double error,
                    int32_t cache_size);


/** ***************************************************************************
 * Check if the given element is in the bloom filter. Remember this may
 * return false positive if a collision occured.
 *
 * Parameters:
 * -----------
 *     bloom  - Pointer to an allocated struct bloom (see above).
 *     buffer - Pointer to buffer containing element to check.
 *     len    - Size of 'buffer'.
 *
 * Return:
 * -------
 *     0 - element is not present
 *     1 - element is present (or false positive due to collision)
 *    -1 - bloom not initialized
 *
 */
int bloom_check(struct bloom * bloom, const void * buffer, int32_t len);


/** ***************************************************************************
 * Add the given element to the bloom filter.
 * The return code indicates if the element (or a collision) was already in,
 * so for the common check+add use case, no need to call check separately.
 *
 * Parameters:
 * -----------
 *     bloom  - Pointer to an allocated struct bloom (see above).
 *     buffer - Pointer to buffer containing element to add.
 *     len    - Size of 'buffer'.
 *
 * Return:
 * -------
 *     0 - element was not present and was added
 *     1 - element (or a collision) had already been added previously
 *    -1 - bloom not initialized
 *
 */
int bloom_add(struct bloom * bloom, const void * buffer, int32_t len);


/** ***************************************************************************
 * Merge other filter into bloom filter.
 * The return code indicates if the merge was successful. Only bloom is updated
 * and other is not modified. Both bloom structures must have same size and
 * error.
 *
 * Parameters:
 * -----------
 *     bloom  - Pointer to an allocated struct bloom modified by merge.
 *     other  - Pointer to an allocated struct bloom not modified by merge.
 *
 * Return:
 * -------
 *     0 - merge success
 *    -1 - bloom not initialized
 *    -2 - bloom and other number  of entries differs
 *    -3 - bloom and other error differs
 *
 */
int bloom_merge(struct bloom * bloom, const struct bloom * other);


/** ***************************************************************************
 * Serialize bloom filter to a buffer.
 * Allocates and serializes bloom struct to a buffer. The buffer pointer is set
 * to the memory with serialized data. The size pointer is set to the buffer
 * size. Use "bloom_deserialize" for deserialization.
 *
 * Serialized format:
 * |size := 4B(BE)|entries := 4B(BE)|error := 8B(IEE754)|bf := size-(4+4+8)*1B|
 *
 * Parameters:
 * -----------
 *     bloom  - Pointer to an allocated bloom struct.
 *     buffer - Pointer to a buffer array.
 *     size   - Pointer to a int.
 *
 * Return:
 * -------
 *     0 - success
 *    -1 - bloom not initialized
 *    -2 - serialization failed
 *
 */
int bloom_serialize(const struct bloom * bloom, uint8_t ** buffer, int32_t * size);


/** ***************************************************************************
 * Deserialize bloom filter from a buffer.
 * The bloom struct is initialized from provided buffer. Use "bloom_serialize"
 * for serialization.
 *
 * Parameters:
 * -----------
 *     bloom  - Pointer to a bloom struct.
 *     buffer - Pointer to a buffer array.
 *
 * Return:
 * -------
 *     0 - success
 *    -2 - deserialization failed
 *
 */
int bloom_deserialize(struct bloom * bloom, const uint8_t * buffer);


/** ***************************************************************************
 * Frees buffer used for serialization.
 *
 * Parameters:
 * -----------
 *     buffer - Pointer to a buffer array.
 *
 */
void bloom_free_serialized_buffer(uint8_t ** buffer);


/** ***************************************************************************
 * Write bloom filter to a file in its serialied form.
 * New file is created if it does not exist. See "bloom_file_read".
 *
 * Parameters:
 * -----------
 *     bloom    - Pointer to a initialized bloom struct.
 *     filename - Path to which the filter is written.
 *
 * Return:
 * -------
 *     0 - success
 *    -1 - could not open (or create) file for writing
 *    -2 - could not write to file
 *    -3 - serialization failed
 *
 */
int bloom_file_write(const struct bloom * bloom, const char * filename);


/** ***************************************************************************
 * Write bloom filter to a file in its serialied form.
 * New file is created if it does not exist. See "bloom_file_read".
 *
 * Parameters:
 * -----------
 *     bloom    - Pointer to a initialized bloom struct.
 *     filename - Path to which the filter is written.
 *
 * Return:
 * -------
 *     0 - success
 *    -1 - could not open file for reading
 *    -2 - could not read from file or file too short
 *    -3 - deserialization failed
 *
 */
int bloom_file_read(struct bloom * bloom, const char * filename);


/** ***************************************************************************
 * Print (to stdout) info about this bloom filter. Debugging aid.
 *
 */
void bloom_print(struct bloom * bloom);


/** ***************************************************************************
 * Deallocate internal storage.
 *
 * Upon return, the bloom struct is no longer usable. You may call bloom_init
 * again on the same struct to reinitialize it again.
 *
 * Parameters:
 * -----------
 *     bloom  - Pointer to an allocated struct bloom (see above).
 *
 * Return: none
 *
 */
void bloom_free(struct bloom * bloom);


/** ***************************************************************************
 * Returns version string compiled into library.
 *
 * Return: version string
 *
 */
const char * bloom_version();

#ifdef __cplusplus
}
#endif

#endif
