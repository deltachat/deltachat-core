/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/** Doubly linked list
 *  @file
 */
#ifndef RNP_LIST_H
#define RNP_LIST_H

#include <stddef.h>
#include <stdbool.h>

/**
 *  @private
 *  Note that all list_item pointers returned from the
 *  API are actually pointers directly to your data,
 *  and thus can be directly cast to the appropriate
 *  type.
 *
 *  The code below will print:
 *      first
 *      second
 *
 *  @code
 *  // always initialize to NULL
 *  list lst = NULL;
 *  list_append(&lst, "second", strlen("second") + 1);
 *  list_insert(&lst, "first", strlen("first") + 1);
 *  assert(list_length(lst) == 2);
 *
 *  list_item *item = list_front(lst);
 *  while (item) {
 *      printf("%s\n", (char*)item);
 *      item = list_next(item);
 *  }
 *  @endcode
 *
 *  Searching:
 *  The code below searches for the value 1 and will
 *  output:
 *      Found 1
 *      Found 1
 *      Found 1
 *
 *  @code
 *  list lst = NULL;
 *  static const int some_ints[] = {0, 1, 1, 2, 3, 4, 1};
 *  for (int i = 0; i < sizeof(some_ints) / sizeof(some_ints[0]); i++) {
 *      list_append(&lst, &some_ints[i], sizeof(some_ints[i]));
 *  }
 *
 *  int one = 1;
 *  list_item *item = list_find(lst, &one, sizeof(one));
 *  while (item) {
 *      printf("Found %d\n", *(int*)item);
 *      item = list_find_next(item, &one, sizeof(one));
 *  }
 *  @endcode
 */

typedef struct list_head *list;
typedef struct list_head  list_head;
typedef struct list_item  list_item;

/** @private
 *  append data to the list
 *
 *  @param lst pointer to the list, which should not be NULL
 *  @param data pointer to the data. If NULL, the new item will
 *         be zero-initialized. Otherwise, the data will be
 *         copied to the new item
 *  @param data_size size of the data, which must be >= 1
 *  @return the new item or NULL if memory allocation failed
 **/
list_item *list_append(list *lst, const void *data, size_t data_size);

/** @private
 *  insert data at the front the list
 *
 *  @param lst pointer to the list, which should not be NULL
 *  @param data pointer to the data. If NULL, the new item will
 *         be zero-initialized. Otherwise, the data will be
 *         copied to the new item.
 *  @param data_size size of the data, which must be >= 1
 *  @return the new item or NULL if memory allocation failed
 **/
list_item *list_insert(list *lst, const void *data, size_t data_size);

/** @private
 *  insert data before a particular item in the list
 *
 *  @param where pointer to the item, which should not be NULL
 *  @param data pointer to the data. If NULL, the new item will
 *         be zero-initialized. Otherwise, the data will be
 *         copied to the new item.
 *  @param data_size size of the data, which must be >= 1
 *  @return the new item or NULL if memory allocation failed
 **/
list_item *list_insert_before(list_item *where, const void *data, size_t data_size);

/** @private
 *  insert data after a particular item in the list
 *
 *  @param where pointer to the item, which should not be NULL
 *  @param data pointer to the data. If NULL, the new item will
 *         be zero-initialized. Otherwise, the data will be
 *         copied to the new item.
 *  @param data_size size of the data, which must be >= 1
 *  @return the new item or NULL if memory allocation failed
 **/
list_item *list_insert_after(list_item *where, const void *data, size_t data_size);

/** @private
 *  check if an item is a member of a list
 *
 *  This is a quick operation, it does not need to traverse the list.
 *
 *  @param lst the list
 *  @param item pointer to the item, which should not be NULL
 *  @return true if the item is a member of the list, false otherwise
 **/
bool list_is_member(list lst, list_item *item);

/** @private
 *  get the number of items in a list
 *
 *  @param lst the list
 *  @return the number of items in the list
 **/
size_t list_length(list lst);

/** @private
 *  remove an item from a list
 *
 *  @param item pointer to the item to remove, which should not be NULL
 **/
void list_remove(list_item *item);

/** @private
 *  destroy a list and all items
 *
 *  @param lst pointer to the list, which should not be NULL
 **/
void list_destroy(list *lst);

/** @private
 *  get the first item in a list
 *
 *  @param lst the list
 *  @return pointer to the item, if any, otherwise NULL
 **/
list_item *list_front(list lst);

/** @private
 *  get the last item in a list
 *
 *  @param lst the list
 *  @return pointer to the item, if any, otherwise
 **/
list_item *list_back(list lst);

/** @private
 *  search the list for some data
 *
 *  **Note**: that this will do a byte-for-byte comparison
 *  of size data_size, so it may not be very efficient,
 *  depending on the data type stored.
 *
 *  @param lst the list
 *  @param data pointer to the data, which should not be NULL
 *  @param data_size size of the data, which must be >= 1
 *  @return pointer to the found item, if any, otherwise NULL
 **/
list_item *list_find(list lst, const void *data, size_t data_size);

/** @private
 *  search the list for some data, starting after the specified
 *  location
 *
 *  **Note**: that this will do a byte-for-byte comparison
 *  of size data_size, so it may not be very efficient,
 *  depending on the data type stored.
 *
 *  @param from pointer to the item, after which the search
 *         will begin. Should not be NULL.
 *  @param data pointer to the data, which should not be NULL
 *  @param data_size size of the data, which must be >= 1
 *  @return pointer to the found item, if any, otherwise NULL
 **/
list_item *list_find_next(list_item *from, const void *data, size_t data_size);

/** @private
 *  get the next item in a list, if any
 *
 *  @param item pointer to the list item, which should not be NULL
 *  @return pointer to the next item, if any, otherwise NULL
 **/
list_item *list_next(list_item *item);

/** @private
 *  get the previous item in a list, if any
 *
 *  @param item pointer to the list item, which should not be NULL
 *  @return pointer to the previous item, if any, otherwise NULL
 **/
list_item *list_prev(list_item *item);

#endif
