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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "list.h"

struct list_head {
    list_item *first, *last;
    size_t     length;
};

struct list_item {
    list_head *head;
    list_item *prev, *next;
};

static list_item *
get_item_ptr(list_item *item)
{
    return item ? (item - 1) : NULL;
}

static list_item *
get_data_ptr(list_item *item)
{
    return item ? (item + 1) : NULL;
}

size_t
list_length(list head)
{
    return head ? head->length : 0;
}

static list_item *
list_do_insert(list *lst, list_item *where, const void *data, size_t data_size)
{
    if (!lst || !data_size) {
        return NULL;
    }
    bool allocated_head = false;
    if (!*lst) {
        *lst = (list_head *) calloc(1, sizeof(**lst));
        allocated_head = true;
        if (!*lst) {
            return NULL;
        }
    }
    list head = *lst;

    list_item *item = (list_item *) malloc(sizeof(*item) + data_size);
    if (!item) {
        if (allocated_head) {
            free(*lst);
            *lst = NULL;
        }
        return NULL;
    }
    if (data) {
        memset(item, 0, sizeof(*item));
        memcpy(get_data_ptr(item), data, data_size);
    } else {
        memset(item, 0, sizeof(*item) + data_size);
    }
    item->head = head;

    if (!head->first) {
        // new list
        head->first = head->last = item;
    } else if (where) {
        // insert before
        item->next = where;
        item->prev = where->prev;
        if (where->prev) {
            where->prev->next = item;
        }
        where->prev = item;
        if (head->first == where) {
            head->first = item;
        }
    } else {
        // append to end
        item->prev = head->last;
        head->last->next = item;
        head->last = item;
    }
    head->length++;
    return item;
}

list_item *
list_append(list *lst, const void *data, size_t data_size)
{
    list_item *item = list_do_insert(lst, NULL, data, data_size);
    return get_data_ptr(item);
}

list_item *
list_insert_after(list_item *where, const void *data, size_t data_size)
{
    where = get_item_ptr(where);
    if (!where) {
        return NULL;
    }
    list_item *item = list_do_insert(&where->head, where->next, data, data_size);
    return get_data_ptr(item);
}

list_item *
list_insert_before(list_item *where, const void *data, size_t data_size)
{
    where = get_item_ptr(where);
    if (!where) {
        return NULL;
    }
    list_item *item = list_do_insert(&where->head, where, data, data_size);
    return get_data_ptr(item);
}

list_item *
list_insert(list *lst, const void *data, size_t data_size)
{
    if (!lst) {
        return NULL;
    }
    list       head = *lst;
    list_item *where = head ? head->first : NULL;
    list_item *item = list_do_insert(lst, where, data, data_size);
    return get_data_ptr(item);
}

bool
list_is_member(list head, list_item *item)
{
    if (!head || !item) {
        return false;
    }
    return get_item_ptr(item)->head == head;
}

list_item *
list_front(list head)
{
    return head ? get_data_ptr(head->first) : NULL;
}

list_item *
list_back(list head)
{
    return head ? get_data_ptr(head->last) : NULL;
}

static list_item *
list_do_find(list_item *item, const void *data, size_t data_size)
{
    if (!item || !data || !data_size) {
        return NULL;
    }
    for (; item; item = item->next) {
        if (memcmp(get_data_ptr(item), data, data_size) == 0) {
            break;
        }
    }
    return item;
}

list_item *
list_find(list head, const void *data, size_t data_size)
{
    list_item *item = list_do_find(get_item_ptr(list_front(head)), data, data_size);
    return get_data_ptr(item);
}

list_item *
list_find_next(list_item *from, const void *data, size_t data_size)
{
    from = get_item_ptr(list_next(from));
    list_item *item = list_do_find(from, data, data_size);
    return get_data_ptr(item);
}

list_item *
list_next(list_item *item)
{
    if (!item || !(item = get_item_ptr(item)->next)) {
        return NULL;
    }
    return get_data_ptr(item);
}

list_item *
list_prev(list_item *item)
{
    if (!item || !(item = get_item_ptr(item)->prev)) {
        return NULL;
    }
    return get_data_ptr(item);
}

void
list_remove(list_item *item)
{
    if (!item) {
        return;
    }
    item = get_item_ptr(item);
    list head = item->head;

    if (item->next) {
        item->next->prev = item->prev;
    }
    if (item->prev) {
        item->prev->next = item->next;
    }
    if (item == head->first) {
        head->first = item->next;
    }
    if (item == head->last) {
        head->last = item->prev;
    }
    free(item);
    head->length--;
}

void
list_destroy(list *lst)
{
    if (!lst || !*lst) {
        return;
    }
    list       head = *lst;
    list_item *item = head->first;
    while (item) {
        list_item *next = item->next;
        free(item);
        item = next;
    }
    free(head);
    *lst = NULL;
}
