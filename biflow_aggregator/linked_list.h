/**
 * @file linked_list.h
 * @author Pavel Siska (siska@cesnet.cz)
 * @brief Implementation of double linked list.
 * @version 1.0
 * @date 16.10.2020
 * 
 * @copyright Copyright (c) 2020 CESNET
 */

#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <iostream>

template<typename T>
struct node
{
    T value;
    struct node<T>* next;
    struct node<T>* prev;

    void init(T data)
    {
        value = data;
    }
};

template<typename T>
class Dll
{
    struct node<T>* head;
    struct node<T>* tail;

public:

    void clear()
    {
        head = nullptr;
        tail = nullptr;
    }

    Dll()
    {
        head = nullptr;
        tail = nullptr;
    }

    inline struct node<T> *begin() noexcept
    {
        return head;
    }

    void insert(struct node<T> *node)
    {
        if (head == nullptr) {
            head = node;
            node->prev = nullptr;
            node->next = nullptr;
            tail = node;
            return;
        } 

        struct node<T>* tmp = tail;
         
        while (tmp != nullptr) {
            if (node->value.passive_timeout < tmp->value.passive_timeout) {
                tmp = tmp->prev;
                continue;
            }

            if (tmp == tail) {
                tmp->next = node;
                node->prev = tmp;
                node->next = nullptr;
                tail = node;
                return;
            } else {
                node->next = tmp->next;
                node->prev = tmp;
                tmp->next->prev = node;
                tmp->next = node;
                return;
            }
        }

        node->prev = nullptr;
        node->next = head;
        head->prev = node;
        head = node;
    }

    void delete_first_node() 
    {
        if (head == nullptr)
            return;
    
        if (head == tail) {
            head = nullptr;
            tail = nullptr;
            return;
        } else {
            head = head->next;
            head->prev = nullptr;
        }
    }

    void delete_node(struct node<T> *node) 
    {
        if (head == tail) {
            head = nullptr;
            tail = nullptr;
        } else if (head == node) {
            head = node->next;
            node->next->prev = nullptr;
        } else if (tail == node) {
            tail = node->prev;
            node->prev->next = nullptr;
        } else {
            node->prev->next = node->next;
            node->next->prev = node->prev;
        }
    }

    void swap(node<T> *node)
    {
        // TODO inplace
        delete_node(node);
        insert(node);
    }
};

#endif // LINKED_LIST