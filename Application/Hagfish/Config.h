#ifndef __HAGFISH_CONFIG_H
#define __HAGFISH_CONFIG_H

#include <sys/types.h>

#define DEFAULT_STACK_SIZE 16384

extern const char *hagfish_config_fmt;

struct component_config {
    size_t path_start, path_len;
    size_t args_start, args_len;

    size_t image_size;
    void *load_address;

    struct component_config *next;
};

struct hagfish_config {
    const char *buf;
    size_t stack_size;
    struct component_config *kernel;
    struct component_config *first_module, *last_module;
};

struct hagfish_config *parse_config(const char *buf, size_t size);

#endif /* __HAGFISH_CONFIG_H */
