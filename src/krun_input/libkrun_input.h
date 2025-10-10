#ifndef _LIBKRUN_INPUT_H
#define _LIBKRUN_INPUT_H

#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// The input backend encountered an internal error
#define KRUN_INPUT_ERR_INTERNAL -1
#define KRUN_INPUT_ERR_EAGAIN -2
#define KRUN_INPUT_ERR_METHOD_UNSUPPORTED -3
#define KRUN_INPUT_ERR_INVALID_PARAM -4


#define KRUN_INPUT_CONFIG_FEATURE_QUERY 1
#define KRUN_INPUT_EVENT_PROVIDER_FEATURE_QUEUE 1

/**
 * Represents an input event similar to Linux input events.
 * This structure is compatible with virtio input events.
 */
struct krun_input_event {
    uint16_t type;  // Event type (EV_KEY, EV_REL, EV_ABS, etc.)
    uint16_t code;  // Event code (key code, relative axis, etc.)
    uint32_t value; // Event value
};

/**
 * Called to create an input backend instance.
 *
 * Arguments:
 *  "instance"    - (Output) pointer to userdata which can be used to represent this/self argument.
 *                  Implementation may set it to any value (even NULL)
 *  "userdata"    - userdata specified in the `krun_input_backend` instance
 *  "reserved"    - reserved/unused for now (arguments passed from libkrun to user)
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_INPUT_ERR_*) otherwise.
 */
typedef int32_t (*krun_input_create_fn)(void **instance, const void *userdata, const void *reserved);

/**
 * Called to destroy the input backend instance.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_input_create`, represents this/self argument
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_INPUT_ERR_*) otherwise.
 */
typedef int32_t (*krun_input_destroy_fn)(void *instance);

/**
 * Gets a file descriptor that becomes ready for reading when input events are available.
 * The implementation should return an eventfd or similar file descriptor that can be used
 * with epoll/poll/select to wait for input events.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_input_create`, represents this/self argument
 *
 * Returns:
 *  A valid file descriptor (>= 0) or a negative error code (KRUN_INPUT_ERR_*) otherwise.
 */
typedef int (*krun_input_get_ready_efd_fn)(void *instance);

/**
 * Fetches the next available input event from the backend.
 * This function should not block. If no events are available, it should return 0.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_input_create`, represents this/self argument
 *  "out_event"   - (Output) pointer to where the event should be written
 *
 * Returns:
 *  1 if an event was successfully retrieved and written to out_event
 *  0 if no events are available
 *  negative error code (KRUN_INPUT_ERR_*) on error
 */
typedef int32_t (*krun_input_next_event_fn)(void *instance, struct krun_input_event *out_event);

struct krun_input_event_provider_vtable {
    krun_input_destroy_fn         destroy;        // (optional)
    krun_input_get_ready_efd_fn   get_ready_efd;  // (required)
    krun_input_next_event_fn      next_event;     // (required)
};

/**
 * Device IDs structure for input devices
 */
struct krun_input_device_ids {
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
};

/**
 * Absolute axis information structure
 */
struct krun_input_absinfo {
    uint32_t min;
    uint32_t max;
    uint32_t fuzz;
    uint32_t flat;
    uint32_t res;
};

/**
 * Called to create an instance of an object
 * 
 * Arguments:
 *  "instance"    - (Output) pointer to userdata which can be used to represent this/self argument.
 *  "userdata"    - userdata specified in the config object
 *  "reserved"    - reserved/unused for now
 * 
 * Returns:
 *  Zero on success or a negative error code (KRUN_INPUT_ERR_*) otherwise.
 */
typedef int32_t (*krun_input_create_fn)(void **instance, const void *userdata, const void *reserved);

/**
 * Function pointer types for querying device configuration
 */
typedef int32_t (*krun_input_query_device_name_fn)(void *instance, uint8_t *name_buf, size_t name_buf_len);
typedef int32_t (*krun_input_query_serial_name_fn)(void *instance, uint8_t *name_buf, size_t name_buf_len);
typedef int32_t (*krun_input_query_device_ids_fn)(void *instance, struct krun_input_device_ids *ids);
typedef int32_t (*krun_input_query_event_capabilities_fn)(void *instance, uint8_t event_type, uint8_t *bitmap_buf, size_t bitmap_buf_len);
typedef int32_t (*krun_input_query_abs_info_fn)(void *instance, uint8_t abs_axis, struct krun_input_absinfo *abs_info);
typedef int32_t (*krun_input_query_properties_fn)(void *instance, uint8_t *bitmap_buf, size_t bitmap_buf_len);

/**
 * Config vtable structure  
 */
struct krun_input_config_vtable {
    krun_input_destroy_fn                  destroy;
    krun_input_query_device_name_fn        query_device_name;
    krun_input_query_serial_name_fn        query_serial_name;
    krun_input_query_device_ids_fn         query_device_ids;
    krun_input_query_event_capabilities_fn query_event_capabilities;
    krun_input_query_abs_info_fn           query_abs_info;
    krun_input_query_properties_fn         query_properties;
};

/**
 * Config object structure
 */
struct krun_input_config {
    uint64_t features;
    void *create_userdata; // (optional)
    krun_input_create_fn create; // Creates the config object
    struct krun_input_config_vtable vtable;
};

/**
 * Events object structure
 */
struct krun_input_event_provider {
    uint64_t features;
    void *create_userdata; // (optional)
    krun_input_create_fn create; // Creates the events object
    struct krun_input_event_provider_vtable vtable;
};

#ifdef __cplusplus
}
#endif

#endif // _LIBKRUN_INPUT_H