#ifndef SYSTEM_PROPERTIES_H
#define SYSTEM_PROPERTIES_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 获取系统属性值
 * @param prop_name 属性名称
 * @param buffer 存储属性值的缓冲区
 * @param buffer_size 缓冲区大小
 * @return 0 表示成功，-1 表示失败
 */
int native_getprop(const char *prop_name, char *buffer, size_t buffer_size);

/**
 * 设置系统属性值
 * @param prop_name 属性名称
 * @param prop_value 属性值
 * @return 0 表示成功，-1 表示失败
 */
int native_setprop(const char *prop_name, const char *prop_value);

#ifdef __cplusplus
}
#endif

#endif // SYSTEM_PROPERTIES_H
