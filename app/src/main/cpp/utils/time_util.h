#ifndef ENVCHECK_TIME_UTIL_H
#define ENVCHECK_TIME_UTIL_H

#include <time.h>

/**
 * 获取单调时钟的当前时间（纳秒）
 */
static inline long get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

#endif // ENVCHECK_TIME_UTIL_H
