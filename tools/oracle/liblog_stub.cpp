/*
 * Host-only liblog stub for the lpmake oracle build. The AOSP host liblog
 * (fake log device) is not part of the pinned public liblog build, and
 * logging has no effect on the metadata bytes lpmake emits. These stubs route
 * the __android_log_* calls libbase's logging.cpp links against to stderr.
 * Not used by any cairn production code.
 */
#include <android/log.h>

#include <cstdio>
#include <cstdarg>

struct __android_log_message;

extern "C" {

void __android_log_write_log_message(struct __android_log_message* log_message) {
    (void)log_message;
}

void __android_log_logd_logger(const struct __android_log_message* log_message) {
    (void)log_message;
}

int __android_log_write(int prio, const char* tag, const char* text) {
    (void)prio;
    fprintf(stderr, "%s: %s\n", tag ? tag : "log", text ? text : "");
    return 1;
}

int __android_log_print(int prio, const char* tag, const char* fmt, ...) {
    (void)prio;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", tag ? tag : "log");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    return 1;
}

int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap) {
    (void)prio;
    fprintf(stderr, "%s: ", tag ? tag : "log");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    return 1;
}

int __android_log_buf_print(int log_id, int prio, const char* tag, const char* fmt, ...) {
    (void)log_id;
    (void)prio;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", tag ? tag : "log");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    return 1;
}

void __android_log_set_default_tag(const char* tag) { (void)tag; }

void __android_log_set_logger(__android_logger_function logger) { (void)logger; }

void __android_log_set_aborter(__android_aborter_function aborter) { (void)aborter; }

void __android_log_call_aborter(const char* abort_message) {
    fprintf(stderr, "abort: %s\n", abort_message ? abort_message : "");
}

int32_t __android_log_get_minimum_priority(void) { return ANDROID_LOG_INFO; }

int32_t __android_log_set_minimum_priority(int32_t priority) {
    (void)priority;
    return ANDROID_LOG_INFO;
}

int __android_log_is_loggable(int prio, const char* tag, int default_prio) {
    (void)prio;
    (void)tag;
    (void)default_prio;
    return 1;
}

} /* extern "C" */
