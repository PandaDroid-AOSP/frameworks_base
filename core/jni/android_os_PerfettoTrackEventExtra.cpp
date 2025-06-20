/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cutils/compiler.h>
#include <cutils/trace.h>
#include <jni.h>
#include <log/log.h>
#include <nativehelper/JNIHelp.h>
#include <nativehelper/scoped_utf_chars.h>
#include <nativehelper/utils.h>
#include <tracing_sdk.h>

#include <list>

namespace android {
template <typename T>
inline static T* toPointer(jlong ptr) {
    return reinterpret_cast<T*>(static_cast<uintptr_t>(ptr));
}

template <typename T>
inline static jlong toJLong(T* ptr) {
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(ptr));
}

/**
 * @brief A thread-safe utility class for converting Java UTF-16 strings to ASCII in JNI
 * environment.
 *
 * StringBuffer provides efficient conversion of Java strings to ASCII with optimized memory
 * handling.
 * It uses a two-tiered buffering strategy:
 * 1. A fast path using pre-allocated thread-local buffers for strings up to 128 characters
 * 2. A fallback path using dynamic allocation for longer strings
 *
 * Non-ASCII characters (>255) are replaced with '?' during conversion. The class maintains
 * thread safety through thread-local storage and provides zero-copy string views for optimal
 * performance.
 *
 * Memory Management:
 * - Uses fixed-size thread-local buffers for both UTF-16 and ASCII characters
 * - Overflow strings are stored in a thread-local list to maintain valid string views
 * - Avoids unnecessary allocations in the common case of small strings
 *
 * Usage example:
 * @code
 * JNIEnv* env = ...;
 * jstring java_string = ...;
 * std::string_view ascii = StringBuffer::utf16_to_ascii(env, java_string);
 * // Use the ASCII string...
 * StringBuffer::reset(); // Clean up when done
 * @endcode
 *
 * Thread Safety: All methods are thread-safe due to thread-local storage.
 */
class StringBuffer {
private:
    static constexpr size_t BASE_SIZE = 128;
    // Temporarily stores the UTF-16 characters retrieved from the Java
    // string before they are converted to ASCII.
    static thread_local inline char char_buffer[BASE_SIZE];
    // For fast-path conversions when the resulting ASCII string fits within
    // the pre-allocated space. All ascii strings in a trace event will be stored
    // here until emitted.
    static thread_local inline jchar jchar_buffer[BASE_SIZE];
    // When the fast-path conversion is not possible (because char_buffer
    // doesn't have enough space), the converted ASCII string is stored
    // in this list. We use list here to avoid moving the strings on resize
    // with vector. This way, we can give out string_views from the stored strings.
    // The additional overhead from list node allocations is fine cos we are already
    // in an extremely unlikely path here and there are other bigger problems if here.
    static thread_local inline std::list<std::string> overflow_strings;
    // current offset into the char_buffer.
    static thread_local inline size_t current_offset{0};
    // This allows us avoid touching the overflow_strings directly in the fast path.
    // Touching it causes some thread local init routine to run which shows up in profiles.
    static thread_local inline bool is_overflow_strings_empty = true;

    static void copy_utf16_to_ascii(const jchar* src, size_t len, char* dst, JNIEnv* env,
                                    jstring str) {
        std::transform(src, src + len, dst,
                       [](jchar c) { return (c <= 0xFF) ? static_cast<char>(c) : '?'; });

        if (src != jchar_buffer) {
            // We hit the slow path to populate src, so we have to release.
            env->ReleaseStringCritical(str, src);
        }
    }

public:
    static void reset() {
        if (!is_overflow_strings_empty) {
            overflow_strings.clear();
            is_overflow_strings_empty = true;
        }
        current_offset = 0;
    }

    // Converts a Java string (jstring) to an ASCII string_view. Characters
    // outside the ASCII range (0-255) are replaced with '?'.
    //
    // @param env The JNI environment.
    // @param val The Java string to convert.
    // @return A string_view representing the ASCII version of the string.
    //         Returns an empty string_view if the input is null or empty.
    static std::string_view utf16_to_ascii(JNIEnv* env, jstring val) {
        if (!val) return "";

        const jsize len = env->GetStringLength(val);
        if (len == 0) return "";

        const jchar* temp_buffer;

        // Fast path: Enough space in jchar_buffer
        if (static_cast<size_t>(len) <= BASE_SIZE) {
            env->GetStringRegion(val, 0, len, jchar_buffer);
            temp_buffer = jchar_buffer;
        } else {
            // Slow path: Fallback to asking ART for the string which will likely
            // allocate and return a copy.
            temp_buffer = env->GetStringCritical(val, nullptr);
        }

        const size_t next_offset = current_offset + len + 1;
        // Fast path: Enough space in char_buffer
        if (BASE_SIZE > next_offset) {
            const size_t start_offset = current_offset;

            copy_utf16_to_ascii(temp_buffer, len, char_buffer + current_offset, env, val);
            char_buffer[current_offset + len] = '\0';

            auto res = std::string_view(char_buffer + current_offset, len);
            current_offset = next_offset;
            return res;
        } else {
            // Slow path: Not enough space in char_buffer. Use overflow_strings.
            // This will cause a string alloc but should be very unlikely to hit.
            std::string& str = overflow_strings.emplace_back(len + 1, '\0');

            copy_utf16_to_ascii(temp_buffer, len, str.data(), env, val);
            is_overflow_strings_empty = false;
            return std::string_view(str);
        }
    }
};

static jlong android_os_PerfettoTrackEventExtraArgInt64_init(JNIEnv* env, jclass, jstring name) {
    return toJLong(new tracing_perfetto::DebugArg<int64_t>(
            StringBuffer::utf16_to_ascii(env, name).data()));
}

static jlong android_os_PerfettoTrackEventExtraArgBool_init(JNIEnv* env, jclass, jstring name) {
    return toJLong(
            new tracing_perfetto::DebugArg<bool>(StringBuffer::utf16_to_ascii(env, name).data()));
}

static jlong android_os_PerfettoTrackEventExtraArgDouble_init(JNIEnv* env, jclass, jstring name) {
    return toJLong(
            new tracing_perfetto::DebugArg<double>(StringBuffer::utf16_to_ascii(env, name).data()));
}

static jlong android_os_PerfettoTrackEventExtraArgString_init(JNIEnv* env, jclass, jstring name) {
    return toJLong(new tracing_perfetto::DebugArg<const char*>(
            StringBuffer::utf16_to_ascii(env, name).data()));
}

static jlong android_os_PerfettoTrackEventExtraArgInt64_delete() {
    return toJLong(&tracing_perfetto::DebugArg<int64_t>::delete_arg);
}

static jlong android_os_PerfettoTrackEventExtraArgBool_delete() {
    return toJLong(&tracing_perfetto::DebugArg<bool>::delete_arg);
}

static jlong android_os_PerfettoTrackEventExtraArgDouble_delete() {
    return toJLong(&tracing_perfetto::DebugArg<double>::delete_arg);
}

static jlong android_os_PerfettoTrackEventExtraArgString_delete() {
    return toJLong(&tracing_perfetto::DebugArg<const char*>::delete_arg);
}

static jlong android_os_PerfettoTrackEventExtraArgInt64_get_extra_ptr(jlong ptr) {
    tracing_perfetto::DebugArg<int64_t>* arg = toPointer<tracing_perfetto::DebugArg<int64_t>>(ptr);
    return toJLong(arg->get());
}

static jlong android_os_PerfettoTrackEventExtraArgBool_get_extra_ptr(jlong ptr) {
    tracing_perfetto::DebugArg<bool>* arg = toPointer<tracing_perfetto::DebugArg<bool>>(ptr);
    return toJLong(arg->get());
}

static jlong android_os_PerfettoTrackEventExtraArgDouble_get_extra_ptr(jlong ptr) {
    tracing_perfetto::DebugArg<double>* arg = toPointer<tracing_perfetto::DebugArg<double>>(ptr);
    return toJLong(arg->get());
}

static jlong android_os_PerfettoTrackEventExtraArgString_get_extra_ptr(jlong ptr) {
    tracing_perfetto::DebugArg<const char*>* arg =
            toPointer<tracing_perfetto::DebugArg<const char*>>(ptr);
    return toJLong(arg->get());
}

static void android_os_PerfettoTrackEventExtraArgInt64_set_value(jlong ptr, jlong val) {
    tracing_perfetto::DebugArg<int64_t>* arg = toPointer<tracing_perfetto::DebugArg<int64_t>>(ptr);
    arg->set_value(val);
}

static void android_os_PerfettoTrackEventExtraArgBool_set_value(jlong ptr, jboolean val) {
    tracing_perfetto::DebugArg<bool>* arg = toPointer<tracing_perfetto::DebugArg<bool>>(ptr);
    arg->set_value(val);
}

static void android_os_PerfettoTrackEventExtraArgDouble_set_value(jlong ptr, jdouble val) {
    tracing_perfetto::DebugArg<double>* arg = toPointer<tracing_perfetto::DebugArg<double>>(ptr);
    arg->set_value(val);
}

static void android_os_PerfettoTrackEventExtraArgString_set_value(JNIEnv* env, jclass, jlong ptr,
                                                                  jstring val) {
    tracing_perfetto::DebugArg<const char*>* arg =
            toPointer<tracing_perfetto::DebugArg<const char*>>(ptr);
    arg->set_value(StringBuffer::utf16_to_ascii(env, val).data());
}

static jlong android_os_PerfettoTrackEventExtraFieldInt64_init() {
    return toJLong(new tracing_perfetto::ProtoField<int64_t>());
}

static jlong android_os_PerfettoTrackEventExtraFieldDouble_init() {
    return toJLong(new tracing_perfetto::ProtoField<double>());
}

static jlong android_os_PerfettoTrackEventExtraFieldString_init() {
    return toJLong(new tracing_perfetto::ProtoField<const char*>());
}

static jlong android_os_PerfettoTrackEventExtraFieldNested_init() {
    return toJLong(new tracing_perfetto::ProtoFieldNested());
}

static jlong android_os_PerfettoTrackEventExtraFieldInt64_delete() {
    return toJLong(&tracing_perfetto::ProtoField<int64_t>::delete_field);
}

static jlong android_os_PerfettoTrackEventExtraFieldDouble_delete() {
    return toJLong(&tracing_perfetto::ProtoField<double>::delete_field);
}

static jlong android_os_PerfettoTrackEventExtraFieldString_delete() {
    return toJLong(&tracing_perfetto::ProtoField<const char*>::delete_field);
}

static jlong android_os_PerfettoTrackEventExtraFieldNested_delete() {
    return toJLong(&tracing_perfetto::ProtoFieldNested::delete_field);
}

static jlong android_os_PerfettoTrackEventExtraFieldInt64_get_extra_ptr(jlong ptr) {
    tracing_perfetto::ProtoField<int64_t>* field =
            toPointer<tracing_perfetto::ProtoField<int64_t>>(ptr);
    return toJLong(field->get());
}

static jlong android_os_PerfettoTrackEventExtraFieldDouble_get_extra_ptr(jlong ptr) {
    tracing_perfetto::ProtoField<double>* field =
            toPointer<tracing_perfetto::ProtoField<double>>(ptr);
    return toJLong(field->get());
}

static jlong android_os_PerfettoTrackEventExtraFieldString_get_extra_ptr(jlong ptr) {
    tracing_perfetto::ProtoField<const char*>* field =
            toPointer<tracing_perfetto::ProtoField<const char*>>(ptr);
    return toJLong(field->get());
}

static jlong android_os_PerfettoTrackEventExtraFieldNested_get_extra_ptr(jlong ptr) {
    tracing_perfetto::ProtoFieldNested* field = toPointer<tracing_perfetto::ProtoFieldNested>(ptr);
    return toJLong(field->get());
}

static void android_os_PerfettoTrackEventExtraFieldInt64_set_value(jlong ptr, jlong id, jlong val) {
    tracing_perfetto::ProtoField<int64_t>* field =
            toPointer<tracing_perfetto::ProtoField<int64_t>>(ptr);
    field->set_value(id, val);
}

static void android_os_PerfettoTrackEventExtraFieldDouble_set_value(jlong ptr, jlong id,
                                                                    jdouble val) {
    tracing_perfetto::ProtoField<double>* field =
            toPointer<tracing_perfetto::ProtoField<double>>(ptr);
    field->set_value(id, val);
}

static void android_os_PerfettoTrackEventExtraFieldString_set_value(JNIEnv* env, jclass, jlong ptr,
                                                                    jlong id, jstring val) {
    tracing_perfetto::ProtoField<const char*>* field =
            toPointer<tracing_perfetto::ProtoField<const char*>>(ptr);
    field->set_value(id, StringBuffer::utf16_to_ascii(env, val).data());
}

static void android_os_PerfettoTrackEventExtraFieldNested_add_field(jlong field_ptr,
                                                                    jlong arg_ptr) {
    tracing_perfetto::ProtoFieldNested* field =
            toPointer<tracing_perfetto::ProtoFieldNested>(field_ptr);
    field->add_field(toPointer<PerfettoTeHlProtoField>(arg_ptr));
}

static void android_os_PerfettoTrackEventExtraFieldNested_set_id(jlong ptr, jlong id) {
    tracing_perfetto::ProtoFieldNested* field = toPointer<tracing_perfetto::ProtoFieldNested>(ptr);
    field->set_id(id);
}

static jlong android_os_PerfettoTrackEventExtraFlow_init() {
    return toJLong(new tracing_perfetto::Flow());
}

static void android_os_PerfettoTrackEventExtraFlow_set_process_flow(jlong ptr, jlong id) {
    tracing_perfetto::Flow* flow = toPointer<tracing_perfetto::Flow>(ptr);
    flow->set_process_flow(id);
}

static void android_os_PerfettoTrackEventExtraFlow_set_process_terminating_flow(jlong ptr,
                                                                                jlong id) {
    tracing_perfetto::Flow* flow = toPointer<tracing_perfetto::Flow>(ptr);
    flow->set_process_terminating_flow(id);
}

static jlong android_os_PerfettoTrackEventExtraFlow_delete() {
    return toJLong(&tracing_perfetto::Flow::delete_flow);
}

static jlong android_os_PerfettoTrackEventExtraFlow_get_extra_ptr(jlong ptr) {
    tracing_perfetto::Flow* flow = toPointer<tracing_perfetto::Flow>(ptr);
    return toJLong(flow->get());
}

static jlong android_os_PerfettoTrackEventExtraNamedTrack_init(JNIEnv* env, jclass, jlong id,
                                                               jstring name, jlong parent_uuid) {
    return toJLong(
            new tracing_perfetto::NamedTrack(id, parent_uuid,
                                             StringBuffer::utf16_to_ascii(env, name).data()));
}

static jlong android_os_PerfettoTrackEventExtraNamedTrack_delete() {
    return toJLong(&tracing_perfetto::NamedTrack::delete_track);
}

static jlong android_os_PerfettoTrackEventExtraNamedTrack_get_extra_ptr(jlong ptr) {
    tracing_perfetto::NamedTrack* track = toPointer<tracing_perfetto::NamedTrack>(ptr);
    return toJLong(track->get());
}

static jlong android_os_PerfettoTrackEventExtraCounterTrack_init(JNIEnv* env, jclass, jstring name,
                                                                 jlong parent_uuid) {
    return toJLong(
            new tracing_perfetto::RegisteredTrack(1, parent_uuid,
                                                  StringBuffer::utf16_to_ascii(env, name).data(),
                                                  true));
}

static jlong android_os_PerfettoTrackEventExtraCounterTrack_delete() {
    return toJLong(&tracing_perfetto::RegisteredTrack::delete_track);
}

static jlong android_os_PerfettoTrackEventExtraCounterTrack_get_extra_ptr(jlong ptr) {
    tracing_perfetto::RegisteredTrack* track = toPointer<tracing_perfetto::RegisteredTrack>(ptr);
    return toJLong(track->get());
}

static jlong android_os_PerfettoTrackEventExtraCounterInt64_init() {
    return toJLong(new tracing_perfetto::Counter<int64_t>());
}

static jlong android_os_PerfettoTrackEventExtraCounterInt64_delete() {
    return toJLong(&tracing_perfetto::Counter<int64_t>::delete_counter);
}

static void android_os_PerfettoTrackEventExtraCounterInt64_set_value(jlong ptr, jlong val) {
    tracing_perfetto::Counter<int64_t>* counter =
            toPointer<tracing_perfetto::Counter<int64_t>>(ptr);
    counter->set_value(val);
}

static jlong android_os_PerfettoTrackEventExtraCounterInt64_get_extra_ptr(jlong ptr) {
    tracing_perfetto::Counter<int64_t>* counter =
            toPointer<tracing_perfetto::Counter<int64_t>>(ptr);
    return toJLong(counter->get());
}

static jlong android_os_PerfettoTrackEventExtraCounterDouble_init() {
    return toJLong(new tracing_perfetto::Counter<double>());
}

static jlong android_os_PerfettoTrackEventExtraCounterDouble_delete() {
    return toJLong(&tracing_perfetto::Counter<double>::delete_counter);
}

static void android_os_PerfettoTrackEventExtraCounterDouble_set_value(jlong ptr, jdouble val) {
    tracing_perfetto::Counter<double>* counter = toPointer<tracing_perfetto::Counter<double>>(ptr);
    counter->set_value(val);
}

static jlong android_os_PerfettoTrackEventExtraCounterDouble_get_extra_ptr(jlong ptr) {
    tracing_perfetto::Counter<double>* counter = toPointer<tracing_perfetto::Counter<double>>(ptr);
    return toJLong(counter->get());
}

static jlong android_os_PerfettoTrackEventExtra_init() {
    return toJLong(new tracing_perfetto::Extra());
}

static jlong android_os_PerfettoTrackEventExtra_delete() {
    return toJLong(&tracing_perfetto::Extra::delete_extra);
}

static void android_os_PerfettoTrackEventExtra_add_arg(jlong extra_ptr, jlong arg_ptr) {
    tracing_perfetto::Extra* extra = toPointer<tracing_perfetto::Extra>(extra_ptr);
    extra->push_extra(toPointer<PerfettoTeHlExtra>(arg_ptr));
}

static void android_os_PerfettoTrackEventExtra_clear_args(jlong ptr) {
    tracing_perfetto::Extra* extra = toPointer<tracing_perfetto::Extra>(ptr);
    extra->clear_extras();
}

static void android_os_PerfettoTrackEventExtra_emit(JNIEnv* env, jclass, jint type, jlong cat_ptr,
                                                    jstring name, jlong extra_ptr) {
    tracing_perfetto::Category* category = toPointer<tracing_perfetto::Category>(cat_ptr);
    tracing_perfetto::trace_event(type, category->get(),
                                  StringBuffer::utf16_to_ascii(env, name).data(),
                                  toPointer<tracing_perfetto::Extra>(extra_ptr));
    StringBuffer::reset();
}

static jlong android_os_PerfettoTrackEventExtraProto_init() {
    return toJLong(new tracing_perfetto::Proto());
}

static jlong android_os_PerfettoTrackEventExtraProto_delete() {
    return toJLong(&tracing_perfetto::Proto::delete_proto);
}

static jlong android_os_PerfettoTrackEventExtraProto_get_extra_ptr(jlong ptr) {
    tracing_perfetto::Proto* proto = toPointer<tracing_perfetto::Proto>(ptr);
    return toJLong(proto->get());
}

static void android_os_PerfettoTrackEventExtraProto_add_field(long proto_ptr, jlong arg_ptr) {
    tracing_perfetto::Proto* proto = toPointer<tracing_perfetto::Proto>(proto_ptr);
    proto->add_field(toPointer<PerfettoTeHlProtoField>(arg_ptr));
}

static void android_os_PerfettoTrackEventExtraProto_clear_fields(jlong ptr) {
    tracing_perfetto::Proto* proto = toPointer<tracing_perfetto::Proto>(ptr);
    proto->clear_fields();
}

static const JNINativeMethod gExtraMethods[] =
        {{"native_init", "()J", (void*)android_os_PerfettoTrackEventExtra_init},
         {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtra_delete},
         {"native_add_arg", "(JJ)V", (void*)android_os_PerfettoTrackEventExtra_add_arg},
         {"native_clear_args", "(J)V", (void*)android_os_PerfettoTrackEventExtra_clear_args},
         {"native_emit", "(IJLjava/lang/String;J)V",
          (void*)android_os_PerfettoTrackEventExtra_emit}};

static const JNINativeMethod gProtoMethods[] =
        {{"native_init", "()J", (void*)android_os_PerfettoTrackEventExtraProto_init},
         {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraProto_delete},
         {"native_get_extra_ptr", "(J)J",
          (void*)android_os_PerfettoTrackEventExtraProto_get_extra_ptr},
         {"native_add_field", "(JJ)V", (void*)android_os_PerfettoTrackEventExtraProto_add_field},
         {"native_clear_fields", "(J)V",
          (void*)android_os_PerfettoTrackEventExtraProto_clear_fields}};

static const JNINativeMethod gArgInt64Methods[] = {
        {"native_init", "(Ljava/lang/String;)J",
         (void*)android_os_PerfettoTrackEventExtraArgInt64_init},
        {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraArgInt64_delete},
        {"native_get_extra_ptr", "(J)J",
         (void*)android_os_PerfettoTrackEventExtraArgInt64_get_extra_ptr},
        {"native_set_value", "(JJ)V", (void*)android_os_PerfettoTrackEventExtraArgInt64_set_value},
};

static const JNINativeMethod gArgBoolMethods[] = {
        {"native_init", "(Ljava/lang/String;)J",
         (void*)android_os_PerfettoTrackEventExtraArgBool_init},
        {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraArgBool_delete},
        {"native_get_extra_ptr", "(J)J",
         (void*)android_os_PerfettoTrackEventExtraArgBool_get_extra_ptr},
        {"native_set_value", "(JZ)V", (void*)android_os_PerfettoTrackEventExtraArgBool_set_value},
};

static const JNINativeMethod gArgDoubleMethods[] = {
        {"native_init", "(Ljava/lang/String;)J",
         (void*)android_os_PerfettoTrackEventExtraArgDouble_init},
        {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraArgDouble_delete},
        {"native_get_extra_ptr", "(J)J",
         (void*)android_os_PerfettoTrackEventExtraArgDouble_get_extra_ptr},
        {"native_set_value", "(JD)V", (void*)android_os_PerfettoTrackEventExtraArgDouble_set_value},
};

static const JNINativeMethod gArgStringMethods[] = {
        {"native_init", "(Ljava/lang/String;)J",
         (void*)android_os_PerfettoTrackEventExtraArgString_init},
        {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraArgString_delete},
        {"native_get_extra_ptr", "(J)J",
         (void*)android_os_PerfettoTrackEventExtraArgString_get_extra_ptr},
        {"native_set_value", "(JLjava/lang/String;)V",
         (void*)android_os_PerfettoTrackEventExtraArgString_set_value},
};

static const JNINativeMethod gFieldInt64Methods[] = {
        {"native_init", "()J", (void*)android_os_PerfettoTrackEventExtraFieldInt64_init},
        {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraFieldInt64_delete},
        {"native_get_extra_ptr", "(J)J",
         (void*)android_os_PerfettoTrackEventExtraFieldInt64_get_extra_ptr},
        {"native_set_value", "(JJJ)V",
         (void*)android_os_PerfettoTrackEventExtraFieldInt64_set_value},
};

static const JNINativeMethod gFieldDoubleMethods[] = {
        {"native_init", "()J", (void*)android_os_PerfettoTrackEventExtraFieldDouble_init},
        {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraFieldDouble_delete},
        {"native_get_extra_ptr", "(J)J",
         (void*)android_os_PerfettoTrackEventExtraFieldDouble_get_extra_ptr},
        {"native_set_value", "(JJD)V",
         (void*)android_os_PerfettoTrackEventExtraFieldDouble_set_value},
};

static const JNINativeMethod gFieldStringMethods[] = {
        {"native_init", "()J", (void*)android_os_PerfettoTrackEventExtraFieldString_init},
        {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraFieldString_delete},
        {"native_get_extra_ptr", "(J)J",
         (void*)android_os_PerfettoTrackEventExtraFieldString_get_extra_ptr},
        {"native_set_value", "(JJLjava/lang/String;)V",
         (void*)android_os_PerfettoTrackEventExtraFieldString_set_value},
};

static const JNINativeMethod gFieldNestedMethods[] =
        {{"native_init", "()J", (void*)android_os_PerfettoTrackEventExtraFieldNested_init},
         {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraFieldNested_delete},
         {"native_get_extra_ptr", "(J)J",
          (void*)android_os_PerfettoTrackEventExtraFieldNested_get_extra_ptr},
         {"native_add_field", "(JJ)V",
          (void*)android_os_PerfettoTrackEventExtraFieldNested_add_field},
         {"native_set_id", "(JJ)V", (void*)android_os_PerfettoTrackEventExtraFieldNested_set_id}};

static const JNINativeMethod gFlowMethods[] = {
        {"native_init", "()J", (void*)android_os_PerfettoTrackEventExtraFlow_init},
        {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraFlow_delete},
        {"native_set_process_flow", "(JJ)V",
         (void*)android_os_PerfettoTrackEventExtraFlow_set_process_flow},
        {"native_set_process_terminating_flow", "(JJ)V",
         (void*)android_os_PerfettoTrackEventExtraFlow_set_process_terminating_flow},
        {"native_get_extra_ptr", "(J)J",
         (void*)android_os_PerfettoTrackEventExtraFlow_get_extra_ptr},
};

static const JNINativeMethod gNamedTrackMethods[] = {
        {"native_init", "(JLjava/lang/String;J)J",
         (void*)android_os_PerfettoTrackEventExtraNamedTrack_init},
        {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraNamedTrack_delete},
        {"native_get_extra_ptr", "(J)J",
         (void*)android_os_PerfettoTrackEventExtraNamedTrack_get_extra_ptr},
};

static const JNINativeMethod gCounterTrackMethods[] =
        {{"native_init", "(Ljava/lang/String;J)J",
          (void*)android_os_PerfettoTrackEventExtraCounterTrack_init},
         {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraCounterTrack_delete},
         {"native_get_extra_ptr", "(J)J",
          (void*)android_os_PerfettoTrackEventExtraCounterTrack_get_extra_ptr}};

static const JNINativeMethod gCounterInt64Methods[] =
        {{"native_init", "()J", (void*)android_os_PerfettoTrackEventExtraCounterInt64_init},
         {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraCounterInt64_delete},
         {"native_set_value", "(JJ)V",
          (void*)android_os_PerfettoTrackEventExtraCounterInt64_set_value},
         {"native_get_extra_ptr", "(J)J",
          (void*)android_os_PerfettoTrackEventExtraCounterInt64_get_extra_ptr}};

static const JNINativeMethod gCounterDoubleMethods[] =
        {{"native_init", "()J", (void*)android_os_PerfettoTrackEventExtraCounterDouble_init},
         {"native_delete", "()J", (void*)android_os_PerfettoTrackEventExtraCounterDouble_delete},
         {"native_set_value", "(JD)V",
          (void*)android_os_PerfettoTrackEventExtraCounterDouble_set_value},
         {"native_get_extra_ptr", "(J)J",
          (void*)android_os_PerfettoTrackEventExtraCounterDouble_get_extra_ptr}};

int register_android_os_PerfettoTrackEventExtra(JNIEnv* env) {
    int res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$ArgInt64",
                                       gArgInt64Methods, NELEM(gArgInt64Methods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register arg int64 native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$ArgBool",
                                   gArgBoolMethods, NELEM(gArgBoolMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register arg bool native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$ArgDouble",
                                   gArgDoubleMethods, NELEM(gArgDoubleMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register arg double native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$ArgString",
                                   gArgStringMethods, NELEM(gArgStringMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register arg string native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$FieldInt64",
                                   gFieldInt64Methods, NELEM(gFieldInt64Methods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register field int64 native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$FieldDouble",
                                   gFieldDoubleMethods, NELEM(gFieldDoubleMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register field double native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$FieldString",
                                   gFieldStringMethods, NELEM(gFieldStringMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register field string native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$FieldNested",
                                   gFieldNestedMethods, NELEM(gFieldNestedMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register field nested native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra", gExtraMethods,
                                   NELEM(gExtraMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register extra native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$Proto", gProtoMethods,
                                   NELEM(gProtoMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register proto native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$Flow", gFlowMethods,
                                   NELEM(gFlowMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register flow native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$NamedTrack",
                                   gNamedTrackMethods, NELEM(gNamedTrackMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register named track native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$CounterTrack",
                                   gCounterTrackMethods, NELEM(gCounterTrackMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register counter track native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$CounterInt64",
                                   gCounterInt64Methods, NELEM(gCounterInt64Methods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register counter int64 native methods.");

    res = jniRegisterNativeMethods(env, "android/os/PerfettoTrackEventExtra$CounterDouble",
                                   gCounterDoubleMethods, NELEM(gCounterDoubleMethods));
    LOG_ALWAYS_FATAL_IF(res < 0, "Unable to register counter double native methods.");
    return 0;
}

} // namespace android
