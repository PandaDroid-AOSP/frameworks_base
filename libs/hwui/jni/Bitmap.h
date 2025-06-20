/*
 * Copyright (C) 2015 The Android Open Source Project
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
#ifndef BITMAP_H_
#define BITMAP_H_

#include <jni.h>
#include <android/bitmap.h>
#include <hwui/Bitmap.h>

struct SkImageInfo;

namespace android {

class Bitmap;

namespace bitmap {

enum BitmapCreateFlags {
    kBitmapCreateFlag_None = 0x0,
    kBitmapCreateFlag_Mutable = 0x1,
    kBitmapCreateFlag_Premultiplied = 0x2,
};

jobject createBitmap(JNIEnv* env, Bitmap* bitmap, int bitmapCreateFlags,
                     jbyteArray ninePatchChunk = nullptr, jobject ninePatchInsets = nullptr,
                     int density = -1, int64_t id = Bitmap::UNDEFINED_BITMAP_ID);

Bitmap& toBitmap(jlong bitmapHandle);

/** Reinitialize a bitmap. bitmap must already have its SkAlphaType set in
    sync with isPremultiplied
*/
void reinitBitmap(JNIEnv* env, jobject javaBitmap, const SkImageInfo& info,
        bool isPremultiplied);

} // namespace bitmap

} // namespace android

#endif /* BITMAP_H_ */
