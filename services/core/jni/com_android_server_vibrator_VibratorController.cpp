/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "VibratorController"

#include <aidl/android/hardware/vibrator/IVibrator.h>
#include <android/binder_parcel.h>
#include <android/binder_parcel_jni.h>
#include <android/persistable_bundle_aidl.h>
#include <android_os_vibrator.h>
#include <nativehelper/JNIHelp.h>
#include <utils/Log.h>
#include <utils/misc.h>
#include <vibratorservice/VibratorHalController.h>

#include "android_runtime/AndroidRuntime.h"
#include "com_android_server_vibrator_VibratorManagerService.h"
#include "core_jni_helpers.h"
#include "jni.h"

namespace Aidl = aidl::android::hardware::vibrator;

using aidl::android::os::PersistableBundle;

namespace android {

static JavaVM* sJvm = nullptr;
static jmethodID sMethodIdOnComplete;
static jclass sFrequencyProfileLegacyClass;
static jmethodID sFrequencyProfileLegacyCtor;
static jclass sFrequencyProfileClass;
static jmethodID sFrequencyProfileCtor;
static struct {
    jmethodID setCapabilities;
    jmethodID setSupportedEffects;
    jmethodID setSupportedBraking;
    jmethodID setPwlePrimitiveDurationMax;
    jmethodID setPwleSizeMax;
    jmethodID setSupportedPrimitive;
    jmethodID setPrimitiveDelayMax;
    jmethodID setCompositionSizeMax;
    jmethodID setQFactor;
    jmethodID setFrequencyProfileLegacy;
    jmethodID setFrequencyProfile;
    jmethodID setMaxEnvelopeEffectSize;
    jmethodID setMinEnvelopeEffectControlPointDurationMillis;
    jmethodID setMaxEnvelopeEffectControlPointDurationMillis;
} sVibratorInfoBuilderClassInfo;
static struct {
    jfieldID id;
    jfieldID scale;
    jfieldID delay;
} sPrimitiveClassInfo;
static struct {
    jfieldID startAmplitude;
    jfieldID endAmplitude;
    jfieldID startFrequencyHz;
    jfieldID endFrequencyHz;
    jfieldID duration;
} sRampClassInfo;
static struct {
    jfieldID amplitude;
    jfieldID frequencyHz;
    jfieldID timeMillis;
} sPwlePointClassInfo;

static std::shared_ptr<vibrator::HalController> findVibrator(int32_t vibratorId) {
    vibrator::ManagerHalController* manager =
            android_server_vibrator_VibratorManagerService_getManager();
    if (manager == nullptr) {
        return nullptr;
    }
    auto result = manager->getVibrator(vibratorId);
    return result.isOk() ? result.value() : nullptr;
}

class VibratorControllerWrapper {
public:
    VibratorControllerWrapper(JNIEnv* env, int32_t vibratorId, jobject callbackListener)
          : mHal(findVibrator(vibratorId)),
            mVibratorId(vibratorId),
            mCallbackListener(env->NewGlobalRef(callbackListener)) {
        LOG_ALWAYS_FATAL_IF(mHal == nullptr,
                            "Failed to connect to vibrator HAL, or vibratorId is invalid");
        LOG_ALWAYS_FATAL_IF(mCallbackListener == nullptr,
                            "Unable to create global reference to vibration callback handler");
    }

    ~VibratorControllerWrapper() {
        auto jniEnv = GetOrAttachJNIEnvironment(sJvm);
        jniEnv->DeleteGlobalRef(mCallbackListener);
    }

    int32_t getVibratorId() const { return mVibratorId; }

    vibrator::Info getVibratorInfo() { return mHal->getInfo(); }

    void initHal() { mHal->init(); }

    template <typename T>
    vibrator::HalResult<T> halCall(const vibrator::HalFunction<vibrator::HalResult<T>>& fn,
                                   const char* functionName) {
        return mHal->doWithRetry(fn, functionName);
    }

    std::function<void()> createCallback(jlong vibrationId, jlong stepId) {
        auto callbackId = ++mCallbackId;
        return [vibrationId, stepId, callbackId, this]() {
            auto currentCallbackId = mCallbackId.load();
            if (!android_os_vibrator_fix_vibration_thread_callback_handling() &&
                currentCallbackId != callbackId) {
                // This callback is from an older HAL call that is no longer relevant
                return;
            }
            auto jniEnv = GetOrAttachJNIEnvironment(sJvm);
            jniEnv->CallVoidMethod(mCallbackListener, sMethodIdOnComplete, mVibratorId, vibrationId,
                                   stepId);
        };
    }

    void disableOldCallbacks() {
        // TODO remove this once android_os_vibrator_fix_vibration_thread_callback_handling removed
        mCallbackId++;
    }

private:
    const std::shared_ptr<vibrator::HalController> mHal;
    const int32_t mVibratorId;
    const jobject mCallbackListener;
    // TODO remove this once android_os_vibrator_fix_vibration_thread_callback_handling removed
    std::atomic<int64_t> mCallbackId;
};

static Aidl::BrakingPwle brakingPwle(Aidl::Braking braking, int32_t duration) {
    Aidl::BrakingPwle pwle;
    pwle.braking = braking;
    pwle.duration = duration;
    return pwle;
}

static Aidl::ActivePwle activePwleFromJavaPrimitive(JNIEnv* env, jobject ramp) {
    Aidl::ActivePwle pwle;
    pwle.startAmplitude =
            static_cast<float>(env->GetFloatField(ramp, sRampClassInfo.startAmplitude));
    pwle.endAmplitude = static_cast<float>(env->GetFloatField(ramp, sRampClassInfo.endAmplitude));
    pwle.startFrequency =
            static_cast<float>(env->GetFloatField(ramp, sRampClassInfo.startFrequencyHz));
    pwle.endFrequency = static_cast<float>(env->GetFloatField(ramp, sRampClassInfo.endFrequencyHz));
    pwle.duration = static_cast<int32_t>(env->GetIntField(ramp, sRampClassInfo.duration));
    return pwle;
}

static Aidl::PwleV2Primitive pwleV2PrimitiveFromJavaPrimitive(JNIEnv* env, jobject pwleObj) {
    Aidl::PwleV2Primitive pwle;
    pwle.amplitude = static_cast<float>(env->GetFloatField(pwleObj, sPwlePointClassInfo.amplitude));
    pwle.frequencyHz =
            static_cast<float>(env->GetFloatField(pwleObj, sPwlePointClassInfo.frequencyHz));
    pwle.timeMillis =
            static_cast<int32_t>(env->GetIntField(pwleObj, sPwlePointClassInfo.timeMillis));
    return pwle;
}

/* Return true if braking is not NONE and the active PWLE starts and ends with zero amplitude. */
static bool shouldBeReplacedWithBraking(Aidl::ActivePwle activePwle, Aidl::Braking braking) {
    return (braking != Aidl::Braking::NONE) && (activePwle.startAmplitude == 0) &&
            (activePwle.endAmplitude == 0);
}

/* Return true if braking is not NONE and the active PWLE only ends with zero amplitude. */
static bool shouldAddLastBraking(Aidl::ActivePwle lastActivePwle, Aidl::Braking braking) {
    return (braking != Aidl::Braking::NONE) && (lastActivePwle.startAmplitude > 0) &&
            (lastActivePwle.endAmplitude == 0);
}

static Aidl::CompositeEffect effectFromJavaPrimitive(JNIEnv* env, jobject primitive) {
    Aidl::CompositeEffect effect;
    effect.primitive = static_cast<Aidl::CompositePrimitive>(
            env->GetIntField(primitive, sPrimitiveClassInfo.id));
    effect.scale = static_cast<float>(env->GetFloatField(primitive, sPrimitiveClassInfo.scale));
    effect.delayMs = static_cast<int32_t>(env->GetIntField(primitive, sPrimitiveClassInfo.delay));
    return effect;
}

static Aidl::VendorEffect vendorEffectFromJavaParcel(JNIEnv* env, jobject vendorData,
                                                     jlong strength, jfloat scale,
                                                     jfloat adaptiveScale) {
    PersistableBundle bundle;
    if (AParcel* parcel = AParcel_fromJavaParcel(env, vendorData); parcel != nullptr) {
        if (binder_status_t status = bundle.readFromParcel(parcel); status == STATUS_OK) {
            AParcel_delete(parcel);
        } else {
            jniThrowExceptionFmt(env, "android/os/BadParcelableException",
                                 "Failed to readFromParcel, status %d (%s)", status,
                                 strerror(-status));
        }
    } else {
        jniThrowExceptionFmt(env, "android/os/BadParcelableException",
                             "Failed to AParcel_fromJavaParcel, for nullptr");
    }

    Aidl::VendorEffect effect;
    effect.vendorData = bundle;
    effect.strength = static_cast<Aidl::EffectStrength>(strength);
    effect.scale = static_cast<float>(scale);
    effect.vendorScale = static_cast<float>(adaptiveScale);
    return effect;
}

static void destroyNativeWrapper(void* ptr) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper) {
        delete wrapper;
    }
}

static jlong vibratorNativeInit(JNIEnv* env, jclass /* clazz */, jint vibratorId,
                                jobject callbackListener) {
    std::unique_ptr<VibratorControllerWrapper> wrapper =
            std::make_unique<VibratorControllerWrapper>(env, vibratorId, callbackListener);
    wrapper->initHal();
    return reinterpret_cast<jlong>(wrapper.release());
}

static jlong vibratorGetNativeFinalizer(JNIEnv* /* env */, jclass /* clazz */) {
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(&destroyNativeWrapper));
}

static jboolean vibratorIsAvailable(JNIEnv* env, jclass /* clazz */, jlong ptr) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorIsAvailable failed because native wrapper was not initialized");
        return JNI_FALSE;
    }
    auto pingFn = [](vibrator::HalWrapper* hal) { return hal->ping(); };
    return wrapper->halCall<void>(pingFn, "ping").isOk() ? JNI_TRUE : JNI_FALSE;
}

static jlong vibratorOn(JNIEnv* env, jclass /* clazz */, jlong ptr, jlong timeoutMs,
                        jlong vibrationId, jlong stepId) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorOn failed because native wrapper was not initialized");
        return -1;
    }
    auto callback = wrapper->createCallback(vibrationId, stepId);
    auto onFn = [timeoutMs, &callback](vibrator::HalWrapper* hal) {
        return hal->on(std::chrono::milliseconds(timeoutMs), callback);
    };
    auto result = wrapper->halCall<void>(onFn, "on");
    return result.isOk() ? timeoutMs : (result.isUnsupported() ? 0 : -1);
}

static void vibratorOff(JNIEnv* env, jclass /* clazz */, jlong ptr) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorOff failed because native wrapper was not initialized");
        return;
    }
    auto offFn = [](vibrator::HalWrapper* hal) { return hal->off(); };
    wrapper->halCall<void>(offFn, "off");
    wrapper->disableOldCallbacks();
}

static void vibratorSetAmplitude(JNIEnv* env, jclass /* clazz */, jlong ptr, jfloat amplitude) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorSetAmplitude failed because native wrapper was not initialized");
        return;
    }
    auto setAmplitudeFn = [amplitude](vibrator::HalWrapper* hal) {
        return hal->setAmplitude(static_cast<float>(amplitude));
    };
    wrapper->halCall<void>(setAmplitudeFn, "setAmplitude");
}

static void vibratorSetExternalControl(JNIEnv* env, jclass /* clazz */, jlong ptr,
                                       jboolean enabled) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorSetExternalControl failed because native wrapper was not initialized");
        return;
    }
    auto setExternalControlFn = [enabled](vibrator::HalWrapper* hal) {
        return hal->setExternalControl(enabled);
    };
    wrapper->halCall<void>(setExternalControlFn, "setExternalControl");
}

static jlong vibratorPerformEffect(JNIEnv* env, jclass /* clazz */, jlong ptr, jlong effect,
                                   jlong strength, jlong vibrationId, jlong stepId) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorPerformEffect failed because native wrapper was not initialized");
        return -1;
    }
    Aidl::Effect effectType = static_cast<Aidl::Effect>(effect);
    Aidl::EffectStrength effectStrength = static_cast<Aidl::EffectStrength>(strength);
    auto callback = wrapper->createCallback(vibrationId, stepId);
    auto performEffectFn = [effectType, effectStrength, &callback](vibrator::HalWrapper* hal) {
        return hal->performEffect(effectType, effectStrength, callback);
    };
    auto result = wrapper->halCall<std::chrono::milliseconds>(performEffectFn, "performEffect");
    return result.isOk() ? result.value().count() : (result.isUnsupported() ? 0 : -1);
}

static jlong vibratorPerformVendorEffect(JNIEnv* env, jclass /* clazz */, jlong ptr,
                                         jobject vendorData, jlong strength, jfloat scale,
                                         jfloat adaptiveScale, jlong vibrationId, jlong stepId) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorPerformVendorEffect failed because native wrapper was not initialized");
        return -1;
    }
    Aidl::VendorEffect effect =
            vendorEffectFromJavaParcel(env, vendorData, strength, scale, adaptiveScale);
    auto callback = wrapper->createCallback(vibrationId, stepId);
    auto performVendorEffectFn = [&effect, &callback](vibrator::HalWrapper* hal) {
        return hal->performVendorEffect(effect, callback);
    };
    auto result = wrapper->halCall<void>(performVendorEffectFn, "performVendorEffect");
    return result.isOk() ? std::numeric_limits<int64_t>::max() : (result.isUnsupported() ? 0 : -1);
}

static jlong vibratorPerformComposedEffect(JNIEnv* env, jclass /* clazz */, jlong ptr,
                                           jobjectArray composition, jlong vibrationId,
                                           jlong stepId) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorPerformComposedEffect failed because native wrapper was not initialized");
        return -1;
    }
    size_t size = env->GetArrayLength(composition);
    std::vector<Aidl::CompositeEffect> effects;
    for (size_t i = 0; i < size; i++) {
        jobject element = env->GetObjectArrayElement(composition, i);
        effects.push_back(effectFromJavaPrimitive(env, element));
    }
    auto callback = wrapper->createCallback(vibrationId, stepId);
    auto performComposedEffectFn = [&effects, &callback](vibrator::HalWrapper* hal) {
        return hal->performComposedEffect(effects, callback);
    };
    auto result = wrapper->halCall<std::chrono::milliseconds>(performComposedEffectFn,
                                                              "performComposedEffect");
    return result.isOk() ? result.value().count() : (result.isUnsupported() ? 0 : -1);
}

static jlong vibratorPerformPwleEffect(JNIEnv* env, jclass /* clazz */, jlong ptr,
                                       jobjectArray waveform, jint brakingId, jlong vibrationId,
                                       jlong stepId) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorPerformPwleEffect failed because native wrapper was not initialized");
        return -1;
    }
    Aidl::Braking braking = static_cast<Aidl::Braking>(brakingId);
    size_t size = env->GetArrayLength(waveform);
    std::vector<Aidl::PrimitivePwle> primitives;
    std::chrono::milliseconds totalDuration(0);
    for (size_t i = 0; i < size; i++) {
        jobject element = env->GetObjectArrayElement(waveform, i);
        Aidl::ActivePwle activePwle = activePwleFromJavaPrimitive(env, element);
        if ((i > 0) && shouldBeReplacedWithBraking(activePwle, braking)) {
            primitives.push_back(brakingPwle(braking, activePwle.duration));
        } else {
            primitives.push_back(activePwle);
        }
        totalDuration += std::chrono::milliseconds(activePwle.duration);

        if ((i == (size - 1)) && shouldAddLastBraking(activePwle, braking)) {
            primitives.push_back(brakingPwle(braking, 0 /* duration */));
        }
    }

    auto callback = wrapper->createCallback(vibrationId, stepId);
    auto performPwleEffectFn = [&primitives, &callback](vibrator::HalWrapper* hal) {
        return hal->performPwleEffect(primitives, callback);
    };
    auto result = wrapper->halCall<void>(performPwleEffectFn, "performPwleEffect");
    return result.isOk() ? totalDuration.count() : (result.isUnsupported() ? 0 : -1);
}

static jlong vibratorPerformPwleV2Effect(JNIEnv* env, jclass /* clazz */, jlong ptr,
                                         jobjectArray waveform, jlong vibrationId, jlong stepId) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorPerformPwleV2Effect failed because native wrapper was not initialized");
        return -1;
    }
    size_t size = env->GetArrayLength(waveform);
    Aidl::CompositePwleV2 composite;
    std::vector<Aidl::PwleV2Primitive> primitives;
    for (size_t i = 0; i < size; i++) {
        jobject element = env->GetObjectArrayElement(waveform, i);
        Aidl::PwleV2Primitive pwle = pwleV2PrimitiveFromJavaPrimitive(env, element);
        primitives.push_back(pwle);
    }
    composite.pwlePrimitives = primitives;

    auto callback = wrapper->createCallback(vibrationId, stepId);
    auto composePwleV2Fn = [&composite, &callback](vibrator::HalWrapper* hal) {
        return hal->composePwleV2(composite, callback);
    };
    auto result = wrapper->halCall<std::chrono::milliseconds>(composePwleV2Fn, "composePwleV2");
    return result.isOk() ? result.value().count() : (result.isUnsupported() ? 0 : -1);
}

static void vibratorAlwaysOnEnable(JNIEnv* env, jclass /* clazz */, jlong ptr, jlong id,
                                   jlong effect, jlong strength) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorAlwaysOnEnable failed because native wrapper was not initialized");
        return;
    }
    auto alwaysOnEnableFn = [id, effect, strength](vibrator::HalWrapper* hal) {
        return hal->alwaysOnEnable(static_cast<int32_t>(id), static_cast<Aidl::Effect>(effect),
                                   static_cast<Aidl::EffectStrength>(strength));
    };
    wrapper->halCall<void>(alwaysOnEnableFn, "alwaysOnEnable");
}

static void vibratorAlwaysOnDisable(JNIEnv* env, jclass /* clazz */, jlong ptr, jlong id) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorAlwaysOnDisable failed because native wrapper was not initialized");
        return;
    }
    auto alwaysOnDisableFn = [id](vibrator::HalWrapper* hal) {
        return hal->alwaysOnDisable(static_cast<int32_t>(id));
    };
    wrapper->halCall<void>(alwaysOnDisableFn, "alwaysOnDisable");
}

static jboolean vibratorGetInfo(JNIEnv* env, jclass /* clazz */, jlong ptr,
                                jobject vibratorInfoBuilder) {
    VibratorControllerWrapper* wrapper = reinterpret_cast<VibratorControllerWrapper*>(ptr);
    if (wrapper == nullptr) {
        ALOGE("vibratorGetInfo failed because native wrapper was not initialized");
        return JNI_FALSE;
    }
    vibrator::Info info = wrapper->getVibratorInfo();
    info.logFailures();

    if (info.capabilities.isOk()) {
        env->CallObjectMethod(vibratorInfoBuilder, sVibratorInfoBuilderClassInfo.setCapabilities,
                              static_cast<jlong>(info.capabilities.value()));
    }
    if (info.supportedEffects.isOk()) {
        std::vector<Aidl::Effect> effects = info.supportedEffects.value();
        jintArray supportedEffects = env->NewIntArray(effects.size());
        env->SetIntArrayRegion(supportedEffects, 0, effects.size(),
                               reinterpret_cast<jint*>(effects.data()));
        env->CallObjectMethod(vibratorInfoBuilder,
                              sVibratorInfoBuilderClassInfo.setSupportedEffects, supportedEffects);
    }
    if (info.supportedBraking.isOk()) {
        std::vector<Aidl::Braking> braking = info.supportedBraking.value();
        jintArray supportedBraking = env->NewIntArray(braking.size());
        env->SetIntArrayRegion(supportedBraking, 0, braking.size(),
                               reinterpret_cast<jint*>(braking.data()));
        env->CallObjectMethod(vibratorInfoBuilder,
                              sVibratorInfoBuilderClassInfo.setSupportedBraking, supportedBraking);
    }
    if (info.pwlePrimitiveDurationMax.isOk()) {
        env->CallObjectMethod(vibratorInfoBuilder,
                              sVibratorInfoBuilderClassInfo.setPwlePrimitiveDurationMax,
                              static_cast<jint>(info.pwlePrimitiveDurationMax.value().count()));
    }
    if (info.pwleSizeMax.isOk()) {
        // Use (pwleMaxSize - 1) to account for a possible extra braking segment added by the
        // vibratorPerformPwleEffect method.
        env->CallObjectMethod(vibratorInfoBuilder, sVibratorInfoBuilderClassInfo.setPwleSizeMax,
                              static_cast<jint>(info.pwleSizeMax.value() - 1));
    }
    if (info.supportedPrimitives.isOk()) {
        auto durations = info.primitiveDurations.valueOr({});
        for (auto& primitive : info.supportedPrimitives.value()) {
            auto primitiveIdx = static_cast<size_t>(primitive);
            auto duration = durations.size() > primitiveIdx ? durations[primitiveIdx].count() : 0;
            env->CallObjectMethod(vibratorInfoBuilder,
                                  sVibratorInfoBuilderClassInfo.setSupportedPrimitive,
                                  static_cast<jint>(primitive), static_cast<jint>(duration));
        }
    }
    if (info.primitiveDelayMax.isOk()) {
        env->CallObjectMethod(vibratorInfoBuilder,
                              sVibratorInfoBuilderClassInfo.setPrimitiveDelayMax,
                              static_cast<jint>(info.primitiveDelayMax.value().count()));
    }
    if (info.compositionSizeMax.isOk()) {
        env->CallObjectMethod(vibratorInfoBuilder,
                              sVibratorInfoBuilderClassInfo.setCompositionSizeMax,
                              static_cast<jint>(info.compositionSizeMax.value()));
    }
    if (info.qFactor.isOk()) {
        env->CallObjectMethod(vibratorInfoBuilder, sVibratorInfoBuilderClassInfo.setQFactor,
                              static_cast<jfloat>(info.qFactor.value()));
    }
    if (info.maxEnvelopeEffectSize.isOk()) {
        env->CallObjectMethod(vibratorInfoBuilder,
                              sVibratorInfoBuilderClassInfo.setMaxEnvelopeEffectSize,
                              static_cast<jint>(info.maxEnvelopeEffectSize.value()));
    }
    if (info.minEnvelopeEffectControlPointDuration.isOk()) {
        env->CallObjectMethod(vibratorInfoBuilder,
                              sVibratorInfoBuilderClassInfo
                                      .setMinEnvelopeEffectControlPointDurationMillis,
                              static_cast<jint>(
                                      info.minEnvelopeEffectControlPointDuration.value().count()));
    }
    if (info.maxEnvelopeEffectControlPointDuration.isOk()) {
        env->CallObjectMethod(vibratorInfoBuilder,
                              sVibratorInfoBuilderClassInfo
                                      .setMaxEnvelopeEffectControlPointDurationMillis,
                              static_cast<jint>(
                                      info.maxEnvelopeEffectControlPointDuration.value().count()));
    }

    jfloat minFrequency = static_cast<jfloat>(info.minFrequency.valueOr(NAN));
    jfloat resonantFrequency = static_cast<jfloat>(info.resonantFrequency.valueOr(NAN));
    jfloat frequencyResolution = static_cast<jfloat>(info.frequencyResolution.valueOr(NAN));
    jfloatArray maxAmplitudes = nullptr;
    if (info.maxAmplitudes.isOk()) {
        std::vector<float> amplitudes = info.maxAmplitudes.value();
        maxAmplitudes = env->NewFloatArray(amplitudes.size());
        env->SetFloatArrayRegion(maxAmplitudes, 0, amplitudes.size(),
                                 reinterpret_cast<jfloat*>(amplitudes.data()));
    }
    jobject frequencyProfileLegacy =
            env->NewObject(sFrequencyProfileLegacyClass, sFrequencyProfileLegacyCtor,
                           resonantFrequency, minFrequency, frequencyResolution, maxAmplitudes);
    env->CallObjectMethod(vibratorInfoBuilder,
                          sVibratorInfoBuilderClassInfo.setFrequencyProfileLegacy,
                          frequencyProfileLegacy);

    if (info.frequencyToOutputAccelerationMap.isOk()) {
        size_t mapSize = info.frequencyToOutputAccelerationMap.value().size();

        jfloatArray frequenciesHz = env->NewFloatArray(mapSize);
        jfloatArray outputAccelerationsGs = env->NewFloatArray(mapSize);

        jfloat* frequenciesHzPtr = env->GetFloatArrayElements(frequenciesHz, nullptr);
        jfloat* outputAccelerationsGsPtr =
                env->GetFloatArrayElements(outputAccelerationsGs, nullptr);

        size_t i = 0;
        for (auto const& dataEntry : info.frequencyToOutputAccelerationMap.value()) {
            frequenciesHzPtr[i] = static_cast<jfloat>(dataEntry.frequencyHz);
            outputAccelerationsGsPtr[i] = static_cast<jfloat>(dataEntry.maxOutputAccelerationGs);
            i++;
        }

        // Release the float pointers
        env->ReleaseFloatArrayElements(frequenciesHz, frequenciesHzPtr, 0);
        env->ReleaseFloatArrayElements(outputAccelerationsGs, outputAccelerationsGsPtr, 0);

        jobject frequencyProfile =
                env->NewObject(sFrequencyProfileClass, sFrequencyProfileCtor, resonantFrequency,
                               frequenciesHz, outputAccelerationsGs);

        env->CallObjectMethod(vibratorInfoBuilder,
                              sVibratorInfoBuilderClassInfo.setFrequencyProfile, frequencyProfile);

        // Delete local references to avoid memory leaks
        env->DeleteLocalRef(frequenciesHz);
        env->DeleteLocalRef(outputAccelerationsGs);
        env->DeleteLocalRef(frequencyProfile);
    }

    return info.shouldRetry() ? JNI_FALSE : JNI_TRUE;
}

static const JNINativeMethod method_table[] = {
        {"nativeInit",
         "(ILcom/android/server/vibrator/VibratorController$OnVibrationCompleteListener;)J",
         (void*)vibratorNativeInit},
        {"getNativeFinalizer", "()J", (void*)vibratorGetNativeFinalizer},
        {"isAvailable", "(J)Z", (void*)vibratorIsAvailable},
        {"on", "(JJJJ)J", (void*)vibratorOn},
        {"off", "(J)V", (void*)vibratorOff},
        {"setAmplitude", "(JF)V", (void*)vibratorSetAmplitude},
        {"performEffect", "(JJJJJ)J", (void*)vibratorPerformEffect},
        {"performVendorEffect", "(JLandroid/os/Parcel;JFFJJ)J", (void*)vibratorPerformVendorEffect},
        {"performComposedEffect", "(J[Landroid/os/vibrator/PrimitiveSegment;JJ)J",
         (void*)vibratorPerformComposedEffect},
        {"performPwleEffect", "(J[Landroid/os/vibrator/RampSegment;IJJ)J",
         (void*)vibratorPerformPwleEffect},
        {"performPwleV2Effect", "(J[Landroid/os/vibrator/PwlePoint;JJ)J",
         (void*)vibratorPerformPwleV2Effect},
        {"setExternalControl", "(JZ)V", (void*)vibratorSetExternalControl},
        {"alwaysOnEnable", "(JJJJ)V", (void*)vibratorAlwaysOnEnable},
        {"alwaysOnDisable", "(JJ)V", (void*)vibratorAlwaysOnDisable},
        {"getInfo", "(JLandroid/os/VibratorInfo$Builder;)Z", (void*)vibratorGetInfo},
};

int register_android_server_vibrator_VibratorController(JavaVM* jvm, JNIEnv* env) {
    sJvm = jvm;
    auto listenerClassName =
            "com/android/server/vibrator/VibratorController$OnVibrationCompleteListener";
    jclass listenerClass = FindClassOrDie(env, listenerClassName);
    sMethodIdOnComplete = GetMethodIDOrDie(env, listenerClass, "onComplete", "(IJJ)V");

    jclass primitiveClass = FindClassOrDie(env, "android/os/vibrator/PrimitiveSegment");
    sPrimitiveClassInfo.id = GetFieldIDOrDie(env, primitiveClass, "mPrimitiveId", "I");
    sPrimitiveClassInfo.scale = GetFieldIDOrDie(env, primitiveClass, "mScale", "F");
    sPrimitiveClassInfo.delay = GetFieldIDOrDie(env, primitiveClass, "mDelay", "I");

    jclass rampClass = FindClassOrDie(env, "android/os/vibrator/RampSegment");
    sRampClassInfo.startAmplitude = GetFieldIDOrDie(env, rampClass, "mStartAmplitude", "F");
    sRampClassInfo.endAmplitude = GetFieldIDOrDie(env, rampClass, "mEndAmplitude", "F");
    sRampClassInfo.startFrequencyHz = GetFieldIDOrDie(env, rampClass, "mStartFrequencyHz", "F");
    sRampClassInfo.endFrequencyHz = GetFieldIDOrDie(env, rampClass, "mEndFrequencyHz", "F");
    sRampClassInfo.duration = GetFieldIDOrDie(env, rampClass, "mDuration", "I");

    jclass pwlePointClass = FindClassOrDie(env, "android/os/vibrator/PwlePoint");
    sPwlePointClassInfo.amplitude = GetFieldIDOrDie(env, pwlePointClass, "mAmplitude", "F");
    sPwlePointClassInfo.frequencyHz = GetFieldIDOrDie(env, pwlePointClass, "mFrequencyHz", "F");
    sPwlePointClassInfo.timeMillis = GetFieldIDOrDie(env, pwlePointClass, "mTimeMillis", "I");

    jclass frequencyProfileLegacyClass =
            FindClassOrDie(env, "android/os/VibratorInfo$FrequencyProfileLegacy");
    sFrequencyProfileLegacyClass =
            static_cast<jclass>(env->NewGlobalRef(frequencyProfileLegacyClass));
    sFrequencyProfileLegacyCtor =
            GetMethodIDOrDie(env, sFrequencyProfileLegacyClass, "<init>", "(FFF[F)V");

    jclass frequencyProfileClass = FindClassOrDie(env, "android/os/VibratorInfo$FrequencyProfile");
    sFrequencyProfileClass = static_cast<jclass>(env->NewGlobalRef(frequencyProfileClass));
    sFrequencyProfileCtor = GetMethodIDOrDie(env, sFrequencyProfileClass, "<init>", "(F[F[F)V");

    jclass vibratorInfoBuilderClass = FindClassOrDie(env, "android/os/VibratorInfo$Builder");
    sVibratorInfoBuilderClassInfo.setCapabilities =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setCapabilities",
                             "(J)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setSupportedEffects =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setSupportedEffects",
                             "([I)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setSupportedBraking =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setSupportedBraking",
                             "([I)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setPwlePrimitiveDurationMax =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setPwlePrimitiveDurationMax",
                             "(I)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setPwleSizeMax =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setPwleSizeMax",
                             "(I)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setSupportedPrimitive =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setSupportedPrimitive",
                             "(II)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setPrimitiveDelayMax =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setPrimitiveDelayMax",
                             "(I)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setCompositionSizeMax =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setCompositionSizeMax",
                             "(I)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setQFactor =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setQFactor",
                             "(F)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setFrequencyProfileLegacy =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setFrequencyProfileLegacy",
                             "(Landroid/os/VibratorInfo$FrequencyProfileLegacy;)"
                             "Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setFrequencyProfile =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setFrequencyProfile",
                             "(Landroid/os/VibratorInfo$FrequencyProfile;)"
                             "Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setMaxEnvelopeEffectSize =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass, "setMaxEnvelopeEffectSize",
                             "(I)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setMinEnvelopeEffectControlPointDurationMillis =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass,
                             "setMinEnvelopeEffectControlPointDurationMillis",
                             "(I)Landroid/os/VibratorInfo$Builder;");
    sVibratorInfoBuilderClassInfo.setMaxEnvelopeEffectControlPointDurationMillis =
            GetMethodIDOrDie(env, vibratorInfoBuilderClass,
                             "setMaxEnvelopeEffectControlPointDurationMillis",
                             "(I)Landroid/os/VibratorInfo$Builder;");

    return jniRegisterNativeMethods(env,
                                    "com/android/server/vibrator/VibratorController$NativeWrapper",
                                    method_table, NELEM(method_table));
}

}; // namespace android
