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

package com.android.server.vibrator;

import static android.os.VibrationAttributes.USAGE_RINGTONE;
import static android.os.VibrationEffect.Composition.PRIMITIVE_CLICK;
import static android.os.VibrationEffect.Composition.PRIMITIVE_SPIN;
import static android.os.VibrationEffect.Composition.PRIMITIVE_TICK;
import static android.os.VibrationEffect.EFFECT_CLICK;
import static android.os.VibrationEffect.EFFECT_TICK;
import static android.os.VibrationEffect.VibrationParameter.targetAmplitude;
import static android.os.VibrationEffect.VibrationParameter.targetFrequency;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.ContextWrapper;
import android.content.pm.PackageManagerInternal;
import android.hardware.vibrator.Braking;
import android.hardware.vibrator.IVibrator;
import android.hardware.vibrator.IVibratorManager;
import android.os.CombinedVibration;
import android.os.Handler;
import android.os.PersistableBundle;
import android.os.PowerManager;
import android.os.Process;
import android.os.SystemClock;
import android.os.UserHandle;
import android.os.VibrationAttributes;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.os.test.TestLooper;
import android.os.vibrator.Flags;
import android.os.vibrator.PrebakedSegment;
import android.os.vibrator.PrimitiveSegment;
import android.os.vibrator.PwlePoint;
import android.os.vibrator.RampSegment;
import android.os.vibrator.StepSegment;
import android.os.vibrator.VibrationConfig;
import android.os.vibrator.VibrationEffectSegment;
import android.platform.test.annotations.DisableFlags;
import android.platform.test.annotations.EnableFlags;
import android.platform.test.flag.junit.CheckFlagsRule;
import android.platform.test.flag.junit.DeviceFlagsValueProvider;
import android.platform.test.flag.junit.SetFlagsRule;
import android.provider.Settings;
import android.util.SparseArray;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.LargeTest;

import com.android.internal.util.test.FakeSettingsProvider;
import com.android.internal.util.test.FakeSettingsProviderRule;
import com.android.server.LocalServices;
import com.android.server.vibrator.VibrationSession.CallerInfo;
import com.android.server.vibrator.VibrationSession.Status;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;

public class VibrationThreadTest {

    private static final int TEST_TIMEOUT_MILLIS = 900;
    private static final int UID = Process.ROOT_UID;
    private static final int DEVICE_ID = 10;
    private static final int VIBRATOR_ID = 1;
    private static final String PACKAGE_NAME = "package";
    private static final VibrationAttributes ATTRS = new VibrationAttributes.Builder().build();
    private static final int TEST_RAMP_STEP_DURATION = 5;
    private static final int TEST_DEFAULT_AMPLITUDE = 255;
    private static final float TEST_DEFAULT_SCALE_LEVEL_GAIN = 1.4f;

    @Rule
    public MockitoRule mMockitoRule = MockitoJUnit.rule();
    @Rule
    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
    @Rule
    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
    @Rule
    public FakeSettingsProviderRule mSettingsProviderRule = FakeSettingsProvider.rule();

    @Mock private PackageManagerInternal mPackageManagerInternalMock;
    @Mock private VibrationThread.VibratorManagerHooks mManagerHooks;
    @Mock private VibratorController.OnVibrationCompleteListener mControllerCallbacks;
    @Mock private VibrationConfig mVibrationConfigMock;
    @Mock private VibratorFrameworkStatsLogger mStatsLoggerMock;

    private ContextWrapper mContextSpy;
    private final Map<Integer, FakeVibratorControllerProvider> mVibratorProviders = new HashMap<>();
    private VibrationSettings mVibrationSettings;
    private VibrationScaler mVibrationScaler;
    private TestLooper mTestLooper;
    private TestLooperAutoDispatcher mCustomTestLooperDispatcher;
    private VibrationThread mThread;

    // Setup every time a new vibration is dispatched to the VibrationThread.
    private SparseArray<VibratorController> mControllers;
    private VibrationStepConductor mVibrationConductor;

    @Before
    public void setUp() throws Exception {
        mTestLooper = new TestLooper();

        when(mVibrationConfigMock.getDefaultVibrationIntensity(anyInt()))
                .thenReturn(Vibrator.VIBRATION_INTENSITY_MEDIUM);
        when(mVibrationConfigMock.getRampStepDurationMs()).thenReturn(TEST_RAMP_STEP_DURATION);
        when(mVibrationConfigMock.getDefaultVibrationAmplitude())
                .thenReturn(TEST_DEFAULT_AMPLITUDE);
        when(mVibrationConfigMock.getDefaultVibrationScaleLevelGain())
                .thenReturn(TEST_DEFAULT_SCALE_LEVEL_GAIN);
        when(mPackageManagerInternalMock.getSystemUiServiceComponent())
                .thenReturn(new ComponentName("", ""));
        doAnswer(answer -> {
            mVibrationConductor.notifyVibratorComplete(
                    answer.getArgument(0), answer.getArgument(2));
            return null;
        }).when(mControllerCallbacks).onComplete(anyInt(), anyLong(), anyLong());

        LocalServices.removeServiceForTest(PackageManagerInternal.class);
        LocalServices.addService(PackageManagerInternal.class, mPackageManagerInternalMock);

        mContextSpy = spy(new ContextWrapper(InstrumentationRegistry.getContext()));
        ContentResolver contentResolver = mSettingsProviderRule.mockContentResolver(mContextSpy);
        when(mContextSpy.getContentResolver()).thenReturn(contentResolver);
        mVibrationSettings = new VibrationSettings(mContextSpy,
                new Handler(mTestLooper.getLooper()), mVibrationConfigMock);
        mVibrationScaler = new VibrationScaler(mVibrationConfigMock, mVibrationSettings);

        mockVibrators(VIBRATOR_ID);

        PowerManager.WakeLock wakeLock = mContextSpy.getSystemService(
                PowerManager.class).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "*vibrator*");
        mThread = new VibrationThread(wakeLock, mManagerHooks);
        mThread.start();
    }

    @After
    public void tearDown() {
        if (mCustomTestLooperDispatcher != null) {
            mCustomTestLooperDispatcher.cancel();
        }
    }

    @Test
    public void vibrate_noVibrator_ignoresVibration() {
        mVibratorProviders.clear();
        CombinedVibration effect = CombinedVibration.createParallel(
                VibrationEffect.get(EFFECT_CLICK));
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mControllerCallbacks, never()).onComplete(anyInt(), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.IGNORED_UNSUPPORTED);
    }

    @Test
    public void vibrate_missingVibrators_ignoresVibration() {
        CombinedVibration effect = CombinedVibration.startSequential()
                .addNext(2, VibrationEffect.get(EFFECT_CLICK))
                .addNext(3, VibrationEffect.get(EFFECT_TICK))
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mControllerCallbacks, never()).onComplete(anyInt(), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.IGNORED_UNSUPPORTED);
    }

    @Test
    public void vibrate_singleVibratorOneShot_runsVibrationAndSetsAmplitude() {
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createOneShot(10, 100);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(10L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(10)).inOrder();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(100)).inOrder();
    }

    @Test
    public void vibrate_oneShotWithoutAmplitudeControl_runsVibrationWithDefaultAmplitude() {
        VibrationEffect effect = VibrationEffect.createOneShot(10, 100);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(10L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(10)).inOrder();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes()).isEmpty();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_singleVibratorWaveform_runsVibrationAndChangesAmplitudes() {
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createWaveform(
                new long[]{5, 5, 5}, new int[]{1, 2, 3}, -1);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(15L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(15)).inOrder();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(1, 2, 3)).inOrder();
    }

    @Test
    @EnableFlags({
            Flags.FLAG_ADAPTIVE_HAPTICS_ENABLED,
            Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING,
    })
    public void vibrate_singleWaveformWithAdaptiveHapticsScaling_scalesAmplitudesProperly() {
        // No user settings scale.
        setUserSetting(Settings.System.RING_VIBRATION_INTENSITY,
                Vibrator.VIBRATION_INTENSITY_MEDIUM);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createWaveform(
                new long[]{5, 5, 5}, new int[]{1, 1, 1}, -1);
        mVibrationScaler.updateAdaptiveHapticsScale(USAGE_RINGTONE, 0.5f);
        CompletableFuture<Void> mRequestVibrationParamsFuture = CompletableFuture.completedFuture(
                null);
        HalVibration vibration = startThreadAndDispatcher(effect, mRequestVibrationParamsFuture,
                USAGE_RINGTONE);
        waitForCompletion();

        verify(mStatsLoggerMock, never()).logVibrationParamRequestTimeout(UID);
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(15)).inOrder();
        List<Float> amplitudes = mVibratorProviders.get(VIBRATOR_ID).getAmplitudes();
        for (int i = 0; i < amplitudes.size(); i++) {
            assertWithMessage("For amplitude index %s", i)
                    .that(amplitudes.get(i)).isLessThan(1 / 255f);
        }
    }

    @Test
    @EnableFlags({
            Flags.FLAG_ADAPTIVE_HAPTICS_ENABLED,
            Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING,
    })
    public void vibrate_withVibrationParamsRequestStalling_timeoutRequestAndApplyNoScaling() {
        // No user settings scale.
        setUserSetting(Settings.System.RING_VIBRATION_INTENSITY,
                Vibrator.VIBRATION_INTENSITY_MEDIUM);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        VibrationEffect effect = VibrationEffect.createWaveform(
                new long[]{5, 5, 5}, new int[]{1, 1, 1}, -1);

        CompletableFuture<Void> neverCompletingFuture = new CompletableFuture<>();
        HalVibration vibration = startThreadAndDispatcher(effect, neverCompletingFuture,
                USAGE_RINGTONE);
        waitForCompletion();

        verify(mStatsLoggerMock).logVibrationParamRequestTimeout(UID);
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(15)).inOrder();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(1, 1, 1)).inOrder();
    }

    @Test
    public void vibrate_singleVibratorRepeatingWaveform_runsVibrationUntilThreadCancelled()
            throws Exception {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        int[] amplitudes = new int[]{1, 2, 3};
        VibrationEffect effect = VibrationEffect.createWaveform(new long[]{5, 5, 5}, amplitudes, 0);
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(
                waitUntil(() -> fakeVibrator.getAmplitudes().size() > 2 * amplitudes.length,
                        TEST_TIMEOUT_MILLIS)).isTrue();
        // Vibration still running after 2 cycles.
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isTrue();

        Vibration.EndInfo cancelVibrationInfo = new Vibration.EndInfo(Status.CANCELLED_SUPERSEDED,
                new CallerInfo(VibrationAttributes.createForUsage(VibrationAttributes.USAGE_ALARM),
                        /* uid= */ 1, /* deviceId= */ -1, /* opPkg= */ null, /* reason= */ null));
        mVibrationConductor.notifyCancelled(cancelVibrationInfo, /* immediate= */ false);
        waitForCompletion();
        assertThat(mThread.isRunningVibrationId(vibration.id)).isFalse();

        verify(mManagerHooks).noteVibratorOn(eq(UID), anyLong());
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verifyCallbacksTriggered(vibration, Status.CANCELLED_SUPERSEDED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        List<Float> playedAmplitudes = fakeVibrator.getAmplitudes();
        assertThat(fakeVibrator.getEffectSegments(vibration.id)).isNotEmpty();
        assertThat(playedAmplitudes).isNotEmpty();

        for (int i = 0; i < playedAmplitudes.size(); i++) {
            assertWithMessage("For amplitude index %s", i)
                    .that(amplitudes[i % amplitudes.length] / 255f)
                    .isWithin(1e-5f).of(playedAmplitudes.get(i));
        }
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_singleVibratorRepeatingShortAlwaysOnWaveform_turnsVibratorOnForLonger()
            throws Exception {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        int[] amplitudes = new int[]{1, 2, 3};
        VibrationEffect effect = VibrationEffect.createWaveform(
                new long[]{1, 10, 100}, amplitudes, 0);
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> !fakeVibrator.getAmplitudes().isEmpty(), TEST_TIMEOUT_MILLIS))
                .isTrue();
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_USER), /* immediate= */ false);
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_USER);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(5000)).inOrder();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_singleVibratorPatternWithZeroDurationSteps_skipsZeroDurationSteps() {
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createWaveform(
                /* timings= */ new long[]{0, 100, 50, 100, 0, 0, 0, 50}, /* repeat= */ -1);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(300L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));

        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactlyElementsIn(expectedOneShots(100L, 150L)).inOrder();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_singleVibratorPatternWithZeroDurationAndAmplitude_skipsZeroDurationSteps() {
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        int[] amplitudes = new int[]{1, 2, 0, 3, 4, 5, 0, 6};
        VibrationEffect effect = VibrationEffect.createWaveform(
                /* timings= */ new long[]{0, 100, 0, 50, 50, 0, 100, 50}, amplitudes,
                /* repeat= */ -1);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(350L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));

        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactlyElementsIn(expectedOneShots(200L, 50L)).inOrder();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @LargeTest
    @Test
    public void vibrate_singleVibratorRepeatingPatternWithZeroDurationSteps_repeatsEffectCorrectly()
            throws Exception {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createWaveform(
                /* timings= */ new long[]{0, 200, 50, 100, 0, 50, 50, 100}, /* repeat= */ 0);
        HalVibration vibration = startThreadAndDispatcher(effect);
        // We are expect this test to repeat the vibration effect twice, which would result in 5
        // segments being played:
        // 200ms ON
        // 150ms ON (100ms + 50ms, skips 0ms)
        // 300ms ON (100ms + 200ms looping to the start and skipping first 0ms)
        // 150ms ON (100ms + 50ms, skips 0ms)
        // 300ms ON (100ms + 200ms looping to the start and skipping first 0ms)
        assertThat(waitUntil(() -> fakeVibrator.getEffectSegments(vibration.id).size() >= 5,
                5000L + TEST_TIMEOUT_MILLIS)).isTrue();
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_USER), /* immediate= */ false);
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_USER);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(
                mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id).subList(0, 5))
                .containsExactlyElementsIn(expectedOneShots(200L, 150L, 300L, 150L, 300L))
                .inOrder();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_singleVibratorPatternWithCallbackDelay_oldCallbacksIgnored() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCompletionCallbackDelay(100); // 100ms delay to notify service.
        fakeVibrator.setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createWaveform(
                /* timings= */ new long[]{0, 200, 50, 400}, /* repeat= */ -1);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion(800 + TEST_TIMEOUT_MILLIS); // 200 + 50 + 400 + 100ms delay

        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), eq(1L));
        // Step id = 2 skipped by the 50ms OFF step after the 200ms ON step.
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), eq(3L));

        // First callback ignored, did not cause the vibrator to turn back on during the 400ms step.
        assertThat(fakeVibrator.getEffectSegments(vibration.id))
                .containsExactlyElementsIn(expectedOneShots(200L, 400L)).inOrder();
    }

    @Test
    public void vibrate_singleVibratorRepeatingPwle_generatesLargestPwles() throws Exception {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_PWLE_EFFECTS);
        fakeVibrator.setMinFrequency(100);
        fakeVibrator.setResonantFrequency(150);
        fakeVibrator.setFrequencyResolution(50);
        fakeVibrator.setMaxAmplitudes(1, 1, 1);
        fakeVibrator.setPwleSizeMax(10);

        VibrationEffect effect = VibrationEffect.startWaveform(targetAmplitude(1))
                // Very long segment so thread will be cancelled after first PWLE is triggered.
                .addTransition(Duration.ofMillis(100), targetFrequency(100))
                .build();
        VibrationEffect repeatingEffect = VibrationEffect.startComposition()
                .repeatEffectIndefinitely(effect)
                .compose();
        HalVibration vibration = startThreadAndDispatcher(repeatingEffect);

        assertThat(waitUntil(() -> !fakeVibrator.getEffectSegments(vibration.id).isEmpty(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_USER), /* immediate= */ false);
        waitForCompletion();

        // PWLE size max was used to generate a single vibrate call with 10 segments.
        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_USER);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectSegments(vibration.id)).hasSize(10);
    }

    @Test
    public void vibrate_singleVibratorRepeatingPrimitives_generatesLargestComposition()
            throws Exception {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        fakeVibrator.setSupportedPrimitives(PRIMITIVE_CLICK);
        fakeVibrator.setCompositionSizeMax(10);

        VibrationEffect effect = VibrationEffect.startComposition()
                // Very long delay so thread will be cancelled after first PWLE is triggered.
                .addPrimitive(PRIMITIVE_CLICK, 1f, 100)
                .compose();
        VibrationEffect repeatingEffect = VibrationEffect.startComposition()
                .repeatEffectIndefinitely(effect)
                .compose();
        HalVibration vibration = startThreadAndDispatcher(repeatingEffect);

        assertThat(waitUntil(() -> !fakeVibrator.getEffectSegments(vibration.id).isEmpty(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_SCREEN_OFF), /* immediate= */ false);
        waitForCompletion();

        // Composition size max was used to generate a single vibrate call with 10 primitives.
        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_SCREEN_OFF);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectSegments(vibration.id)).hasSize(10);
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_singleVibratorRepeatingLongAlwaysOnWaveform_turnsVibratorOnForACycle()
            throws Exception {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        int[] amplitudes = new int[]{1, 2, 3};
        VibrationEffect effect = VibrationEffect.createWaveform(
                new long[]{5000, 500, 50}, amplitudes, 0);
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> !fakeVibrator.getAmplitudes().isEmpty(), TEST_TIMEOUT_MILLIS))
                .isTrue();
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_USER), /* immediate= */ false);
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_USER);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(5550)).inOrder();
    }

    @LargeTest
    @Test
    public void vibrate_singleVibratorRepeatingAlwaysOnWaveform_turnsVibratorBackOn()
            throws Exception {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        int expectedOnDuration = SetAmplitudeVibratorStep.REPEATING_EFFECT_ON_DURATION;

        VibrationEffect effect = VibrationEffect.createWaveform(
                /* timings= */ new long[]{expectedOnDuration - 100, 50},
                /* amplitudes= */ new int[]{1, 2}, /* repeat= */ 0);
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> fakeVibrator.getEffectSegments(vibration.id).size() > 1,
                expectedOnDuration + TEST_TIMEOUT_MILLIS)).isTrue();
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_USER), /* immediate= */ false);
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_USER);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        List<VibrationEffectSegment> effectSegments = fakeVibrator.getEffectSegments(vibration.id);
        // First time, turn vibrator ON for the expected fixed duration.
        assertThat(effectSegments.get(0).getDuration()).isEqualTo(expectedOnDuration);
        // Vibrator turns off in the middle of the second execution of the first step. Expect it to
        // be turned back ON at least for the fixed duration + the remaining duration of the step.
        assertThat(effectSegments.get(1).getDuration()).isGreaterThan(expectedOnDuration);
        // Set amplitudes for a cycle {1, 2}, start second loop then turn it back on to same value.
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes().subList(0, 4))
                .containsExactlyElementsIn(expectedAmplitudes(1, 2, 1, 1))
                .inOrder();
    }

    @Test
    public void vibrate_singleVibratorPredefinedCancel_cancelsVibrationImmediately()
            throws Exception {
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        mVibratorProviders.get(VIBRATOR_ID).setSupportedPrimitives(PRIMITIVE_CLICK);

        VibrationEffect effect = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK, 1f, 100)
                .addPrimitive(PRIMITIVE_CLICK, 1f, 100)
                .addPrimitive(PRIMITIVE_CLICK, 1f, 100)
                .compose();
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> mControllers.get(VIBRATOR_ID).isVibrating(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();

        // Run cancel in a separate thread so if VibrationThread.cancel blocks then this test should
        // fail at waitForCompletion(vibrationThread) if the vibration not cancelled immediately.
        Thread cancellingThread =
                new Thread(() -> mVibrationConductor.notifyCancelled(
                        new Vibration.EndInfo(Status.CANCELLED_BY_SETTINGS_UPDATE),
                        /* immediate= */ false));
        cancellingThread.start();

        waitForCompletion(/* timeout= */ 50);
        cancellingThread.join();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_SETTINGS_UPDATE);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
    }

    @Test
    @EnableFlags(Flags.FLAG_VENDOR_VIBRATION_EFFECTS)
    public void vibrate_singleVibratorVendorEffectCancel_cancelsVibrationImmediately()
            throws Exception {
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_PERFORM_VENDOR_EFFECTS);
        // Set long vendor effect duration to check it gets cancelled quickly.
        mVibratorProviders.get(VIBRATOR_ID).setVendorEffectDuration(10 * TEST_TIMEOUT_MILLIS);

        VibrationEffect effect = VibrationEffect.createVendorEffect(createTestVendorData());
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> mControllers.get(VIBRATOR_ID).isVibrating(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();

        // Run cancel in a separate thread so if VibrationThread.cancel blocks then this test should
        // fail at waitForCompletion(vibrationThread) if the vibration not cancelled immediately.
        Thread cancellingThread =
                new Thread(() -> mVibrationConductor.notifyCancelled(
                        new Vibration.EndInfo(Status.CANCELLED_BY_SETTINGS_UPDATE),
                        /* immediate= */ false));
        cancellingThread.start();

        waitForCompletion(/* timeout= */ 50);
        cancellingThread.join();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_SETTINGS_UPDATE);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
    }

    @Test
    public void vibrate_singleVibratorWaveformCancel_cancelsVibrationImmediately()
            throws Exception {
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);

        VibrationEffect effect = VibrationEffect.createWaveform(new long[]{100}, new int[]{100}, 0);
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> mControllers.get(VIBRATOR_ID).isVibrating(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();

        // Run cancel in a separate thread so if VibrationThread.cancel blocks then this test should
        // fail at waitForCompletion(vibrationThread) if the vibration not cancelled immediately.
        Thread cancellingThread =
                new Thread(() -> mVibrationConductor.notifyCancelled(
                        new Vibration.EndInfo(Status.CANCELLED_BY_SCREEN_OFF),
                        /* immediate= */ false));
        cancellingThread.start();

        waitForCompletion(/* timeout= */ 50);
        cancellingThread.join();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_SCREEN_OFF);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
    }

    @Test
    public void vibrate_singleVibratorPrebaked_runsVibration() {
        mVibratorProviders.get(1).setSupportedEffects(VibrationEffect.EFFECT_THUD);

        VibrationEffect effect = VibrationEffect.get(VibrationEffect.EFFECT_THUD);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(20L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedPrebaked(VibrationEffect.EFFECT_THUD)).inOrder();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_singleVibratorPrebakedAndUnsupportedEffectWithFallback_runsFallback() {
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect fallback = VibrationEffect.createOneShot(10, 100);
        HalVibration vibration = createVibration(CombinedVibration.createParallel(
                VibrationEffect.get(EFFECT_CLICK)));
        vibration.fillFallbacks(unused -> fallback);
        startThreadAndDispatcher(vibration);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(10L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(10)).inOrder();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(100)).inOrder();
    }

    @Test
    public void vibrate_singleVibratorPrebakedAndUnsupportedEffect_ignoresVibration() {
        VibrationEffect effect = VibrationEffect.get(EFFECT_CLICK);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(0L));
        verify(mManagerHooks, never()).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks, never())
                .onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.IGNORED_UNSUPPORTED);
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id)).isEmpty();
    }

    @Test
    @EnableFlags(Flags.FLAG_VENDOR_VIBRATION_EFFECTS)
    public void vibrate_singleVibratorVendorEffect_runsVibration() {
        mVibratorProviders.get(1).setCapabilities(IVibrator.CAP_PERFORM_VENDOR_EFFECTS);

        VibrationEffect effect = VibrationEffect.createVendorEffect(createTestVendorData());
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID),
                eq(PerformVendorEffectVibratorStep.VENDOR_EFFECT_MAX_DURATION_MS));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getVendorEffects(vibration.id))
                .containsExactly(effect).inOrder();
    }

    @Test
    public void vibrate_singleVibratorComposed_runsVibration() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        fakeVibrator.setSupportedPrimitives(PRIMITIVE_CLICK, PRIMITIVE_TICK);

        VibrationEffect effect = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK, 1f)
                .addPrimitive(PRIMITIVE_TICK, 0.5f)
                .compose();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(40L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectSegments(vibration.id))
                .containsExactly(
                        expectedPrimitive(PRIMITIVE_CLICK, 1, 0),
                        expectedPrimitive(PRIMITIVE_TICK, 0.5f, 0))
                .inOrder();
    }

    @Test
    @DisableFlags(Flags.FLAG_PRIMITIVE_COMPOSITION_ABSOLUTE_DELAY)
    public void vibrate_singleVibratorComposedAndNoCapability_triggersHalAndReturnsUnsupported() {
        VibrationEffect effect = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK, 1f)
                .compose();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(0L));
        verify(mManagerHooks, never()).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks, never())
                .onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.IGNORED_UNSUPPORTED);
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id)).isEmpty();
    }

    @Test
    @EnableFlags(Flags.FLAG_PRIMITIVE_COMPOSITION_ABSOLUTE_DELAY)
    public void vibrate_singleVibratorComposedAndNoCapability_ignoresVibration() {
        VibrationEffect effect = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK, 1f)
                .compose();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks, never()).noteVibratorOn(eq(UID), anyLong());
        verify(mManagerHooks, never()).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks, never())
                .onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.IGNORED_UNSUPPORTED);
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id)).isEmpty();
    }

    @Test
    public void vibrate_singleVibratorLargeComposition_splitsVibratorComposeCalls() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        fakeVibrator.setSupportedPrimitives(PRIMITIVE_CLICK, PRIMITIVE_TICK, PRIMITIVE_SPIN);
        fakeVibrator.setCompositionSizeMax(2);

        VibrationEffect effect = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK, 1f)
                .addPrimitive(PRIMITIVE_TICK, 0.5f)
                .addPrimitive(PRIMITIVE_SPIN, 0.8f)
                .compose();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.FINISHED);
        // Vibrator compose called twice.
        verify(mControllerCallbacks, times(2))
                .onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        assertThat(fakeVibrator.getEffectSegments(vibration.id)).hasSize(3);
    }

    @Test
    @DisableFlags(Flags.FLAG_NORMALIZED_PWLE_EFFECTS)
    public void vibrate_singleVibratorComposedEffects_runsDifferentVibrations() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setSupportedEffects(EFFECT_CLICK);
        fakeVibrator.setSupportedPrimitives(PRIMITIVE_CLICK, PRIMITIVE_TICK);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS,
                IVibrator.CAP_COMPOSE_PWLE_EFFECTS, IVibrator.CAP_AMPLITUDE_CONTROL);
        fakeVibrator.setMinFrequency(100);
        fakeVibrator.setResonantFrequency(150);
        fakeVibrator.setFrequencyResolution(50);
        fakeVibrator.setMaxAmplitudes(
                0.5f /* 100Hz*/, 1 /* 150Hz */, 0.6f /* 200Hz */);

        VibrationEffect effect = VibrationEffect.startComposition()
                .addEffect(VibrationEffect.createOneShot(10, 100))
                .addPrimitive(PRIMITIVE_CLICK, 1f)
                .addPrimitive(PRIMITIVE_TICK, 0.5f)
                .addEffect(VibrationEffect.get(EFFECT_CLICK))
                .addEffect(VibrationEffect.startWaveform()
                        .addTransition(Duration.ofMillis(10),
                                targetAmplitude(1), targetFrequency(100))
                        .addTransition(Duration.ofMillis(20), targetFrequency(120))
                        .build())
                .addEffect(VibrationEffect.get(EFFECT_CLICK))
                .compose();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        // Use first duration the vibrator is turned on since we cannot estimate the clicks.
        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(10L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks, times(5))
                .onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(
                        expectedOneShot(10),
                        expectedPrimitive(PRIMITIVE_CLICK, 1, 0),
                        expectedPrimitive(PRIMITIVE_TICK, 0.5f, 0),
                        expectedPrebaked(EFFECT_CLICK),
                        expectedRamp(/* startAmplitude= */ 0, /* endAmplitude= */ 0.5f,
                                /* startFrequencyHz= */ 150, /* endFrequencyHz= */ 100,
                                /* duration= */ 10),
                        expectedRamp(/* startAmplitude= */ 0.5f, /* endAmplitude= */ 0.7f,
                                /* startFrequencyHz= */ 100, /* endFrequencyHz= */ 120,
                                /* duration= */ 20),
                        expectedPrebaked(EFFECT_CLICK))
                .inOrder();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(100)).inOrder();
    }

    @Test
    public void vibrate_singleVibratorComposedWithFallback_replacedInTheMiddleOfComposition() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setSupportedEffects(EFFECT_CLICK);
        fakeVibrator.setSupportedPrimitives(PRIMITIVE_CLICK, PRIMITIVE_TICK);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);

        VibrationEffect fallback = VibrationEffect.createOneShot(10, 100);
        VibrationEffect effect = VibrationEffect.startComposition()
                .addEffect(VibrationEffect.get(EFFECT_CLICK))
                .addPrimitive(PRIMITIVE_CLICK, 1f)
                .addEffect(VibrationEffect.get(EFFECT_TICK))
                .addPrimitive(PRIMITIVE_TICK, 0.5f)
                .compose();
        HalVibration vibration = createVibration(CombinedVibration.createParallel(effect));
        vibration.fillFallbacks(unused -> fallback);
        startThreadAndDispatcher(vibration);
        waitForCompletion();

        // Use first duration the vibrator is turned on since we cannot estimate the clicks.
        verify(mManagerHooks).noteVibratorOn(eq(UID), anyLong());
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks, times(4))
                .onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        List<VibrationEffectSegment> segments =
                mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id);
        assertWithMessage("Wrong segments: %s", segments).that(segments.size()).isGreaterThan(3);
        assertThat(segments.get(0)).isInstanceOf(PrebakedSegment.class);
        assertThat(segments.get(1)).isInstanceOf(PrimitiveSegment.class);
        for (int i = 2; i < segments.size() - 1; i++) {
            // One or more step segments as fallback for the EFFECT_TICK.
            assertWithMessage("For segment index %s", i)
                    .that(segments.get(i)).isInstanceOf(StepSegment.class);
        }
        assertThat(segments.get(segments.size() - 1)).isInstanceOf(PrimitiveSegment.class);
    }

    @Test
    @EnableFlags(Flags.FLAG_NORMALIZED_PWLE_EFFECTS)
    public void vibrate_singleVibratorPwle_runsComposePwleV2() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_PWLE_EFFECTS_V2);
        fakeVibrator.setResonantFrequency(150);
        fakeVibrator.setFrequenciesHz(new float[]{30f, 50f, 100f, 120f, 150f});
        fakeVibrator.setOutputAccelerationsGs(new float[]{0.3f, 0.5f, 1.0f, 0.8f, 0.6f});
        fakeVibrator.setMaxEnvelopeEffectSize(10);
        fakeVibrator.setMinEnvelopeEffectControlPointDurationMillis(20);

        VibrationEffect effect = new VibrationEffect.WaveformEnvelopeBuilder()
                .addControlPoint(/*amplitude=*/ 0.1f, /*frequencyHz=*/ 60f, /*durationMillis=*/ 20)
                .addControlPoint(/*amplitude=*/ 0.3f, /*frequencyHz=*/ 100f, /*durationMillis=*/ 30)
                .addControlPoint(/*amplitude=*/ 0.4f, /*frequencyHz=*/ 120f, /*durationMillis=*/ 20)
                .addControlPoint(/*amplitude=*/ 0.0f, /*frequencyHz=*/ 120f, /*durationMillis=*/ 30)
                .build();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(100L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectPwlePoints(vibration.id))
                .containsExactly(
                        expectedPwle(0.0f, 60f, 0),
                        expectedPwle(0.1f, 60f, 20),
                        expectedPwle(0.3f, 100f, 30),
                        expectedPwle(0.4f, 120f, 20),
                        expectedPwle(0.0f, 120f, 30))
                .inOrder();

    }

    @Test
    @EnableFlags(Flags.FLAG_NORMALIZED_PWLE_EFFECTS)
    public void vibrate_singleVibratorBasicPwle_runsComposePwleV2() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_PWLE_EFFECTS_V2);
        fakeVibrator.setResonantFrequency(150);
        fakeVibrator.setFrequenciesHz(new float[]{50f, 100f, 120f, 150f});
        fakeVibrator.setOutputAccelerationsGs(new float[]{0.05f, 1.0f, 3.0f, 2.0f});
        fakeVibrator.setMaxEnvelopeEffectSize(10);
        fakeVibrator.setMinEnvelopeEffectControlPointDurationMillis(20);

        VibrationEffect effect = new VibrationEffect.BasicEnvelopeBuilder()
                .setInitialSharpness(/*initialSharpness=*/ 1.0f)
                .addControlPoint(/*intensity=*/ 1.0f, /*sharpness=*/ 1.0f, /*durationMillis=*/ 20)
                .addControlPoint(/*intensity=*/ 1.0f, /*sharpness=*/ 1.0f, /*durationMillis=*/ 100)
                .addControlPoint(/*intensity=*/ 0.0f, /*sharpness=*/ 1.0f, /*durationMillis=*/ 100)
                .build();

        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(220L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectPwlePoints(vibration.id))
                .containsExactly(
                        expectedPwle(0.0f, 150f, 0),
                        expectedPwle(1.0f, 150f, 20),
                        expectedPwle(1.0f, 150f, 100),
                        expectedPwle(0.0f, 150f, 100))
                .inOrder();

    }

    @Test
    @EnableFlags(Flags.FLAG_NORMALIZED_PWLE_EFFECTS)
    public void vibrate_singleVibratorPwle_withInitialFrequency_runsComposePwleV2() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_PWLE_EFFECTS_V2);
        fakeVibrator.setResonantFrequency(150);
        fakeVibrator.setFrequenciesHz(new float[]{30f, 50f, 100f, 120f, 150f});
        fakeVibrator.setOutputAccelerationsGs(new float[]{0.3f, 0.5f, 1.0f, 0.8f, 0.6f});
        fakeVibrator.setMaxEnvelopeEffectSize(10);
        fakeVibrator.setMinEnvelopeEffectControlPointDurationMillis(20);

        VibrationEffect effect = new VibrationEffect.WaveformEnvelopeBuilder()
                .setInitialFrequencyHz(/*initialFrequencyHz=*/ 30)
                .addControlPoint(/*amplitude=*/ 0.1f, /*frequencyHz=*/ 60f, /*durationMillis=*/ 20)
                .addControlPoint(/*amplitude=*/ 0.3f, /*frequencyHz=*/ 100f, /*durationMillis=*/ 30)
                .addControlPoint(/*amplitude=*/ 0.4f, /*frequencyHz=*/ 120f, /*durationMillis=*/ 20)
                .addControlPoint(/*amplitude=*/ 0.0f, /*frequencyHz=*/ 120f, /*durationMillis=*/ 30)
                .build();

        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(100L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectPwlePoints(vibration.id))
                .containsExactly(
                        expectedPwle(0.0f, 30f, 0),
                        expectedPwle(0.1f, 60f, 20),
                        expectedPwle(0.3f, 100f, 30),
                        expectedPwle(0.4f, 120f, 20),
                        expectedPwle(0.0f, 120f, 30))
                .inOrder();
    }

    @Test
    @EnableFlags(Flags.FLAG_NORMALIZED_PWLE_EFFECTS)
    public void vibrate_singleVibratorPwle_TooManyControlPoints_splitsAndRunsComposePwleV2() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_PWLE_EFFECTS_V2);
        fakeVibrator.setResonantFrequency(150);
        fakeVibrator.setFrequenciesHz(new float[]{30f, 50f, 100f, 120f, 150f});
        fakeVibrator.setOutputAccelerationsGs(new float[]{0.3f, 0.5f, 1.0f, 0.8f, 0.6f});
        fakeVibrator.setMaxEnvelopeEffectSize(3);
        fakeVibrator.setMinEnvelopeEffectControlPointDurationMillis(20);

        VibrationEffect effect = new VibrationEffect.WaveformEnvelopeBuilder()
                .addControlPoint(/*amplitude=*/ 0.8f, /*frequencyHz=*/ 100f, /*durationMillis=*/ 30)
                .addControlPoint(/*amplitude=*/ 0.0f, /*frequencyHz=*/ 100f, /*durationMillis=*/ 30)
                // Waveform will be split here, after vibration goes to zero amplitude
                .addControlPoint(/*amplitude=*/ 0.9f, /*frequencyHz=*/ 100f, /*durationMillis=*/ 30)
                .addControlPoint(/*amplitude=*/ 0.4f, /*frequencyHz=*/ 100f, /*durationMillis=*/ 30)
                // Waveform will be split here at lowest amplitude.
                .addControlPoint(/*amplitude=*/ 0.6f, /*frequencyHz=*/ 100f, /*durationMillis=*/ 30)
                .addControlPoint(/*amplitude=*/ 0.7f, /*frequencyHz=*/ 100f, /*durationMillis=*/ 30)
                .build();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.FINISHED);
        // Vibrator compose called 3 times with 2 segments instead of 2 times with 3 segments.
        // Using best split points instead of max-packing PWLEs.
        verify(mControllerCallbacks, times(3))
                .onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectPwlePoints(vibration.id))
                .containsExactly(
                        expectedPwle(0.0f, 100f, 0),
                        expectedPwle(0.8f, 100f, 30),
                        expectedPwle(0.0f, 100f, 30),
                        expectedPwle(0.9f, 100f, 0),
                        expectedPwle(0.4f, 100f, 30),
                        expectedPwle(0.6f, 100f, 0),
                        expectedPwle(0.7f, 100f, 30))
                .inOrder();
    }

    @Test
    @DisableFlags(Flags.FLAG_NORMALIZED_PWLE_EFFECTS)
    public void vibrate_singleVibratorPwle_runsComposePwle() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_PWLE_EFFECTS);
        fakeVibrator.setSupportedBraking(Braking.CLAB);
        fakeVibrator.setMinFrequency(100);
        fakeVibrator.setResonantFrequency(150);
        fakeVibrator.setFrequencyResolution(50);
        fakeVibrator.setMaxAmplitudes(
                0.5f /* 100Hz*/, 1 /* 150Hz */, 0.6f /* 200Hz */);

        VibrationEffect effect = VibrationEffect.startWaveform(targetAmplitude(1))
                .addSustain(Duration.ofMillis(10))
                .addTransition(Duration.ofMillis(20), targetAmplitude(0))
                .addTransition(Duration.ZERO, targetAmplitude(0.8f), targetFrequency(100))
                .addSustain(Duration.ofMillis(30))
                .addTransition(Duration.ofMillis(40), targetAmplitude(0.6f), targetFrequency(200))
                .build();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(100L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
        assertThat(fakeVibrator.getEffectSegments(vibration.id))
                .containsExactly(
                        expectedRamp(/* amplitude= */ 1, /* frequencyHz= */ 150,
                                /* duration= */ 10),
                        expectedRamp(/* startAmplitude= */ 1, /* endAmplitude= */ 0,
                                /* startFrequencyHz= */ 150, /* endFrequencyHz= */ 150,
                                /* duration= */ 20),
                        expectedRamp(/* amplitude= */ 0.5f, /* frequencyHz= */ 100,
                                /* duration= */ 30),
                        expectedRamp(/* startAmplitude= */ 0.5f, /* endAmplitude= */ 0.6f,
                                /* startFrequencyHz= */ 100, /* endFrequencyHz= */ 200,
                                /* duration= */ 40))
                .inOrder();
        assertThat(fakeVibrator.getBraking(vibration.id)).containsExactly(Braking.CLAB).inOrder();
    }

    @Test
    public void vibrate_singleVibratorLargePwle_splitsComposeCallWhenAmplitudeIsLowest() {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_COMPOSE_PWLE_EFFECTS);
        fakeVibrator.setMinFrequency(100);
        fakeVibrator.setResonantFrequency(150);
        fakeVibrator.setFrequencyResolution(50);
        fakeVibrator.setMaxAmplitudes(1, 1, 1);
        fakeVibrator.setPwleSizeMax(3);

        VibrationEffect effect = VibrationEffect.startWaveform(targetAmplitude(1))
                .addSustain(Duration.ofMillis(10))
                .addTransition(Duration.ofMillis(20), targetAmplitude(0))
                // Waveform will be split here, after vibration goes to zero amplitude
                .addTransition(Duration.ZERO, targetAmplitude(0.8f), targetFrequency(100))
                .addSustain(Duration.ofMillis(30))
                .addTransition(Duration.ofMillis(40), targetAmplitude(0.6f), targetFrequency(200))
                // Waveform will be split here at lowest amplitude.
                .addTransition(Duration.ofMillis(40), targetAmplitude(0.7f), targetFrequency(200))
                .addTransition(Duration.ofMillis(40), targetAmplitude(0.6f), targetFrequency(200))
                .build();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.FINISHED);

        // Vibrator compose called 3 times with 2 segments instead of 2 times with 3 segments.
        // Using best split points instead of max-packing PWLEs.
        verify(mControllerCallbacks, times(3))
                .onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        assertThat(fakeVibrator.getEffectSegments(vibration.id)).hasSize(6);
    }

    @Test
    public void vibrate_singleVibratorCancelled_vibratorStopped() throws Exception {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createWaveform(new long[]{5}, new int[]{100}, 0);
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> fakeVibrator.getAmplitudes().size() > 2, TEST_TIMEOUT_MILLIS))
                .isTrue();
        // Vibration still running after 2 cycles.
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isTrue();

        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BINDER_DIED), /* immediate= */ false);
        waitForCompletion();
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BINDER_DIED);
    }

    @Test
    public void vibrate_singleVibrator_skipsSyncedCallbacks() {
        mVibratorProviders.get(1).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        HalVibration vibration = startThreadAndDispatcher(VibrationEffect.createOneShot(10, 100));
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.FINISHED);
        verify(mManagerHooks, never()).prepareSyncedVibration(anyLong(), any());
        verify(mManagerHooks, never()).triggerSyncedVibration(anyLong());
        verify(mManagerHooks, never()).cancelSyncedVibration();
    }

    @Test
    public void vibrate_multipleExistingAndMissingVibrators_vibratesOnlyExistingOnes() {
        mVibratorProviders.get(1).setSupportedEffects(EFFECT_TICK);

        CombinedVibration effect = CombinedVibration.startParallel()
                .addVibrator(VIBRATOR_ID, VibrationEffect.get(EFFECT_TICK))
                .addVibrator(2, VibrationEffect.get(EFFECT_TICK))
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(20L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verify(mControllerCallbacks, never()).onComplete(eq(2), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedPrebaked(EFFECT_TICK)).inOrder();
    }

    @Test
    public void vibrate_multipleMono_runsSameEffectInAllVibrators() {
        mockVibrators(1, 2, 3);
        mVibratorProviders.get(1).setSupportedEffects(EFFECT_CLICK);
        mVibratorProviders.get(2).setSupportedEffects(EFFECT_CLICK);
        mVibratorProviders.get(3).setSupportedEffects(EFFECT_CLICK);

        CombinedVibration effect = CombinedVibration.createParallel(
                VibrationEffect.get(EFFECT_CLICK));
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(20L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(1), eq(vibration.id), anyLong());
        verify(mControllerCallbacks).onComplete(eq(2), eq(vibration.id), anyLong());
        verify(mControllerCallbacks).onComplete(eq(3), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(1).isVibrating()).isFalse();
        assertThat(mControllers.get(2).isVibrating()).isFalse();
        assertThat(mControllers.get(3).isVibrating()).isFalse();

        VibrationEffectSegment expected = expectedPrebaked(EFFECT_CLICK);
        assertThat(mVibratorProviders.get(1).getEffectSegments(vibration.id))
                .containsExactly(expected).inOrder();
        assertThat(mVibratorProviders.get(2).getEffectSegments(vibration.id))
                .containsExactly(expected).inOrder();
        assertThat(mVibratorProviders.get(3).getEffectSegments(vibration.id))
                .containsExactly(expected).inOrder();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_multipleStereo_runsVibrationOnRightVibrators() {
        mockVibrators(1, 2, 3, 4);
        mVibratorProviders.get(1).setSupportedEffects(EFFECT_CLICK);
        mVibratorProviders.get(2).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        mVibratorProviders.get(3).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        mVibratorProviders.get(4).setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        mVibratorProviders.get(4).setSupportedPrimitives(PRIMITIVE_CLICK);

        VibrationEffect composed = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK)
                .compose();
        CombinedVibration effect = CombinedVibration.startParallel()
                .addVibrator(1, VibrationEffect.get(EFFECT_CLICK))
                .addVibrator(2, VibrationEffect.createOneShot(10, 100))
                .addVibrator(3, VibrationEffect.createWaveform(
                        new long[]{10, 10}, new int[]{1, 2}, -1))
                .addVibrator(4, composed)
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(20L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(1), eq(vibration.id), anyLong());
        verify(mControllerCallbacks).onComplete(eq(2), eq(vibration.id), anyLong());
        verify(mControllerCallbacks).onComplete(eq(3), eq(vibration.id), anyLong());
        verify(mControllerCallbacks).onComplete(eq(4), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(1).isVibrating()).isFalse();
        assertThat(mControllers.get(2).isVibrating()).isFalse();
        assertThat(mControllers.get(3).isVibrating()).isFalse();
        assertThat(mControllers.get(4).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(1).getEffectSegments(vibration.id))
                .containsExactly(expectedPrebaked(EFFECT_CLICK)).inOrder();
        assertThat(mVibratorProviders.get(2).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(10)).inOrder();
        assertThat(mVibratorProviders.get(2).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(100)).inOrder();
        assertThat(mVibratorProviders.get(3).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(20)).inOrder();
        assertThat(mVibratorProviders.get(3).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(1, 2)).inOrder();
        assertThat(mVibratorProviders.get(4).getEffectSegments(vibration.id))
                .containsExactly(expectedPrimitive(PRIMITIVE_CLICK, 1, 0)).inOrder();
    }

    @Test
    public void vibrate_multipleSequential_runsVibrationInOrderWithDelays() {
        mockVibrators(1, 2, 3);
        mVibratorProviders.get(1).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        mVibratorProviders.get(2).setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        mVibratorProviders.get(2).setSupportedPrimitives(PRIMITIVE_CLICK);
        mVibratorProviders.get(3).setSupportedEffects(EFFECT_CLICK);

        VibrationEffect composed = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK)
                .compose();
        CombinedVibration effect = CombinedVibration.startSequential()
                .addNext(3, VibrationEffect.get(EFFECT_CLICK), /* delay= */ 50)
                .addNext(1, VibrationEffect.createOneShot(10, 100), /* delay= */ 50)
                .addNext(2, composed, /* delay= */ 50)
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect);

        waitForCompletion();
        InOrder verifier = inOrder(mControllerCallbacks);
        verifier.verify(mControllerCallbacks).onComplete(eq(3), eq(vibration.id), anyLong());
        verifier.verify(mControllerCallbacks).onComplete(eq(1), eq(vibration.id), anyLong());
        verifier.verify(mControllerCallbacks).onComplete(eq(2), eq(vibration.id), anyLong());

        InOrder batteryVerifier = inOrder(mManagerHooks);
        batteryVerifier.verify(mManagerHooks).noteVibratorOn(eq(UID), eq(20L));
        batteryVerifier.verify(mManagerHooks).noteVibratorOff(eq(UID));
        batteryVerifier.verify(mManagerHooks).noteVibratorOn(eq(UID), eq(10L));
        batteryVerifier.verify(mManagerHooks).noteVibratorOff(eq(UID));
        batteryVerifier.verify(mManagerHooks).noteVibratorOn(eq(UID), eq(20L));
        batteryVerifier.verify(mManagerHooks).noteVibratorOff(eq(UID));

        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(1).isVibrating()).isFalse();
        assertThat(mControllers.get(2).isVibrating()).isFalse();
        assertThat(mControllers.get(3).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(1).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(10)).inOrder();
        assertThat(mVibratorProviders.get(1).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(100)).inOrder();
        assertThat(mVibratorProviders.get(2).getEffectSegments(vibration.id))
                .containsExactly(expectedPrimitive(PRIMITIVE_CLICK, 1, 0)).inOrder();
        assertThat(mVibratorProviders.get(3).getEffectSegments(vibration.id))
                .containsExactly(expectedPrebaked(EFFECT_CLICK)).inOrder();
    }

    @Test
    public void vibrate_multipleSyncedCallbackTriggered_finishSteps() throws Exception {
        int[] vibratorIds = new int[]{1, 2};
        mockVibrators(vibratorIds);
        mVibratorProviders.get(1).setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        mVibratorProviders.get(1).setSupportedPrimitives(PRIMITIVE_CLICK);
        mVibratorProviders.get(2).setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        mVibratorProviders.get(2).setSupportedPrimitives(PRIMITIVE_CLICK);
        when(mManagerHooks.prepareSyncedVibration(anyLong(), eq(vibratorIds))).thenReturn(true);

        VibrationEffect composed = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK, 1, 100)
                .compose();
        CombinedVibration effect = CombinedVibration.createParallel(composed);
        // We create the HalVibration here to obtain the vibration id and use it to mock the
        // required response when calling triggerSyncedVibration.
        HalVibration vibration = createVibration(effect);
        when(mManagerHooks.triggerSyncedVibration(eq(vibration.id))).thenReturn(true);
        startThreadAndDispatcher(vibration);

        assertThat(waitUntil(
                () -> !mVibratorProviders.get(1).getEffectSegments(vibration.id).isEmpty()
                        && !mVibratorProviders.get(2).getEffectSegments(vibration.id).isEmpty(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        mVibrationConductor.notifySyncedVibrationComplete();
        waitForCompletion();

        long expectedCap = IVibratorManager.CAP_SYNC | IVibratorManager.CAP_PREPARE_COMPOSE;
        verify(mManagerHooks).prepareSyncedVibration(eq(expectedCap), eq(vibratorIds));
        verify(mManagerHooks).triggerSyncedVibration(eq(vibration.id));
        verify(mManagerHooks, never()).cancelSyncedVibration();
        verifyCallbacksTriggered(vibration, Status.FINISHED);

        VibrationEffectSegment expected = expectedPrimitive(PRIMITIVE_CLICK, 1, 100);
        assertThat(mVibratorProviders.get(1).getEffectSegments(vibration.id))
                .containsExactly(expected).inOrder();
        assertThat(mVibratorProviders.get(2).getEffectSegments(vibration.id))
                .containsExactly(expected).inOrder();
    }

    @Test
    public void vibrate_multipleSynced_callsPrepareAndTriggerCallbacks() {
        int[] vibratorIds = new int[]{1, 2, 3, 4};
        mockVibrators(vibratorIds);
        mVibratorProviders.get(1).setSupportedEffects(EFFECT_CLICK);
        mVibratorProviders.get(4).setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        mVibratorProviders.get(4).setSupportedPrimitives(PRIMITIVE_CLICK);
        when(mManagerHooks.prepareSyncedVibration(anyLong(), any())).thenReturn(true);

        VibrationEffect composed = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK)
                .compose();
        CombinedVibration effect = CombinedVibration.startParallel()
                .addVibrator(1, VibrationEffect.get(EFFECT_CLICK))
                .addVibrator(2, VibrationEffect.createOneShot(10, 100))
                .addVibrator(3, VibrationEffect.createWaveform(new long[]{10}, new int[]{100}, -1))
                .addVibrator(4, composed)
                .combine();
        // We create the HalVibration here to obtain the vibration id and use it to mock the
        // required response when calling triggerSyncedVibration.
        HalVibration vibration = createVibration(effect);
        when(mManagerHooks.triggerSyncedVibration(eq(vibration.id))).thenReturn(true);
        startThreadAndDispatcher(vibration);
        waitForCompletion();

        long expectedCap = IVibratorManager.CAP_SYNC
                | IVibratorManager.CAP_PREPARE_ON
                | IVibratorManager.CAP_PREPARE_PERFORM
                | IVibratorManager.CAP_PREPARE_COMPOSE
                | IVibratorManager.CAP_MIXED_TRIGGER_ON
                | IVibratorManager.CAP_MIXED_TRIGGER_PERFORM
                | IVibratorManager.CAP_MIXED_TRIGGER_COMPOSE;
        verify(mManagerHooks).prepareSyncedVibration(eq(expectedCap), eq(vibratorIds));
        verify(mManagerHooks).triggerSyncedVibration(eq(vibration.id));
        verify(mManagerHooks, never()).cancelSyncedVibration();
        verifyCallbacksTriggered(vibration, Status.FINISHED);
    }

    @Test
    public void vibrate_multipleSyncedPrepareFailed_skipTriggerStepAndVibrates() {
        int[] vibratorIds = new int[]{1, 2};
        mockVibrators(vibratorIds);
        mVibratorProviders.get(1).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        mVibratorProviders.get(2).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        when(mManagerHooks.prepareSyncedVibration(anyLong(), any())).thenReturn(false);

        CombinedVibration effect = CombinedVibration.startParallel()
                .addVibrator(1, VibrationEffect.createOneShot(10, 100))
                .addVibrator(2, VibrationEffect.createWaveform(new long[]{5}, new int[]{200}, -1))
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        long expectedCap = IVibratorManager.CAP_SYNC | IVibratorManager.CAP_PREPARE_ON;
        verify(mManagerHooks).prepareSyncedVibration(eq(expectedCap), eq(vibratorIds));
        verify(mManagerHooks, never()).triggerSyncedVibration(eq(vibration.id));
        verify(mManagerHooks, never()).cancelSyncedVibration();

        assertThat(mVibratorProviders.get(1).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(10)).inOrder();
        assertThat(mVibratorProviders.get(1).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(100)).inOrder();
        assertThat(mVibratorProviders.get(2).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(5)).inOrder();
        assertThat(mVibratorProviders.get(2).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(200)).inOrder();
    }

    @Test
    public void vibrate_multipleSyncedTriggerFailed_cancelPreparedVibrationAndSkipSetAmplitude() {
        int[] vibratorIds = new int[]{1, 2};
        mockVibrators(vibratorIds);
        mVibratorProviders.get(2).setSupportedEffects(EFFECT_CLICK);
        when(mManagerHooks.prepareSyncedVibration(anyLong(), any())).thenReturn(true);

        CombinedVibration effect = CombinedVibration.startParallel()
                .addVibrator(1, VibrationEffect.createOneShot(10, 100))
                .addVibrator(2, VibrationEffect.get(EFFECT_CLICK))
                .combine();
        // We create the HalVibration here to obtain the vibration id and use it to mock the
        // required response when calling triggerSyncedVibration.
        HalVibration vibration = createVibration(effect);
        when(mManagerHooks.triggerSyncedVibration(eq(vibration.id))).thenReturn(false);
        startThreadAndDispatcher(vibration);
        waitForCompletion();

        long expectedCap = IVibratorManager.CAP_SYNC
                | IVibratorManager.CAP_PREPARE_ON
                | IVibratorManager.CAP_PREPARE_PERFORM
                | IVibratorManager.CAP_MIXED_TRIGGER_ON
                | IVibratorManager.CAP_MIXED_TRIGGER_PERFORM;
        verify(mManagerHooks).prepareSyncedVibration(eq(expectedCap), eq(vibratorIds));
        verify(mManagerHooks).triggerSyncedVibration(eq(vibration.id));
        verify(mManagerHooks).cancelSyncedVibration();
        assertThat(mVibratorProviders.get(1).getAmplitudes()).isEmpty();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_multipleWaveforms_playsWaveformsInParallel() throws Exception {
        mockVibrators(1, 2, 3);
        mVibratorProviders.get(1).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        mVibratorProviders.get(2).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        mVibratorProviders.get(3).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        CombinedVibration effect = CombinedVibration.startParallel()
                .addVibrator(1, VibrationEffect.createWaveform(
                        new long[]{5, 10, 10}, new int[]{1, 2, 3}, -1))
                .addVibrator(2, VibrationEffect.createWaveform(
                        new long[]{20, 60}, new int[]{4, 5}, -1))
                .addVibrator(3, VibrationEffect.createWaveform(
                        new long[]{60}, new int[]{6}, -1))
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect);

        // All vibrators are turned on in parallel.
        assertThat(waitUntil(
                () -> mControllers.get(1).isVibrating()
                        && mControllers.get(2).isVibrating()
                        && mControllers.get(3).isVibrating(),
                TEST_TIMEOUT_MILLIS)).isTrue();

        waitForCompletion();

        verify(mManagerHooks).noteVibratorOn(eq(UID), eq(80L));
        verify(mManagerHooks).noteVibratorOff(eq(UID));
        verify(mControllerCallbacks).onComplete(eq(1), eq(vibration.id), anyLong());
        verify(mControllerCallbacks).onComplete(eq(2), eq(vibration.id), anyLong());
        verify(mControllerCallbacks).onComplete(eq(3), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(1).isVibrating()).isFalse();
        assertThat(mControllers.get(2).isVibrating()).isFalse();
        assertThat(mControllers.get(3).isVibrating()).isFalse();

        assertThat(mVibratorProviders.get(1).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(25)).inOrder();
        assertThat(mVibratorProviders.get(2).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(80)).inOrder();
        assertThat(mVibratorProviders.get(3).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(60)).inOrder();
        assertThat(mVibratorProviders.get(1).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(1, 2, 3)).inOrder();
        assertThat(mVibratorProviders.get(2).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(4, 5)).inOrder();
        assertThat(mVibratorProviders.get(3).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(6)).inOrder();

    }

    @Test
    public void vibrate_withRampDown_vibrationFinishedAfterDurationAndBeforeRampDown()
            throws Exception {
        int expectedDuration = 100;
        int rampDownDuration = 200;

        when(mVibrationConfigMock.getRampDownDurationMs()).thenReturn(rampDownDuration);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        HalVibration vibration = createVibration(
                CombinedVibration.createParallel(
                        VibrationEffect.createOneShot(
                                expectedDuration, VibrationEffect.DEFAULT_AMPLITUDE)));

        long startTime = SystemClock.elapsedRealtime();
        startThreadAndDispatcher(vibration);

        vibration.waitForEnd();
        long vibrationEndTime = SystemClock.elapsedRealtime();

        waitForCompletion(rampDownDuration + TEST_TIMEOUT_MILLIS);
        long completionTime = SystemClock.elapsedRealtime();

        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        // Vibration ends before ramp down, thread completed after ramp down
        assertThat(vibrationEndTime - startTime).isLessThan(expectedDuration + rampDownDuration);
        assertThat(completionTime - startTime).isAtLeast(expectedDuration + rampDownDuration);
    }

    @Test
    public void vibrate_withVibratorCallbackDelayShorterThanTimeout_vibrationFinishedAfterDelay() {
        long expectedDuration = 10;
        long callbackDelay = VibrationStepConductor.CALLBACKS_EXTRA_TIMEOUT / 2;

        mVibratorProviders.get(VIBRATOR_ID).setCompletionCallbackDelay(callbackDelay);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        HalVibration vibration = createVibration(
                CombinedVibration.createParallel(
                        VibrationEffect.createOneShot(
                                expectedDuration, VibrationEffect.DEFAULT_AMPLITUDE)));

        long startTime = SystemClock.elapsedRealtime();
        startThreadAndDispatcher(vibration);

        waitForCompletion(TEST_TIMEOUT_MILLIS);
        long vibrationEndTime = SystemClock.elapsedRealtime();

        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        assertThat(vibrationEndTime - startTime).isAtLeast(expectedDuration + callbackDelay);
    }

    @LargeTest
    @Test
    public void vibrate_withVibratorCallbackDelayLongerThanTimeout_vibrationFinishedAfterTimeout() {
        long expectedDuration = 10;
        long callbackTimeout = VibrationStepConductor.CALLBACKS_EXTRA_TIMEOUT;
        long callbackDelay = callbackTimeout * 2;

        mVibratorProviders.get(VIBRATOR_ID).setCompletionCallbackDelay(callbackDelay);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        HalVibration vibration = createVibration(
                CombinedVibration.createParallel(
                        VibrationEffect.createOneShot(
                                expectedDuration, VibrationEffect.DEFAULT_AMPLITUDE)));

        long startTime = SystemClock.elapsedRealtime();
        startThreadAndDispatcher(vibration);

        waitForCompletion(callbackDelay + TEST_TIMEOUT_MILLIS);
        long vibrationEndTime = SystemClock.elapsedRealtime();

        verify(mControllerCallbacks, never())
                .onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        // Vibration ends and thread completes after timeout, before the HAL callback
        assertThat(vibrationEndTime - startTime).isAtLeast(expectedDuration + callbackTimeout);
        assertThat(vibrationEndTime - startTime).isLessThan(expectedDuration + callbackDelay);
    }

    @LargeTest
    @Test
    public void vibrate_withWaveform_totalVibrationTimeRespected() {
        int totalDuration = 10_000; // 10s
        int stepDuration = 25; // 25ms

        // 25% of the first waveform step will be spent on the native on() call.
        // 25% of each waveform step will be spent on the native setAmplitude() call..
        mVibratorProviders.get(VIBRATOR_ID).setOnLatency(stepDuration / 4);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        int stepCount = totalDuration / stepDuration;
        long[] timings = new long[stepCount];
        int[] amplitudes = new int[stepCount];
        Arrays.fill(timings, stepDuration);
        Arrays.fill(amplitudes, VibrationEffect.DEFAULT_AMPLITUDE);
        VibrationEffect effect = VibrationEffect.createWaveform(timings, amplitudes, -1);

        long startTime = SystemClock.elapsedRealtime();
        startThreadAndDispatcher(effect);

        waitForCompletion(totalDuration + TEST_TIMEOUT_MILLIS);
        long delay = Math.abs(SystemClock.elapsedRealtime() - startTime - totalDuration);

        // Allow some delay for thread scheduling and callback triggering.
        int maxDelay = (int) (0.05 * totalDuration); // < 5% of total duration
        assertThat(delay).isLessThan(maxDelay);
    }

    @LargeTest
    @Test
    public void vibrate_cancelSlowVibrator_cancelIsNotBlockedByVibrationThread() throws Exception {
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setSupportedEffects(EFFECT_CLICK);

        long latency = 5_000; // 5s
        fakeVibrator.setOnLatency(latency);

        VibrationEffect effect = VibrationEffect.get(EFFECT_CLICK);
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> !fakeVibrator.getEffectSegments(vibration.id).isEmpty(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();

        // Run cancel in a separate thread so if VibrationThread.cancel blocks then this test should
        // fail at waitForCompletion(cancellingThread).
        Thread cancellingThread = new Thread(
                () -> mVibrationConductor.notifyCancelled(
                        new Vibration.EndInfo(Status.CANCELLED_BY_USER), /* immediate= */ false));
        cancellingThread.start();

        // Cancelling the vibration should be fast and return right away, even if the thread is
        // stuck at the slow call to the vibrator.
        cancellingThread.join(/* timeout= */ 50);

        // After the vibrator call ends the vibration is cancelled and the vibrator is turned off.
        waitForCompletion(/* timeout= */ latency + TEST_TIMEOUT_MILLIS);
        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_USER);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
    }

    @Test
    public void vibrate_multiplePredefinedCancel_cancelsVibrationImmediately() throws Exception {
        mockVibrators(1, 2);
        mVibratorProviders.get(1).setSupportedEffects(EFFECT_CLICK);
        mVibratorProviders.get(2).setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        mVibratorProviders.get(2).setSupportedPrimitives(PRIMITIVE_CLICK);

        CombinedVibration effect = CombinedVibration.startParallel()
                .addVibrator(1, VibrationEffect.get(EFFECT_CLICK))
                .addVibrator(2, VibrationEffect.startComposition()
                        .addPrimitive(PRIMITIVE_CLICK, 1f, 100)
                        .addPrimitive(PRIMITIVE_CLICK, 1f, 100)
                        .addPrimitive(PRIMITIVE_CLICK, 1f, 100)
                        .compose())
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> mControllers.get(2).isVibrating(), TEST_TIMEOUT_MILLIS))
                .isTrue();
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();

        // Run cancel in a separate thread so if VibrationThread.cancel blocks then this test should
        // fail at waitForCompletion(vibrationThread) if the vibration not cancelled immediately.
        Thread cancellingThread = new Thread(
                () -> mVibrationConductor.notifyCancelled(
                        new Vibration.EndInfo(Status.CANCELLED_BY_SCREEN_OFF),
                        /* immediate= */ false));
        cancellingThread.start();

        waitForCompletion(/* timeout= */ 50);
        cancellingThread.join();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_SCREEN_OFF);
        assertThat(mControllers.get(1).isVibrating()).isFalse();
        assertThat(mControllers.get(2).isVibrating()).isFalse();
    }

    @Test
    @EnableFlags(Flags.FLAG_VENDOR_VIBRATION_EFFECTS)
    public void vibrate_multipleVendorEffectCancel_cancelsVibrationImmediately() throws Exception {
        mockVibrators(1, 2);
        mVibratorProviders.get(1).setCapabilities(IVibrator.CAP_PERFORM_VENDOR_EFFECTS);
        mVibratorProviders.get(1).setVendorEffectDuration(10 * TEST_TIMEOUT_MILLIS);
        mVibratorProviders.get(2).setCapabilities(IVibrator.CAP_PERFORM_VENDOR_EFFECTS);
        mVibratorProviders.get(2).setVendorEffectDuration(10 * TEST_TIMEOUT_MILLIS);

        CombinedVibration effect = CombinedVibration.startParallel()
                .addVibrator(1, VibrationEffect.createVendorEffect(createTestVendorData()))
                .addVibrator(2, VibrationEffect.createVendorEffect(createTestVendorData()))
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> mControllers.get(2).isVibrating(), TEST_TIMEOUT_MILLIS))
                .isTrue();
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();

        // Run cancel in a separate thread so if VibrationThread.cancel blocks then this test should
        // fail at waitForCompletion(vibrationThread) if the vibration not cancelled immediately.
        Thread cancellingThread = new Thread(
                () -> mVibrationConductor.notifyCancelled(
                        new Vibration.EndInfo(Status.CANCELLED_BY_SCREEN_OFF),
                        /* immediate= */ false));
        cancellingThread.start();

        waitForCompletion(/* timeout= */ 50);
        cancellingThread.join();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_SCREEN_OFF);
        assertThat(mControllers.get(1).isVibrating()).isFalse();
        assertThat(mControllers.get(2).isVibrating()).isFalse();
    }

    @Test
    public void vibrate_multipleWaveformCancel_cancelsVibrationImmediately() throws Exception {
        mockVibrators(1, 2);
        mVibratorProviders.get(1).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        mVibratorProviders.get(2).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        CombinedVibration effect = CombinedVibration.startParallel()
                .addVibrator(1, VibrationEffect.createWaveform(
                        new long[]{100, 100}, new int[]{1, 2}, 0))
                .addVibrator(2, VibrationEffect.createOneShot(100, 100))
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> mControllers.get(1).isVibrating()
                        && mControllers.get(2).isVibrating(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();

        // Run cancel in a separate thread so if VibrationThread.cancel blocks then this test should
        // fail at waitForCompletion(vibrationThread) if the vibration not cancelled immediately.
        Thread cancellingThread = new Thread(
                () -> mVibrationConductor.notifyCancelled(
                        new Vibration.EndInfo(Status.CANCELLED_BY_SCREEN_OFF),
                        /* immediate= */ false));
        cancellingThread.start();

        waitForCompletion(/* timeout= */ 50);
        cancellingThread.join();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_SCREEN_OFF);
        assertThat(mControllers.get(1).isVibrating()).isFalse();
        assertThat(mControllers.get(2).isVibrating()).isFalse();
    }

    @Test
    public void vibrate_binderDied_cancelsVibration() throws Exception {
        VibrationEffect effect = VibrationEffect.createWaveform(new long[]{5}, new int[]{100}, 0);
        HalVibration vibration = startThreadAndDispatcher(effect);

        assertThat(waitUntil(() -> mControllers.get(VIBRATOR_ID).isVibrating(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();

        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BINDER_DIED), /* immediate= */ false);
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BINDER_DIED);
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .isNotEmpty();
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_waveformWithRampDown_addsRampDownAfterVibrationCompleted() {
        when(mVibrationConfigMock.getRampDownDurationMs()).thenReturn(15);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createWaveform(
                new long[]{5, 5, 5}, new int[]{60, 120, 240}, -1);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);

        // Duration extended for 5 + 5 + 5 + 15.
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(30)).inOrder();
        List<Float> amplitudes = mVibratorProviders.get(VIBRATOR_ID).getAmplitudes();
        assertThat(amplitudes.size()).isGreaterThan(3);
        assertThat(amplitudes.subList(0, 3))
                .containsExactlyElementsIn(expectedAmplitudes(60, 120, 240))
                .inOrder();
        for (int i = 3; i < amplitudes.size(); i++) {
            assertWithMessage("For amplitude index %s", i)
                    .that(amplitudes.get(i)).isLessThan(amplitudes.get(i - 1));
        }
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_waveformWithRampDown_triggersCallbackWhenOriginalVibrationEnds()
            throws Exception {
        when(mVibrationConfigMock.getRampDownDurationMs()).thenReturn(10_000);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createOneShot(10, 200);
        HalVibration vibration = startThreadAndDispatcher(effect);

        // Vibration completed but vibrator not yet released.
        vibration.waitForEnd();
        verify(mManagerHooks, never()).onVibrationThreadReleased(anyLong());

        // Thread still running ramp down.
        assertThat(mThread.isRunningVibrationId(vibration.id)).isTrue();

        // Duration extended for 10 + 10000.
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(10_010)).inOrder();

        // Will stop the ramp down right away.
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_SETTINGS_UPDATE), /* immediate= */ true);
        waitForCompletion();

        // Does not cancel already finished vibration, but releases vibrator.
        assertThat(vibration.getStatus()).isNotEqualTo(Status.CANCELLED_BY_SETTINGS_UPDATE);
        verify(mManagerHooks).onVibrationThreadReleased(vibration.id);
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_waveformCancelledWithRampDown_addsRampDownAfterVibrationCancelled()
            throws Exception {
        when(mVibrationConfigMock.getRampDownDurationMs()).thenReturn(15);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);

        VibrationEffect effect = VibrationEffect.createOneShot(10_000, 240);
        HalVibration vibration = startThreadAndDispatcher(effect);
        assertThat(waitUntil(() -> mControllers.get(VIBRATOR_ID).isVibrating(),
                TEST_TIMEOUT_MILLIS)).isTrue();
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_USER), /* immediate= */ false);
        waitForCompletion();

        verifyCallbacksTriggered(vibration, Status.CANCELLED_BY_USER);

        // Duration extended for 10000 + 15.
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(10_015)).inOrder();
        List<Float> amplitudes = mVibratorProviders.get(VIBRATOR_ID).getAmplitudes();
        assertThat(amplitudes.size()).isGreaterThan(1);
        for (int i = 1; i < amplitudes.size(); i++) {
            assertWithMessage("For amplitude index %s", i)
                    .that(amplitudes.get(i)).isLessThan(amplitudes.get(i - 1));
        }
    }

    @Test
    public void vibrate_predefinedWithRampDown_doesNotAddRampDown() {
        when(mVibrationConfigMock.getRampDownDurationMs()).thenReturn(15);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        mVibratorProviders.get(VIBRATOR_ID).setSupportedEffects(EFFECT_CLICK);

        VibrationEffect effect = VibrationEffect.get(EFFECT_CLICK);
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedPrebaked(EFFECT_CLICK)).inOrder();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes()).isEmpty();
    }

    @Test
    @EnableFlags(Flags.FLAG_VENDOR_VIBRATION_EFFECTS)
    public void vibrate_vendorEffectWithRampDown_doesNotAddRampDown() {
        when(mVibrationConfigMock.getRampDownDurationMs()).thenReturn(15);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_PERFORM_VENDOR_EFFECTS);

        VibrationEffect effect = VibrationEffect.createVendorEffect(createTestVendorData());
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getVendorEffects(vibration.id))
                .containsExactly(effect).inOrder();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes()).isEmpty();
    }

    @Test
    public void vibrate_composedWithRampDown_doesNotAddRampDown() {
        when(mVibrationConfigMock.getRampDownDurationMs()).thenReturn(15);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL,
                IVibrator.CAP_COMPOSE_EFFECTS);
        mVibratorProviders.get(VIBRATOR_ID).setSupportedPrimitives(PRIMITIVE_CLICK);

        VibrationEffect effect = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK)
                .compose();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);

        assertThat(mVibratorProviders.get(VIBRATOR_ID).getEffectSegments(vibration.id))
                .containsExactly(expectedPrimitive(PRIMITIVE_CLICK, 1, 0)).inOrder();
        assertThat(mVibratorProviders.get(VIBRATOR_ID).getAmplitudes()).isEmpty();
    }

    @Test
    @DisableFlags(Flags.FLAG_NORMALIZED_PWLE_EFFECTS)
    public void vibrate_pwleWithRampDown_doesNotAddRampDown() {
        when(mVibrationConfigMock.getRampDownDurationMs()).thenReturn(15);
        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        fakeVibrator.setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL,
                IVibrator.CAP_COMPOSE_PWLE_EFFECTS);
        fakeVibrator.setMinFrequency(100);
        fakeVibrator.setResonantFrequency(150);
        fakeVibrator.setFrequencyResolution(50);
        fakeVibrator.setMaxAmplitudes(1, 1, 1);
        fakeVibrator.setPwleSizeMax(2);

        VibrationEffect effect = VibrationEffect.startWaveform()
                .addTransition(Duration.ofMillis(1), targetAmplitude(1))
                .build();
        HalVibration vibration = startThreadAndDispatcher(effect);
        waitForCompletion();

        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration.id), anyLong());
        verifyCallbacksTriggered(vibration, Status.FINISHED);

        assertThat(fakeVibrator.getEffectSegments(vibration.id))
                .containsExactly(expectedRamp(0, 1, 150, 150, 1)).inOrder();
        assertThat(fakeVibrator.getAmplitudes()).isEmpty();
    }

    @Test
    public void vibrate_multipleVibrations_withCancel() throws Exception {
        mVibratorProviders.get(VIBRATOR_ID).setSupportedEffects(EFFECT_CLICK, EFFECT_TICK);
        mVibratorProviders.get(VIBRATOR_ID).setSupportedPrimitives(PRIMITIVE_CLICK);
        mVibratorProviders.get(VIBRATOR_ID).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL,
                IVibrator.CAP_COMPOSE_EFFECTS);

        // A simple effect, followed by a repeating effect that gets cancelled, followed by another
        // simple effect.
        VibrationEffect effect1 = VibrationEffect.get(EFFECT_CLICK);
        VibrationEffect effect2 = VibrationEffect.startComposition()
                .repeatEffectIndefinitely(VibrationEffect.get(EFFECT_TICK))
                .compose();
        VibrationEffect effect3 = VibrationEffect.startComposition()
                .addPrimitive(PRIMITIVE_CLICK)
                .compose();
        VibrationEffect effect4 = VibrationEffect.createOneShot(8000, 100);
        VibrationEffect effect5 = VibrationEffect.get(EFFECT_CLICK);

        HalVibration vibration1 = startThreadAndDispatcher(effect1);
        waitForCompletion();

        HalVibration vibration2 = startThreadAndDispatcher(effect2);
        // Effect2 won't complete on its own. Cancel it after a couple of repeats.
        Thread.sleep(150);  // More than two TICKs.
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_USER), /* immediate= */ false);
        waitForCompletion();

        HalVibration vibration3 = startThreadAndDispatcher(effect3);
        waitForCompletion();

        // Effect4 is a long oneshot, but it gets cancelled as fast as possible.
        long start4 = System.currentTimeMillis();
        HalVibration vibration4 = startThreadAndDispatcher(effect4);
        mVibrationConductor.notifyCancelled(
                new Vibration.EndInfo(Status.CANCELLED_BY_SCREEN_OFF), /* immediate= */ true);
        waitForCompletion();
        long duration4 = System.currentTimeMillis() - start4;

        // Effect5 is to show that things keep going after the immediate cancel.
        HalVibration vibration5 = startThreadAndDispatcher(effect5);
        waitForCompletion();

        FakeVibratorControllerProvider fakeVibrator = mVibratorProviders.get(VIBRATOR_ID);
        assertThat(mControllers.get(VIBRATOR_ID).isVibrating()).isFalse();

        // Effect1
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration1.id), anyLong());
        verifyCallbacksTriggered(vibration1, Status.FINISHED);

        assertThat(fakeVibrator.getEffectSegments(vibration1.id))
                .containsExactly(expectedPrebaked(EFFECT_CLICK)).inOrder();

        // Effect2: repeating, cancelled.
        verify(mControllerCallbacks, atLeast(2))
                .onComplete(eq(VIBRATOR_ID), eq(vibration2.id), anyLong());
        verifyCallbacksTriggered(vibration2, Status.CANCELLED_BY_USER);

        // The exact count of segments might vary, so just check that there's more than 2 and
        // all elements are the same segment.
        List<VibrationEffectSegment> actualSegments2 =
                fakeVibrator.getEffectSegments(vibration2.id);
        assertThat(actualSegments2.size()).isGreaterThan(2);
        for (VibrationEffectSegment segment : actualSegments2) {
            assertThat(segment).isEqualTo(expectedPrebaked(EFFECT_TICK));
        }

        // Effect3
        verify(mControllerCallbacks).onComplete(eq(VIBRATOR_ID), eq(vibration3.id), anyLong());
        verifyCallbacksTriggered(vibration3, Status.FINISHED);
        assertThat(fakeVibrator.getEffectSegments(vibration3.id))
                .containsExactly(expectedPrimitive(PRIMITIVE_CLICK, 1, 0)).inOrder();

        // Effect4: cancelled quickly.
        verifyCallbacksTriggered(vibration4, Status.CANCELLED_BY_SCREEN_OFF);
        assertThat(duration4).isLessThan(2000);

        // Effect5: played normally after effect4, which may or may not have played.
        assertThat(fakeVibrator.getEffectSegments(vibration5.id))
                .containsExactly(expectedPrebaked(EFFECT_CLICK)).inOrder();
    }

    @EnableFlags(Flags.FLAG_FIX_VIBRATION_THREAD_CALLBACK_HANDLING)
    @Test
    public void vibrate_multipleVibratorsSequentialInSession_runsInOrderWithoutDelaysAndNoOffs() {
        mockVibrators(1, 2, 3);
        mVibratorProviders.get(1).setCapabilities(IVibrator.CAP_AMPLITUDE_CONTROL);
        mVibratorProviders.get(2).setCapabilities(IVibrator.CAP_COMPOSE_EFFECTS);
        mVibratorProviders.get(2).setSupportedPrimitives(PRIMITIVE_CLICK);
        mVibratorProviders.get(3).setSupportedEffects(EFFECT_CLICK);

        CombinedVibration effect = CombinedVibration.startSequential()
                .addNext(3, VibrationEffect.get(EFFECT_CLICK), /* delay= */ TEST_TIMEOUT_MILLIS)
                .addNext(1,
                        VibrationEffect.createWaveform(
                                new long[] {TEST_TIMEOUT_MILLIS, TEST_TIMEOUT_MILLIS}, -1),
                        /* delay= */ TEST_TIMEOUT_MILLIS)
                .addNext(2,
                        VibrationEffect.startComposition()
                                .addPrimitive(PRIMITIVE_CLICK, 1, /* delay= */ TEST_TIMEOUT_MILLIS)
                                .compose(),
                        /* delay= */ TEST_TIMEOUT_MILLIS)
                .combine();
        HalVibration vibration = startThreadAndDispatcher(effect, /* isInSession= */ true);

        // Should not timeout as delays will not affect in session playback time.
        waitForCompletion();

        // Vibrating state remains ON until session resets it.
        verifyCallbacksTriggered(vibration, Status.FINISHED);
        assertThat(mControllers.get(1).isVibrating()).isTrue();
        assertThat(mControllers.get(2).isVibrating()).isTrue();
        assertThat(mControllers.get(3).isVibrating()).isTrue();

        assertThat(mVibratorProviders.get(1).getOffCount()).isEqualTo(0);
        assertThat(mVibratorProviders.get(2).getOffCount()).isEqualTo(0);
        assertThat(mVibratorProviders.get(3).getOffCount()).isEqualTo(0);
        assertThat(mVibratorProviders.get(1).getEffectSegments(vibration.id))
                .containsExactly(expectedOneShot(TEST_TIMEOUT_MILLIS)).inOrder();
        assertThat(mVibratorProviders.get(1).getAmplitudes())
                .containsExactlyElementsIn(expectedAmplitudes(255)).inOrder();
        assertThat(mVibratorProviders.get(2).getEffectSegments(vibration.id))
                .containsExactly(expectedPrimitive(PRIMITIVE_CLICK, 1, TEST_TIMEOUT_MILLIS))
                .inOrder();
        assertThat(mVibratorProviders.get(3).getEffectSegments(vibration.id))
                .containsExactly(expectedPrebaked(EFFECT_CLICK)).inOrder();
    }

    private void mockVibrators(int... vibratorIds) {
        for (int vibratorId : vibratorIds) {
            mVibratorProviders.put(vibratorId,
                    new FakeVibratorControllerProvider(mTestLooper.getLooper()));
        }
    }

    private void setUserSetting(String settingName, int value) {
        Settings.System.putIntForUser(
                mContextSpy.getContentResolver(), settingName, value, UserHandle.USER_CURRENT);
        // FakeSettingsProvider doesn't support testing triggering ContentObserver yet.
        mVibrationSettings.mSettingObserver.onChange(false);
    }

    private HalVibration startThreadAndDispatcher(VibrationEffect effect) {
        return startThreadAndDispatcher(CombinedVibration.createParallel(effect));
    }

    private HalVibration startThreadAndDispatcher(CombinedVibration effect) {
        return startThreadAndDispatcher(createVibration(effect));
    }

    private HalVibration startThreadAndDispatcher(CombinedVibration effect, boolean isInSession) {
        return startThreadAndDispatcher(createVibration(effect), isInSession,
                /* requestVibrationParamsFuture= */ null);
    }

    private HalVibration startThreadAndDispatcher(HalVibration vib) {
        return startThreadAndDispatcher(vib, /* isInSession= */ false,
                /* requestVibrationParamsFuture= */ null);
    }

    private HalVibration startThreadAndDispatcher(VibrationEffect effect,
            CompletableFuture<Void> requestVibrationParamsFuture, int usage) {
        VibrationAttributes attrs = new VibrationAttributes.Builder()
                .setUsage(usage)
                .build();
        HalVibration vib = new HalVibration(
                new CallerInfo(attrs, UID, DEVICE_ID, PACKAGE_NAME, "reason"),
                CombinedVibration.createParallel(effect));
        return startThreadAndDispatcher(vib, /* isInSession= */ false,
                requestVibrationParamsFuture);
    }

    private HalVibration startThreadAndDispatcher(HalVibration vib, boolean isInSession,
            CompletableFuture<Void> requestVibrationParamsFuture) {
        mControllers = createVibratorControllers();
        DeviceAdapter deviceAdapter = new DeviceAdapter(mVibrationSettings, mControllers);
        mVibrationConductor = new VibrationStepConductor(vib, isInSession, mVibrationSettings,
                deviceAdapter, mVibrationScaler, mStatsLoggerMock, requestVibrationParamsFuture,
                mManagerHooks);
        assertThat(mThread.runVibrationOnVibrationThread(mVibrationConductor)).isTrue();
        return mVibrationConductor.getVibration();
    }

    private boolean waitUntil(BooleanSupplier predicate, long timeout)
            throws InterruptedException {
        long timeoutTimestamp = SystemClock.uptimeMillis() + timeout;
        boolean predicateResult = false;
        while (!predicateResult && SystemClock.uptimeMillis() < timeoutTimestamp) {
            Thread.sleep(10);
            predicateResult = predicate.getAsBoolean();
        }
        return predicateResult;
    }

    private void waitForCompletion() {
        waitForCompletion(TEST_TIMEOUT_MILLIS);
    }

    private void waitForCompletion(long timeout) {
        assertWithMessage("Timed out waiting for VibrationThread to become idle")
                .that(mThread.waitForThreadIdle(timeout)).isTrue();
        mTestLooper.dispatchAll();  // Flush callbacks
    }

    private HalVibration createVibration(CombinedVibration effect) {
        return new HalVibration(new CallerInfo(ATTRS, UID, DEVICE_ID, PACKAGE_NAME, "reason"),
                effect);
    }

    private SparseArray<VibratorController> createVibratorControllers() {
        SparseArray<VibratorController> array = new SparseArray<>();
        for (Map.Entry<Integer, FakeVibratorControllerProvider> e : mVibratorProviders.entrySet()) {
            int id = e.getKey();
            array.put(id, e.getValue().newVibratorController(id, mControllerCallbacks));
        }
        // Start a looper for the vibrationcontrollers if it's not already running.
        // TestLooper.AutoDispatchThread has a fixed 1s duration. Use a custom auto-dispatcher.
        if (mCustomTestLooperDispatcher == null) {
            mCustomTestLooperDispatcher = new TestLooperAutoDispatcher(mTestLooper);
            mCustomTestLooperDispatcher.start();
        }
        return array;
    }

    private static PersistableBundle createTestVendorData() {
        PersistableBundle vendorData = new PersistableBundle();
        vendorData.putInt("id", 1);
        vendorData.putDouble("scale", 0.5);
        vendorData.putBoolean("loop", false);
        vendorData.putLongArray("amplitudes", new long[] { 0, 255, 128 });
        vendorData.putString("label", "vibration");
        return vendorData;
    }

    private VibrationEffectSegment expectedOneShot(long millis) {
        return new StepSegment(VibrationEffect.DEFAULT_AMPLITUDE,
                /* frequencyHz= */ 0, (int) millis);
    }

    private List<VibrationEffectSegment> expectedOneShots(long... millis) {
        return Arrays.stream(millis)
                .mapToObj(this::expectedOneShot)
                .collect(Collectors.toList());
    }

    private VibrationEffectSegment expectedPrebaked(int effectId) {
        return new PrebakedSegment(effectId, false, VibrationEffect.EFFECT_STRENGTH_MEDIUM);
    }

    private VibrationEffectSegment expectedPrimitive(int primitiveId, float scale, int delay) {
        return new PrimitiveSegment(primitiveId, scale, delay);
    }

    private VibrationEffectSegment expectedRamp(float amplitude, float frequencyHz, int duration) {
        return expectedRamp(amplitude, amplitude, frequencyHz, frequencyHz, duration);
    }

    private VibrationEffectSegment expectedRamp(float startAmplitude, float endAmplitude,
            float startFrequencyHz, float endFrequencyHz, int duration) {
        return new RampSegment(startAmplitude, endAmplitude, startFrequencyHz, endFrequencyHz,
                duration);
    }

    private PwlePoint expectedPwle(float amplitude, float frequencyHz, int timeMillis) {
        return new PwlePoint(amplitude, frequencyHz, timeMillis);
    }

    private List<Float> expectedAmplitudes(int... amplitudes) {
        return Arrays.stream(amplitudes)
                .mapToObj(amplitude -> amplitude / 255f)
                .collect(Collectors.toList());
    }

    private void verifyCallbacksTriggered(HalVibration vibration, Status expectedStatus) {
        assertThat(vibration.getStatus()).isEqualTo(expectedStatus);
        verify(mManagerHooks).onVibrationThreadReleased(eq(vibration.id));
    }

    private static final class TestLooperAutoDispatcher extends Thread {
        private final TestLooper mTestLooper;
        private boolean mCancelled;

        TestLooperAutoDispatcher(TestLooper testLooper) {
            mTestLooper = testLooper;
        }

        @Override
        public void run() {
            while (!mCancelled) {
                mTestLooper.dispatchAll();
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }

        public void cancel() {
            mCancelled = true;
        }
    }
}
