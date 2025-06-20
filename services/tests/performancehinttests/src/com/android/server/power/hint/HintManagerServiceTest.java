/*
 * Copyright (C) 2021 The Android Open Source Project
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

package com.android.server.power.hint;


import static com.android.server.power.hint.HintManagerService.CLEAN_UP_UID_DELAY_MILLIS;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.annotation.NonNull;
import android.app.ActivityManager;
import android.app.ActivityManagerInternal;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.hardware.common.fmq.MQDescriptor;
import android.hardware.power.ChannelConfig;
import android.hardware.power.ChannelMessage;
import android.hardware.power.CpuHeadroomParams;
import android.hardware.power.CpuHeadroomResult;
import android.hardware.power.GpuHeadroomParams;
import android.hardware.power.GpuHeadroomResult;
import android.hardware.power.IPower;
import android.hardware.power.SessionConfig;
import android.hardware.power.SessionTag;
import android.hardware.power.SupportInfo;
import android.hardware.power.WorkDuration;
import android.os.Binder;
import android.os.CpuHeadroomParamsInternal;
import android.os.GpuHeadroomParamsInternal;
import android.os.IBinder;
import android.os.IHintManager;
import android.os.IHintSession;
import android.os.PerformanceHintManager;
import android.os.Process;
import android.os.RemoteException;
import android.os.SessionCreationConfig;
import android.platform.test.annotations.RequiresFlagsEnabled;
import android.platform.test.flag.junit.CheckFlagsRule;
import android.platform.test.flag.junit.DeviceFlagsValueProvider;
import android.platform.test.flag.junit.SetFlagsRule;
import android.util.Log;

import androidx.test.InstrumentationRegistry;

import com.android.server.FgThread;
import com.android.server.LocalServices;
import com.android.server.power.hint.HintManagerService.AppHintSession;
import com.android.server.power.hint.HintManagerService.Injector;
import com.android.server.power.hint.HintManagerService.NativeWrapper;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/**
 * Tests for {@link com.android.server.power.hint.HintManagerService}.
 *
 * Build/Install/Run:
 * atest FrameworksServicesTests:HintManagerServiceTest
 */
public class HintManagerServiceTest {
    private static final String TAG = "HintManagerServiceTest";
    private List<File> mFilesCreated = new ArrayList<>();

    private static WorkDuration makeWorkDuration(
            long timestamp, long duration, long workPeriodStartTime,
            long cpuDuration, long gpuDuration) {
        WorkDuration out = new WorkDuration();
        out.timeStampNanos = timestamp;
        out.durationNanos = duration;
        out.workPeriodStartTimestampNanos = workPeriodStartTime;
        out.cpuDurationNanos = cpuDuration;
        out.gpuDurationNanos = gpuDuration;
        return out;
    }

    private static final long DEFAULT_HINT_PREFERRED_RATE = 16666666L;
    private static final long DEFAULT_TARGET_DURATION = 16666666L;
    private static final long DOUBLED_TARGET_DURATION = 33333333L;
    private static final long CONCURRENCY_TEST_DURATION_SEC = 10;
    private static final int UID = Process.myUid();
    private static final int TID = Process.myPid();
    private static final int TGID = Process.getThreadGroupLeader(TID);
    private static final int[] SESSION_TIDS_A = new int[] {TID};
    private static final int[] SESSION_TIDS_B = new int[] {TID};
    private static final int[] SESSION_TIDS_C = new int[] {TID};
    private static final long[] DURATIONS_THREE = new long[] {1L, 100L, 1000L};
    private static final long[] TIMESTAMPS_THREE = new long[] {1L, 2L, 3L};
    private static final long[] SESSION_PTRS = new long[] {11L, 22L, 33L};
    private static final long[] SESSION_IDS = new long[] {1L, 11L, 111L};
    private static final long[] DURATIONS_ZERO = new long[] {};
    private static final long[] TIMESTAMPS_ZERO = new long[] {};
    private static final long[] TIMESTAMPS_TWO = new long[] {1L, 2L};
    private static final WorkDuration[] WORK_DURATIONS_FIVE = new WorkDuration[] {
            makeWorkDuration(1L, 11L, 1L, 8L, 4L),
            makeWorkDuration(2L, 13L, 2L, 8L, 6L),
            makeWorkDuration(3L, 333333333L, 3L, 8L, 333333333L),
            makeWorkDuration(2L, 13L, 2L, 0L, 6L),
            makeWorkDuration(2L, 13L, 2L, 8L, 0L),
    };
    private static final String TEST_APP_NAME = "com.android.test.app";

    @Mock
    private Context mContext;
    @Mock
    private HintManagerService.NativeWrapper mNativeWrapperMock;
    @Mock
    private IPower mIPowerMock;
    @Mock
    private ActivityManagerInternal mAmInternalMock;
    @Mock
    private PackageManager mMockPackageManager;
    @Mock
    private IHintManager.IHintManagerClient mClientCallback;
    @Rule
    public final CheckFlagsRule mCheckFlagsRule =
            DeviceFlagsValueProvider.createCheckFlagsRule();
    @Rule
    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();

    private HintManagerService mService;
    private ChannelConfig mConfig;
    private SupportInfo mSupportInfo;

    private static Answer<Long> fakeCreateWithConfig(Long ptr, Long sessionId) {
        return new Answer<Long>() {
            public Long answer(InvocationOnMock invocation) {
                ((SessionConfig) invocation.getArguments()[5]).id = sessionId;
                return ptr;
            }
        };
    }

    private SupportInfo makeDefaultSupportInfo() {
        mSupportInfo = new SupportInfo();
        mSupportInfo.usesSessions = true;
        // By default, mark everything as fully supported
        mSupportInfo.sessionHints = -1;
        mSupportInfo.sessionModes = -1;
        mSupportInfo.modes = -1;
        mSupportInfo.boosts = -1;
        mSupportInfo.sessionTags = -1;
        mSupportInfo.headroom = new SupportInfo.HeadroomSupportInfo();
        mSupportInfo.headroom.isCpuSupported = true;
        mSupportInfo.headroom.cpuMinIntervalMillis = 1000;
        mSupportInfo.headroom.isGpuSupported = true;
        mSupportInfo.headroom.gpuMinIntervalMillis = 1000;
        mSupportInfo.compositionData = new SupportInfo.CompositionDataSupportInfo();
        return mSupportInfo;
    }

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        mConfig = new ChannelConfig();
        mConfig.readFlagBitmask = 1;
        mConfig.writeFlagBitmask = 2;
        mConfig.channelDescriptor = new MQDescriptor<ChannelMessage, Byte>();
        mConfig.eventFlagDescriptor = new MQDescriptor<Byte, Byte>();
        ApplicationInfo applicationInfo = new ApplicationInfo();
        applicationInfo.category = ApplicationInfo.CATEGORY_GAME;
        mSupportInfo = makeDefaultSupportInfo();
        when(mContext.getPackageManager()).thenReturn(mMockPackageManager);
        when(mMockPackageManager.getNameForUid(anyInt())).thenReturn(TEST_APP_NAME);
        when(mMockPackageManager.getApplicationInfo(eq(TEST_APP_NAME), anyInt()))
                .thenReturn(applicationInfo);
        when(mNativeWrapperMock.halGetHintSessionPreferredRate())
                .thenReturn(DEFAULT_HINT_PREFERRED_RATE);
        when(mNativeWrapperMock.halCreateHintSession(eq(TGID), eq(UID), eq(SESSION_TIDS_A),
                eq(DEFAULT_TARGET_DURATION))).thenReturn(SESSION_PTRS[0]);
        when(mNativeWrapperMock.halCreateHintSession(eq(TGID), eq(UID), eq(SESSION_TIDS_B),
                eq(DOUBLED_TARGET_DURATION))).thenReturn(SESSION_PTRS[1]);
        when(mNativeWrapperMock.halCreateHintSession(eq(TGID), eq(UID), eq(SESSION_TIDS_C),
                eq(0L))).thenReturn(SESSION_PTRS[2]);
        when(mNativeWrapperMock.halCreateHintSessionWithConfig(eq(TGID), eq(UID),
                eq(SESSION_TIDS_A), eq(DEFAULT_TARGET_DURATION), anyInt(),
                any(SessionConfig.class))).thenAnswer(fakeCreateWithConfig(SESSION_PTRS[0],
                SESSION_IDS[0]));
        when(mNativeWrapperMock.halCreateHintSessionWithConfig(eq(TGID), eq(UID),
                eq(SESSION_TIDS_B), eq(DOUBLED_TARGET_DURATION), anyInt(),
                any(SessionConfig.class))).thenAnswer(fakeCreateWithConfig(SESSION_PTRS[1],
                SESSION_IDS[1]));
        when(mNativeWrapperMock.halCreateHintSessionWithConfig(eq(TGID), eq(UID),
                eq(SESSION_TIDS_C), eq(0L), anyInt(),
                any(SessionConfig.class))).thenAnswer(fakeCreateWithConfig(SESSION_PTRS[2],
                    SESSION_IDS[2]));

        when(mIPowerMock.getInterfaceVersion()).thenReturn(6);
        when(mIPowerMock.getSupportInfo()).thenReturn(mSupportInfo);
        when(mIPowerMock.getSessionChannel(anyInt(), anyInt())).thenReturn(mConfig);
        when(mIPowerMock.getSupportInfo()).thenReturn(mSupportInfo);
        LocalServices.removeServiceForTest(ActivityManagerInternal.class);
        LocalServices.addService(ActivityManagerInternal.class, mAmInternalMock);
    }

    @After
    public void tearDown() {
        for (File file : mFilesCreated) {
            file.delete();
        }
    }

    /**
     * Mocks the creation calls, but without support for new createHintSessionWithConfig method
     */
    public void makeConfigCreationUnsupported() {
        reset(mNativeWrapperMock);
        when(mNativeWrapperMock.halGetHintSessionPreferredRate())
                .thenReturn(DEFAULT_HINT_PREFERRED_RATE);
        when(mNativeWrapperMock.halCreateHintSession(eq(TGID), eq(UID), eq(SESSION_TIDS_A),
                eq(DEFAULT_TARGET_DURATION))).thenReturn(SESSION_PTRS[0]);
        when(mNativeWrapperMock.halCreateHintSession(eq(TGID), eq(UID), eq(SESSION_TIDS_B),
                eq(DOUBLED_TARGET_DURATION))).thenReturn(SESSION_PTRS[1]);
        when(mNativeWrapperMock.halCreateHintSession(eq(TGID), eq(UID), eq(SESSION_TIDS_C),
                eq(0L))).thenReturn(SESSION_PTRS[2]);
        when(mNativeWrapperMock.halCreateHintSessionWithConfig(anyInt(), anyInt(),
                any(int[].class), anyLong(), anyInt(),
                any(SessionConfig.class))).thenThrow(new UnsupportedOperationException());
    }

    static class NativeWrapperFake extends NativeWrapper {
        @Override
        public void halInit() {
        }

        @Override
        public long halGetHintSessionPreferredRate() {
            return 1;
        }

        @Override
        public long halCreateHintSession(int tgid, int uid, int[] tids, long durationNanos) {
            return 1;
        }

        @Override
        public long halCreateHintSessionWithConfig(int tgid, int uid, int[] tids,
                long durationNanos, int tag, SessionConfig config) {
            return 1;
        }

        @Override
        public void halPauseHintSession(long halPtr) {
        }

        @Override
        public void halResumeHintSession(long halPtr) {
        }

        @Override
        public void halCloseHintSession(long halPtr) {
        }

        @Override
        public void halUpdateTargetWorkDuration(long halPtr, long targetDurationNanos) {
        }

        @Override
        public void halReportActualWorkDuration(
                long halPtr, long[] actualDurationNanos, long[] timeStampNanos) {
        }

        @Override
        public void halSendHint(long halPtr, int hint) {
        }

        @Override
        public void halSetThreads(long halPtr, int[] tids) {
        }

        @Override
        public void halSetMode(long halPtr, int mode, boolean enabled) {
        }
    }

    private HintManagerService createService() {
        mService = new HintManagerService(mContext, new Injector() {
            NativeWrapper createNativeWrapper() {
                return mNativeWrapperMock;
            }
            IPower createIPower() {
                return mIPowerMock;
            }
        });
        return mService;
    }

    private HintManagerService createServiceWithFakeWrapper() {
        mService = new HintManagerService(mContext, new Injector() {
            NativeWrapper createNativeWrapper() {
                return new NativeWrapperFake();
            }
            IPower createIPower() {
                return mIPowerMock;
            }
        });
        return mService;
    }

    private SessionCreationConfig makeSessionCreationConfig(int[] tids,
            long targetWorkDurationNanos) {
        SessionCreationConfig config = new SessionCreationConfig();
        config.tids = tids;
        config.targetWorkDurationNanos = targetWorkDurationNanos;
        return config;
    }

    @Test
    public void testInitializeService() {
        HintManagerService service = createService();
        verify(mNativeWrapperMock).halInit();
        assertThat(service.mHintSessionPreferredRate).isEqualTo(DEFAULT_HINT_PREFERRED_RATE);
    }

    @Test
    public void testCreateHintSessionInvalidPid() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(new int[]{TID, 1}, DEFAULT_TARGET_DURATION);
        // Make sure we throw exception when adding a TID doesn't belong to the processes
        // In this case, we add `init` PID into the list.
        SessionConfig config = new SessionConfig();
        assertThrows(SecurityException.class,
                () -> service.getBinderServiceInstance().createHintSessionWithConfig(token,
                        SessionTag.OTHER, creationConfig, config));
    }

    @Test
    public void testCreateHintSessionFallback() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        makeConfigCreationUnsupported();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        IHintSession a = service.getBinderServiceInstance().createHintSessionWithConfig(token,
                SessionTag.OTHER, creationConfig, new SessionConfig()).session;
        assertNotNull(a);

        creationConfig.tids = SESSION_TIDS_B;
        creationConfig.targetWorkDurationNanos = DOUBLED_TARGET_DURATION;
        IHintSession b = service.getBinderServiceInstance().createHintSessionWithConfig(token,
                SessionTag.OTHER, creationConfig, new SessionConfig()).session;
        assertNotEquals(a, b);

        creationConfig.tids = SESSION_TIDS_C;
        creationConfig.targetWorkDurationNanos = 0L;
        IHintSession c = service.getBinderServiceInstance().createHintSessionWithConfig(token,
                SessionTag.OTHER, creationConfig, new SessionConfig()).session;
        assertNotNull(c);
        verify(mNativeWrapperMock, times(3)).halCreateHintSession(anyInt(), anyInt(),
                any(int[].class), anyLong());
    }

    @Test
    public void testCreateHintSessionWithConfig() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        SessionConfig config = new SessionConfig();
        IHintSession a = service.getBinderServiceInstance().createHintSessionWithConfig(token,
                SessionTag.OTHER, creationConfig, config).session;
        assertNotNull(a);
        assertEquals(SESSION_IDS[0], config.id);

        SessionConfig config2 = new SessionConfig();
        creationConfig.tids = SESSION_TIDS_B;
        creationConfig.targetWorkDurationNanos = DOUBLED_TARGET_DURATION;
        IHintSession b = service.getBinderServiceInstance().createHintSessionWithConfig(token,
                SessionTag.APP, creationConfig, config2).session;
        assertNotEquals(a, b);
        assertEquals(SESSION_IDS[1], config2.id);

        SessionConfig config3 = new SessionConfig();
        creationConfig.tids = SESSION_TIDS_C;
        creationConfig.targetWorkDurationNanos = 0L;
        IHintSession c = service.getBinderServiceInstance().createHintSessionWithConfig(token,
                SessionTag.GAME, creationConfig, config3).session;
        assertNotNull(c);
        assertEquals(SESSION_IDS[2], config3.id);
        verify(mNativeWrapperMock, times(3)).halCreateHintSessionWithConfig(anyInt(), anyInt(),
                any(int[].class), anyLong(), anyInt(), any(SessionConfig.class));
    }

    @Test
    public void testCreateGraphicsPipelineSessions() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();

        IHintManager.HintManagerClientData data = service.getBinderServiceInstance()
                .registerClient(mClientCallback);

        final int threadCount = data.maxGraphicsPipelineThreads;

        long sessionPtr1 = 1111L;
        long sessionId1 = 11111L;
        CountDownLatch stopLatch1 = new CountDownLatch(1);
        int[] tids1 = createThreads(threadCount, stopLatch1);
        when(mNativeWrapperMock.halCreateHintSessionWithConfig(eq(TGID), eq(UID), eq(tids1),
                eq(DEFAULT_TARGET_DURATION), anyInt(), any(SessionConfig.class)))
                .thenAnswer(fakeCreateWithConfig(sessionPtr1, sessionId1));
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(tids1, DEFAULT_TARGET_DURATION);

        creationConfig.modesToEnable = new int[] {1}; // GRAPHICS_PIPELINE

        SessionConfig config = new SessionConfig();
        IHintSession a = service.getBinderServiceInstance().createHintSessionWithConfig(token,
                SessionTag.OTHER, creationConfig, config).session;
        assertNotNull(a);
        assertEquals(sessionId1, config.id);

        creationConfig.tids = createThreads(1, stopLatch1);

        assertEquals(service.getBinderServiceInstance().createHintSessionWithConfig(token,
                    SessionTag.OTHER, creationConfig, config).pipelineThreadLimitExceeded, true);
    }

    @Test
    public void testPauseResumeHintSession() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        // Set session to background and calling updateHintAllowedByProcState() would invoke
        // pause();
        service.mUidObserver.onUidStateChanged(
                a.mUid, ActivityManager.PROCESS_STATE_TRANSIENT_BACKGROUND, 0, 0);

        // Using CountDownLatch to ensure above onUidStateChanged() job was digested.
        final CountDownLatch latch = new CountDownLatch(1);
        FgThread.getHandler().post(() -> {
            latch.countDown();
        });
        latch.await();
        assertFalse(service.mUidObserver.isUidForeground(a.mUid));
        verify(mNativeWrapperMock, times(1)).halPauseHintSession(anyLong());

        // Set session to foreground and calling updateHintAllowedByProcState() would invoke
        // resume();
        service.mUidObserver.onUidStateChanged(
                a.mUid, ActivityManager.PROCESS_STATE_IMPORTANT_FOREGROUND, 0, 0);

        // Using CountDownLatch to ensure above onUidStateChanged() job was digested.
        final CountDownLatch latch2 = new CountDownLatch(1);
        FgThread.getHandler().post(() -> {
            latch2.countDown();
        });
        latch2.await();

        assertTrue(service.mUidObserver.isUidForeground(a.mUid));
        verify(mNativeWrapperMock, times(1)).halResumeHintSession(anyLong());
    }

    @Test
    public void testCloseHintSession() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        IHintSession a = service.getBinderServiceInstance().createHintSessionWithConfig(token,
                SessionTag.OTHER, creationConfig, new SessionConfig()).session;

        a.close();
        verify(mNativeWrapperMock, times(1)).halCloseHintSession(anyLong());
    }

    @Test
    public void testUpdateTargetWorkDuration() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        IHintSession a = service.getBinderServiceInstance().createHintSessionWithConfig(token,
                SessionTag.OTHER, creationConfig, new SessionConfig()).session;

        assertThrows(IllegalArgumentException.class, () -> {
            a.updateTargetWorkDuration(-1L);
        });

        a.updateTargetWorkDuration(100L);
        verify(mNativeWrapperMock, times(1)).halUpdateTargetWorkDuration(anyLong(), eq(100L));
    }

    @Test
    public void testReportActualWorkDuration() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        a.updateTargetWorkDuration(100L);
        a.reportActualWorkDuration(DURATIONS_THREE, TIMESTAMPS_THREE);
        verify(mNativeWrapperMock, times(1)).halReportActualWorkDuration(anyLong(),
                eq(DURATIONS_THREE), eq(TIMESTAMPS_THREE));

        assertThrows(IllegalArgumentException.class, () -> {
            a.reportActualWorkDuration(DURATIONS_ZERO, TIMESTAMPS_THREE);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            a.reportActualWorkDuration(DURATIONS_THREE, TIMESTAMPS_ZERO);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            a.reportActualWorkDuration(DURATIONS_THREE, TIMESTAMPS_TWO);
        });

        reset(mNativeWrapperMock);
        // Set session to background, then the duration would not be updated.
        service.mUidObserver.onUidStateChanged(
                a.mUid, ActivityManager.PROCESS_STATE_TRANSIENT_BACKGROUND, 0, 0);

        // Using CountDownLatch to ensure above onUidStateChanged() job was digested.
        final CountDownLatch latch = new CountDownLatch(1);
        FgThread.getHandler().post(() -> {
            latch.countDown();
        });
        latch.await();

        assertFalse(service.mUidObserver.isUidForeground(a.mUid));
        a.reportActualWorkDuration(DURATIONS_THREE, TIMESTAMPS_THREE);
        verify(mNativeWrapperMock, never()).halReportActualWorkDuration(anyLong(), any(), any());
    }

    @Test
    public void testSendHint() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        a.sendHint(PerformanceHintManager.Session.CPU_LOAD_RESET);
        verify(mNativeWrapperMock, times(1)).halSendHint(anyLong(),
                eq(PerformanceHintManager.Session.CPU_LOAD_RESET));

        assertThrows(IllegalArgumentException.class, () -> {
            a.sendHint(-1);
        });

        reset(mNativeWrapperMock);
        // Set session to background, then the duration would not be updated.
        service.mUidObserver.onUidStateChanged(
                a.mUid, ActivityManager.PROCESS_STATE_TRANSIENT_BACKGROUND, 0, 0);
        FgThread.getHandler().runWithScissors(() -> { }, 500);
        assertFalse(service.mUidObserver.isUidForeground(a.mUid));
        a.sendHint(PerformanceHintManager.Session.CPU_LOAD_RESET);
        verify(mNativeWrapperMock, never()).halSendHint(anyLong(), anyInt());
    }

    @Test
    public void testDoHintInBackground() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        service.mUidObserver.onUidStateChanged(
                a.mUid, ActivityManager.PROCESS_STATE_IMPORTANT_BACKGROUND, 0, 0);

        // Using CountDownLatch to ensure above onUidStateChanged() job was digested.
        final CountDownLatch latch = new CountDownLatch(1);
        FgThread.getHandler().post(() -> {
            latch.countDown();
        });
        latch.await();

        assertFalse(service.mUidObserver.isUidForeground(a.mUid));
    }

    @Test
    public void testDoHintInForeground() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        service.mUidObserver.onUidStateChanged(
                a.mUid, ActivityManager.PROCESS_STATE_IMPORTANT_FOREGROUND, 0, 0);
        assertTrue(service.mUidObserver.isUidForeground(a.mUid));
    }

    @Test
    public void testSetThreads() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        a.updateTargetWorkDuration(100L);

        assertThrows(IllegalArgumentException.class, () -> {
            a.setThreads(new int[]{});
        });

        a.setThreads(SESSION_TIDS_B);
        verify(mNativeWrapperMock, times(1)).halSetThreads(anyLong(), eq(SESSION_TIDS_B));
        assertArrayEquals(SESSION_TIDS_B, a.getThreadIds());

        reset(mNativeWrapperMock);
        // Set session to background, then the duration would not be updated.
        service.mUidObserver.onUidStateChanged(
                a.mUid, ActivityManager.PROCESS_STATE_TRANSIENT_BACKGROUND, 0, 0);
        FgThread.getHandler().runWithScissors(() -> { }, 500);
        assertFalse(service.mUidObserver.isUidForeground(a.mUid));
        a.setThreads(SESSION_TIDS_A);
        verify(mNativeWrapperMock, never()).halSetThreads(anyLong(), any());
    }

    @Test
    @RequiresFlagsEnabled(Flags.FLAG_POWERHINT_THREAD_CLEANUP)
    public void testNoCleanupDeadThreadsForPrevPowerHalVersion() throws Exception {
        reset(mIPowerMock);
        when(mIPowerMock.getInterfaceVersion()).thenReturn(3);
        HintManagerService service = createService();
        IBinder token = new Binder();
        int threadCount = 2;
        long sessionPtr1 = 111;
        CountDownLatch stopLatch1 = new CountDownLatch(1);
        int[] tids1 = createThreads(threadCount, stopLatch1);
        when(mNativeWrapperMock.halCreateHintSessionWithConfig(eq(TGID), eq(UID), eq(tids1),
                eq(DEFAULT_TARGET_DURATION), anyInt(), any(SessionConfig.class)))
                .thenReturn(sessionPtr1);
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(tids1, DEFAULT_TARGET_DURATION);
        AppHintSession session1 = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;
        assertNotNull(session1);

        // trigger UID state change by making the process foreground->background, but because the
        // power hal version is too low, this should result in no cleanup as setThreads don't fire.
        service.mUidObserver.onUidStateChanged(UID,
                ActivityManager.PROCESS_STATE_IMPORTANT_FOREGROUND, 0, 0);
        service.mUidObserver.onUidStateChanged(UID,
                ActivityManager.PROCESS_STATE_IMPORTANT_BACKGROUND, 0, 0);
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1000) + TimeUnit.MILLISECONDS.toNanos(
                CLEAN_UP_UID_DELAY_MILLIS));
        verify(mNativeWrapperMock, never()).halSetThreads(eq(sessionPtr1), any());
        reset(mNativeWrapperMock);
        // this should resume but not update the threads as no cleanup was performed
        service.mUidObserver.onUidStateChanged(UID,
                ActivityManager.PROCESS_STATE_IMPORTANT_FOREGROUND, 0, 0);
        verify(mNativeWrapperMock, never()).halSetThreads(eq(sessionPtr1), any());
    }


    @Test
    @RequiresFlagsEnabled(Flags.FLAG_POWERHINT_THREAD_CLEANUP)
    public void testCleanupDeadThreads() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        int threadCount = 2;

        long sessionPtr1 = 111;
        CountDownLatch stopLatch1 = new CountDownLatch(1);
        int[] tids1 = createThreads(threadCount, stopLatch1);
        when(mNativeWrapperMock.halCreateHintSessionWithConfig(eq(TGID), eq(UID), eq(tids1),
                eq(DEFAULT_TARGET_DURATION), anyInt(), any(SessionConfig.class)))
                .thenReturn(sessionPtr1);
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(tids1, DEFAULT_TARGET_DURATION);
        AppHintSession session1 = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;
        assertNotNull(session1);

        // let all session 1 threads to exit and the cleanup should force pause the session 1
        stopLatch1.countDown();
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(100));
        service.mUidObserver.onUidStateChanged(UID,
                ActivityManager.PROCESS_STATE_IMPORTANT_FOREGROUND, 0, 0);
        service.mUidObserver.onUidStateChanged(UID,
                ActivityManager.PROCESS_STATE_IMPORTANT_BACKGROUND, 0, 0);
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1000) + TimeUnit.MILLISECONDS.toNanos(
                CLEAN_UP_UID_DELAY_MILLIS));
        verify(mNativeWrapperMock, times(1)).halPauseHintSession(eq(sessionPtr1));
        verify(mNativeWrapperMock, never()).halSetThreads(eq(sessionPtr1), any());
        verifyAllHintsEnabled(session1, false);
        service.mUidObserver.onUidStateChanged(UID,
                ActivityManager.PROCESS_STATE_IMPORTANT_FOREGROUND, 0, 0);
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1000));
        assertArrayEquals(tids1, session1.getTidsInternal());
        verifyAllHintsEnabled(session1, false);
        reset(mNativeWrapperMock);

        // in foreground, set new tids for session 1 then it should be resumed and all hints allowed
        stopLatch1 = new CountDownLatch(1);
        tids1 = createThreads(threadCount, stopLatch1);
        session1.setThreads(tids1);
        verify(mNativeWrapperMock, times(1)).halSetThreads(eq(sessionPtr1), eq(tids1));
        verify(mNativeWrapperMock, times(1)).halResumeHintSession(eq(sessionPtr1));
        verifyAllHintsEnabled(session1, true);
        reset(mNativeWrapperMock);

        // let all session 1 and 2 non isolated threads to exit
        stopLatch1.countDown();
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(100));
        service.mUidObserver.onUidStateChanged(UID,
                ActivityManager.PROCESS_STATE_IMPORTANT_BACKGROUND, 0, 0);
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1000) + TimeUnit.MILLISECONDS.toNanos(
                CLEAN_UP_UID_DELAY_MILLIS));
        verify(mNativeWrapperMock, times(1)).halPauseHintSession(eq(sessionPtr1));
        verify(mNativeWrapperMock, never()).halSetThreads(eq(sessionPtr1), any());
        // in background, set threads for session 1 then it should not be force paused next time
        session1.setThreads(SESSION_TIDS_A);
        // the new TIDs pending list should be updated
        assertArrayEquals(SESSION_TIDS_A, session1.getTidsInternal());
        verifyAllHintsEnabled(session1, false);
        reset(mNativeWrapperMock);

        service.mUidObserver.onUidStateChanged(UID,
                ActivityManager.PROCESS_STATE_IMPORTANT_FOREGROUND, 0, 0);
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1000) + TimeUnit.MILLISECONDS.toNanos(
                CLEAN_UP_UID_DELAY_MILLIS));
        verify(mNativeWrapperMock, times(1)).halSetThreads(eq(sessionPtr1),
                eq(SESSION_TIDS_A));
        verifyAllHintsEnabled(session1, true);
    }

    private void verifyAllHintsEnabled(AppHintSession session, boolean verifyEnabled) {
        session.reportActualWorkDuration2(new WorkDuration[]{makeWorkDuration(1, 3, 2, 1, 1000)});
        session.reportActualWorkDuration(new long[]{1}, new long[]{2});
        session.updateTargetWorkDuration(3);
        session.setMode(0, true);
        session.sendHint(1);
        if (verifyEnabled) {
            verify(mNativeWrapperMock, times(1)).halReportActualWorkDuration(
                    eq(session.mHalSessionPtr), any());
            verify(mNativeWrapperMock, times(1)).halSetMode(eq(session.mHalSessionPtr), anyInt(),
                    anyBoolean());
            verify(mNativeWrapperMock, times(1)).halUpdateTargetWorkDuration(
                    eq(session.mHalSessionPtr), anyLong());
            verify(mNativeWrapperMock, times(1)).halSendHint(eq(session.mHalSessionPtr), anyInt());
        } else {
            verify(mNativeWrapperMock, never()).halReportActualWorkDuration(
                    eq(session.mHalSessionPtr), any());
            verify(mNativeWrapperMock, never()).halSetMode(eq(session.mHalSessionPtr), anyInt(),
                    anyBoolean());
            verify(mNativeWrapperMock, never()).halUpdateTargetWorkDuration(
                    eq(session.mHalSessionPtr), anyLong());
            verify(mNativeWrapperMock, never()).halSendHint(eq(session.mHalSessionPtr), anyInt());
        }
    }

    private int[] createThreads(int threadCount, CountDownLatch stopLatch)
            throws InterruptedException {
        int[] tids = new int[threadCount];
        AtomicInteger k = new AtomicInteger(0);
        CountDownLatch latch = new CountDownLatch(threadCount);
        for (int j = 0; j < threadCount; j++) {
            Thread thread = new Thread(() -> {
                try {
                    tids[k.getAndIncrement()] = android.os.Process.myTid();
                    latch.countDown();
                    stopLatch.await();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            });
            thread.start();
        }
        latch.await();
        return tids;
    }

    @Test
    public void testSetMode() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        a.setMode(0, true);
        verify(mNativeWrapperMock, times(1)).halSetMode(anyLong(),
                eq(0), eq(true));

        a.setMode(0, false);
        verify(mNativeWrapperMock, times(1)).halSetMode(anyLong(),
                eq(0), eq(false));
    }

    @Test
    public void testSetModeSessionInBackGround() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        // Set session to background, then the duration would not be updated.
        service.mUidObserver.onUidStateChanged(
                a.mUid, ActivityManager.PROCESS_STATE_TRANSIENT_BACKGROUND, 0, 0);
        FgThread.getHandler().runWithScissors(() -> {
        }, 500);
        assertFalse(service.mUidObserver.isUidForeground(a.mUid));
        a.setMode(0, true);
        verify(mNativeWrapperMock, never()).halSetMode(anyLong(), anyInt(), anyBoolean());
    }

    @Test
    public void testSetModeInvalid() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        assertThrows(IllegalArgumentException.class, () -> {
            a.setMode(-1, true);
        });
    }

    @Test
    public void testSetModeUponSessionCreation() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);
        creationConfig.modesToEnable = new int[] {0, 1};

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;
        assertNotNull(a);
        verify(mNativeWrapperMock, times(1)).halSetMode(anyLong(),
                eq(0), eq(true));
        verify(mNativeWrapperMock, times(1)).halSetMode(anyLong(),
                eq(1), eq(true));
    }

    @Test
    public void testGetChannel() throws Exception {
        HintManagerService service = createService();
        Binder token = new Binder();

        // Should only call once, after caching the first call
        ChannelConfig config = service.getBinderServiceInstance().getSessionChannel(token);
        ChannelConfig config2 = service.getBinderServiceInstance().getSessionChannel(token);
        verify(mIPowerMock, times(1)).getSessionChannel(eq(TGID), eq(UID));
        assertEquals(config.readFlagBitmask, mConfig.readFlagBitmask);
        assertEquals(config.writeFlagBitmask, mConfig.writeFlagBitmask);
        assertEquals(config2.readFlagBitmask, mConfig.readFlagBitmask);
        assertEquals(config2.writeFlagBitmask, mConfig.writeFlagBitmask);
    }

    @Test
    public void testGetChannelTwice() throws Exception {
        HintManagerService service = createService();
        Binder token = new Binder();

        service.getBinderServiceInstance().getSessionChannel(token);
        verify(mIPowerMock, times(1)).getSessionChannel(eq(TGID), eq(UID));
        service.getBinderServiceInstance().closeSessionChannel();
        verify(mIPowerMock, times(1)).closeSessionChannel(eq(TGID), eq(UID));

        clearInvocations(mIPowerMock);

        service.getBinderServiceInstance().getSessionChannel(token);
        verify(mIPowerMock, times(1)).getSessionChannel(eq(TGID), eq(UID));
        service.getBinderServiceInstance().closeSessionChannel();
        verify(mIPowerMock, times(1)).closeSessionChannel(eq(TGID), eq(UID));
    }

    @Test
    public void testGetChannelFails() throws Exception {
        HintManagerService service = createService();
        Binder token = new Binder();

        when(mIPowerMock.getSessionChannel(anyInt(), anyInt())).thenThrow(RemoteException.class);

        assertThrows(IllegalStateException.class, () -> {
            service.getBinderServiceInstance().getSessionChannel(token);
        });
    }


    @Test
    public void testGetChannelBadVersion() throws Exception {
        when(mIPowerMock.getInterfaceVersion()).thenReturn(3);
        HintManagerService service = createService();
        Binder token = new Binder();

        reset(mIPowerMock);
        when(mIPowerMock.getInterfaceVersion()).thenReturn(3);
        when(mIPowerMock.getSessionChannel(anyInt(), anyInt())).thenReturn(mConfig);

        ChannelConfig channel = service.getBinderServiceInstance().getSessionChannel(token);
        verify(mIPowerMock, times(0)).getSessionChannel(eq(TGID), eq(UID));
        assertNull(channel);
    }

    @Test
    public void testCloseChannel() throws Exception {
        HintManagerService service = createService();
        Binder token = new Binder();

        service.getBinderServiceInstance().getSessionChannel(token);
        service.getBinderServiceInstance().closeSessionChannel();
        verify(mIPowerMock, times(1)).closeSessionChannel(eq(TGID), eq(UID));
    }

    @Test
    public void testCloseChannelFails() throws Exception {
        HintManagerService service = createService();
        Binder token = new Binder();

        service.getBinderServiceInstance().getSessionChannel(token);

        doThrow(RemoteException.class).when(mIPowerMock).closeSessionChannel(anyInt(), anyInt());

        assertThrows(IllegalStateException.class, () -> {
            service.getBinderServiceInstance().closeSessionChannel();
        });
    }

    @Test
    public void testDoubleClose() throws Exception {
        HintManagerService service = createService();
        Binder token = new Binder();

        service.getBinderServiceInstance().getSessionChannel(token);
        service.getBinderServiceInstance().closeSessionChannel();
        service.getBinderServiceInstance().closeSessionChannel();
        verify(mIPowerMock, times(1)).closeSessionChannel(eq(TGID), eq(UID));
    }

    // This test checks that concurrent operations from different threads on IHintService,
    // IHintSession and UidObserver will not cause data race or deadlock. Ideally we should also
    // check the output of threads' reportActualDuration performance to detect lock starvation
    // but the result is not stable, so it's better checked manually.
    @Test
    public void testConcurrency() throws Exception {
        HintManagerService service = createServiceWithFakeWrapper();
        // initialize session threads to run in parallel
        final int sessionCount = 10;
        // the signal that the main thread will send to session threads to check for run or exit
        AtomicReference<Boolean> shouldRun = new AtomicReference<>(true);
        // the signal for main test thread to wait for session threads and notifier thread to
        // finish and exit
        CountDownLatch latch = new CountDownLatch(sessionCount + 1);
        // list of exceptions with one per session thread or notifier thread
        List<AtomicReference<Exception>> execs = new ArrayList<>(sessionCount + 1);
        List<Thread> threads = new ArrayList<>(sessionCount + 1);
        for (int i = 0; i < sessionCount; i++) {
            final AtomicReference<Exception> exec = new AtomicReference<>();
            execs.add(exec);
            int j = i;
            Thread app = new Thread(() -> {
                try {
                    while (shouldRun.get()) {
                        runAppHintSession(service, j, shouldRun);
                    }
                } catch (Exception e) {
                    exec.set(e);
                } finally {
                    latch.countDown();
                }
            });
            threads.add(app);
        }

        // initialize a UID state notifier thread to run in parallel
        final AtomicReference<Exception> notifierExec = new AtomicReference<>();
        execs.add(notifierExec);
        Thread notifier = new Thread(() -> {
            try {
                long min = Long.MAX_VALUE;
                long max = Long.MIN_VALUE;
                long sum = 0;
                int count = 0;
                while (shouldRun.get()) {
                    long start = System.nanoTime();
                    service.mUidObserver.onUidStateChanged(UID,
                            ActivityManager.PROCESS_STATE_IMPORTANT_FOREGROUND, 0, 0);
                    long elapsed = System.nanoTime() - start;
                    sum += elapsed;
                    count++;
                    min = Math.min(min, elapsed);
                    max = Math.max(max, elapsed);
                    LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(500));
                    service.mUidObserver.onUidStateChanged(UID,
                            ActivityManager.PROCESS_STATE_TRANSIENT_BACKGROUND, 0, 0);
                    // let the cleanup work proceed
                    LockSupport.parkNanos(
                            TimeUnit.MILLISECONDS.toNanos(500) + TimeUnit.MILLISECONDS.toNanos(
                                    CLEAN_UP_UID_DELAY_MILLIS));
                }
                Log.d(TAG, "notifier thread min " + min + " max " + max + " avg " + sum / count);
                service.mUidObserver.onUidGone(UID, true);
            } catch (Exception e) {
                notifierExec.set(e);
            } finally {
                latch.countDown();
            }
        });
        threads.add(notifier);

        // start all the threads
        for (Thread thread : threads) {
            thread.start();
        }
        // keep the test running for a few seconds
        LockSupport.parkNanos(TimeUnit.SECONDS.toNanos(CONCURRENCY_TEST_DURATION_SEC));
        // send signal to stop all threads
        shouldRun.set(false);
        // wait for all threads to exit
        latch.await();
        // check if any thread throws exception
        for (AtomicReference<Exception> exec : execs) {
            if (exec.get() != null) {
                throw exec.get();
            }
        }
    }

    private void runAppHintSession(HintManagerService service, int logId,
            AtomicReference<Boolean> shouldRun) throws Exception {
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;
        // we will start some threads and get their valid TIDs to update
        int threadCount = 3;
        // the list of TIDs
        int[] tids = new int[threadCount];
        // atomic index for each thread to set its TID in the list
        AtomicInteger k = new AtomicInteger(0);
        // signal for the session main thread to wait for child threads to finish updating TIDs
        CountDownLatch latch = new CountDownLatch(threadCount);
        // signal for the session main thread to notify child threads to exit
        CountDownLatch stopLatch = new CountDownLatch(1);
        for (int j = 0; j < threadCount; j++) {
            Thread thread = new Thread(() -> {
                try {
                    tids[k.getAndIncrement()] = android.os.Process.myTid();
                    latch.countDown();
                    stopLatch.await();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            });
            thread.start();
        }
        latch.await();
        a.setThreads(tids);
        // we don't need the threads to exist after update
        stopLatch.countDown();
        a.updateTargetWorkDuration(5);
        // measure the time it takes in HintManagerService to run reportActualDuration
        long min = Long.MAX_VALUE;
        long max = Long.MIN_VALUE;
        long sum = 0;
        int count = 0;
        List<Long> values = new ArrayList<>();
        long testStart = System.nanoTime();
        // run report actual for 4-second per cycle
        while (shouldRun.get() && System.nanoTime() - testStart < TimeUnit.SECONDS.toNanos(
                Math.min(4, CONCURRENCY_TEST_DURATION_SEC))) {
            long start = System.nanoTime();
            a.reportActualWorkDuration(new long[]{5}, new long[]{start});
            long elapsed = System.nanoTime() - start;
            values.add(elapsed);
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
            sum += elapsed;
            count++;
            min = Math.min(min, elapsed);
            max = Math.max(max, elapsed);
        }
        Collections.sort(values);
        if (!values.isEmpty()) {
            Log.d(TAG, "app thread " + logId + " min " + min + " max " + max
                    + " avg " + sum / count + " count " + count
                    + " 80th " + values.get((int) (values.size() * 0.8))
                    + " 90th " + values.get((int) (values.size() * 0.9))
                    + " 95th " + values.get((int) (values.size() * 0.95)));
        } else {
            Log.w(TAG, "No reportActualWorkDuration executed");
        }
        a.close();
    }

    @Test
    public void testReportActualWorkDuration2() throws Exception {
        HintManagerService service = createService();
        IBinder token = new Binder();
        SessionCreationConfig creationConfig =
                makeSessionCreationConfig(SESSION_TIDS_A, DEFAULT_TARGET_DURATION);

        AppHintSession a = (AppHintSession) service.getBinderServiceInstance()
                .createHintSessionWithConfig(token, SessionTag.OTHER,
                        creationConfig, new SessionConfig()).session;

        a.updateTargetWorkDuration(100L);
        a.reportActualWorkDuration2(WORK_DURATIONS_FIVE);
        verify(mNativeWrapperMock, times(1)).halReportActualWorkDuration(anyLong(),
                eq(WORK_DURATIONS_FIVE));

        assertThrows(IllegalArgumentException.class, () -> {
            a.reportActualWorkDuration2(new WorkDuration[] {});
        });

        assertThrows(IllegalArgumentException.class, () -> {
            a.reportActualWorkDuration2(
                    new WorkDuration[] {makeWorkDuration(1L, 11L, -1L, 8L, 4L)});
        });

        assertThrows(IllegalArgumentException.class, () -> {
            a.reportActualWorkDuration2(new WorkDuration[] {makeWorkDuration(1L, 0L, 1L, 8L, 4L)});
        });

        assertThrows(IllegalArgumentException.class, () -> {
            a.reportActualWorkDuration2(new WorkDuration[] {makeWorkDuration(1L, 11L, 1L, 0L, 0L)});
        });

        assertThrows(IllegalArgumentException.class, () -> {
            a.reportActualWorkDuration2(
                    new WorkDuration[] {makeWorkDuration(1L, 11L, 1L, 8L, -1L)});
        });

        reset(mNativeWrapperMock);
        // Set session to background, then the duration would not be updated.
        service.mUidObserver.onUidStateChanged(
                a.mUid, ActivityManager.PROCESS_STATE_TRANSIENT_BACKGROUND, 0, 0);

        // Using CountDownLatch to ensure above onUidStateChanged() job was digested.
        final CountDownLatch latch = new CountDownLatch(1);
        FgThread.getHandler().post(() -> {
            latch.countDown();
        });
        latch.await();

        assertFalse(service.mUidObserver.isUidForeground(a.mUid));
        a.reportActualWorkDuration2(WORK_DURATIONS_FIVE);
        verify(mNativeWrapperMock, never()).halReportActualWorkDuration(anyLong(), any(), any());
    }

    @Test
    public void testChannelDiesWhenTokenDies() throws Exception {
        HintManagerService service = createService();

        class DyingToken extends Binder {
            DeathRecipient mToNotify;
            @Override
            public void linkToDeath(@NonNull DeathRecipient recipient, int flags) {
                mToNotify = recipient;
                super.linkToDeath(recipient, flags);
            }

            public void fakeDeath() {
                mToNotify.binderDied();
            }
        }

        DyingToken token = new DyingToken();

        service.getBinderServiceInstance().getSessionChannel(token);
        verify(mIPowerMock, times(1)).getSessionChannel(eq(TGID), eq(UID));
        assertTrue(service.hasChannel(TGID, UID));

        token.fakeDeath();

        assertFalse(service.hasChannel(TGID, UID));
        verify(mIPowerMock, times(1)).closeSessionChannel(eq(TGID), eq(UID));

        clearInvocations(mIPowerMock);

        token = new DyingToken();
        service.getBinderServiceInstance().getSessionChannel(token);
        verify(mIPowerMock, times(1)).getSessionChannel(eq(TGID), eq(UID));
        assertTrue(service.hasChannel(TGID, UID));
    }

    @Test
    public void testHeadroomPowerHalNotSupported() throws Exception {
        when(mIPowerMock.getInterfaceVersion()).thenReturn(5);
        HintManagerService service = createService();
        assertThrows(UnsupportedOperationException.class, () -> {
            service.getBinderServiceInstance().getCpuHeadroom(null);
        });
        assertThrows(UnsupportedOperationException.class, () -> {
            service.getBinderServiceInstance().getGpuHeadroom(null);
        });
        assertThrows(UnsupportedOperationException.class, () -> {
            service.getBinderServiceInstance().getCpuHeadroomMinIntervalMillis();
        });
        assertThrows(UnsupportedOperationException.class, () -> {
            service.getBinderServiceInstance().getGpuHeadroomMinIntervalMillis();
        });
    }

    @Test
    public void testCpuHeadroomInvalidParams() {
        HintManagerService service = createService();
        final CpuHeadroomParamsInternal param1 = new CpuHeadroomParamsInternal();
        param1.calculationType = 100;
        assertThrows(IllegalArgumentException.class, () -> {
            service.getBinderServiceInstance().getCpuHeadroom(param1);
        });

        final CpuHeadroomParamsInternal param2 = new CpuHeadroomParamsInternal();
        param2.calculationWindowMillis = 49;
        assertThrows(IllegalArgumentException.class, () -> {
            service.getBinderServiceInstance().getCpuHeadroom(param2);
        });
        param2.calculationWindowMillis = 10001;
        assertThrows(IllegalArgumentException.class, () -> {
            service.getBinderServiceInstance().getCpuHeadroom(param2);
        });

        final CpuHeadroomParamsInternal param3 = new CpuHeadroomParamsInternal();
        param3.tids = new int[]{1, 2, 3, 4, 5, 6};
        assertThrows(IllegalArgumentException.class, () -> {
            service.getBinderServiceInstance().getCpuHeadroom(param3);
        });
    }

    @Test
    public void testGpuHeadroomInvalidParams() {
        HintManagerService service = createService();
        final GpuHeadroomParamsInternal param1 = new GpuHeadroomParamsInternal();
        param1.calculationType = 100;
        assertThrows(IllegalArgumentException.class, () -> {
            service.getBinderServiceInstance().getGpuHeadroom(param1);
        });

        final GpuHeadroomParamsInternal param2 = new GpuHeadroomParamsInternal();
        param2.calculationWindowMillis = 49;
        assertThrows(IllegalArgumentException.class, () -> {
            service.getBinderServiceInstance().getGpuHeadroom(param2);
        });
        param2.calculationWindowMillis = 10001;
        assertThrows(IllegalArgumentException.class, () -> {
            service.getBinderServiceInstance().getGpuHeadroom(param2);
        });
    }

    @Test
    public void testCpuHeadroomCpuProcStatPath() throws Exception {
        File dir = InstrumentationRegistry.getTargetContext().getFilesDir();
        dir.mkdir();
        String procStatFileStr = "mock_proc_stat";
        File file = new File(dir, procStatFileStr);
        mFilesCreated.add(file);
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write("cpu  2000 3000 4000 0 0 0 0 0 0 0".getBytes());
        }
        HintManagerService service = createService();
        service.setProcStatPathOverride(file.getPath());

        CpuHeadroomParamsInternal params1 = new CpuHeadroomParamsInternal();
        CpuHeadroomParams halParams1 = new CpuHeadroomParams();
        halParams1.calculationType = CpuHeadroomParams.CalculationType.MIN;
        halParams1.tids = new int[]{Process.myPid()};

        float headroom1 = 0.1f;
        CpuHeadroomResult halRet1 = CpuHeadroomResult.globalHeadroom(headroom1);
        when(mIPowerMock.getCpuHeadroom(eq(halParams1))).thenReturn(halRet1);
        clearInvocations(mIPowerMock);
        assertEquals(halRet1, service.getBinderServiceInstance().getCpuHeadroom(params1));
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams1));
        // expire the cache but cpu proc hasn't changed so we expect no value return
        Thread.sleep(1100);
        clearInvocations(mIPowerMock);
        assertEquals(null, service.getBinderServiceInstance().getCpuHeadroom(params1));
        verify(mIPowerMock, times(0)).getCpuHeadroom(eq(halParams1));

        // update user jiffies with 500 equivalent jiffies, which is not sufficient cpu time
        Thread.sleep(1100);
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(("cpu  " + (2000 + (int) (500 / service.mJiffyMillis))
                    + " 3000 4000 0 0 0 0 0 0 0").getBytes());
        }
        clearInvocations(mIPowerMock);
        assertEquals(null, service.getBinderServiceInstance().getCpuHeadroom(params1));
        verify(mIPowerMock, times(0)).getCpuHeadroom(eq(halParams1));

        // update nice jiffies with 600 equivalent jiffies, now it exceeds 1000ms requirement
        Thread.sleep(1100);
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(("cpu  " + (2000 + (int) (500 / service.mJiffyMillis))
                    + " " + +(3000 + (int) (600 / service.mJiffyMillis))
                    + " 4000 0 0 0 0 0 0 0").getBytes());
        }
        clearInvocations(mIPowerMock);
        assertEquals(halRet1, service.getBinderServiceInstance().getCpuHeadroom(params1));
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams1));
    }


    @Test
    public void testCpuHeadroomCache() throws Exception {
        CpuHeadroomParamsInternal params1 = new CpuHeadroomParamsInternal();
        CpuHeadroomParams halParams1 = new CpuHeadroomParams();
        halParams1.calculationType = CpuHeadroomParams.CalculationType.MIN;
        halParams1.tids = new int[]{Process.myPid()};

        CpuHeadroomParamsInternal params2 = new CpuHeadroomParamsInternal();
        params2.usesDeviceHeadroom = true;
        params2.calculationType = CpuHeadroomParams.CalculationType.MIN;
        CpuHeadroomParams halParams2 = new CpuHeadroomParams();
        halParams2.calculationType = CpuHeadroomParams.CalculationType.MIN;
        halParams2.tids = new int[]{};

        CountDownLatch latch = new CountDownLatch(2);
        int[] tids = createThreads(2, latch);
        CpuHeadroomParamsInternal params3 = new CpuHeadroomParamsInternal();
        params3.tids = tids;
        params3.calculationType = CpuHeadroomParams.CalculationType.AVERAGE;
        CpuHeadroomParams halParams3 = new CpuHeadroomParams();
        halParams3.tids = tids;
        halParams3.calculationType = CpuHeadroomParams.CalculationType.AVERAGE;

        CpuHeadroomParamsInternal params4 = new CpuHeadroomParamsInternal();
        params4.calculationWindowMillis = 123;
        CpuHeadroomParams halParams4 = new CpuHeadroomParams();
        halParams4.calculationType = CpuHeadroomParams.CalculationType.MIN;
        halParams4.calculationWindowMillis = 123;
        halParams4.tids = new int[]{Process.myPid()};

        float headroom1 = 0.1f;
        CpuHeadroomResult halRet1 = CpuHeadroomResult.globalHeadroom(headroom1);
        when(mIPowerMock.getCpuHeadroom(eq(halParams1))).thenReturn(halRet1);
        float headroom2 = 0.2f;
        CpuHeadroomResult halRet2 = CpuHeadroomResult.globalHeadroom(headroom2);
        when(mIPowerMock.getCpuHeadroom(eq(halParams2))).thenReturn(halRet2);
        float headroom3 = 0.3f;
        CpuHeadroomResult halRet3 = CpuHeadroomResult.globalHeadroom(headroom3);
        when(mIPowerMock.getCpuHeadroom(eq(halParams3))).thenReturn(halRet3);
        float headroom4 = 0.4f;
        CpuHeadroomResult halRet4 = CpuHeadroomResult.globalHeadroom(headroom4);
        when(mIPowerMock.getCpuHeadroom(eq(halParams4))).thenReturn(halRet4);

        HintManagerService service = createService();
        clearInvocations(mIPowerMock);

        assertEquals(halRet1, service.getBinderServiceInstance().getCpuHeadroom(params1));
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams1));
        assertEquals(halRet2, service.getBinderServiceInstance().getCpuHeadroom(params2));
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams2));
        assertEquals(halRet3, service.getBinderServiceInstance().getCpuHeadroom(params3));
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams3));
        assertEquals(halRet4, service.getBinderServiceInstance().getCpuHeadroom(params4));
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams4));

        // verify cache is working
        clearInvocations(mIPowerMock);
        assertEquals(halRet1, service.getBinderServiceInstance().getCpuHeadroom(params1));
        assertEquals(halRet2, service.getBinderServiceInstance().getCpuHeadroom(params2));
        assertEquals(halRet3, service.getBinderServiceInstance().getCpuHeadroom(params3));
        assertEquals(halRet4, service.getBinderServiceInstance().getCpuHeadroom(params4));
        verify(mIPowerMock, times(0)).getCpuHeadroom(any());

        // after 500ms more it should be served with cache
        Thread.sleep(500);
        clearInvocations(mIPowerMock);
        assertEquals(halRet1, service.getBinderServiceInstance().getCpuHeadroom(params1));
        assertEquals(halRet2, service.getBinderServiceInstance().getCpuHeadroom(params2));
        assertEquals(halRet3, service.getBinderServiceInstance().getCpuHeadroom(params3));
        assertEquals(halRet4, service.getBinderServiceInstance().getCpuHeadroom(params4));
        verify(mIPowerMock, times(0)).getCpuHeadroom(any());

        // after 1+ seconds it should be served from HAL as it exceeds 1000 millis interval
        Thread.sleep(600);
        clearInvocations(mIPowerMock);
        assertEquals(halRet1, service.getBinderServiceInstance().getCpuHeadroom(params1));
        assertEquals(halRet2, service.getBinderServiceInstance().getCpuHeadroom(params2));
        assertEquals(halRet3, service.getBinderServiceInstance().getCpuHeadroom(params3));
        assertEquals(halRet4, service.getBinderServiceInstance().getCpuHeadroom(params4));
        verify(mIPowerMock, times(4)).getCpuHeadroom(any());
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams1));
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams2));
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams3));
        verify(mIPowerMock, times(1)).getCpuHeadroom(eq(halParams4));
        latch.countDown();
    }

    @Test
    public void testGetCpuHeadroomDifferentAffinity() throws Exception {
        CountDownLatch latch = new CountDownLatch(2);
        int[] tids = createThreads(2, latch);
        CpuHeadroomParamsInternal params = new CpuHeadroomParamsInternal();
        params.tids = tids;
        CpuHeadroomParams halParams = new CpuHeadroomParams();
        halParams.tids = tids;
        float headroom = 0.1f;
        CpuHeadroomResult halRet = CpuHeadroomResult.globalHeadroom(headroom);
        String ret1 = runAndWaitForCommand("taskset -p 1 " + tids[0]);
        String ret2 = runAndWaitForCommand("taskset -p 3 " + tids[1]);

        HintManagerService service = createService();
        clearInvocations(mIPowerMock);
        when(mIPowerMock.getCpuHeadroom(eq(halParams))).thenReturn(halRet);
        assertThrows("taskset cmd return: " + ret1 + "\n" + ret2, IllegalStateException.class,
                () -> service.getBinderServiceInstance().getCpuHeadroom(params));
        verify(mIPowerMock, times(0)).getCpuHeadroom(any());
    }

    private String runAndWaitForCommand(String command) throws Exception {
        java.lang.Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        StringBuilder res = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            res.append(line);
        }
        process.waitFor();
        // somehow the exit code can be 1 for the taskset command though it exits successfully,
        // thus we just return the output
        return res.toString();
    }

    @Test
    public void testGpuHeadroomCache() throws Exception {
        GpuHeadroomParamsInternal params1 = new GpuHeadroomParamsInternal();
        GpuHeadroomParams halParams1 = new GpuHeadroomParams();
        halParams1.calculationType = GpuHeadroomParams.CalculationType.MIN;

        GpuHeadroomParamsInternal params2 = new GpuHeadroomParamsInternal();
        params2.calculationType = GpuHeadroomParams.CalculationType.AVERAGE;
        params2.calculationWindowMillis = 123;
        GpuHeadroomParams halParams2 = new GpuHeadroomParams();
        halParams2.calculationType = GpuHeadroomParams.CalculationType.AVERAGE;
        halParams2.calculationWindowMillis = 123;

        float headroom1 = 0.1f;
        GpuHeadroomResult halRet1 = GpuHeadroomResult.globalHeadroom(headroom1);
        when(mIPowerMock.getGpuHeadroom(eq(halParams1))).thenReturn(halRet1);
        float headroom2 = 0.2f;
        GpuHeadroomResult halRet2 = GpuHeadroomResult.globalHeadroom(headroom2);
        when(mIPowerMock.getGpuHeadroom(eq(halParams2))).thenReturn(halRet2);
        HintManagerService service = createService();
        clearInvocations(mIPowerMock);

        assertEquals(halRet1, service.getBinderServiceInstance().getGpuHeadroom(params1));
        assertEquals(halRet2, service.getBinderServiceInstance().getGpuHeadroom(params2));
        verify(mIPowerMock, times(2)).getGpuHeadroom(any());
        verify(mIPowerMock, times(1)).getGpuHeadroom(eq(halParams1));
        verify(mIPowerMock, times(1)).getGpuHeadroom(eq(halParams2));

        // verify cache is working
        clearInvocations(mIPowerMock);
        assertEquals(halRet1, service.getBinderServiceInstance().getGpuHeadroom(params1));
        assertEquals(halRet2, service.getBinderServiceInstance().getGpuHeadroom(params2));
        verify(mIPowerMock, times(0)).getGpuHeadroom(any());

        // after 500ms it should be served with cache
        Thread.sleep(500);
        clearInvocations(mIPowerMock);
        assertEquals(halRet1, service.getBinderServiceInstance().getGpuHeadroom(params1));
        assertEquals(halRet2, service.getBinderServiceInstance().getGpuHeadroom(params2));
        verify(mIPowerMock, times(0)).getGpuHeadroom(any());

        // after 1+ seconds it should be served from HAL as it exceeds 1000 millis interval
        Thread.sleep(600);
        clearInvocations(mIPowerMock);
        assertEquals(halRet1, service.getBinderServiceInstance().getGpuHeadroom(params1));
        assertEquals(halRet2, service.getBinderServiceInstance().getGpuHeadroom(params2));
        verify(mIPowerMock, times(2)).getGpuHeadroom(any());
        verify(mIPowerMock, times(1)).getGpuHeadroom(eq(halParams1));
        verify(mIPowerMock, times(1)).getGpuHeadroom(eq(halParams2));
    }

    @Test
    public void testRegisteringClient() throws Exception {
        HintManagerService service = createService();
        IHintManager.HintManagerClientData data = service.getBinderServiceInstance()
                .registerClient(mClientCallback);
        assertNotNull(data);
        assertEquals(data.supportInfo, mSupportInfo);
    }

    @Test
    public void testRegisteringClientOnV4() throws Exception {
        when(mIPowerMock.getInterfaceVersion()).thenReturn(4);
        HintManagerService service = createService();
        IHintManager.HintManagerClientData data = service.getBinderServiceInstance()
                .registerClient(mClientCallback);
        assertNotNull(data);
        assertEquals(data.supportInfo.usesSessions, true);
        assertEquals(data.supportInfo.boosts, 0);
        assertEquals(data.supportInfo.modes, 0);
        assertEquals(data.supportInfo.sessionHints, 31);
        assertEquals(data.supportInfo.sessionModes, 0);
        assertEquals(data.supportInfo.sessionTags, 0);
        assertEquals(data.powerHalVersion, 4);
        assertEquals(data.preferredRateNanos, DEFAULT_HINT_PREFERRED_RATE);
    }

    @Test
    public void testRegisteringClientOnV5() throws Exception {
        when(mIPowerMock.getInterfaceVersion()).thenReturn(5);
        HintManagerService service = createService();
        IHintManager.HintManagerClientData data = service.getBinderServiceInstance()
                .registerClient(mClientCallback);
        assertNotNull(data);
        assertEquals(data.supportInfo.usesSessions, true);
        assertEquals(data.supportInfo.boosts, 0);
        assertEquals(data.supportInfo.modes, 0);
        assertEquals(data.supportInfo.sessionHints, 255);
        assertEquals(data.supportInfo.sessionModes, 1);
        assertEquals(data.supportInfo.sessionTags, 31);
        assertEquals(data.powerHalVersion, 5);
        assertEquals(data.preferredRateNanos, DEFAULT_HINT_PREFERRED_RATE);
    }

    @Test
    public void testSettingUpOldClientWhenUnsupported() throws Exception {
        when(mIPowerMock.getInterfaceVersion()).thenReturn(5);
        // Mock unsupported to modify the default support behavior
        when(mNativeWrapperMock.halGetHintSessionPreferredRate())
                .thenReturn(-1L);
        HintManagerService service = createService();
        IHintManager.HintManagerClientData data = service.getBinderServiceInstance()
                .registerClient(mClientCallback);
        assertNotNull(data);
        assertEquals(data.supportInfo.usesSessions, false);
        assertEquals(data.supportInfo.boosts, 0);
        assertEquals(data.supportInfo.modes, 0);
        assertEquals(data.supportInfo.sessionHints, 0);
        assertEquals(data.supportInfo.sessionModes, 0);
        assertEquals(data.supportInfo.sessionTags, 0);
        assertEquals(data.powerHalVersion, 5);
        assertEquals(data.preferredRateNanos, -1);
    }
}
