/*
 * Copyright (C) 2018 The Android Open Source Project
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

package com.android.server.power;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyFloat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.thermal.TemperatureThreshold;
import android.hardware.thermal.ThrottlingSeverity;
import android.os.CoolingDevice;
import android.os.Flags;
import android.os.IBinder;
import android.os.IPowerManager;
import android.os.IThermalEventListener;
import android.os.IThermalHeadroomListener;
import android.os.IThermalService;
import android.os.IThermalStatusListener;
import android.os.PowerManager;
import android.os.RemoteException;
import android.os.Temperature;
import android.platform.test.annotations.DisableFlags;
import android.platform.test.annotations.EnableFlags;
import android.platform.test.flag.junit.SetFlagsRule;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.server.SystemService;
import com.android.server.power.ThermalManagerService.TemperatureWatcher;
import com.android.server.power.ThermalManagerService.ThermalHalWrapper;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * atest $ANDROID_BUILD_TOP/frameworks/base/services/tests/servicestests/src/com/android/server
 * /power/ThermalManagerServiceTest.java
 */
@SmallTest
@RunWith(AndroidJUnit4.class)
public class ThermalManagerServiceTest {
    @ClassRule
    public static final SetFlagsRule.ClassRule mSetFlagsClassRule = new SetFlagsRule.ClassRule();
    @Rule
    public final SetFlagsRule mSetFlagsRule = mSetFlagsClassRule.createSetFlagsRule();

    private static final long CALLBACK_TIMEOUT_MILLI_SEC = 5000;
    private ThermalManagerService mService;
    private ThermalHalFake mFakeHal;
    private PowerManager mPowerManager;
    @Mock
    private Context mContext;
    @Mock
    private IPowerManager mIPowerManagerMock;
    @Mock
    private IThermalService mIThermalServiceMock;
    @Mock
    private IThermalHeadroomListener mHeadroomListener;
    @Mock
    private IThermalEventListener mEventListener1;
    @Mock
    private IThermalEventListener mEventListener2;
    @Mock
    private IThermalStatusListener mStatusListener1;
    @Mock
    private IThermalStatusListener mStatusListener2;

    /**
     * Fake Hal class.
     */
    private class ThermalHalFake extends ThermalHalWrapper {
        private static final int INIT_STATUS = Temperature.THROTTLING_NONE;
        private final List<Temperature> mTemperatureList = new ArrayList<>();
        private AtomicInteger mGetCurrentTemperaturesCalled = new AtomicInteger();
        private List<CoolingDevice> mCoolingDeviceList = new ArrayList<>();
        private List<TemperatureThreshold> mTemperatureThresholdList = initializeThresholds();

        private Temperature mSkin1 = new Temperature(28, Temperature.TYPE_SKIN, "skin1",
                INIT_STATUS);
        private Temperature mSkin2 = new Temperature(31, Temperature.TYPE_SKIN, "skin2",
                INIT_STATUS);
        private Temperature mBattery = new Temperature(34, Temperature.TYPE_BATTERY, "batt",
                INIT_STATUS);
        private Temperature mUsbPort = new Temperature(37, Temperature.TYPE_USB_PORT, "usbport",
                INIT_STATUS);
        private CoolingDevice mCpu = new CoolingDevice(40, CoolingDevice.TYPE_BATTERY, "cpu");
        private CoolingDevice mGpu = new CoolingDevice(43, CoolingDevice.TYPE_BATTERY, "gpu");
        private Map<Integer, Float> mForecastSkinTemperatures = null;
        private int mForecastSkinTemperaturesCalled = 0;
        private boolean mForecastSkinTemperaturesError = false;

        private List<TemperatureThreshold> initializeThresholds() {
            ArrayList<TemperatureThreshold> thresholds = new ArrayList<>();

            TemperatureThreshold skinThreshold = new TemperatureThreshold();
            skinThreshold.type = Temperature.TYPE_SKIN;
            skinThreshold.name = "skin1";
            skinThreshold.hotThrottlingThresholds = new float[7 /*ThrottlingSeverity#len*/];
            skinThreshold.coldThrottlingThresholds = new float[7 /*ThrottlingSeverity#len*/];
            for (int i = 0; i < skinThreshold.hotThrottlingThresholds.length; ++i) {
                // Sets NONE to 25.0f, SEVERE to 40.0f, and SHUTDOWN to 55.0f
                skinThreshold.hotThrottlingThresholds[i] = 25.0f + 5.0f * i;
            }
            thresholds.add(skinThreshold);

            TemperatureThreshold cpuThreshold = new TemperatureThreshold();
            cpuThreshold.type = Temperature.TYPE_CPU;
            cpuThreshold.name = "cpu";
            cpuThreshold.hotThrottlingThresholds = new float[7 /*ThrottlingSeverity#len*/];
            cpuThreshold.coldThrottlingThresholds = new float[7 /*ThrottlingSeverity#len*/];
            for (int i = 0; i < cpuThreshold.hotThrottlingThresholds.length; ++i) {
                if (i == ThrottlingSeverity.SEVERE) {
                    cpuThreshold.hotThrottlingThresholds[i] = 95.0f;
                } else {
                    cpuThreshold.hotThrottlingThresholds[i] = Float.NaN;
                }
            }
            thresholds.add(cpuThreshold);

            return thresholds;
        }

        ThermalHalFake() {
            mTemperatureList.add(mSkin1);
            mTemperatureList.add(mSkin2);
            mTemperatureList.add(mBattery);
            mTemperatureList.add(mUsbPort);
            mCoolingDeviceList.add(mCpu);
            mCoolingDeviceList.add(mGpu);
            mGetCurrentTemperaturesCalled.set(0);
        }

        void enableForecastSkinTemperature() {
            mForecastSkinTemperatures = Map.of(0, 22.0f, 10, 25.0f, 20, 28.0f,
                    30, 31.0f, 40, 34.0f, 50, 37.0f, 60, 40.0f);
        }

        void disableForecastSkinTemperature() {
            mForecastSkinTemperatures = null;
        }

        void failForecastSkinTemperature() {
            mForecastSkinTemperaturesError = true;
        }

        void updateTemperatureList(Temperature... temperatures) {
            synchronized (mTemperatureList) {
                mTemperatureList.clear();
                mTemperatureList.addAll(Arrays.asList(temperatures));
            }
        }

        @Override
        protected List<Temperature> getCurrentTemperatures(boolean shouldFilter, int type) {
            List<Temperature> ret = new ArrayList<>();
            synchronized (mTemperatureList) {
                mGetCurrentTemperaturesCalled.incrementAndGet();
                for (Temperature temperature : mTemperatureList) {
                    if (shouldFilter && type != temperature.getType()) {
                        continue;
                    }
                    ret.add(temperature);
                }
            }
            return ret;
        }

        @Override
        protected List<CoolingDevice> getCurrentCoolingDevices(boolean shouldFilter, int type) {
            List<CoolingDevice> ret = new ArrayList<>();
            for (CoolingDevice cdev : mCoolingDeviceList) {
                if (shouldFilter && type != cdev.getType()) {
                    continue;
                }
                ret.add(cdev);
            }
            return ret;
        }

        @Override
        protected List<TemperatureThreshold> getTemperatureThresholds(boolean shouldFilter,
                int type) {
            List<TemperatureThreshold> ret = new ArrayList<>();
            for (TemperatureThreshold threshold : mTemperatureThresholdList) {
                if (shouldFilter && type != threshold.type) {
                    continue;
                }
                ret.add(threshold);
            }
            return ret;
        }

        @Override
        protected float forecastSkinTemperature(int forecastSeconds) {
            mForecastSkinTemperaturesCalled++;
            if (mForecastSkinTemperaturesError) {
                throw new RuntimeException();
            }
            if (mForecastSkinTemperatures == null) {
                throw new UnsupportedOperationException();
            }
            return mForecastSkinTemperatures.get(forecastSeconds);
        }

        @Override
        protected boolean connectToHal() {
            return true;
        }

        @Override
        protected void dump(PrintWriter pw, String prefix) {
            pw.print(prefix);
            pw.println("ThermalHAL AIDL 1  connected: yes");
        }
    }

    private void assertListEqualsIgnoringOrder(List<?> actual, List<?> expected) {
        HashSet<?> actualSet = new HashSet<>(actual);
        HashSet<?> expectedSet = new HashSet<>(expected);
        assertEquals(expectedSet, actualSet);
    }

    @Before
    public void setUp() throws RemoteException {
        MockitoAnnotations.initMocks(this);
        mFakeHal = new ThermalHalFake();
        mPowerManager = new PowerManager(mContext, mIPowerManagerMock, mIThermalServiceMock, null);
        when(mContext.getSystemServiceName(PowerManager.class)).thenReturn(Context.POWER_SERVICE);
        when(mContext.getSystemService(PowerManager.class)).thenReturn(mPowerManager);
        resetListenerMock();
        mService = new ThermalManagerService(mContext, mFakeHal);
        mService.onBootPhase(SystemService.PHASE_ACTIVITY_MANAGER_READY);
    }

    private void resetListenerMock() {
        reset(mEventListener1);
        reset(mStatusListener1);
        reset(mEventListener2);
        reset(mStatusListener2);
        reset(mHeadroomListener);
        doReturn(mock(IBinder.class)).when(mEventListener1).asBinder();
        doReturn(mock(IBinder.class)).when(mStatusListener1).asBinder();
        doReturn(mock(IBinder.class)).when(mEventListener2).asBinder();
        doReturn(mock(IBinder.class)).when(mStatusListener2).asBinder();
        doReturn(mock(IBinder.class)).when(mHeadroomListener).asBinder();
    }

    @Test
    public void testRegister() throws Exception {
        mService = new ThermalManagerService(mContext, mFakeHal);
        // Register callbacks before AMS ready and verify they are called after AMS is ready
        assertTrue(mService.mService.registerThermalEventListener(mEventListener1));
        assertTrue(mService.mService.registerThermalStatusListener(mStatusListener1));
        assertTrue(mService.mService.registerThermalEventListenerWithType(mEventListener2,
                Temperature.TYPE_SKIN));
        assertTrue(mService.mService.registerThermalStatusListener(mStatusListener2));
        Thread.sleep(CALLBACK_TIMEOUT_MILLI_SEC);
        resetListenerMock();
        mService.onBootPhase(SystemService.PHASE_ACTIVITY_MANAGER_READY);
        assertTrue(mService.mService.registerThermalHeadroomListener(mHeadroomListener));

        ArgumentCaptor<Temperature> captor = ArgumentCaptor.forClass(Temperature.class);
        verify(mEventListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(4)).notifyThrottling(captor.capture());
        assertListEqualsIgnoringOrder(mFakeHal.mTemperatureList, captor.getAllValues());
        verify(mStatusListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onStatusChange(Temperature.THROTTLING_NONE);
        captor = ArgumentCaptor.forClass(Temperature.class);
        verify(mEventListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(2)).notifyThrottling(captor.capture());
        assertListEqualsIgnoringOrder(
                new ArrayList<>(Arrays.asList(mFakeHal.mSkin1, mFakeHal.mSkin2)),
                captor.getAllValues());
        verify(mStatusListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onStatusChange(Temperature.THROTTLING_NONE);
        resetListenerMock();

        // Register callbacks after AMS ready and verify they are called
        assertTrue(mService.mService.registerThermalEventListener(mEventListener1));
        assertTrue(mService.mService.registerThermalStatusListener(mStatusListener1));
        captor = ArgumentCaptor.forClass(Temperature.class);
        verify(mEventListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(4)).notifyThrottling(captor.capture());
        assertListEqualsIgnoringOrder(mFakeHal.mTemperatureList, captor.getAllValues());
        verify(mStatusListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onStatusChange(Temperature.THROTTLING_NONE);

        // Register new callbacks and verify old ones are not called (remained same) while new
        // ones are called
        assertTrue(mService.mService.registerThermalEventListenerWithType(mEventListener2,
                Temperature.TYPE_SKIN));
        assertTrue(mService.mService.registerThermalStatusListener(mStatusListener2));
        verify(mEventListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(4)).notifyThrottling(any(Temperature.class));
        verify(mStatusListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onStatusChange(Temperature.THROTTLING_NONE);
        captor = ArgumentCaptor.forClass(Temperature.class);
        verify(mEventListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(2)).notifyThrottling(captor.capture());
        assertListEqualsIgnoringOrder(
                new ArrayList<>(Arrays.asList(mFakeHal.mSkin1, mFakeHal.mSkin2)),
                captor.getAllValues());
        verify(mStatusListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onStatusChange(Temperature.THROTTLING_NONE);
    }

    @Test
    public void testNotifyThrottling() throws Exception {
        assertTrue(mService.mService.registerThermalEventListener(mEventListener1));
        assertTrue(mService.mService.registerThermalStatusListener(mStatusListener1));
        assertTrue(mService.mService.registerThermalEventListenerWithType(mEventListener2,
                Temperature.TYPE_SKIN));
        assertTrue(mService.mService.registerThermalStatusListener(mStatusListener2));
        Thread.sleep(CALLBACK_TIMEOUT_MILLI_SEC);
        resetListenerMock();

        int status = Temperature.THROTTLING_SEVERE;
        // Should only notify event not status
        Temperature newBattery = new Temperature(50, Temperature.TYPE_BATTERY, "batt", status);
        mFakeHal.mCallback.onTemperatureChanged(newBattery);
        verify(mEventListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).notifyThrottling(newBattery);
        verify(mStatusListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onStatusChange(anyInt());
        verify(mEventListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).notifyThrottling(newBattery);
        verify(mStatusListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onStatusChange(anyInt());
        resetListenerMock();
        // Notify both event and status
        Temperature newSkin = new Temperature(50, Temperature.TYPE_SKIN, "skin1", status);
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        verify(mEventListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).notifyThrottling(newSkin);
        verify(mStatusListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onStatusChange(status);
        verify(mEventListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).notifyThrottling(newSkin);
        verify(mStatusListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onStatusChange(status);
        resetListenerMock();
        // Back to None, should only notify event not status
        status = Temperature.THROTTLING_NONE;
        newBattery = new Temperature(50, Temperature.TYPE_BATTERY, "batt", status);
        mFakeHal.mCallback.onTemperatureChanged(newBattery);
        verify(mEventListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).notifyThrottling(newBattery);
        verify(mStatusListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onStatusChange(anyInt());
        verify(mEventListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).notifyThrottling(newBattery);
        verify(mStatusListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onStatusChange(anyInt());
        resetListenerMock();
        // Should also notify status
        newSkin = new Temperature(50, Temperature.TYPE_SKIN, "skin1", status);
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        verify(mEventListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).notifyThrottling(newSkin);
        verify(mStatusListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onStatusChange(status);
        verify(mEventListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).notifyThrottling(newSkin);
        verify(mStatusListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onStatusChange(status);
    }

    @Test
    @EnableFlags({Flags.FLAG_ALLOW_THERMAL_THRESHOLDS_CALLBACK})
    public void testNotifyThrottling_headroomCallback() throws Exception {
        assertTrue(mService.mService.registerThermalHeadroomListener(mHeadroomListener));
        Thread.sleep(CALLBACK_TIMEOUT_MILLI_SEC);
        resetListenerMock();
        int status = Temperature.THROTTLING_SEVERE;
        mFakeHal.updateTemperatureList();

        // Should not notify on non-skin type
        Temperature newBattery = new Temperature(37, Temperature.TYPE_BATTERY, "batt", status);
        mFakeHal.mCallback.onTemperatureChanged(newBattery);
        verify(mHeadroomListener, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onHeadroomChange(anyFloat(), anyFloat(), anyInt(), any());
        resetListenerMock();

        // Notify headroom on skin temperature change
        Temperature newSkin = new Temperature(37, Temperature.TYPE_SKIN, "skin1", status);
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        verify(mHeadroomListener, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onHeadroomChange(eq(0.9f), anyFloat(), anyInt(),
                eq(new float[]{Float.NaN, 0.6666667f, 0.8333333f, 1.0f, 1.1666666f, 1.3333334f,
                        1.5f}));
        resetListenerMock();

        // Same or similar temperature should not trigger in a short period
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        newSkin = new Temperature(36.9f, Temperature.TYPE_SKIN, "skin1", status);
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        newSkin = new Temperature(37.1f, Temperature.TYPE_SKIN, "skin1", status);
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        verify(mHeadroomListener, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onHeadroomChange(anyFloat(), anyFloat(), anyInt(), any());
        resetListenerMock();

        // Significant temperature should trigger in a short period
        newSkin = new Temperature(34f, Temperature.TYPE_SKIN, "skin1", status);
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        verify(mHeadroomListener, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onHeadroomChange(eq(0.8f), anyFloat(), anyInt(),
                eq(new float[]{Float.NaN, 0.6666667f, 0.8333333f, 1.0f, 1.1666666f, 1.3333334f,
                        1.5f}));
        resetListenerMock();
        newSkin = new Temperature(40f, Temperature.TYPE_SKIN, "skin1", status);
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        verify(mHeadroomListener, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onHeadroomChange(eq(1.0f), anyFloat(), anyInt(),
                eq(new float[]{Float.NaN, 0.6666667f, 0.8333333f, 1.0f, 1.1666666f, 1.3333334f,
                        1.5f}));
    }

    @Test
    public void testGetCurrentTemperatures() throws RemoteException {
        assertListEqualsIgnoringOrder(mFakeHal.getCurrentTemperatures(false, 0),
                Arrays.asList(mService.mService.getCurrentTemperatures()));
        assertListEqualsIgnoringOrder(
                mFakeHal.getCurrentTemperatures(true, Temperature.TYPE_SKIN),
                Arrays.asList(mService.mService.getCurrentTemperaturesWithType(
                        Temperature.TYPE_SKIN)));
    }

    @Test
    public void testGetCurrentStatus() throws RemoteException {
        int status = Temperature.THROTTLING_SEVERE;
        Temperature newSkin = new Temperature(100, Temperature.TYPE_SKIN, "skin1", status);
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        assertEquals(status, mService.mService.getCurrentThermalStatus());
        int battStatus = Temperature.THROTTLING_EMERGENCY;
        Temperature newBattery = new Temperature(60, Temperature.TYPE_BATTERY, "batt", battStatus);
        assertEquals(status, mService.mService.getCurrentThermalStatus());
    }

    @Test
    public void testThermalShutdown() throws RemoteException {
        int status = Temperature.THROTTLING_SHUTDOWN;
        Temperature newSkin = new Temperature(100, Temperature.TYPE_SKIN, "skin1", status);
        mFakeHal.mCallback.onTemperatureChanged(newSkin);
        verify(mIPowerManagerMock, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).shutdown(false, PowerManager.SHUTDOWN_THERMAL_STATE, false);
        Temperature newBattery = new Temperature(60, Temperature.TYPE_BATTERY, "batt", status);
        mFakeHal.mCallback.onTemperatureChanged(newBattery);
        verify(mIPowerManagerMock, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).shutdown(false, PowerManager.SHUTDOWN_BATTERY_THERMAL_STATE, false);
    }

    @Test
    public void testNoHal() throws RemoteException {
        mService = new ThermalManagerService(mContext);
        // Do no call onActivityManagerReady to skip connect HAL
        assertTrue(mService.mService.registerThermalEventListener(mEventListener1));
        assertTrue(mService.mService.registerThermalStatusListener(mStatusListener1));
        assertTrue(mService.mService.registerThermalEventListenerWithType(mEventListener2,
                Temperature.TYPE_SKIN));
        assertFalse(mService.mService.registerThermalHeadroomListener(mHeadroomListener));
        verify(mEventListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).notifyThrottling(any(Temperature.class));
        verify(mStatusListener1, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onStatusChange(Temperature.THROTTLING_NONE);
        verify(mEventListener2, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).notifyThrottling(any(Temperature.class));
        verify(mHeadroomListener, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onHeadroomChange(anyFloat(), anyFloat(), anyInt(), any());

        assertEquals(0, Arrays.asList(mService.mService.getCurrentTemperatures()).size());
        assertEquals(0, Arrays.asList(mService.mService.getCurrentTemperaturesWithType(
                Temperature.TYPE_SKIN)).size());
        assertEquals(Temperature.THROTTLING_NONE, mService.mService.getCurrentThermalStatus());
        assertTrue(Float.isNaN(mService.mService.getThermalHeadroom(0)));

        assertTrue(mService.mService.unregisterThermalEventListener(mEventListener1));
        assertTrue(mService.mService.unregisterThermalEventListener(mEventListener2));
        assertTrue(mService.mService.unregisterThermalStatusListener(mStatusListener1));
        assertFalse(mService.mService.unregisterThermalHeadroomListener(mHeadroomListener));
    }

    @Test
    public void testGetCurrentCoolingDevices() throws RemoteException {
        assertListEqualsIgnoringOrder(mFakeHal.getCurrentCoolingDevices(false, 0),
                Arrays.asList(mService.mService.getCurrentCoolingDevices()));
        assertListEqualsIgnoringOrder(
                mFakeHal.getCurrentCoolingDevices(false, CoolingDevice.TYPE_BATTERY),
                Arrays.asList(mService.mService.getCurrentCoolingDevices()));
        assertListEqualsIgnoringOrder(
                mFakeHal.getCurrentCoolingDevices(true, CoolingDevice.TYPE_CPU),
                Arrays.asList(mService.mService.getCurrentCoolingDevicesWithType(
                        CoolingDevice.TYPE_CPU)));
    }

    @Test
    public void testGetThermalHeadroomInputRange() throws RemoteException {
        assertTrue(Float.isNaN(mService.mService.getThermalHeadroom(
                ThermalManagerService.MIN_FORECAST_SEC - 1)));
        assertTrue(Float.isNaN(mService.mService.getThermalHeadroom(
                ThermalManagerService.MAX_FORECAST_SEC + 1)));
    }

    @Test
    @DisableFlags({Flags.FLAG_ALLOW_THERMAL_HAL_SKIN_FORECAST})
    public void testGetThermalHeadroom_handlerUpdateTemperatures()
            throws RemoteException, InterruptedException {
        // test that handler will at least enqueue one message to periodically read temperatures
        // even if there is sample seeded from HAL temperature callback
        String temperatureName = "skin1";
        Temperature temperature = new Temperature(100, Temperature.TYPE_SKIN, temperatureName,
                Temperature.THROTTLING_NONE);
        mFakeHal.mCallback.onTemperatureChanged(temperature);
        float headroom = mService.mService.getThermalHeadroom(0);
        // the callback temperature 100C (headroom > 1.0f) sample should have been appended by the
        // immediately scheduled fake HAL current temperatures read (mSkin1, mSkin2), and because
        // there are less samples for prediction, the latest temperature mSkin1 is used to calculate
        // headroom (mSkin2 has no threshold), which is 0.6f (28C vs threshold 40C).
        assertEquals(0.6f, headroom, 0.01f);
        // one called by service onActivityManagerReady, one called by handler on headroom call
        assertEquals(2, mFakeHal.mGetCurrentTemperaturesCalled.get());
        // periodic read should update the samples history, so the headroom should increase 0.1f
        // as current temperature goes up by 3C every 1100ms.
        for (int i = 1; i < 5; i++) {
            Temperature newTemperature = new Temperature(mFakeHal.mSkin1.getValue() + 3 * i,
                    Temperature.TYPE_SKIN,
                    temperatureName,
                    Temperature.THROTTLING_NONE);
            mFakeHal.updateTemperatureList(newTemperature);
            // wait for handler to update temperature
            Thread.sleep(1100);
            // assert that only one callback was scheduled to query HAL when making multiple
            // headroom calls
            assertEquals(2 + i, mFakeHal.mGetCurrentTemperaturesCalled.get());
            headroom = mService.mService.getThermalHeadroom(0);
            assertEquals(0.6f + 0.1f * i, headroom, 0.01f);
        }
    }

    @Test
    @EnableFlags({Flags.FLAG_ALLOW_THERMAL_HAL_SKIN_FORECAST})
    public void testGetThermalHeadroom_halForecast() throws RemoteException {
        mFakeHal.mForecastSkinTemperaturesCalled = 0;
        mFakeHal.enableForecastSkinTemperature();
        mService = new ThermalManagerService(mContext, mFakeHal);
        mService.onBootPhase(SystemService.PHASE_ACTIVITY_MANAGER_READY);
        assertTrue(mService.mIsHalSkinForecastSupported.get());
        assertEquals(1, mFakeHal.mForecastSkinTemperaturesCalled);
        mFakeHal.mForecastSkinTemperaturesCalled = 0;

        assertEquals(1.0f, mService.mService.getThermalHeadroom(60), 0.01f);
        assertEquals(0.9f, mService.mService.getThermalHeadroom(50), 0.01f);
        assertEquals(0.8f, mService.mService.getThermalHeadroom(40), 0.01f);
        assertEquals(0.7f, mService.mService.getThermalHeadroom(30), 0.01f);
        assertEquals(0.6f, mService.mService.getThermalHeadroom(20), 0.01f);
        assertEquals(0.5f, mService.mService.getThermalHeadroom(10), 0.01f);
        assertEquals(0.4f, mService.mService.getThermalHeadroom(0), 0.01f);
        assertEquals(7, mFakeHal.mForecastSkinTemperaturesCalled);
    }

    @Test
    @EnableFlags({Flags.FLAG_ALLOW_THERMAL_HAL_SKIN_FORECAST})
    public void testGetThermalHeadroom_halForecast_disabledOnMultiThresholds()
            throws RemoteException {
        mFakeHal.mForecastSkinTemperaturesCalled = 0;
        List<TemperatureThreshold> thresholds = mFakeHal.initializeThresholds();
        TemperatureThreshold skinThreshold = new TemperatureThreshold();
        skinThreshold.type = Temperature.TYPE_SKIN;
        skinThreshold.name = "skin2";
        skinThreshold.hotThrottlingThresholds = new float[7 /*ThrottlingSeverity#len*/];
        skinThreshold.coldThrottlingThresholds = new float[7 /*ThrottlingSeverity#len*/];
        for (int i = 0; i < skinThreshold.hotThrottlingThresholds.length; ++i) {
            // Sets NONE to 45.0f, SEVERE to 60.0f, and SHUTDOWN to 75.0f
            skinThreshold.hotThrottlingThresholds[i] = 45.0f + 5.0f * i;
        }
        thresholds.add(skinThreshold);
        mFakeHal.mTemperatureThresholdList = thresholds;
        mFakeHal.enableForecastSkinTemperature();
        mService = new ThermalManagerService(mContext, mFakeHal);
        mService.onBootPhase(SystemService.PHASE_ACTIVITY_MANAGER_READY);
        assertFalse("HAL skin forecast should be disabled on multiple SKIN thresholds",
                mService.mIsHalSkinForecastSupported.get());
        mService.mService.getThermalHeadroom(10);
        assertEquals(0, mFakeHal.mForecastSkinTemperaturesCalled);
    }

    @Test
    @EnableFlags({Flags.FLAG_ALLOW_THERMAL_HAL_SKIN_FORECAST,
            Flags.FLAG_ALLOW_THERMAL_THRESHOLDS_CALLBACK})
    public void testGetThermalHeadroom_halForecast_disabledOnMultiThresholdsCallback()
            throws RemoteException {
        mFakeHal.mForecastSkinTemperaturesCalled = 0;
        mFakeHal.enableForecastSkinTemperature();
        mService = new ThermalManagerService(mContext, mFakeHal);
        mService.onBootPhase(SystemService.PHASE_ACTIVITY_MANAGER_READY);
        assertTrue(mService.mIsHalSkinForecastSupported.get());
        assertEquals(1, mFakeHal.mForecastSkinTemperaturesCalled);
        mFakeHal.mForecastSkinTemperaturesCalled = 0;

        TemperatureThreshold newThreshold = new TemperatureThreshold();
        newThreshold.name = "skin2";
        newThreshold.type = Temperature.TYPE_SKIN;
        newThreshold.hotThrottlingThresholds = new float[]{
                Float.NaN, 43.0f, 46.0f, 49.0f, Float.NaN, Float.NaN, Float.NaN
        };
        mFakeHal.mCallback.onThresholdChanged(newThreshold);
        mService.mService.getThermalHeadroom(10);
        assertEquals(0, mFakeHal.mForecastSkinTemperaturesCalled);
    }

    @Test
    @EnableFlags({Flags.FLAG_ALLOW_THERMAL_HAL_SKIN_FORECAST})
    public void testGetThermalHeadroom_halForecast_errorOnHal() throws RemoteException {
        mFakeHal.mForecastSkinTemperaturesCalled = 0;
        mFakeHal.enableForecastSkinTemperature();
        mService = new ThermalManagerService(mContext, mFakeHal);
        mService.onBootPhase(SystemService.PHASE_ACTIVITY_MANAGER_READY);
        assertTrue(mService.mIsHalSkinForecastSupported.get());
        assertEquals(1, mFakeHal.mForecastSkinTemperaturesCalled);
        mFakeHal.mForecastSkinTemperaturesCalled = 0;

        mFakeHal.disableForecastSkinTemperature();
        assertTrue(Float.isNaN(mService.mService.getThermalHeadroom(10)));
        assertEquals(1, mFakeHal.mForecastSkinTemperaturesCalled);
        mFakeHal.enableForecastSkinTemperature();
        assertFalse(Float.isNaN(mService.mService.getThermalHeadroom(10)));
        assertEquals(2, mFakeHal.mForecastSkinTemperaturesCalled);
        mFakeHal.failForecastSkinTemperature();
        assertTrue(Float.isNaN(mService.mService.getThermalHeadroom(10)));
        assertEquals(3, mFakeHal.mForecastSkinTemperaturesCalled);
    }

    @Test
    @EnableFlags({Flags.FLAG_ALLOW_THERMAL_THRESHOLDS_CALLBACK,
            Flags.FLAG_ALLOW_THERMAL_HEADROOM_THRESHOLDS})
    public void testTemperatureWatcherUpdateSevereThresholds() throws Exception {
        assertTrue(mService.mService.registerThermalHeadroomListener(mHeadroomListener));
        verify(mHeadroomListener, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onHeadroomChange(eq(0.6f), eq(0.6f), anyInt(),
                aryEq(new float[]{Float.NaN, 0.6666667f, 0.8333333f, 1.0f, 1.1666666f, 1.3333334f,
                        1.5f}));
        resetListenerMock();
        TemperatureWatcher watcher = mService.mTemperatureWatcher;
        TemperatureThreshold newThreshold = new TemperatureThreshold();
        newThreshold.name = "skin1";
        newThreshold.type = Temperature.TYPE_SKIN;
        // significant change in threshold (> 0.3C) should trigger a callback
        newThreshold.hotThrottlingThresholds = new float[]{
                Float.NaN, 43.0f, 46.0f, 49.0f, Float.NaN, Float.NaN, Float.NaN
        };
        mFakeHal.mCallback.onThresholdChanged(newThreshold);
        synchronized (watcher.mSamples) {
            Float threshold = watcher.mSevereThresholds.get("skin1");
            assertNotNull(threshold);
            assertEquals(49.0f, threshold, 0.0f);
            assertArrayEquals("Got" + Arrays.toString(watcher.mHeadroomThresholds),
                    new float[]{Float.NaN, 0.8f, 0.9f, 1.0f, Float.NaN, Float.NaN, Float.NaN},
                    watcher.mHeadroomThresholds, 0.01f);
        }
        verify(mHeadroomListener, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(1)).onHeadroomChange(eq(0.3f), eq(0.3f), anyInt(),
                aryEq(new float[]{Float.NaN, 0.8f, 0.9f, 1.0f, Float.NaN, Float.NaN, Float.NaN}));
        resetListenerMock();

        // same or similar threshold callback data within a second should not trigger callback
        mFakeHal.mCallback.onThresholdChanged(newThreshold);
        newThreshold.hotThrottlingThresholds = new float[]{
                Float.NaN, 43.1f, 45.9f, 49.0f, Float.NaN, Float.NaN, Float.NaN
        };
        mFakeHal.mCallback.onThresholdChanged(newThreshold);
        verify(mHeadroomListener, timeout(CALLBACK_TIMEOUT_MILLI_SEC)
                .times(0)).onHeadroomChange(anyFloat(), anyFloat(), anyInt(), any());
    }

    @Test
    public void testTemperatureWatcherUpdateHeadroomThreshold() {
        TemperatureWatcher watcher = mService.mTemperatureWatcher;
        synchronized (watcher.mSamples) {
            Arrays.fill(watcher.mHeadroomThresholds, Float.NaN);
        }
        TemperatureThreshold threshold = new TemperatureThreshold();
        threshold.hotThrottlingThresholds = new float[]{Float.NaN, 40, 46, 49, 64, 70, 79};
        synchronized (watcher.mSamples) {
            watcher.updateTemperatureThresholdLocked(threshold, false /*override*/);
            assertArrayEquals(new float[]{Float.NaN, 0.7f, 0.9f, 1.0f, 1.5f, 1.7f, 2.0f},
                    watcher.mHeadroomThresholds, 0.01f);
        }

        // when another sensor reports different threshold, we expect to see smaller one to be used
        threshold = new TemperatureThreshold();
        threshold.hotThrottlingThresholds = new float[]{Float.NaN, 37, 46, 52, 64, 100, 200};
        synchronized (watcher.mSamples) {
            watcher.updateTemperatureThresholdLocked(threshold, false /*override*/);
            assertArrayEquals(new float[]{Float.NaN, 0.5f, 0.8f, 1.0f, 1.4f, 1.7f, 2.0f},
                    watcher.mHeadroomThresholds, 0.01f);
        }
    }

    @Test
    public void testGetThermalHeadroomThresholds() throws Exception {
        float[] expected = new float[]{Float.NaN, 0.1f, 0.2f, 0.3f, 0.4f, Float.NaN, 0.6f};
        when(mIThermalServiceMock.getThermalHeadroomThresholds()).thenReturn(expected);
        Map<Integer, Float> thresholds1 = mPowerManager.getThermalHeadroomThresholds();
        verify(mIThermalServiceMock, times(1)).getThermalHeadroomThresholds();
        checkHeadroomThresholds(expected, thresholds1);

        reset(mIThermalServiceMock);
        expected = new float[]{Float.NaN, 0.2f, 0.3f, 0.4f, 0.4f, Float.NaN, 0.6f};
        when(mIThermalServiceMock.getThermalHeadroomThresholds()).thenReturn(expected);
        Map<Integer, Float> thresholds2 = mPowerManager.getThermalHeadroomThresholds();
        verify(mIThermalServiceMock, times(1)).getThermalHeadroomThresholds();
        checkHeadroomThresholds(expected, thresholds2);
    }

    private void checkHeadroomThresholds(float[] expected, Map<Integer, Float> thresholds) {
        for (int status = PowerManager.THERMAL_STATUS_LIGHT;
                status <= PowerManager.THERMAL_STATUS_SHUTDOWN; status++) {
            if (Float.isNaN(expected[status])) {
                assertFalse(thresholds.containsKey(status));
            } else {
                assertEquals(expected[status], thresholds.get(status), 0.01f);
            }
        }
    }

    @Test
    public void testGetThermalHeadroomThresholdsOnDefaultHalResult() throws Exception {
        TemperatureWatcher watcher = mService.mTemperatureWatcher;
        ArrayList<TemperatureThreshold> thresholds = new ArrayList<>();
        mFakeHal.mTemperatureThresholdList = thresholds;
        watcher.getAndUpdateThresholds();
        synchronized (watcher.mSamples) {
            assertArrayEquals(
                    new float[]{Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN,
                            Float.NaN},
                    watcher.mHeadroomThresholds, 0.01f);
        }
        TemperatureThreshold nanThresholds = new TemperatureThreshold();
        nanThresholds.name = "nan";
        nanThresholds.type = Temperature.TYPE_SKIN;
        nanThresholds.hotThrottlingThresholds = new float[ThrottlingSeverity.SHUTDOWN + 1];
        nanThresholds.coldThrottlingThresholds = new float[ThrottlingSeverity.SHUTDOWN + 1];
        Arrays.fill(nanThresholds.hotThrottlingThresholds, Float.NaN);
        Arrays.fill(nanThresholds.coldThrottlingThresholds, Float.NaN);
        thresholds.add(nanThresholds);
        watcher.getAndUpdateThresholds();
        synchronized (watcher.mSamples) {
            assertArrayEquals(
                    new float[]{Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN,
                            Float.NaN},
                    watcher.mHeadroomThresholds, 0.01f);
        }
    }

    @Test
    public void testTemperatureWatcherGetSlopeOf() throws RemoteException {
        TemperatureWatcher watcher = mService.mTemperatureWatcher;
        List<TemperatureWatcher.Sample> samples = new ArrayList<>();
        for (int i = 0; i < 30; ++i) {
            samples.add(watcher.createSampleForTesting(i, (float) (i / 2 * 2)));
        }
        assertEquals(1.0f, watcher.getSlopeOf(samples), 0.01f);
    }

    @Test
    public void testTemperatureWatcherNormalizeTemperature() throws RemoteException {
        assertEquals(0.5f,
                TemperatureWatcher.normalizeTemperature(25.0f, 40.0f), 0.0f);

        // Temperatures more than 30 degrees below the SEVERE threshold should be clamped to 0.0f
        assertEquals(0.0f,
                TemperatureWatcher.normalizeTemperature(0.0f, 40.0f), 0.0f);

        // Temperatures above the SEVERE threshold should not be clamped
        assertEquals(2.0f,
                TemperatureWatcher.normalizeTemperature(70.0f, 40.0f), 0.0f);
    }

    @Test
    public void testTemperatureWatcherGetForecast() throws RemoteException {
        TemperatureWatcher watcher = mService.mTemperatureWatcher;

        ArrayList<TemperatureWatcher.Sample> samples = new ArrayList<>();

        // Add a single sample
        samples.add(watcher.createSampleForTesting(0, 25.0f));
        watcher.mSamples.put("skin1", samples);

        // Because there are not enough samples to compute the linear regression,
        // no matter how far ahead we forecast, we should receive the same value
        assertEquals(0.5f, watcher.getForecast(0), 0.0f);
        assertEquals(0.5f, watcher.getForecast(5), 0.0f);

        // Add some time-series data
        for (int i = 1; i < 20; ++i) {
            samples.add(watcher.createSampleForTesting(1000 * i, 25.0f + 0.5f * i));
        }

        // Now the forecast should vary depending on how far ahead we are trying to predict
        assertEquals(0.9f, watcher.getForecast(4), 0.02f);
        assertEquals(1.0f, watcher.getForecast(10), 0.02f);

        // If there are no thresholds, then we shouldn't receive a headroom value
        watcher.mSevereThresholds.erase();
        assertTrue(Float.isNaN(watcher.getForecast(0)));
    }

    @Test
    public void testTemperatureWatcherGetForecastUpdate() throws Exception {
        TemperatureWatcher watcher = mService.mTemperatureWatcher;

        // Reduce the inactivity threshold to speed up testing
        watcher.mInactivityThresholdMillis = 2000;

        // Make sure mSamples is empty before updateTemperature
        assertTrue(isWatcherSamplesEmpty(watcher));

        // Call getForecast once to trigger updateTemperature
        watcher.getForecast(0);

        // After 1 second, the samples should be updated
        Thread.sleep(1000);
        assertFalse(isWatcherSamplesEmpty(watcher));

        // After mInactivityThresholdMillis, the samples should be cleared
        Thread.sleep(watcher.mInactivityThresholdMillis);
        assertTrue(isWatcherSamplesEmpty(watcher));
    }

    // Helper function to hold mSamples lock, avoid GuardedBy lint errors
    private boolean isWatcherSamplesEmpty(TemperatureWatcher watcher) {
        synchronized (watcher.mSamples) {
            return watcher.mSamples.isEmpty();
        }
    }

    @Test
    public void testDump() throws Exception {
        assertTrue(mService.mService.registerThermalEventListener(mEventListener1));
        assertTrue(mService.mService.registerThermalStatusListener(mStatusListener1));
        assertTrue(mService.mService.registerThermalEventListenerWithType(mEventListener2,
                Temperature.TYPE_SKIN));
        assertTrue(mService.mService.registerThermalStatusListener(mStatusListener2));

        when(mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP))
                .thenReturn(PackageManager.PERMISSION_GRANTED);
        final StringWriter out = new StringWriter();
        PrintWriter pw = new PrintWriter(out);
        mService.dumpInternal(new FileDescriptor(), pw, null);
        final String dumpStr = out.toString();
        assertThat(dumpStr).contains("IsStatusOverride: false");
        assertThat(dumpStr).contains(
                "ThermalEventListeners:\n"
                        + "\tcallbacks: 2\n"
                        + "\tkilled: false\n"
                        + "\tbroadcasts count: -1");
        assertThat(dumpStr).contains(
                "ThermalStatusListeners:\n"
                        + "\tcallbacks: 2\n"
                        + "\tkilled: false\n"
                        + "\tbroadcasts count: -1");
        assertThat(dumpStr).contains("Thermal Status: 0");
        assertThat(dumpStr).contains(
                "Cached temperatures:\n"
                        + "\tTemperature{mValue=37.0, mType=4, mName=usbport, mStatus=0}\n"
                        + "\tTemperature{mValue=34.0, mType=2, mName=batt, mStatus=0}\n"
                        + "\tTemperature{mValue=28.0, mType=3, mName=skin1, mStatus=0}\n"
                        + "\tTemperature{mValue=31.0, mType=3, mName=skin2, mStatus=0}"
        );
        assertThat(dumpStr).contains("HAL Ready: true\n"
                + "HAL connection:\n"
                + "\tThermalHAL AIDL 1  connected: yes");
        assertThat(dumpStr).contains("Current temperatures from HAL:\n"
                + "\tTemperature{mValue=28.0, mType=3, mName=skin1, mStatus=0}\n"
                + "\tTemperature{mValue=31.0, mType=3, mName=skin2, mStatus=0}\n"
                + "\tTemperature{mValue=34.0, mType=2, mName=batt, mStatus=0}\n"
                + "\tTemperature{mValue=37.0, mType=4, mName=usbport, mStatus=0}\n");
        assertThat(dumpStr).contains("Current cooling devices from HAL:\n"
                + "\tCoolingDevice{mValue=40, mType=1, mName=cpu}\n"
                + "\tCoolingDevice{mValue=43, mType=1, mName=gpu}\n");
        assertThat(dumpStr).contains("Temperature static thresholds from HAL:\n"
                + "\tTemperatureThreshold{mType=3, mName=skin1, mHotThrottlingThresholds=[25.0, "
                + "30.0, 35.0, 40.0, 45.0, 50.0, 55.0], mColdThrottlingThresholds=[0.0, 0.0, 0.0,"
                + " 0.0, 0.0, 0.0, 0.0]}\n"
                + "\tTemperatureThreshold{mType=0, mName=cpu, mHotThrottlingThresholds=[NaN, NaN,"
                + " NaN, 95.0, NaN, NaN, NaN], mColdThrottlingThresholds=[0.0, 0.0, 0.0, 0.0, 0"
                + ".0, 0.0, 0.0]}");
    }
}
