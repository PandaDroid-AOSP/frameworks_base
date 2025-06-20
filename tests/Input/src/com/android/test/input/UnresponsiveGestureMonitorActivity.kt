/**
 * Copyright (c) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

// InputMonitor is deprecated, but we still need to test it.
@file:Suppress("DEPRECATION")

package com.android.test.input

import android.app.Activity
import android.hardware.input.InputManager
import android.os.Bundle
import android.os.Looper
import android.os.Process
import android.util.Log
import android.view.InputChannel
import android.view.InputEvent
import android.view.InputEventReceiver
import android.view.InputMonitor
import android.view.MotionEvent

class UnresponsiveReceiver(channel: InputChannel, looper: Looper, val service: IAnrTestService) :
    InputEventReceiver(channel, looper) {
    companion object {
        const val TAG = "UnresponsiveReceiver"
    }

    override fun onInputEvent(event: InputEvent) {
        Log.i(TAG, "Received $event")
        // Not calling 'finishInputEvent' in order to trigger the ANR
        service.notifyMotion(event as MotionEvent)
    }
}

class UnresponsiveGestureMonitorActivity : Activity() {
    companion object {
        const val MONITOR_NAME = "unresponsive gesture monitor"
    }

    private lateinit var mInputEventReceiver: InputEventReceiver
    private lateinit var mInputMonitor: InputMonitor
    private lateinit var service: IAnrTestService

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val bundle = intent.getBundleExtra("serviceBundle")!!
        service = IAnrTestService.Stub.asInterface(bundle.getBinder("serviceBinder"))
        val inputManager = checkNotNull(getSystemService(InputManager::class.java))
        mInputMonitor = inputManager.monitorGestureInput(MONITOR_NAME, displayId)
        mInputEventReceiver =
            UnresponsiveReceiver(mInputMonitor.getInputChannel(), Looper.myLooper()!!, service)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        service.provideActivityInfo(
            window.decorView.windowToken,
            display.displayId,
            Process.myPid(),
        )
    }
}
