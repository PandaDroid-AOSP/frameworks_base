/*
 * Copyright (C) 2023 The Android Open Source Project
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

package com.android.systemui.notetask

import android.content.Intent
import android.graphics.drawable.Icon
import android.os.UserHandle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.android.systemui.SysuiTestCase
import com.android.systemui.notetask.NoteTaskBubblesController.NoteTaskBubblesService
import com.android.systemui.res.R
import com.android.wm.shell.bubbles.Bubbles
import com.google.common.truth.Truth.assertThat
import java.util.Optional
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito.verify
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.never
import org.mockito.kotlin.whenever

/** atest SystemUITests:NoteTaskBubblesServiceTest */
@SmallTest
@RunWith(AndroidJUnit4::class)
internal class NoteTaskBubblesServiceTest : SysuiTestCase() {

    @Mock private lateinit var bubbles: Bubbles

    private fun createServiceBinder(bubbles: Bubbles? = this.bubbles) =
        NoteTaskBubblesService(Optional.ofNullable(bubbles)).onBind(Intent())
            as INoteTaskBubblesService

    @Before
    fun setUp() {
        MockitoAnnotations.initMocks(this)
    }

    @Test
    fun areBubblesAvailable_bubblesNotNull_shouldReturnTrue() {
        assertThat(createServiceBinder().areBubblesAvailable()).isTrue()
    }

    @Test
    fun areBubblesAvailable_bubblesNull_shouldReturnFalse() {
        assertThat(createServiceBinder(bubbles = null).areBubblesAvailable()).isFalse()
    }

    @Test
    fun showOrHideNoteBubble_defaultExpandBehavior_shouldCallBubblesApi() {
        val intent = Intent()
        val user = UserHandle.SYSTEM
        val icon = Icon.createWithResource(context, R.drawable.ic_note_task_shortcut_widget)
        val bubbleExpandBehavior = NoteTaskBubbleExpandBehavior.DEFAULT
        whenever(bubbles.isBubbleExpanded(any())).thenReturn(false)

        createServiceBinder().showOrHideNoteBubble(intent, user, icon, bubbleExpandBehavior)

        verify(bubbles).showOrHideNoteBubble(intent, user, icon)
    }

    @Test
    fun showOrHideNoteBubble_keepIfExpanded_bubbleShown_shouldNotCallBubblesApi() {
        val intent = Intent().apply { setPackage("test") }
        val user = UserHandle.SYSTEM
        val icon = Icon.createWithResource(context, R.drawable.ic_note_task_shortcut_widget)
        val bubbleExpandBehavior = NoteTaskBubbleExpandBehavior.KEEP_IF_EXPANDED
        whenever(bubbles.isBubbleExpanded(any())).thenReturn(true)

        createServiceBinder().showOrHideNoteBubble(intent, user, icon, bubbleExpandBehavior)

        verify(bubbles, never()).showOrHideNoteBubble(intent, user, icon)
    }

    @Test
    fun showOrHideNoteBubble_keepIfExpanded_bubbleNotShown_shouldCallBubblesApi() {
        val intent = Intent().apply { setPackage("test") }
        val user = UserHandle.SYSTEM
        val icon = Icon.createWithResource(context, R.drawable.ic_note_task_shortcut_widget)
        val bubbleExpandBehavior = NoteTaskBubbleExpandBehavior.KEEP_IF_EXPANDED
        whenever(bubbles.isBubbleExpanded(any())).thenReturn(false)

        createServiceBinder().showOrHideNoteBubble(intent, user, icon, bubbleExpandBehavior)

        verify(bubbles).showOrHideNoteBubble(intent, user, icon)
    }
}
