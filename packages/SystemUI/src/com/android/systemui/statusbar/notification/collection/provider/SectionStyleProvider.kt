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

package com.android.systemui.statusbar.notification.collection.provider

import com.android.systemui.dagger.SysUISingleton
import com.android.systemui.statusbar.notification.collection.PipelineEntry
import com.android.systemui.statusbar.notification.collection.SortBySectionTimeFlag
import com.android.systemui.statusbar.notification.collection.listbuilder.NotifSection
import com.android.systemui.statusbar.notification.collection.listbuilder.pluggable.NotifSectioner
import com.android.systemui.statusbar.notification.stack.BUCKET_PEOPLE
import javax.inject.Inject

/**
 * A class which is used to classify the sections.
 * NOTE: This class exists to avoid putting metadata like "isMinimized" on the NotifSection
 */
@SysUISingleton
class SectionStyleProvider @Inject constructor(
        private val highPriorityProvider: HighPriorityProvider) {
    private lateinit var silentSections: Set<NotifSectioner>
    private lateinit var lowPrioritySections: Set<NotifSectioner>

    /**
     * Feed the provider the information it needs about which sections should have minimized top
     * level views, so that it can calculate the correct minimized state.
     */
    fun setMinimizedSections(sections: Collection<NotifSectioner>) {
        lowPrioritySections = sections.toSet()
    }

    /**
     * Determine if the given section is minimized.
     */
    fun isMinimizedSection(section: NotifSection): Boolean {
        return lowPrioritySections.contains(section.sectioner)
    }

    /**
     * Determine if the given entry is minimized.
     */
    @JvmOverloads
    fun isMinimized(entry: PipelineEntry, ifNotInSection: Boolean = true): Boolean {
        val section = entry.section ?: return ifNotInSection
        return isMinimizedSection(section)
    }

    /**
     * Feed the provider the information it needs about which sections are silent, so that it can
     * calculate which entries are in a "silent" section.
     */
    fun setSilentSections(sections: Collection<NotifSectioner>) {
        silentSections = sections.toSet()
    }

    /**
     * Determine if the given section is silent.
     */
    fun isSilentSection(section: NotifSection): Boolean {
        return silentSections.contains(section.sectioner)
    }

    /**
     * Determine if the given entry is silent.
     */
    @JvmOverloads
    fun isSilent(entry: PipelineEntry, ifNotInSection: Boolean = true): Boolean {
        val section = entry.section ?: return ifNotInSection
        if (SortBySectionTimeFlag.isEnabled) {
            if (entry.section?.bucket == BUCKET_PEOPLE) {
                return !highPriorityProvider.isHighPriorityConversation(entry)
            }
            return isSilentSection(section)
        } else {
            return isSilentSection(section)
        }
    }
}
