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

package com.android.systemui.ambient.touch.scrim;

import com.android.systemui.shade.ShadeExpansionChangeEvent;

/**
 * {@link ScrimController} provides an interface for the different consumers of scrolling/expansion
 * events over the dream.
 */
public interface ScrimController {
    /**
     * Called at the start of expansion before any expansion amount updates.
     * @param scrimmed true when the bouncer should show scrimmed, false when user will be dragging.
     */
    default void show(boolean scrimmed) {
    }

    /**
     * Called for every expansion update.
     * @param event {@link ShadeExpansionChangeEvent} detailing the change.
     */
    default void expand(ShadeExpansionChangeEvent event) {
    }

    /**
     * Called at the end of the movement.
     */
    default void reset() {
    }
}
