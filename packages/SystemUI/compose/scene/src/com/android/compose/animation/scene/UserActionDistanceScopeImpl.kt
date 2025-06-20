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

package com.android.compose.animation.scene

import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.MotionScheme
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import com.android.compose.animation.scene.transformation.PropertyTransformationScope

internal class ElementStateScopeImpl(private val layoutImpl: SceneTransitionLayoutImpl) :
    ElementStateScope {
    override fun ElementKey.targetSize(content: ContentKey): IntSize? {
        return layoutImpl.elements[this]?.stateByContent?.get(content)?.targetSize.takeIf {
            it != Element.SizeUnspecified
        }
    }

    override fun ElementKey.approachSize(content: ContentKey): IntSize? {
        return layoutImpl.elements[this]?.stateByContent?.get(content)?.approachSize.takeIf {
            it != Element.SizeUnspecified
        }
    }

    override fun ElementKey.targetOffset(content: ContentKey): Offset? {
        return layoutImpl.elements[this]?.stateByContent?.get(content)?.targetOffset.takeIf {
            it != Offset.Unspecified
        }
    }

    override fun ContentKey.targetSize(): IntSize? {
        return layoutImpl.content(this).targetSize.takeIf { it != Element.SizeUnspecified }
    }
}

internal class UserActionDistanceScopeImpl(private val layoutImpl: SceneTransitionLayoutImpl) :
    UserActionDistanceScope, ElementStateScope by layoutImpl.elementStateScope {
    override val density: Float
        get() = layoutImpl.density.density

    override val fontScale: Float
        get() = layoutImpl.density.fontScale
}

internal class PropertyTransformationScopeImpl(private val layoutImpl: SceneTransitionLayoutImpl) :
    PropertyTransformationScope, ElementStateScope by layoutImpl.elementStateScope {
    override val density: Float
        get() = layoutImpl.density.density

    override val fontScale: Float
        get() = layoutImpl.density.fontScale

    override val layoutDirection: LayoutDirection
        get() = layoutImpl.layoutDirection

    @ExperimentalMaterial3ExpressiveApi
    override val motionScheme: MotionScheme
        get() = layoutImpl.state.motionScheme
}
