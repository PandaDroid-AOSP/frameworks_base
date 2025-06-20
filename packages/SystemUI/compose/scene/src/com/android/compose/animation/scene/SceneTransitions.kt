/*
 * Copyright 2023 The Android Open Source Project
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

import androidx.compose.animation.core.AnimationSpec
import androidx.compose.animation.core.snap
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.util.fastForEach
import com.android.compose.animation.scene.content.state.TransitionState
import com.android.compose.animation.scene.transformation.PropertyTransformation
import com.android.compose.animation.scene.transformation.SharedElementTransformation
import com.android.compose.animation.scene.transformation.TransformationMatcher
import com.android.compose.animation.scene.transformation.TransformationWithRange
import com.android.internal.jank.Cuj.CujType

/** The transitions configuration of a [SceneTransitionLayout]. */
class SceneTransitions
internal constructor(
    internal val transitionSpecs: List<TransitionSpecImpl>,
    internal val interruptionHandler: InterruptionHandler,
) {
    private val transitionCache =
        mutableMapOf<
            ContentKey,
            MutableMap<ContentKey, MutableMap<TransitionKey?, TransitionSpecImpl>>,
        >()

    internal fun transitionSpec(
        from: ContentKey,
        to: ContentKey,
        key: TransitionKey?,
    ): TransitionSpecImpl {
        return transitionCache
            .getOrPut(from) { mutableMapOf() }
            .getOrPut(to) { mutableMapOf() }
            .getOrPut(key) { findSpec(from, to, key) }
    }

    private fun findSpec(
        from: ContentKey,
        to: ContentKey,
        key: TransitionKey?,
    ): TransitionSpecImpl {
        val spec = transition(from, to, key) { it.from == from && it.to == to }
        if (spec != null) {
            return spec
        }

        val reversed = transition(from, to, key) { it.from == to && it.to == from }
        if (reversed != null) {
            return reversed.reversed()
        }

        val relaxedSpec =
            transition(from, to, key) {
                (it.from == from && it.to == null) || (it.to == to && it.from == null)
            }
        if (relaxedSpec != null) {
            return relaxedSpec
        }

        val relaxedReversed =
            transition(from, to, key) {
                (it.from == to && it.to == null) || (it.to == from && it.from == null)
            }
        if (relaxedReversed != null) {
            return relaxedReversed.reversed()
        }

        return if (key != null) {
            findSpec(from, to, null)
        } else {
            defaultTransition(from, to)
        }
    }

    private fun transition(
        from: ContentKey,
        to: ContentKey,
        key: TransitionKey?,
        filter: (TransitionSpecImpl) -> Boolean,
    ): TransitionSpecImpl? {
        var match: TransitionSpecImpl? = null
        transitionSpecs.fastForEach { spec ->
            if (spec.key == key && filter(spec)) {
                if (match != null) {
                    error("Found multiple transition specs for transition $from => $to")
                }
                match = spec
            }
        }
        return match
    }

    private fun defaultTransition(from: ContentKey, to: ContentKey) =
        TransitionSpecImpl(
            key = null,
            from,
            to,
            cuj = null,
            previewTransformationSpec = null,
            reversePreviewTransformationSpec = null,
            TransformationSpec.EmptyProvider,
        )

    companion object {
        val Empty =
            SceneTransitions(
                transitionSpecs = emptyList(),
                interruptionHandler = DefaultInterruptionHandler,
            )
    }
}

/** The definition of a transition between [from] and [to]. */
internal interface TransitionSpec {
    /** The key of this [TransitionSpec]. */
    val key: TransitionKey?

    /**
     * The content we are transitioning from. If `null`, this spec can be used to animate from any
     * content.
     */
    val from: ContentKey?

    /**
     * The content we are transitioning to. If `null`, this spec can be used to animate from any
     * content.
     */
    val to: ContentKey?

    /** The CUJ covered by this transition. */
    @CujType val cuj: Int?

    /**
     * Return a reversed version of this [TransitionSpec] for a transition going from [to] to
     * [from].
     */
    fun reversed(): TransitionSpec

    /**
     * The [TransformationSpec] associated to this [TransitionSpec] for the given [transition].
     *
     * Note that this is called once whenever a transition associated to this [TransitionSpec] is
     * started.
     */
    fun transformationSpec(transition: TransitionState.Transition): TransformationSpec

    /**
     * The preview [TransformationSpec] associated to this [TransitionSpec] for the given
     * [transition].
     *
     * Note that this is called once whenever a transition associated to this [TransitionSpec] is
     * started.
     */
    fun previewTransformationSpec(transition: TransitionState.Transition): TransformationSpec?
}

internal interface TransformationSpec {
    /**
     * The [AnimationSpec] used to animate the associated transition progress from `0` to `1` when
     * the transition is triggered (i.e. it is not gesture-based).
     */
    val progressSpec: AnimationSpec<Float>?

    /**
     * The distance it takes for this transition to animate from 0% to 100% when it is driven by a
     * [UserAction].
     *
     * If `null`, a default distance will be used that depends on the [UserAction] performed.
     */
    val distance: UserActionDistance?

    /** The list of [TransformationMatcher] applied to elements during this transformation. */
    val transformationMatchers: List<TransformationMatcher>

    companion object {
        internal val Empty =
            TransformationSpecImpl(
                progressSpec = snap(),
                distance = null,
                transformationMatchers = emptyList(),
            )
        internal val EmptyProvider = { _: TransitionState.Transition -> Empty }
    }
}

internal class TransitionSpecImpl(
    override val key: TransitionKey?,
    override val from: ContentKey?,
    override val to: ContentKey?,
    override val cuj: Int?,
    private val previewTransformationSpec:
        ((TransitionState.Transition) -> TransformationSpecImpl)? =
        null,
    private val reversePreviewTransformationSpec:
        ((TransitionState.Transition) -> TransformationSpecImpl)? =
        null,
    private val transformationSpec: (TransitionState.Transition) -> TransformationSpecImpl,
) : TransitionSpec {
    override fun reversed(): TransitionSpecImpl {
        return TransitionSpecImpl(
            key = key,
            from = to,
            to = from,
            cuj = cuj,
            previewTransformationSpec = reversePreviewTransformationSpec,
            reversePreviewTransformationSpec = previewTransformationSpec,
            transformationSpec = { transition ->
                val reverse = transformationSpec.invoke(transition)
                TransformationSpecImpl(
                    progressSpec = reverse.progressSpec,
                    distance = reverse.distance,
                    transformationMatchers =
                        reverse.transformationMatchers.map {
                            TransformationMatcher(
                                matcher = it.matcher,
                                factory = it.factory,
                                range = it.range?.reversed(),
                            )
                        },
                )
            },
        )
    }

    override fun transformationSpec(
        transition: TransitionState.Transition
    ): TransformationSpecImpl = transformationSpec.invoke(transition)

    override fun previewTransformationSpec(
        transition: TransitionState.Transition
    ): TransformationSpecImpl? = previewTransformationSpec?.invoke(transition)
}

/**
 * An implementation of [TransformationSpec] that allows the quick retrieval of an element
 * [ElementTransformations].
 */
internal class TransformationSpecImpl(
    override val progressSpec: AnimationSpec<Float>?,
    override val distance: UserActionDistance?,
    override val transformationMatchers: List<TransformationMatcher>,
) : TransformationSpec {
    private val cache = mutableMapOf<ElementKey, MutableMap<ContentKey, ElementTransformations?>>()

    internal fun transformations(
        element: ElementKey,
        content: ContentKey,
    ): ElementTransformations? {
        return cache
            .getOrPut(element) { mutableMapOf() }
            .getOrPut(content) { computeTransformations(element, content) }
    }

    internal fun hasTransformation(element: ElementKey, content: ContentKey): Boolean {
        return transformations(element, content) != null
    }

    /** Filter [transformationMatchers] to compute the [ElementTransformations] of [element]. */
    private fun computeTransformations(
        element: ElementKey,
        content: ContentKey,
    ): ElementTransformations? {
        var shared: TransformationWithRange<SharedElementTransformation>? = null
        var offset: TransformationWithRange<PropertyTransformation<Offset>>? = null
        var size: TransformationWithRange<PropertyTransformation<IntSize>>? = null
        var drawScale: TransformationWithRange<PropertyTransformation<Scale>>? = null
        var alpha: TransformationWithRange<PropertyTransformation<Float>>? = null

        transformationMatchers.fastForEach { transformationMatcher ->
            if (!transformationMatcher.matcher.matches(element, content)) {
                return@fastForEach
            }

            val transformation = transformationMatcher.factory.create()
            val property =
                when (transformation) {
                    is SharedElementTransformation -> {
                        throwIfNotNull(shared, element, name = "shared")
                        shared =
                            TransformationWithRange(transformation, transformationMatcher.range)
                        return@fastForEach
                    }
                    is PropertyTransformation<*> -> transformation.property
                }

            when (property) {
                is PropertyTransformation.Property.Offset -> {
                    throwIfNotNull(offset, element, name = "offset")
                    offset =
                        TransformationWithRange(
                            transformation as PropertyTransformation<Offset>,
                            transformationMatcher.range,
                        )
                }
                is PropertyTransformation.Property.Size -> {
                    throwIfNotNull(size, element, name = "size")
                    size =
                        TransformationWithRange(
                            transformation as PropertyTransformation<IntSize>,
                            transformationMatcher.range,
                        )
                }
                is PropertyTransformation.Property.Scale -> {
                    throwIfNotNull(drawScale, element, name = "drawScale")
                    drawScale =
                        TransformationWithRange(
                            transformation as PropertyTransformation<Scale>,
                            transformationMatcher.range,
                        )
                }
                is PropertyTransformation.Property.Alpha -> {
                    throwIfNotNull(alpha, element, name = "alpha")
                    alpha =
                        TransformationWithRange(
                            transformation as PropertyTransformation<Float>,
                            transformationMatcher.range,
                        )
                }
            }
        }

        return if (
            shared == null && offset == null && size == null && drawScale == null && alpha == null
        ) {
            null
        } else {
            ElementTransformations(shared, offset, size, drawScale, alpha)
        }
    }

    private fun throwIfNotNull(
        previous: TransformationWithRange<*>?,
        element: ElementKey,
        name: String,
    ) {
        if (previous != null) {
            error("$element has multiple $name transformations")
        }
    }
}

/** The transformations of an element during a transition. */
internal class ElementTransformations(
    val shared: TransformationWithRange<SharedElementTransformation>?,
    val offset: TransformationWithRange<PropertyTransformation<Offset>>?,
    val size: TransformationWithRange<PropertyTransformation<IntSize>>?,
    val drawScale: TransformationWithRange<PropertyTransformation<Scale>>?,
    val alpha: TransformationWithRange<PropertyTransformation<Float>>?,
)
