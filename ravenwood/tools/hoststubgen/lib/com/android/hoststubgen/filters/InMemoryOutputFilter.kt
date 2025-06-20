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
package com.android.hoststubgen.filters

import com.android.hoststubgen.addNonNullElement
import com.android.hoststubgen.asm.ClassNodes
import com.android.hoststubgen.asm.toHumanReadableClassName
import com.android.hoststubgen.asm.toHumanReadableMethodName
import com.android.hoststubgen.asm.toJvmClassName
import com.android.hoststubgen.log

// TODO: Validate all input names.

class InMemoryOutputFilter(
    private val classes: ClassNodes,
    fallback: OutputFilter,
) : DelegatingFilter(fallback) {
    private val mPolicies = mutableMapOf<String, FilterPolicyWithReason>()
    private val mRenames = mutableMapOf<String, String>()
    private val mRedirectionClasses = mutableMapOf<String, String>()
    private val mClassLoadHooks = mutableMapOf<String, String>()
    private val mMethodCallReplaceSpecs = mutableListOf<MethodCallReplaceSpec>()
    private val mTypeRenameSpecs = mutableListOf<TypeRenameSpec>()

    private fun getClassKey(className: String): String {
        return className.toHumanReadableClassName()
    }

    private fun getFieldKey(className: String, fieldName: String): String {
        return getClassKey(className) + "." + fieldName
    }

    private fun getMethodKey(className: String, methodName: String, signature: String): String {
        return getClassKey(className) + "." + methodName + ";" + signature
    }

    private fun checkClass(className: String) {
        if (classes.findClass(className) == null) {
            log.w("Unknown class $className")
        }
    }

    private fun checkField(className: String, fieldName: String) {
        if (classes.findField(className, fieldName) == null) {
            log.w("Unknown field $className.$fieldName")
        }
    }

    private fun checkMethod(
        className: String,
        methodName: String,
        descriptor: String
    ) {
        if (descriptor == "*") {
            return
        }
        if (classes.findMethod(className, methodName, descriptor) == null) {
            log.w("Unknown method $className.$methodName$descriptor")
        }
    }

    override fun getPolicyForClass(className: String): FilterPolicyWithReason {
        return mPolicies[getClassKey(className)] ?: super.getPolicyForClass(className)
    }

    fun setPolicyForClass(className: String, policy: FilterPolicyWithReason) {
        checkClass(className)
        mPolicies[getClassKey(className)] = policy
    }

    override fun getPolicyForField(className: String, fieldName: String): FilterPolicyWithReason {
        return mPolicies[getFieldKey(className, fieldName)]
            ?: super.getPolicyForField(className, fieldName)
    }

    fun setPolicyForField(className: String, fieldName: String, policy: FilterPolicyWithReason) {
        checkField(className, fieldName)
        mPolicies[getFieldKey(className, fieldName)] = policy
    }

    override fun getPolicyForMethod(
        className: String,
        methodName: String,
        descriptor: String,
    ): FilterPolicyWithReason {
        return mPolicies[getMethodKey(className, methodName, descriptor)]
            ?: mPolicies[getMethodKey(className, methodName, "*")]
            ?: super.getPolicyForMethod(className, methodName, descriptor)
    }

    fun setPolicyForMethod(
        className: String,
        methodName: String,
        descriptor: String,
        policy: FilterPolicyWithReason,
    ) {
        checkMethod(className, methodName, descriptor)
        mPolicies[getMethodKey(className, methodName, descriptor)] = policy
    }

    override fun getRenameTo(className: String, methodName: String, descriptor: String): String? {
        return mRenames[getMethodKey(className, methodName, descriptor)]
            ?: mRenames[getMethodKey(className, methodName, "*")]
            ?: super.getRenameTo(className, methodName, descriptor)
    }

    fun setRenameTo(className: String, methodName: String, descriptor: String, toName: String) {
        checkMethod(className, methodName, descriptor)
        checkMethod(className, toName, descriptor)
        mRenames[getMethodKey(className, methodName, descriptor)] = toName
    }

    override fun getRedirectionClass(className: String): String? {
        return mRedirectionClasses[getClassKey(className)]
            ?: super.getRedirectionClass(className)
    }

    fun setRedirectionClass(from: String, to: String) {
        checkClass(from)

        // Redirection classes may be provided from other jars, so we can't do this check.
        // ensureClassExists(to)
        mRedirectionClasses[getClassKey(from)] = to.toJvmClassName()
    }

    override fun getClassLoadHooks(className: String): List<String> {
        return addNonNullElement(
            super.getClassLoadHooks(className),
            mClassLoadHooks[getClassKey(className)]
        )
    }

    fun setClassLoadHook(className: String, methodName: String) {
        mClassLoadHooks[getClassKey(className)] = methodName.toHumanReadableMethodName()
    }

    override fun hasAnyMethodCallReplace(): Boolean {
        return mMethodCallReplaceSpecs.isNotEmpty() || super.hasAnyMethodCallReplace()
    }

    override fun getMethodCallReplaceTo(
        className: String,
        methodName: String,
        descriptor: String,
    ): MethodReplaceTarget? {
        // Maybe use 'Tri' if we end up having too many replacements.
        mMethodCallReplaceSpecs.forEach {
            if (className == it.fromClass &&
                methodName == it.fromMethod
            ) {
                if (it.fromDescriptor == "*" || descriptor == it.fromDescriptor) {
                    return MethodReplaceTarget(it.toClass, it.toMethod)
                }
            }
        }
        return super.getMethodCallReplaceTo(className, methodName, descriptor)
    }

    fun setMethodCallReplaceSpec(spec: MethodCallReplaceSpec) {
        mMethodCallReplaceSpecs.add(spec)
    }

    override fun remapType(className: String): String? {
        mTypeRenameSpecs.forEach {
            if (it.typeInternalNamePattern.matcher(className).matches()) {
                return it.typeInternalNamePrefix + className
            }
        }
        return super.remapType(className)
    }

    fun setRemapTypeSpec(spec: TypeRenameSpec) {
        mTypeRenameSpecs.add(spec)
    }
}
