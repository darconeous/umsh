package com.voria.umsh.app.debug

import androidx.compose.runtime.Composable
import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.AppRuntime

/** Release builds have no Developer section; the debug source set's is the real one. */
@Suppress("UNUSED_PARAMETER")
@Composable
fun DeveloperSection(host: AppCoreHost, runtime: AppRuntime) = Unit

/** Release builds have no staging store; the debug source set's is the real one. */
@Suppress("UNUSED_PARAMETER")
@Composable
fun StagingStoreActions(host: AppCoreHost) = Unit
