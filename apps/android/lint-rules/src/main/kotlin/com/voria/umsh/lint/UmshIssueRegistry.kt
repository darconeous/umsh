package com.voria.umsh.lint

import com.android.tools.lint.client.api.IssueRegistry
import com.android.tools.lint.client.api.Vendor
import com.android.tools.lint.detector.api.CURRENT_API
import com.android.tools.lint.detector.api.Issue

class UmshIssueRegistry : IssueRegistry() {
    override val issues: List<Issue> = listOf(ComposeLiteralTextDetector.ISSUE)
    override val api: Int = CURRENT_API
    override val minApi: Int = CURRENT_API
    override val vendor: Vendor = Vendor(vendorName = "UMSH")
}
