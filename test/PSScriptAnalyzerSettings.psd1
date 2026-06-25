@{
    Severity = @('Error', 'Warning')
    ExcludeRules = @(
        # Install UX is intentionally console output, not a pipeline object.
        'PSAvoidUsingWriteHost',
        # False positives: Remove-CynPathEntry is a PURE string function; New-CynTempDir and
        # Remove-CynFromUserPath are thin helpers - ShouldProcess plumbing would be overbuild.
        'PSUseShouldProcessForStateChangingFunctions',
        # False positive: 'Test-CynPathContains' parses as a plural noun but is correctly named.
        'PSUseSingularNouns'
    )
}
