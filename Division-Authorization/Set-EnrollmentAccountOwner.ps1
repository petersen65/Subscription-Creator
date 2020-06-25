<#
    .SYNOPSIS
        Assign a new owner to an existing Azure enrollment account (EA portal view).

    .DESCRIPTION
        The existing cloud context account is used to grant permissions for an existing
        service principal to an enrollment account. The service principal can be created as part
        of an Azure Automation account creation (run-as connection).

        PREREQUISITES
        The existing cloud context account needs to be in the Owner role on the target enrollment account.

        REQUIRED AUTOMATION ASSETS
        N/A

    .PARAMETER AccountOwnerObjectId
        Azure AD service principal object id that will be granted the Owner role on a target enrollment account.
    
    .PARAMETER Remove
        Reverts the operation and de-authorizes the Azure AD service principal.

    .PARAMETER Abort
        Aborts the operation and displays a summary of the current authorization role assignments.
    
    .NOTES
        AUTHOR: Michael Petersen
        LASTEDIT: June 17, 2020
#>

Param
(
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[{(]?[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$")]
    [string] $AccountOwnerObjectId = '00000000-0000-0000-0000-000000000000',

    [Parameter(Mandatory = $false)]
    [switch] $Remove,

    [Parameter(Mandatory = $false)]
    [switch] $Abort
)

# Stop immediately if something does not work
$ErrorActionPreference = 'Stop'

# Helper functions
function DisplayCommonErrorMessage([string] $Stage) {
    Write-Host
    Write-Host -Object "An error occured in stage '$Stage'. "
    Write-Host -Object 'Please re-run the script and supply valid parameters.'
    Write-Host
}

function DisplayEnrollmentAccountSummary ([string] $EnrollmentAccountObjectId) {
    Write-Host
    Write-Host -Object 'Role assignments summary of target enrollment account:'

    Get-AzRoleAssignment `
        -Scope "/providers/Microsoft.Billing/enrollmentAccounts/$enrollmentAccountObjectId" `
    | Format-Table -Property @('DisplayName', 'SignInName', 'ObjectId', 'ObjectType', 'RoleDefinitionName')
}

# Existing Azure context is assumed and required
if (!(Get-AzContext)) {
    throw 'Existing Azure cloud context required!'
}

try {
    # Assume that the existing cloud context account is in the Owner role of 1 enrollment account
    $enrollmentAccounts = Get-AzEnrollmentAccount -ErrorAction 'SilentlyContinue'

    if (!$enrollmentAccounts) {
        throw 'Existing cloud context account it not in the Owner role of an enrollment account!'
    }

    $enrollmentAccountObjectId = $enrollmentAccounts[0].ObjectId
    DisplayEnrollmentAccountSummary -EnrollmentAccountObjectId $enrollmentAccountObjectId

    if ($Abort) {
        return
    }
}
catch {
    DisplayCommonErrorMessage -Stage 'Enrollment Account Retrieval'
    Write-Host $_
    return
}

if (!$Remove) {
    try {
        Write-Host -Object 'Authorize a new owner to an existing Azure enrollment account ...'

        # Prepare existence check for target enrollment account role assignment
        $roleAssignment = Get-AzRoleAssignment `
            -ObjectId $AccountOwnerObjectId `
            -RoleDefinitionName 'Owner' `
            -Scope "/providers/Microsoft.Billing/enrollmentAccounts/$enrollmentAccountObjectId" `
            -ErrorAction 'SilentlyContinue'
    
        if (!$roleAssignment) {
            # Grant Owner role permissions for an existing service principal to the target enrollment account
            New-AzRoleAssignment `
                -ObjectId $AccountOwnerObjectId `
                -RoleDefinitionName 'Owner' `
                -Scope "/providers/Microsoft.Billing/enrollmentAccounts/$enrollmentAccountObjectId" `
            | Out-Null
        }
        else {
            # Authorization existence check
            Write-Host -Object 'Service principal was already authorized on target enrollment account'
        }
        
        DisplayEnrollmentAccountSummary -EnrollmentAccountObjectId $enrollmentAccountObjectId
        Write-Host -Object 'Authorization successfully finished!'
    }
    catch {
        DisplayCommonErrorMessage -Stage 'Grant Owner Role'
        Write-Host $_
        return
    }
}
else {
    try {
        Write-Host -Object 'De-authorize the owner for an existing Azure enrollment account ...'
           
        # Remove Owner role permissions of an service principal from the target enrollment account
        Remove-AzRoleAssignment `
            -ObjectId $AccountOwnerObjectId `
            -RoleDefinitionName 'Owner' `
            -Scope "/providers/Microsoft.Billing/enrollmentAccounts/$enrollmentAccountObjectId" `
            -ErrorAction 'SilentlyContinue'
        
        DisplayEnrollmentAccountSummary -EnrollmentAccountObjectId $enrollmentAccountObjectId
        Write-Host -Object 'De-authorization successfully finished!'
    }
    catch {
        DisplayCommonErrorMessage -Stage 'Remove Owner Role'
        Write-Host $_
        return
    }
}