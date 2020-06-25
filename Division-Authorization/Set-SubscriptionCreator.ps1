<#
    .SYNOPSIS
        Authorize Azure AD identity for executing elevated subscription creator logic runbook.

    .DESCRIPTION
        Assign an user or a group from Azure AD the Azure Automation roles needed for automatic subscription creation.

        PREREQUISITES
        Subscription Creator deployment must exist within the target subscription of the interactive user.

        REQUIRED AUTOMATION ASSETS
        N/A.

    .PARAMETER AutomationAccountName
        Automation account name of the Subscription Creator deployment.

    .PARAMETER ResourceGroupName
        Resource group name of the Subscription Creator deployment.

    .PARAMETER DivisionName
        Division name for which the user or group is authorized to automatically create subscriptions.

    .PARAMETER UserOrGroupObjectId
        User or group id from Azure AD that will be authorized for division specific subscription creation.

    .PARAMETER Remove
        Reverts the operation and de-authorizes the Azure AD identity.

    .PARAMETER Abort
        Aborts the operation and displays a summary of the current authorization role assignments.
    
    .NOTES
        AUTHOR: Michael Petersen
        LASTEDIT: June 17, 2020
#>

Param
(
    [Parameter(Mandatory = $false)]
    [ValidateLength(3, 50)]
    [string] $AutomationAccountName = 'subscription-creator',

    [Parameter(Mandatory = $false)]
    [ValidateLength(3, 50)]
    [string] $ResourceGroupName = 'Subscription-Management',

    [Parameter(Mandatory = $true)]
    [string] $DivisionName,

    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[{(]?[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$")]
    [string] $UserOrGroupObjectId = '00000000-0000-0000-0000-000000000000',

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

function DisplayTargetDivisionSummary ([string] $AutomationAccountId, [string] $RunbookId) {
    Write-Host
    Write-Host -Object 'Role assignments summary of target division:'
    
    Write-Host
    Write-Host -Object 'Role assignments summary of automation account:'

    Get-AzRoleAssignment -Scope $AutomationAccountId -RoleDefinitionName 'Automation Job Operator'  `
    | Format-Table -Property @('DisplayName', 'SignInName', 'ObjectId', 'ObjectType', 'RoleDefinitionName')

    Write-Host -Object 'Role assignments summary of division runbook:'
    
    Get-AzRoleAssignment -Scope $RunbookId -RoleDefinitionName 'Automation Runbook Operator' `
    | Format-Table -Property @('DisplayName', 'SignInName', 'ObjectId', 'ObjectType', 'RoleDefinitionName')
}

# Existing Azure context is assumed and required
if (!(Get-AzContext)) {
    throw 'Existing Azure cloud context required!'
}

try {
    # Retrieve automation account that is used as subscription creator
    $automationAccount = Get-AzResource `
        -ResourceGroupName $ResourceGroupName `
        -ResourceType 'Microsoft.Automation/automationAccounts' `
        -ResourceName $AutomationAccountName `
        -ErrorAction 'SilentlyContinue'

    # Retrieve parent runbook that implements division specific logic
    $runBook = Get-AzResource `
        -ResourceGroupName $ResourceGroupName `
        -ResourceType 'Microsoft.Automation/automationAccounts/runbooks' `
        -ResourceName $DivisionName `
        -ErrorAction 'SilentlyContinue'

    if (!$automationAccount) {
        throw "Automation account '$AutomationAccountName' not found!"
    }
    
    if (!$runBook) {
        throw "Automation runbook '$DivisionName' not found!"
    }

    DisplayTargetDivisionSummary -AutomationAccountId $automationAccount.ResourceId -RunbookId $runBook.ResourceId

    if ($Abort) {
        return
    }
}
catch {
    DisplayCommonErrorMessage -Stage 'Automation Account Retrieval'
    Write-Host $_
    return
}

try {
    if (!$Remove) {
        Write-Host -Object 'Authorize user or group to execute jobs on the subscription creator automation account ...'

        # Prepare existence check for subscription creator automation account role assignment
        $accountRoleAssignment = Get-AzRoleAssignment `
            -ObjectId $UserOrGroupObjectId `
            -RoleDefinitionName 'Automation Job Operator' `
            -Scope $automationAccount.ResourceId `
            -ErrorAction 'SilentlyContinue'

        # Prepare existence check for subscription creator logic runbook role assignment
        $runbookRoleAssignment = Get-AzRoleAssignment `
            -ObjectId $UserOrGroupObjectId `
            -RoleDefinitionName 'Automation Runbook Operator' `
            -Scope $runBook.ResourceId `
            -ErrorAction 'SilentlyContinue'
    
        # Authorize user or group to allow it to execute jobs on the subscription creator automation account
        if (!$accountRoleAssignment) {
            New-AzRoleAssignment `
                -ObjectId $UserOrGroupObjectId `
                -RoleDefinitionName 'Automation Job Operator' `
                -Scope $automationAccount.ResourceId `
            | Out-Null
        }

        # Authorize user or group to allow it to execute an elevated subscription creator logic runbook
        if (!$runbookRoleAssignment) {
            New-AzRoleAssignment `
                -ObjectId $UserOrGroupObjectId `
                -RoleDefinitionName 'Automation Runbook Operator' `
                -Scope $runBook.ResourceId `
            | Out-Null
        }

        # Authorization existence check
        if ($accountRoleAssignment -or $runbookRoleAssignment) {
            Write-Host -Object 'User or group was already authorized on subscription creator automation account'
        }
    
        DisplayTargetDivisionSummary -AutomationAccountId $automationAccount.ResourceId -RunbookId $runBook.ResourceId
        Write-Host -Object 'Authorization successfully finished!'
    }
    else {
        Write-Host -Object 'De-authorize user or group on the subscription creator automation account ...'
    
        # De-authorize user or group to execute jobs on the subscription creator automation account
        Remove-AzRoleAssignment `
            -ObjectId $UserOrGroupObjectId `
            -RoleDefinitionName 'Automation Job Operator' `
            -Scope $automationAccount.ResourceId `
            -ErrorAction 'SilentlyContinue'
    
        # De-authorize user or group to execute an elevated subscription creator logic runbook
        Remove-AzRoleAssignment `
            -ObjectId $UserOrGroupObjectId `
            -RoleDefinitionName 'Automation Runbook Operator' `
            -Scope $runBook.ResourceId `
            -ErrorAction 'SilentlyContinue'
    
        DisplayTargetDivisionSummary -AutomationAccountId $automationAccount.ResourceId -RunbookId $runBook.ResourceId
        Write-Host -Object 'De-authorization successfully finished!'
    }    
}
catch {
    DisplayCommonErrorMessage -Stage 'User Or Group Authorization'
    Write-Host $_
    return
}
