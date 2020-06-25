<#
    .SYNOPSIS
        Azure Subscription Creator for division 'Division One'.

    .DESCRIPTION
        The runbook is to be used as a parent runbook and calls a child runbook which implements common 
        subscription creation logic. This parent runbook must be authorized to specific users which are 
        allowed to execute elevated subscription creator logic on behalf of them.

        REQUIRED AUTOMATION ASSETS
        .\Division-Child.ps1

    .PARAMETER ParentManagementGroupId
        Parent management group id which reflects the division for which a subscription has to be created.

    .PARAMETER ManagementGroupId
        Management group for the newly created subscription which will be created if it does not exist.
        The id must be unique under all management groups that share a single Azure AD tenant.

    .PARAMETER ManagementGroupDisplayName
        Management group display name for the newly created subscription.

    .PARAMETER EnrollmentAccountObjectId
        Object id of the enrollment account under which the new subscription will be created (EA portal view).

    .PARAMETER SubscriptionName
        Name for the new subscription which is not unique (only the subscription id is unique).

    .PARAMETER SubscriptionOwnerId
        Azure AD user object id who will be granted the Owner role on the newly created subscription.

    .NOTES
        AUTHOR: Michael Petersen
        LASTEDIT: June 25, 2020
#>

Param
(
    [Parameter(Mandatory = $true)]
    [string] $ParentManagementGroupId,

    [Parameter(Mandatory = $true)]
    [ValidateLength(3, 50)]
    [string] $ManagementGroupId,

    [Parameter(Mandatory = $true)]
    [ValidateLength(3, 50)]
    [string] $ManagementGroupDisplayName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[{(]?[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$")]
    [string] $EnrollmentAccountObjectId,

    [Parameter(Mandatory = $true)]
    [ValidateLength(3, 30)]
    [string] $SubscriptionName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[{(]?[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$")]
    [string] $SubscriptionOwnerId
)

# Invoke a child runbook by using inline execution
.\Division-Child.ps1 `
    -ParentManagementGroupId $ParentManagementGroupId `
    -ManagementGroupId $ManagementGroupId `
    -ManagementGroupDisplayName $ManagementGroupDisplayName `
    -EnrollmentAccountObjectId $EnrollmentAccountObjectId `
    -SubscriptionName $SubscriptionName `
    -SubscriptionOwnerId $SubscriptionOwnerId