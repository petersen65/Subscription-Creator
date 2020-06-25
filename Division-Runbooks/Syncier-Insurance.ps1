<#
    .SYNOPSIS
        Azure Subscription Creator for Syncier Insurance.

    .DESCRIPTION
        The runbook is to be used as a child runbook and called by parent runbooks which implement
        Syncier division specific logic. The parent runbooks are authorized to specific users which are allowed
        to execute elevated subscription creator logic for their assigned Syncier division.

        Syncier Insurance specific subscription creation runbook that must be authorized to its division users.

        PREREQUISITES
        The service principal of the Azure Automation run-as connection needs to be in the Owner role
        on the target enrollment account and on the target root management group.

        REQUIRED AUTOMATION ASSETS
        .\Division-Child.ps1

    .PARAMETER ManagementGroupId
        Management group for the newly created subscription which will be created if it does not exist.
        The id must be unique under all management groups that share a single Azure AD tenant.

    .PARAMETER ManagementGroupDisplayName
        Management group display name for the newly created subscription.

    .PARAMETER SubscriptionName
        Name for the new subscription which is not unique (only the subscription id is unique).

    .NOTES
        AUTHOR: Michael Petersen
        LASTEDIT: June 6, 2020
#>

Param
(
    [Parameter(Mandatory = $true)]
    [ValidateLength(3, 50)]
    [string] $ManagementGroupId,

    [Parameter(Mandatory = $true)]
    [ValidateLength(3, 50)]
    [string] $ManagementGroupDisplayName,

    [Parameter(Mandatory = $true)]
    [ValidateLength(3, 30)]
    [string] $SubscriptionName
)

$enrollmentAccountObjectId = "3f64d191-6f42-42fb-896d-703f40c6e129"
$subscriptionOwnerId = "1ca173f4-176b-4a81-90e0-939fec1070fd"

# Invoke a child runbook by using inline execution
.\Division-Child.ps1 -ParentManagementGroupId 'syncier-insurance' -ManagementGroupId $ManagementGroupId -ManagementGroupDisplayName $ManagementGroupDisplayName -EnrollmentAccountObjectId $enrollmentAccountObjectId -SubscriptionName $SubscriptionName -SubscriptionOwnerId $subscriptionOwnerId