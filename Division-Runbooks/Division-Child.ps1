<#
    .SYNOPSIS
        Azure Subscription Creator for all parent divisions.

    .DESCRIPTION
        The runbook is to be used as a child runbook and called by parent runbooks which implement
        division specific logic. The parent runbooks are authorized to specific users which are allowed
        to execute elevated subscription creator logic for their assigned division.

        PREREQUISITES
        The service principal of the Azure Automation run-as connection needs to be in the Owner role
        on the target enrollment account and on the target root management group.

        REQUIRED AUTOMATION ASSETS
        N/A

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

# Stop immediately if something does not work
$ErrorActionPreference = 'Stop'

try {
    # Connect to the Azure cloud with a service principal that has the Owner role on
    # the target enrollment account and on the target root management group
    Write-Output -InputObject 'Connecting to Azure Cloud via Automation Connection'
    $runAsConnection = Get-AutomationConnection -Name 'AzureRunAsConnection'

    Connect-AzAccount `
        -ServicePrincipal `
        -Tenant $runAsConnection.TenantID `
        -ApplicationId $runAsConnection.ApplicationID `
        -CertificateThumbprint $runAsConnection.CertificateThumbprint

    Write-Output -InputObject 'Connected to Azure Cloud via Automation Connection'
}
catch [System.Management.Automation.CommandNotFoundException] {
    # Fallback while running outside of Azure Automation and within an integrated development environment
    # where the environment variables APPLICATION_ID, DEVELOPER_SECRET, SUBSCRIPTION_ID, and TENANT_ID must be set
    # to enable a non-interactive login to the Azure cloud under a developer service principal
    Write-Output -InputObject 'Connecting to Azure Cloud via Development Credential'
    Clear-AzContext -Scope 'Process' -Force

    $developmentCredential = New-Object `
        -TypeName 'System.Management.Automation.PSCredential' `
        -ArgumentList @($Env:APPLICATION_ID, (ConvertTo-SecureString -String $Env:DEVELOPER_SECRET -AsPlainText -Force))

    Connect-AzAccount `
        -Scope 'Process' `
        -ServicePrincipal `
        -Credential $developmentCredential `
        -Subscription $Env:SUBSCRIPTION_ID `
        -Tenant $Env:TENANT_ID

    Write-Output -InputObject 'Connected to Azure Cloud via Development Credential'
}

# Create or use existing management group below a given parent management group
if (!(Get-AzManagementGroup -GroupName $ManagementGroupId -ErrorAction SilentlyContinue)) {
    Write-Output -InputObject 'Creating new Management Group with adjusted role assignments'

    New-AzManagementGroup `
        -GroupName $ManagementGroupId `
        -DisplayName $ManagementGroupDisplayName `
        -ParentId "/providers/Microsoft.Management/managementgroups/$ParentManagementGroupId"

    # Remove direct automatic Owner role assigment of creating service principal to rely on existing
    # inherited role assignments up to the root management group
    for ($i = 1; $i -le 6; $i++) {
        # Retry until all IAM caches are stale but not more than 1 minute to avoid deadlock
        try {
            Remove-AzRoleAssignment `
                -ObjectId (Get-AzADServicePrincipal `
                -ApplicationId (Get-AzContext).Account.Id).Id `
                -RoleDefinitionName 'Owner' `
                -Scope "/providers/Microsoft.Management/managementgroups/$ManagementGroupId"

            # Circuit breaker pattern
            Write-Output -InputObject 'Created new Management Group with adjusted role assignments'
            break
        }
        catch {
            Write-Output -InputObject "Role assignment adjustment retry $i"
            Start-Sleep -Seconds 10

            if ($i -eq 6) {
                Write-Output -InputObject 'Created new Management Group without adjusted role assignments'
            }
        }
    }
}
else {
    Write-Output -InputObject 'Detected existing Management Group and avoided any modifications'
}

try {
    # Finally create the new subscription under a given enrollment account and with a new direct owner assignment
    Write-Output -InputObject "Creating new subscription under Enrollment Account: $EnrollmentAccountObjectId"

    $subscription = New-AzSubscription `
        -OfferType 'MS-AZR-0017P' `
        -Name $SubscriptionName `
        -EnrollmentAccountObjectId $EnrollmentAccountObjectId `
        -OwnerObjectId $SubscriptionOwnerId

    Write-Output -InputObject "Created new subscription under Enrollment Account: $EnrollmentAccountObjectId"
}
catch [Microsoft.Azure.Management.Subscription.Models.ErrorResponseException] {
    # Fallback while running outside of Azure Automation and within an integrated development environment
    # where the developer or his service principal does not have subscription creation privileges
    $subscription = Get-AzSubscription -SubscriptionName $SubscriptionName
    Write-Output -InputObject 'Subscription creation failed and retrieval of development subscription was done'
}

# Move the newly created subscription from the root management group to its target management group below
# the authorized division parent management group
Write-Output -InputObject "Moving subscription under Management Group: $ManagementGroupId"
New-AzManagementGroupSubscription -GroupName $ManagementGroupId -SubscriptionId $subscription.Id
Write-Output -InputObject "Subscription moved under Management Group: $ManagementGroupId"