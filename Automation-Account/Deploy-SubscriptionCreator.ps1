<#
    .SYNOPSIS
        Deploy the Subscription Creator to a target subscription.

    .DESCRIPTION
        The Subscription Creator deployment will fully automatically create Azure subscriptions. The Subscription
        Creator itself must be deployed to a central IT Operations Azure subscription where its creation logic will run.
        Division specific users can then be authorized to start the highly privileged creation process without the
        need for them to have any administrative Azure permissions.

        PREREQUISITES
        The interactive login account needs to be in the Owner role on the root management group and requires
        the privilege to create Azure AD application credentials (e.g. Azure AD Application Administrators role).

        REQUIRED AUTOMATION ASSETS
        N/A

    .PARAMETER AutomationAccountName
        Automation account name of the Subscription Creator deployment.

    .PARAMETER ResourceGroupName
        Resource group name of the Subscription Creator deployment.

    .PARAMETER Location
        Location for the Subscription Creator deployment.

    .PARAMETER IgnorableErrors
        Defines how to handle ignorable errors during the Subscription Creator deployment.

    .PARAMETER NoRoleAssignmentsRestore
        Do not restore role assignments for deleted runbooks that have been recreated through a deployment.

    .PARAMETER Remove
        Reverts the operation and removes the Subscription Creator deployment (exept its run-as account from Azure AD).

    .PARAMETER All
        Evaluated in addition to the 'Remove' parameter. If provided, it will also delete the run-as account from Azure AD.

    .PARAMETER Confirm
        Prompts for a confirmation before executing the command.

    .NOTES
        AUTHOR: Michael Petersen
        LASTEDIT: June 25, 2020
#>

Param
(
    [Parameter(Mandatory = $false)]
    [ValidateLength(3, 50)]
    [string] $AutomationAccountName = 'subscription-creator',

    [Parameter(Mandatory = $false)]
    [ValidateLength(3, 50)]
    [string] $ResourceGroupName = 'Subscription-Management',

    [Parameter(Mandatory = $false)]
    [ValidateLength(3, 30)]
    [string] $Location = 'westeurope',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Continue', 'SilentlyContinue', 'Inquire')]
    [string] $IgnorableErrors = 'SilentlyContinue',

    [Parameter(Mandatory = $false)]
    [switch] $NoRoleAssignmentsRestore,

    [Parameter(Mandatory = $false)]
    [switch] $Remove,

    [Parameter(Mandatory = $false)]
    [switch] $All,
    
    [Parameter(Mandatory = $false)]
    [bool] $Confirm = $true
)

# Stop immediately if something does not work
$ErrorActionPreference = 'Stop'

# Helper functions
function CreatePfxCertificate([string] $CertificateName) {
    # Windows with PowerShell 5.1
    if ($PSVersionTable.PSEdition -eq 'Desktop' `
            -and $PSVersionTable.PSVersion.Major -ge 5 `
            -and $PSVersionTable.PSVersion.Minor -ge 1) {
        # Create password for the PFX certificate file format
        $certificatePassword = ConvertTo-SecureString -String (New-Guid).Guid -AsPlainText -Force

        # Create self-signed certificate to be used for certificate based authentication of the automation connection
        $certificate = New-SelfSignedCertificate `
            -DnsName $CertificateName `
            -CertStoreLocation 'Cert:/CurrentUser/My/' `
            -KeyExportPolicy 'Exportable' `
            -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' `
            -NotAfter (Get-Date).AddMonths(12) `
            -HashAlgorithm 'SHA256'

        # Export self-signed certificate in PFX format to the local filesystem
        Export-PfxCertificate `
            -Cert "Cert:/CurrentUser/My/$($certificate.Thumbprint)" `
            -FilePath "$CertificateName.pfx" `
            -Password $certificatePassword -Force | Out-Null

        # Remove self-signed certificate from local Windows certificate store
        Remove-Item -Path "Cert:/CurrentUser/My/$($certificate.Thumbprint)" -Force | Out-Null
    }
    # PowerShell Core 7.0 on Linux or MacOS
    elseif ($PSVersionTable.PSEdition -eq 'Core' `
            -and $PSVersionTable.PSVersion.Major -ge 7 `
            -and $PSVersionTable.PSVersion.Minor -ge 0 -and `
        ($IsLinux -or $IsMacOS)) {
        # Create string-based password for the PFX certificate file format
        $certificatePassword = $(((New-Guid).Guid).ToLower().Replace('-', 'x').Substring(0, 24))

        # Create self-signed certificate to be used for certificate based authentication of the automation connection
        openssl req -x509 -nodes -new -newkey rsa:4096 -passout "pass:$certificatePassword" -out "$CertificateName.crt" -keyout "$CertificateName.key" -sha256 -days 365 -config 'openssl.conf'
        openssl pkcs12 -export -passin "pass:$certificatePassword" -passout "pass:$certificatePassword" -out "$CertificateName.pfx" -inkey "$CertificateName.key" -in "$CertificateName.crt"

        # Convert string-based password into secure string password
        $certificatePassword = ConvertTo-SecureString -String $certificatePassword -AsPlainText -Force
    }
    else {
        throw 'Operating system or PowerShell version not supported!'
    }

    # Full qualified path to PFX certificate file
    $pathToCertFile = Join-Path -Path (Get-Location) -ChildPath "$CertificateName.pfx"

    # Create X509 certificate object based on PFX format in the local filesystem
    $pfxCertificate = New-Object `
        -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2' `
        -ArgumentList @($pathToCertFile, $certificatePassword)

    # Return custom object with complete certificate data
    New-Object -TypeName 'PSObject' -Property @{
        PfxCertificate      = $pfxCertificate;
        CertificateName     = $CertificateName;
        CertificatePassword = $certificatePassword;
        CertificatePath     = $pathToCertFile;
        CertificateValue    = ([System.Convert]::ToBase64String($pfxCertificate.GetRawCertData()));
        StartDate           = $pfxCertificate.NotBefore;
        EndDate             = $pfxCertificate.NotAfter
    }
}

function CreateAutomationRunAsAccount([psobject] $CertificateData, [string] $RunAsAccountName) {
    # Create or re-use Azure AD application to be used for the automation run-as account
    $application = Get-AzADApplication `
        -DisplayName $RunAsAccountName `
        -ErrorAction 'SilentlyContinue'

    if (!$application) {
        # Create new Azure AD application
        $guid = (New-Guid).Guid

        $application = New-AzADApplication `
            -DisplayName $RunAsAccountName `
            -HomePage "http://$guid" `
            -IdentifierUris "http://$guid"

        # Create Azure AD service principal from an application identity template
        New-AzADServicePrincipal `
            -ApplicationId $application.ApplicationId `
            -Role 'Contributor' `
            -Scope "/subscriptions/$subscriptionId" `
            -WarningAction $IgnorableErrors `
            -ErrorAction $IgnorableErrors `
        | Out-Null
    }
    else {
        # Remove certificate based secrets from the existing Azure AD application
        Remove-AzADAppCredential -ApplicationId $application.ApplicationId -Force
    }

    # Create certificate based secret for Azure AD application
    New-AzADAppCredential `
        -ApplicationId $application.ApplicationId `
        -CertValue $CertificateData.CertificateValue `
        -StartDate $CertificateData.StartDate `
        -EndDate $CertificateData.EndDate | Out-Null

    # Return application id of created or reused Azure AD application
    $application.ApplicationId
}

function RemoveAutomationRunAsAccount([string] $RunAsAccountName, [string] $TenantId, [string] $SubscriptionId) {
    # Retrieve automation account run-as connection identity
    $application = Get-AzADApplication -DisplayName $RunAsAccountName -ErrorAction 'SilentlyContinue'

    if ($application) {
        # Remove Owner role of run-as connection identity on root management group
        Remove-AzRoleAssignment `
            -ServicePrincipalName $application.ApplicationId `
            -RoleDefinitionName 'Owner' `
            -Scope "/providers/Microsoft.Management/managementGroups/$TenantId" `
            -ErrorAction $IgnorableErrors

        # Remove Contributor role of run-as connection identity on subscription
        Remove-AzRoleAssignment `
            -ServicePrincipalName $application.ApplicationId `
            -RoleDefinitionName 'Contributor' `
            -Scope "/subscriptions/$SubscriptionId" `
            -ErrorAction $IgnorableErrors

        # Remove Azure AD application and its service principal
        $application | Remove-AzADApplication -Force -ErrorAction 'SilentlyContinue'
    }
}

function CreateAutomationConnection(
    [string] $ConnectionName,
    [string] $ApplicationId,
    [string] $TenantId,
    [string] $SubscriptionId,
    [psobject] $CertificateData,
    [string] $ResourceGroupName,
    [string] $AutomationAccountName) {
    # Create Azure Automation certificate asset used to authenticate the run-as service principal
    New-AzAutomationCertificate `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName `
        -Path $CertificateData.CertificatePath `
        -Name $CertificateData.CertificateName `
        -Password $CertificateData.CertificatePassword `
        -Description 'This certificate is used to authenticate with the service principal that was automatically created for this account.' `
    | Out-Null

    # Create Azure Automation connection asset used to access the target Azure subscription of the automation account
    $connectionFieldValues = @{
        'ApplicationId'         = $ApplicationId;
        'TenantId'              = $TenantId;
        'CertificateThumbprint' = $CertificateData.PfxCertificate.Thumbprint;
        'SubscriptionId'        = $SubscriptionId
    }

    New-AzAutomationConnection `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName `
        -Name $ConnectionName `
        -ConnectionTypeName 'AzureServicePrincipal' `
        -ConnectionFieldValues $connectionFieldValues `
        -Description 'This connection contains information about the service principal that was automatically created for this automation account.' `
    | Out-Null
}

function RemoveAutomationConnection(
    [string] $ConnectionName,
    [string] $CertificateName,
    [string] $ResourceGroupName,
    [string] $AutomationAccountName) {
    # Only try to remove automation assets on an existing automation account
    if (Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction 'SilentlyContinue') {
        # Remove Azure Automation connection asset
        Remove-AzAutomationConnection `
            -Name $ConnectionName `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName `
            -ErrorAction $IgnorableErrors -Force `
        | Out-Null

        # Remove Azure Automation certificate asset
        Remove-AzAutomationCertificate `
            -Name $CertificateName `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName `
            -ErrorAction $IgnorableErrors `
        | Out-Null
    }
}

function RemoveAutomationRunbooks(
    [string] $ResourceGroupName,
    [string] $AutomationAccountName) {
    # Try to retrieve automation account
    $automationAccount = Get-AzAutomationAccount `
        -ResourceGroupName $ResourceGroupName `
        -Name $AutomationAccountName `
        -ErrorAction 'SilentlyContinue'

    # All role assignments on all runbooks
    $allRoleAssignments = New-Object -TypeName 'System.Collections.Hashtable'

    # Only try to remove automation runbooks on an existing automation account
    if ($automationAccount) {
        $runbooks = Get-AzAutomationRunbook `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName
        
        foreach ($runbook in $runbooks) {
            $resource = Get-AzResource -Name $runbook.Name -ResourceGroupName $runbook.ResourceGroupName
            $roleAssignment = $null

            $roleAssignment = Get-AzRoleAssignment `
                -RoleDefinitionName 'Automation Runbook Operator' `
                -Scope $resource.ResourceId `
                -ErrorAction 'SilentlyContinue'
            
            if ($roleAssignment) {
                $allRoleAssignments.Add($runbook.Name, $roleAssignment)
            }
        }

        $runbooks | Remove-AzAutomationRunbook -ErrorAction $IgnorableErrors -Force | Out-Null
    }

    $allRoleAssignments
}

function RestoreAutomationRunbooksRoleAssignments (
    [string] $ResourceGroupName,
    [string] $AutomationAccountName, 
    [System.Collections.Hashtable] $AllRoleAssignments) {
    # Retrieve all runbooks from an existing automation account
    $runbooks = Get-AzAutomationRunbook `
        -ResourceGroupName $ResourceGroupName `
        -AutomationAccountName $AutomationAccountName

    # Restore role assignments for deleted runbooks that have been recreated through a deployment
    foreach ($runbook in $runbooks) {
        if ($AllRoleAssignments.ContainsKey($runbook.Name)) {
            $roleAssignment = $AllRoleAssignments[$runbook.Name]
            $resource = Get-AzResource -Name $runbook.Name -ResourceGroupName $runbook.ResourceGroupName

            for ($i = 0; $i -lt 6; $i++) {
                # Retry until all IAM caches are stale but not more than 1 minute to avoid deadlock
                try {
                    $roleAssignment | New-AzRoleAssignment -Scope $resource.ResourceId | Out-Null
                    # Circuit breaker pattern
                    break;
                }
                catch {
                    Start-Sleep -Seconds 10
                }
            }
        }
    }
}

function DisplayCommonErrorMessage([string] $Stage) {
    Write-Host
    Write-Host -Object "An error occured in stage '$Stage'. "
    Write-Host -Object 'Please re-run the script to retry or use the "-Remove" parameter to remove the deployment.'
    Write-Host
}

# Existing Azure context is assumed and required
if (!(Get-AzContext)) {
    throw 'Existing Azure cloud context required!'
}

# Global variables
$tenantId = (Get-AzContext).Tenant.Id
$subscriptionId = (Get-AzContext).Subscription.Id

# Confirmation procedure
if ($Confirm) {
    $subscriptionName = (Get-AzContext).Subscription.Name

    if (!$Remove) {
        Write-Host -Object 'Please confirm the deployment creation context:' -ForegroundColor 'Green'
    }
    else {
        Write-Host -Object 'Please confirm the deployment removal context:' -ForegroundColor 'Red'
    }

    Write-Host

    Write-Host `
        -Object @(
        "    Subscription name: $subscriptionName", 
        "    Subscription id: $subscriptionId", 
        "    Tenant id: $tenantId", 
        "    Resource group: $ResourceGroupName", 
        "    Automation account: $AutomationAccountName") `
        -Separator "`r`n"

    Write-Host
    $response = Read-Host -Prompt 'Are you sure to continue (y/n)'

    if ($response.ToLower() -ne 'y') {
        return
    }
    
    Write-Host
}

# Create or remove the deployment
if (!$Remove) {
    # Create or re-create the Subscription Creator deployment
    $certificateName = "AzureRunAsCertificate"
    $connectionName = "AzureRunAsConnection"
    Write-Host -Object 'Creating subscription creator deployment ...'

    try {
        # Create or re-use resource group for deployment
        Write-Host -Object 'Creating or reusing deployment staging resources ' -NoNewline

        New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Force -ErrorAction 'SilentlyContinue' `
        | Out-Null

        $stagingAccount = Get-AzStorageAccount `
            -ResourceGroupName $ResourceGroupName `
            -ErrorAction 'SilentlyContinue' | `
            Where-Object -Property StorageAccountName -Value 'staging*' -Like

        # Create or re-use storage account for resource staging purposes
        if (!$stagingAccount) {
            # Create new storage account
            Write-Host -Object "." -NoNewline
            $accountName = ('staging' + ((New-Guid).Guid).ToLower().Replace('-', 'x')).Substring(0, 24)

            $stagingAccount = New-AzStorageAccount `
                -ResourceGroupName $ResourceGroupName `
                -AccountName $accountName `
                -Location $Location `
                -SkuName Standard_LRS
        }
        else {
            # Reuse existing storage account
            Write-Host -Object '.' -NoNewline
            $stagingAccount = $stagingAccount[0]

            # Clean up existing staged resources
            Remove-AzStorageContainer `
                -Name 'staging' `
                -Context $stagingAccount.Context `
                -Force `
                -ErrorAction $IgnorableErrors
        }

        # Create new storage container for resource staging purposes
        do {
            # Retry until all asynchronous operations are done
            try {
                $stagingContainer = New-AzStorageContainer `
                    -Name 'staging' `
                    -Permission 'Blob' `
                    -Context $stagingAccount.Context

                # Circuit breaker pattern
                Write-Host -Object '.' -NoNewline
                break
            }
            catch {
                Write-Host -Object '.' -NoNewline
                Start-Sleep -Seconds 10
            }
        } while ($true)

        $stagingUri = $stagingContainer.CloudBlobContainer.StorageUri.PrimaryUri.AbsoluteUri

        # Upload all division runbooks to the staging storage account
        Write-Host -Object '.'

        Get-ChildItem -Path '../Division-Runbooks/' -Filter '*.ps1' -File -Recurse | `
            Set-AzStorageBlobContent -Container $stagingContainer.Name -Context $stagingAccount.Context -Force `
        | Out-Null
    }
    catch {
        DisplayCommonErrorMessage -Stage 'Staging Resources Management'
        Write-Host $_
        return
    }

    try {
        # Remove automation account runbooks on an existing automation account
        # because all runbooks will be replaced with new versions
        $allRoleAssignments = RemoveAutomationRunbooks `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName

        # Remove automation account connections assets on an existing automation account
        # because a new certificate secret will be created
        RemoveAutomationConnection `
            -ConnectionName $connectionName `
            -CertificateName $certificateName `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName

        # Remove subscription creator automation account
        Write-Host -Object 'Deploy or re-deploy automation account (expect up to 10 minutes)  ' -NoNewline

        # Deploy ARM template for the subscription creator automation account
        Get-Job | Remove-Job
        $templateFilePath = Join-Path -Path (Get-Location) -ChildPath 'azuredeploy.json'
        $deploymentName = 'subscription-creator--' + (Get-Date -Format 'MM-dd-yyyy--HH-mm')

        $runbookNames = Get-ChildItem -Path '../Division-Runbooks/' -File -Recurse -Filter '*.ps1' `
        | Split-Path -Leaf `
        | ForEach-Object -Process { ($_.Split('.'))[0] }

        $templateParameters = @{ 
            'stagingUri'        = $stagingUri; 
            'automationAccount' = $AutomationAccountName;
            'runbookNames'      = $runbookNames
        }

        New-AzResourceGroupDeployment `
            -Name $deploymentName `
            -Mode 'Incremental' `
            -DeploymentDebugLogLevel 'None' `
            -ResourceGroupName $ResourceGroupName `
            -TemplateFile $templateFilePath `
            -TemplateParameterObject $templateParameters `
            -AsJob `
        | Out-Null

        $job = Get-Job -Command 'New-AzResourceGroupDeployment'
        $animation = "/-\|/-\|"
        $i = 0

        # Animate while waiting for job completion
        do {
            Write-Host -Object @("`b`b", $animation[($i++) % $animation.Length]) -NoNewline
            Start-Sleep -Seconds 0.7
        } until ($job.State -eq 'Completed')

        Write-Host
        $deployment = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $deploymentName

        if ($deployment.ProvisioningState -ne 'Succeeded') {
            throw "Deployment '$($deployment.DeploymentName)' of ARM template for the subscription creator automation account failed!"
        }
        else {
            if (!$NoRoleAssignmentsRestore) {
                Write-Host -Object 'Restoring automation runbooks authorization role assignments'
            
                RestoreAutomationRunbooksRoleAssignments `
                    -ResourceGroupName $ResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -AllRoleAssignments $allRoleAssignments
            }

            Write-Host -Object "Automation account successfully deployed with deployment '$($deployment.DeploymentName)'"
        }
    }
    catch {
        DisplayCommonErrorMessage -Stage 'Automation Account Deployment'
        Write-Host $_
        return
    }
    finally {
        # Remove temporary staging storage account
        $stagingAccount | Remove-AzStorageAccount -Force
    }

    # Deploy automation account run-as connection and assign it the Owner role on the root management group level as well as
    # the Contributor role on the subscription that contains the subscription creator automation account (all below)
    Write-Host -Object 'Deploy or re-use certificate based credentials and secrets ...'

    try {
        # Create X509 certificate stored in Windows certificate store and on local disk
        $certificateData = CreatePfxCertificate -CertificateName $certificateName

        # Create or re-use Azure AD application as run-as account for Azure automation runbooks
        $applicationId = CreateAutomationRunAsAccount `
            -CertificateData $certificateData `
            -RunAsAccountName "$AutomationAccountName $connectionName"

        # Returned from script for later usage
        $runAsServicePrincipalId = (Get-AzADServicePrincipal -ApplicationId $applicationId).Id

        # Create automation account connection and certificate assets
        CreateAutomationConnection `
            -ConnectionName $connectionName `
            -ApplicationId $applicationId `
            -CertificateData $certificateData `
            -TenantId $tenantId `
            -SubscriptionId $subscriptionId `
            -ResourceGroupName $ResourceGroupName `
            -AutomationAccountName $AutomationAccountName
    }
    catch {
        DisplayCommonErrorMessage -Stage 'Automation Connection Creation'
        Write-Host $_
        return
    }
    finally {
        # Remove self-signed certificate from local filesystem
        Remove-Item -Path ".\$certificateName.???" -Force
    }

    Write-Host -Object 'Authorize automation run-as connection as Owner on the root management group ' -NoNewline

    for ($i = 0; $i -lt 6; $i++) {
        # Retry until all IAM caches are stale but not more than 1 minute to avoid deadlock
        try {
            # Assign automation account run-as service principal the Owner role on the root management group level
            New-AzRoleAssignment `
                -ServicePrincipalName $applicationId `
                -RoleDefinitionName 'Owner' `
                -Scope "/providers/Microsoft.Management/managementGroups/$tenantId" `
            | Out-Null

            # Circuit breaker pattern
            Write-Host -Object '.'
            break
        }
        catch [Microsoft.Rest.Azure.CloudException] {
            if ($_.Exception.Message -contains 'The role assignment already exists.') {
                Write-Host
                Write-Host -Object 'Run-as service principal was already in the Owner role'
                break
            }
            else {
                Write-Host -Object '.' -NoNewline
                Start-Sleep -Seconds 10
            }
        }
        catch {
            Write-Host -Object '.' -NoNewline
            Start-Sleep -Seconds 10
        }
    }

    Write-Host -Object @('RunAs Account Service Principal Id', $runAsServicePrincipalId) -Separator ': '
    Write-Host -Object 'Subscription Creator deployment successfully finished!'
}
else {
    # Remove the Subscription Creator deployment
    $connectionName = 'AzureRunAsConnection'
    Write-Host -Object 'Removing subscription creator deployment ...'

    try {
        # Remove resource group and its contained deployments
        Remove-AzResourceGroup -Name $ResourceGroupName -Force -ErrorAction $IgnorableErrors | Out-Null
    }
    catch {
        DisplayCommonErrorMessage -Stage 'Resource Group Removal'
        Write-Host $_
        return
    }

    try {
        if ($All) {
            # Remove Azure AD application that was used as run-as account for Azure automation runbooks
            Write-Host -Object 'Removing authorizations and Azure AD application of run-as service principal ...'

            RemoveAutomationRunAsAccount `
                -RunAsAccountName "$AutomationAccountName $connectionName" `
                -TenantId $tenantId `
                -SubscriptionId $subscriptionId
        }
    }
    catch {
        DisplayCommonErrorMessage -Stage 'Automation RunAs Account Removal'
        Write-Host $_
        return
    }

    Write-Host -Object 'Subscription Creator deployment successfully removed!'
}