# Requires VSCode and PowerShell terminal (not PowerShell Integrated Console), Azure CloudShell or Windows PowerShell x64 v5.1
# For Windows required: Install-Module -Name 'AzureAD'

try {
    Get-AzureADTenantDetail | Out-Null
}
catch {
    Write-Host -Object "Please use 'Connect-AzureAD' to connect to Azure AD and 'Connect-AzAccount' to connect to Azure"
    throw 'Existing Azure Active Directory context required!'
}

if (!(Get-AzContext)) {
    Write-Host -Object "Please use 'Connect-AzureAD' to connect to Azure AD and 'Connect-AzAccount' to connect to Azure"
    throw 'Existing Azure cloud context required!'
}

$allApplications = Get-AzureADApplication
Write-Host -Object 'Summary of all Azure Active Directory applications:'

foreach ($application in $allApplications) {
    $owners = Get-AzureADApplicationOwner -ObjectId $application.ObjectId
    $servicePrincipal = Get-AzureADServicePrincipal -SearchString $application.DisplayName
    Write-Host
    
    Write-Host -Object @(
        $application.DisplayName, 
        "{ AppId=$($application.AppId)", 
        "ObjectId=$($application.ObjectId) }") `
        -Separator ', '

    if ($owners) {
        foreach ($owner in $owners) {
            Write-Host -Object @(
                '   Owner'
                "{ Name=$($owner.DisplayName)", 
                "UPN=$($owner.UserPrincipalName)", 
                "ObjectId=$($owner.ObjectId) }") `
                -Separator ', '
        }
    }

    if ($servicePrincipal) {
        Write-Host
        
        Write-Host -Object @(
            '   Service Principal', 
            "{ Name=$($servicePrincipal.DisplayName)",
            "ObjectId=$($servicePrincipal.ObjectId) }") `
            -Separator ', '

        foreach ($context in (Get-AzContext -ListAvailable)) {
            $subscription = $context.Subscription

            $roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$($subscription.Id)" `
            | Where-Object -Property 'ObjectId' -Value $servicePrincipal.ObjectId -EQ `
            | Select-Object -Property @('DisplayName', 'RoleDefinitionName', 'Scope')
    
            foreach ($assignment in $roleAssignments) {
                Write-Host -Object @(
                    "      Subscription, { Name=$($subscription.Name), Id=$($subscription.Id) }", 
                    "         $($assignment.RoleDefinitionName)", 
                    "         $($assignment.Scope)") `
                    -Separator "`r`n"
            }
                
        }
    }
}

Write-Host
Write-Host -Object 'Done!'