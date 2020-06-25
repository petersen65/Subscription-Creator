# Requires VSCode and PowerShell terminal (not PowerShell Integrated Console), Azure CloudShell or Windows PowerShell x64 v5.1
# For Windows required: Install-Module -Name 'AzureAD'

try {
    Get-AzureADTenantDetail | Out-Null
}
catch {
    Write-Host -Object "Please use 'Connect-AzureAD' to connect to Azure AD"
    throw 'Existing Azure Active Directory context required!'
}

$allEnabledRoles = Get-AzureADDirectoryRole | Sort-Object -Property 'DisplayName'
Write-Host -Object 'Summary of all Azure Active Directory roles that contain members:'

foreach ($role in $allEnabledRoles) {
    $roleMembers = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId|Sort-Object -Property 'DisplayName'
    
    if ($roleMembers) {
        Write-Host
        Write-Host -Object $role.DisplayName
        
        foreach ($member in $roleMembers) { 
            Write-Host -Object @($member.DisplayName, $member.ObjectId, $member.UserPrincipalName) -Separator '   ' 
        }
    }
}

Write-Host
Write-Host -Object 'Done!'