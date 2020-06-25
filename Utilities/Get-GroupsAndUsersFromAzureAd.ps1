# Requires VSCode and PowerShell terminal (not PowerShell Integrated Console), Azure CloudShell or Windows PowerShell x64 v5.1
# For Windows required: Install-Module -Name 'AzureAD'

try {
    Get-AzureADTenantDetail | Out-Null
}
catch {
    Write-Host -Object "Please use 'Connect-AzureAD' to connect to Azure AD"
    throw 'Existing Azure Active Directory context required!'
}

$allGroups = Get-AzureADGroup|Sort-Object -Property DisplayName
Write-Host -Object 'Summary of all Azure Active Directory groups that contain members:'

foreach ($group in $allGroups) {
    $groupMembers = Get-AzureADGroupMember -ObjectId $group.ObjectId|Sort-Object -Property DisplayName
    
    if ($groupMembers) {
        Write-Host
        Write-Host -Object $group.DisplayName
        
        foreach ($member in $groupMembers) { 
            Write-Host -Object @($member.DisplayName, $member.ObjectId, $member.UserPrincipalName) -Separator '   ' 
        }
    }
}

Write-Host
Write-Host -Object 'Done!'