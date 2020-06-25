# Azure Subscriptions and Management Groups

Source code for automatic creation of Azure subscriptions and management groups

## Use Case Description

The expected use case for the “Subscription Creator” solution is as follows:

- The use case begins with an IT operations person that has access to the needed Azure AD accounts to manage Azure AD, the Azure cloud, and the EA enrollment accounts. The solution requires that N+1 credentials are used to manage
- 1 x for Azure AD and the Azure cloud (Azure AD application developer/administrator, root management group owner)
- N x EA enrollment accounts (enrollment account owner)
- It is required that the IT operations team has owner access to a central Azure subscription which is only used for central IT operations purposes (e.g. automation, logging, auditing). Access to this subscription is limited to the Azure cloud IT operations team.
- The IT operations person is working on a privileged access workstation with Windows 10 2004 or Ubuntu 18.04 with PowerShell Core 7. For Windows PowerShell 5.1 or for PowerShell Core 7 the Azure management commands must be installed with `Install-Module -Name 'Az'`. After the installation of the module the IT operations person connects to the central Azure subscription with:

  ```
  Connect-AzAccount -Tenant '<Azure AD Tenant Id>' -Subscription '<Subscription Id>'
  Connect-AzAccount -Tenant '66ea81d9-217d-48ac-8598-98b36b1836ff' -Subscription '73130a42-5d59-4f10-b77a-405431053830'
  ```

- After being connected to the central Azure subscription the PowerShell script `Deploy-SubscriptionCreator.ps1` can be called without any parameters. The deployment process takes up to 10 minutes to complete. By using `Deploy-SubscriptionCreator.ps1 -Remove` the complete deployment can be removed without removing the solution’s service principal from Azure AD. To also remove and deauthorize the service principal the script can be called with the additional `All` parameter: `Deploy-SubscriptionCreator.ps1 -Remove -All`.

  ```
  git clone https://github.com/syncier/abs-subscriptions-and-management-groups.git
  cd ./abs-subscriptions-and-management-groups/Automation-Account/
  ./Deploy-SubscriptionCreator.ps1
  ```

- After the IT operations person finished the deployment she needs to extract the Azure AD object id of the solution’s service principal by copying the script output value from 'RunAs Account Service Principal Id: xxxxxxxx-0000-0000-0000-xxxxxxxxxxxx' to a variable:

  ```
  $objectId = 'xxxxxxxx-0000-0000-0000-xxxxxxxxxxxx'
  ```

- Now the IT operations person can authorize the solution’s service principal in N x EA enrollment accounts by using

  ```
  Set-EnrollmentAccountOwner.ps1 -AccountOwnerObjectId $objectId [-SupportMfa]
  ```

- Please note that this script above expects to log you in interactively with existing EA enrollment account owner credentials. These credentials are also used to connect a user to the EA portal. Only Azure AD user credentials can be used with the script to manage EA enrollment accounts. In contrast to the others scripts, this EA enrollment account script will log in the user interactively with optional MFA support (fallback to browser-based device-code login).
- Having the above prerequisites in place the IT operations person can now authorize the “Subscription Creator” solution to end-users by calling the script:

  ```
  Set-SubscriptionCreator.ps1 -DivisionName 'Syncier-Insurance' -UserOrGroupObjectId (Get-AzADGroup -DisplayName syncier-insurance-administrators).Id

  # used to authorize individual users
  Set-SubscriptionCreator.ps1 -DivisionName 'Syncier-Insurance' -UserOrGroupObjectId (Get-AzADUser -StartsWith 'firstname lastname').Id
  ```

- The PowerShell script call above authorizes a user ‘firstname lastname’ to execute the venture runbook ‘Syncier-Insurance’ which will create subscriptions on behalf of the user for the Syncier venture ‘Insurance’. This user can only view and execute the single Syncier venture runbook in his Azure portal. Other resources from the solution are not accessible for the solution end-user.
- Finally the IT operations person can deauthorize a group or user by calling the same script with the `Remove` parameter:

  ```
  Set-SubscriptionCreator.ps1 -DivisionName 'Syncier-Insurance' -Remove -UserOrGroupObjectId (Get-AzADGroup -DisplayName syncier-insurance-administrators).Id
  Set-SubscriptionCreator.ps1 -DivisionName 'Syncier-Insurance' -Remove -UserOrGroupObjectId (Get-AzADUser -StartsWith 'firstname lastname').Id
  ```

## Test Cases

### Preparation for Azure Cloudshell

```
Set-Location -Path './clouddrive/'
git clone 'https://github.com/syncier/abs-subscriptions-and-management-groups.git'
Set-Location -Path './abs-subscriptions-and-management-groups/'
git checkout 'subscription-creation'
Set-Location -Path './Automation-Account/'
Get-Help './Deploy-SubscriptionCreator.ps1' -Detailed
```

### Test 1

Deployment of Subscription Creator, please carefully read script description prerequisites

```
.\Deploy-SubscriptionCreator.ps1 -ResourceGroupName 'My-Subscription-Management' -AutomationAccountName 'my-subscription-creator' -Location 'westeurope'
```

Removal of Subscription Creator, but don't remove its RunAs account in Azure AD and from RBAC assignments

```
.\Deploy-SubscriptionCreator.ps1 -ResourceGroupName 'My-Subscription-Management' -AutomationAccountName 'my-subscription-creator' -Location 'westeurope' -Remove
```

Removal of Subscription Creator, remove its RunAs account from Azure AD and from RBAC assignments

```
.\Deploy-SubscriptionCreator.ps1 -ResourceGroupName 'My-Subscription-Management' -AutomationAccountName 'my-subscription-creator' -Location 'westeurope' -Remove -All
```

### Test 2

Deployment of Subscription Creator with standard-values, please carefully read script description prerequisites

```
.\Deploy-SubscriptionCreator.ps1
```

Removal of Subscription Creator with standard-values, first remove its RunAs account from Azure AD and then remove the RBAC assignments with a second removal call

```
.\Deploy-SubscriptionCreator.ps1 -Remove
.\Deploy-SubscriptionCreator.ps1 -Remove -All
```

### Test 3

Deployment of Subscription Creator, please carefully read script description prerequisites

```
.\Deploy-SubscriptionCreator.ps1 -ResourceGroupName 'My-Subscription-Management' -AutomationAccountName 'my-subscription-creator'
```

Wait a minute, kill the script with ctrl+c or kill the shell

Re-deployment and removal of Subscription Creator, all must complete successfully

```
.\Deploy-SubscriptionCreator.ps1 -ResourceGroupName 'My-Subscription-Management' -AutomationAccountName 'my-subscription-creator'
.\Deploy-SubscriptionCreator.ps1 -ResourceGroupName 'My-Subscription-Management' -AutomationAccountName 'my-subscription-creator' -Remove -All
```

### Test 4

Deployment of Subscription Creator, please carefully read script description prerequisites

```
.\Deploy-SubscriptionCreator.ps1 -ResourceGroupName 'My-Subscription-Management' -AutomationAccountName 'my-subscription-creator'
```

Copy the script output value from 'RunAs Account Service Principal Id: xxxxxxxx-0000-0000-0000-xxxxxxxxxxxx'
Follow the interactive user interface and instructions from the Enrollment Account Owner script, quit the script as needed

```
Set-Location -Path '../Division-Authorization/'
Set-EnrollmentAccountOwner.ps1 -AccountOwnerObjectId 'xxxxxxxx-0000-0000-0000-xxxxxxxxxxxx' -SupportMfa
```

Identify an Azure AD user account 'firstname lastname' that has no Azure permissions and authorize her for Subscription Creation

```
$userObjectId = (Get-AzADUser -StartsWith 'firstname lastname').Id
Set-SubscriptionCreator.ps1 -DivisionName 'Syncier-Insurance' -UserOrGroupObjectId $userObjectId
```

Login to the Azure portal <https://portal.azure.com> with the user account 'firstname lastname'
With this user account you must only see 1 runbook with the name 'Syncier-Insurance'. Select this runbook and hit Start, then fill out 3 parameters:

```
MANAGEMENTGROUPID             : mgid-1
MANAGEMENTGROUPDISPLAYNAME    : MG 1
SUBSCRIPTIONNAME              : My Subscription
```

Wait in the Output blade to see the diagnostic results (all should work and no errors are expected)

Deauthorize the user account 'firstname lastname' and test whether the user still has access (this should not the case)

```
Set-SubscriptionCreator.ps1 -DivisionName 'Syncier-Insurance' -UserOrGroupObjectId $userObjectId -Remove
```

Removal of Subscription Creator, remove its RunAs account from Azure AD and from RBAC assignments

```
Set-Location -Path '../Automation-Account/'
.\Deploy-SubscriptionCreator.ps1 -ResourceGroupName 'My-Subscription-Management' -AutomationAccountName 'my-subscription-creator' -Remove -All
```
