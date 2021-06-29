## Defender ATP Kusto Queries 

##### 1. List of all Defender Endpoint Alerts
`SecurityAlert
| where ProviderName == "MDATP"
| sort by TimeGenerated`


##### 2. Test Alert of Endpoint connected into log analytics
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "[Test Alert] Suspicious Powershell commandline"
| sort by TimeGenerated`

##### 3. Suspected credential theft activity
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Suspected credential theft activity"
| sort by TimeGenerated`

##### 4. Suspicious screen capture activity
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Suspicious screen capture activity"
| sort by TimeGenerated`

##### 5. Password hashes dumped from LSASS memory
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Password hashes dumped from LSASS memory"
| sort by TimeGenerated`

##### 6. Malicious credential theft tool execution detected
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Malicious credential theft tool execution detected"
| sort by TimeGenerated`

##### 7. Unsanctioned cloud app access was blocked
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Unsanctioned cloud app access was blocked"
| sort by TimeGenerated`

##### 8. Suspicious Remote WMI Execution
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Suspicious Remote WMI Execution"
| sort by TimeGenerated`

##### 9. Pass-the-ticket attack
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Pass-the-ticket attack"
| sort by TimeGenerated`

##### 10. A script with suspicious content was observed
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "A script with suspicious content was observed"
| sort by TimeGenerated`

##### 11. Suspicious PowerShell command line
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Suspicious PowerShell command line"
| sort by TimeGenerated`

##### 12. Sensitive credential memory read
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Sensitive credential memory read"
| sort by TimeGenerated`

##### 13. Password hashes dumped from LSASS memory
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Password hashes dumped from LSASS memory"
| sort by TimeGenerated`

##### 14. Suspicious connection to legitimate web service
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Suspicious connection to legitimate web service"
| sort by TimeGenerated`

##### 15. Shellcode from DNS response
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Shellcode from DNS response"
| sort by TimeGenerated`

##### 16. Privilege escalation using token duplication
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Privilege escalation using token duplication"
| sort by TimeGenerated`

##### 17. A process was injected with potentially malicious code
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "A process was injected with potentially malicious code"
| sort by TimeGenerated`

##### 18. Network request to TOR anonymization service
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Network request to TOR anonymization service"
| sort by TimeGenerated`

##### 19. A malicious PowerShell Cmdlet was invoked on the machine
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "A malicious PowerShell Cmdlet was invoked on the machine"
| sort by TimeGenerated`

##### 20. Sensitive credential memory read
`SecurityAlert
| where ProviderName == "MDATP"
| where DisplayName == "Sensitive credential memory read"
| sort by TimeGenerated`

## Microsoft Cloud Application Security 
##### 21. List all MCAS Alerts
`SecurityAlert​ | where ProductName == "Microsoft Cloud App Security"​ ​ 
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| sort by TimeGenerated`

## Azure Active Directory

##### 22. Failed Login Attempts
`SigninLogs
| sort by TimeGenerated
| where ResultDescription == 'Invalid username or password or Invalid on-premise username or password.'
| summarize by TimeGenerated, OperationName, AlternateSignInName, AppDisplayName`

With IP Address Location:

`SigninLogs | sort by TimeGenerated | where ResultDescription == 'Invalid username or password or Invalid on-premise username or password.' | summarize by TimeGenerated, OperationName, AlternateSignInName, AppDisplayName, IPAddress`

##### 23. Modified Domain Federation Trust Settings

`AuditLogs
| where OperationName =~ "Set federation settings on domain"`

##### 23. Failed Login Attempts with Location details
`SigninLogs
| sort by TimeGenerated
| where ResultDescription == 'Invalid username or password or Invalid on-premise username or password.'
| summarize by TimeGenerated, OperationName, AlternateSignInName, AppDisplayName, tostring(LocationDetails)`

##### 24. Risky Sign In Attempts

`SecurityAlert
    | where ProductName == "Azure Active Directory Identity Protection"
| sort by TimeGenerated`

##### 25. Brute Force Attack Against Azure Portal

`let failureCountThreshold = 5;
let successCountThreshold = 1;
let authenticationWindow = 20m;
let aadFunc = (tableName:string){
table(tableName)
| extend DeviceDetail = todynamic(DeviceDetail), Status = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city), Region = tostring(LocationDetails.countryOrRegion)
| where AppDisplayName has "Azure Portal"
// Split out failure versus non-failure types
| extend FailureOrSuccess = iff(ResultType in ("0", "50125", "50140", "70043", "70044"), "Success", "Failure")
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), IPAddress = make_set(IPAddress), make_set(OS), make_set(Browser), make_set(City),
make_set(State), make_set(Region),make_set(ResultType), FailureCount = countif(FailureOrSuccess=="Failure"), SuccessCount = countif(FailureOrSuccess=="Success") 
by bin(TimeGenerated, authenticationWindow), UserDisplayName, UserPrincipalName, AppDisplayName, Type
| where FailureCount >= failureCountThreshold and SuccessCount >= successCountThreshold
| mvexpand IPAddress
| extend IPAddress = tostring(IPAddress)
| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress 
};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt`

##### 26. MFA Disabled for a User
`(union isfuzzy=true
(AuditLogs 
| where OperationName =~ "Disable Strong Authentication"
| extend IPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) 
| extend InitiatedByUser = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
 tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend Targetprop = todynamic(TargetResources)
| extend TargetUser = tostring(Targetprop[0].userPrincipalName) 
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by User = TargetUser, InitiatedByUser , Operation = OperationName , CorrelationId, IPAddress, Category, Source = SourceSystem , AADTenantId, Type
),
(AWSCloudTrail
| where EventName in~ ("DeactivateMFADevice", "DeleteVirtualMFADevice") 
| extend InstanceProfileName = tostring(parse_json(RequestParameters).InstanceProfileName)
| extend TargetUser = tostring(parse_json(RequestParameters).userName)
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by User = TargetUser, Source = EventSource , Operation = EventName , TenantorInstance_Detail = InstanceProfileName, IPAddress = SourceIpAddress
)
)
| extend timestamp = StartTimeUtc, AccountCustomEntity = User, IPCustomEntity = IPAddress`

## Azure Acitive Directroy Idnetity Protection

##### 25. Unfamiliar Sign-in 
`SecurityAlert
| where AlertName == "Unfamiliar sign-in properties"`

