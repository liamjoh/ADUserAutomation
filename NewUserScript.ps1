#Script to create a new user.
#Created by liamjoh
#Module imports if needed
Import-Module -Name PnP.PowerShell
Import-Module ActiveDirectory

#Read configfile for credentials
$configFileContent = Get-Content -Path "YOUR_PATH_TO_CREDENTIALS_TEXT"
$config = @{}

#Remake the value inte to values
foreach ($line in $configFileContent) {
    $key, $value = $line -split "=", 2
    $config[$key.Trim()] = $value.Trim()
}

#Create new values from the file content
$loginname = $config["Username"]
$password = $config["Password"]
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force


#Define Credentials towards AD
$cred = New-Object System.Management.Automation.PSCredential($loginname, $securePassword)

function ReplaceSpecialChars([string]$string) {
    # define replacements:
    @{
        "æ" = "a"
        "ø" = "o"
    }.GetEnumerator() | foreach {
        $string = $string.Replace($_.Key, $_.Value)
    }
    return $string
}

function ReplaceSpecialChars2([string]$string) {
    # define replacements:
    @{
        "Æ" = "A"
        "Ø" = "O"
    }.GetEnumerator() | foreach {
        $string = $string.Replace($_.Key, $_.Value)
    }
    return $string
}


function RemoveDiacritics([System.String] $text)
{

if ([System.String]::IsNullOrEmpty($text))
{
    return text;
}
    $Normalized = $text.Normalize([System.Text.NormalizationForm]::FormD)
    $NewString = New-Object -TypeName System.Text.StringBuilder

    $normalized.ToCharArray() | ForEach{
            if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($psitem) -ne [Globalization.UnicodeCategory]::NonSpacingMark)
            {
                [void]$NewString.Append($psitem)
            }
        }

    return ReplaceSpecialChars2(ReplaceSpecialChars($NewString.ToString()))
}



  Function New-SveviaUser{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$firstName,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$lastName,
	
    [Parameter(Mandatory=$True,Position=3)]
    [string]$username,
	
    [Parameter(Mandatory=$True,Position=4)]
    [string]$upn
    )


$userName = [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($userName))
$upn = [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($upn))

    Write-host "Final username: $userName" 
    write-host "Final UPN: $upn"
    Add-Content -Path "YOUR_PATH_TO_TXT" -Value "$userName"

    New-ADUser -Name "$userName" -DisplayName "$lastName $firstName" -GivenName "$firstName" -Surname "$lastName" -SamAccountName $userName -Path "YOUR_AD_PATH" -UserPrincipalName $upn -Credential $cred
}



#Asking for user details.
$firstName = Read-Host "Firstname"
$lastName = Read-Host "Lastname"
#$orgshort = Read-Host "Department"

#Generating a password for the user.

Function Generate-RandomPassword {
    param (
        [int]$Length = 12
    )

    $LowercaseChars = "abcdefghijklmnopqrstuvwxyz"
    $UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $NumberChars = "0123456789"
    $SymbolChars = "!@%*()_-+=?/"

    # Initialize with at least one character from each category
    $Password = $LowercaseChars[(Get-Random -Minimum 0 -Maximum $LowercaseChars.Length)]
    $Password += $UppercaseChars[(Get-Random -Minimum 0 -Maximum $UppercaseChars.Length)]
    $Password += $NumberChars[(Get-Random -Minimum 0 -Maximum $NumberChars.Length)]
    $Password += $SymbolChars[(Get-Random -Minimum 0 -Maximum $SymbolChars.Length)]

    # Calculate how many characters are left to reach the desired length
    $RemainingLength = $Length - 4

    # Combine all character sets
    $AllChars = $LowercaseChars + $UppercaseChars + $NumberChars + $SymbolChars

    # Add random characters from the combined set to fulfill the remaining length
    $Random = New-Object System.Random
    for ($i = 0; $i -lt $RemainingLength; $i++) {
        $RandomIndex = $Random.Next(0, $AllChars.Length)
        $Password += $AllChars[$RandomIndex]
    }

    # Shuffle the password characters
    $ShuffledChars = $Password.ToCharArray() | Get-Random -Count $Password.Length
    $Password = -join $ShuffledChars

    return $Password
}

$Password = Generate-RandomPassword -Length 12 -IncludeLowercase -IncludeUppercase -IncludeNumbers -IncludeSymbols
$Password2 = $Password
$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force


#DO loop to verify that an email for an existing user is provided. This loop is only needed if you have a big company with different upn suffixes.

$UserExists = $false

do {
    try {
        $UserMail = Read-Host "Provide the manager's email" -ErrorAction Stop
        $User = Get-ADUser -Filter {mail -eq $UserMail} -Properties samAccountName -ErrorAction Stop
        $UserMobile = (Get-ADUser -Identity $User -Properties mobile).mobile
        
        # Setting up upnsuffix from provided user
        $domainSuffix = $UserMail -replace '^[^@]+@'
        
        if ($domainSuffix -eq 'yourcompannyname.com') {
            $Company = 'yourcompany'
        } elseif ($domainSuffix -eq 'othercompanyname.com') {
            $Company = 'othercompanyname'
        } else {
            Write-Host "Invalid domain suffix: $domainSuffix" -ForegroundColor Yellow
            continue 
        }
        
        $UserExists = $true
    }
    catch {
        Write-Host "Couldn't find a user with $UserMail in AD." -ForegroundColor Yellow
        $UserExists = $false
    }
} until ($UserExists)


do {
    $ManagerExists = $false
    try {
        $ManagerSAM = $User.samAccountName
        $Manager = Get-ADUser -Filter {samAccountName -eq $ManagerSAM} -ErrorAction Stop
        $ManagerExists = $true
    }
    catch {
        Write-Host "Couldn't find anyone with the username $ManagerSAM in AD." -ForegroundColor Yellow
    }
} until ($ManagerExists)

Write-Host "Manager found!: $($Manager.Name)" -ForegroundColor Green

#Getting UPNSuffix from manager mail
$upnSuffix = $UserMail.Substring($UserMail.IndexOf("@"))


#DO Loop for licensing

Do {
    $licenses = Read-Host "Should the user have M365 E-Licenses? (Y / N)"
} until ( 'y', 'n' -contains $licenses ) 


#DO loop forcing userID to be 6 numbers
do{
    try{
        $UserID = 0
        [long]$UserID = Read-Host "UserID" -ErrorAction Stop
        if(($UserID.ToString().Length -ne 6)){
            Write-Host "UserID has to be 6 numbers long." -ForegroundColor Yellow
        }
    }
    catch{
        Write-Host "UserID has to be written in numbers." -ForegroundColor Yellow
    }
}until(($UserID.ToString().Length -eq 6))


Start-Sleep -Seconds 1


#DO loop Forcing externalID to 6 numbers
do{
    try{
        $ExID = 0
        [long]$ExID = Read-Host "ExternalID" -ErrorAction Stop
        if(($ExID.ToString().Length -ne 6)){
            Write-Host "ExternalID has to be 6 numbers long." -ForegroundColor Yellow
        }
    }
    catch{
        Write-Host "ExternalID has to be written in numbers." -ForegroundColor Yellow
    }
}until(($ExID.ToString().Length -eq 6))


Start-Sleep -Seconds 1

#Generates a SamAccountName

 
$testDB = Get-Content -Path "Filepath"
$userName = RemoveDiacritics( "Somethingyouwantbeforetheusername" + $firstName.Substring(0, 2).ToLower() + $lastName.Substring(0, 2).ToLower())

#Generates a new SamAccountName if the first one is taken
$i = 1
while(((Get-ADUser -Credential $cred -filter {sAMAccountName -eq $userName}) -ne $null) -or $testDB -contains $userName){
    if($i -ge 100){
        $userName = $userName.Substring(0,$userName.Length-3) + $i
    }
    elseif($i -ge 10){
        $userName = $userName.Substring(0,$userName.Length-2) + $i
    }
    else{
        $userName = $userName.Substring(0,$userName.Length-1) + $i
    }
    $i++
}

#Generates a UserPrincipalName.
   
$upn = RemoveDiacritics($firstName.ToLower()+"."+$lastName.ToLower()+$upnsuffix.ToLower())
if((Get-ADUser -Credential $cred -filter {UserPrincipalName -eq $upn}) -ne $null){
	$middleName = Read-Host -Prompt "UPN Exists, please add middlename"
    $upn = RemoveDiacritics($firstName.ToLower()+"."+ $middleName.ToLower() +"."+$lastName.ToLower()+$upnsuffix.ToLower())
}


#Runs New-ADUser function.
New-ADUser -firstName $firstName -lastName $lastName -username $userName -upn $upn

Write-Host "Setting up the remaining attributes" -ForegroundColor Cyan

Start-Sleep -Seconds 5

#Checking so that the Mailaddress is not already in use and asks
$MailAddress = $upn
while((Get-ADUser -Credential $cred -Filter {EmailAddress -eq $MailAddress}) -ne $null){
    Write-Host "The email is already in use by $((Get-ADUser -Filter {EmailAddress -eq $MailAddress}).samAccountName)." -ForegroundColor Yellow
    $MailAddress = Read-Host "New Email-address"
}

$WO = Read-Host "Ticket Number"

Start-Sleep -Seconds 1

#Sets attributes for the account.

Set-ADUser -Credential $cred -Identity $userName -Replace @{'mailNickname' = $userName}
Set-ADUser -Credential $cred -Identity $userName -Replace @{'ProxyAddresses' = "SMTP:" + $MailAddress}
#Set-ADUser -Credential $cred -Identity $userName -Replace @{'uid' = $ExID}
Set-ADUser -Credential $cred -Identity $userName -Replace @{'company' = $Company}
Set-ADUser -Credential $cred -Identity $userName -Replace @{'employeeID' = $ExID}
Set-ADUser -Credential $cred -Identity $userName -Replace @{'employeeNumber' = $UserID}
Set-ADUser -Credential $cred -Identity $userName -EmailAddress $MailAddress
Set-ADUser -Credential $cred -Identity $userName -Manager $ManagerSAM
Set-ADUser -Credential $cred -Identity $userName -Description $WO
Set-ADAccountPassword -Credential $cred -Identity $userName -Reset -NewPassword $SecurePassword
Enable-ADAccount -Credential $cred -Identity $userName
Set-ADUser -Credential $cred -Identity $userName -ChangePasswordAtLogon $true
#Set-ADUser -Credential $cred -Identity $userName -Replace @{'department' = $orgshort}

#Adds the account to standard AD Groups
Add-ADGroupMember -Credential $cred -Identity "GROUPNAME" -Members $userName

Start-sleep -Seconds 2

if($licenses -eq "Y"){
   Add-ADGroupMember -Credential $cred -Identity "YOUR_GROUPNAME_FOR_M365_LICENSES" -Members $userName

   }else{
   
   Add-ADGroupMember -Credential $cred -Identity "YOUR_GROUPNAME_FOR_M365_LICENSES" -Members $userName
}


Write-Host "$((Get-Culture).TextInfo.ToTitleCase($KontoTyp)) ACCOUNT CREATED: $userName" -ForegroundColor Green

Start-Sleep -Seconds 1

#Settings for mailout function

$clientID = "YOUR_CLIENT_ID"
$Clientsecret = "YOUR_CLIENT_SECRET"
$tenantID = "YOUR_TENANT_ID"
$MailSender = "YOUR_MAILSENDER_ACCOUNT_EMAIL"

#Connection to Microsoft Graph

$tokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $clientId
    Client_Secret = $clientSecret
}
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
$headers = @{
    "Authorization" = "Bearer $($tokenResponse.access_token)"
    "Content-type"  = "application/json"
}

# Mailout function
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "New User account created",
                          "body": {
                            "contentType": "HTML",
                            "content": "New account has been created with the following details: <br>
                            <br>
                            <br>
                            Name: $firstName $lastName <br>
                            Email: $MailAddress <br>
                            Username: $userName <br>
                            Employment Number: $ExID <br>
                            <br>
                            You'll recieve the password in a text message together with this email.<br>
                            <br>
                            Kind Regards, <br>
                            Servicedesk <br>
                            <br>
                            <br>
                            ATTENTION: You cannot respond to this e-mail! <br>

                            "
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$UserMail"
                              }
                            }
                          ],
                          "ccRecipients": [
                            {
                              "emailAddress": {
                                "address": "YOUR_CC_ADDRESS"
                              }
                            }
                          ]

                        },
                        "saveToSentItems": "false"
                      }
"@

Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonsend -ContentType "application/json;charset=UTF-8"


$apiEndpoint = "YOUR_API_ENDPOINT_HERE"
$apiKey = "YOUR_API_KEY_HERE"



$jsonPayload = @{
    "apiKey" = $apiKey
    "content-type" = "application/json"
    "to" = $UserMobile
    "body" = "YOUR_TEXT_MESSAGE_HERE"
    "smsSender" = "SENDERNAME"
    "sendNow" = $true
} | ConvertTo-Json


$headers = @{
    "Content-Type" = "application/json;charset-UTF8"
    "api-key" = $apiKey
}

Invoke-RestMethod -Uri $apiEndpoint -Method POST -Headers $headers -Body $jsonPayload


Write-Host "`n`n Email has been sent to $UserMail, Password has been sent to $UserMobile via text message."
Write-Host "`n`n Press a button to end script"
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

