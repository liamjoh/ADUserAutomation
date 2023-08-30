#Script made by Liamjoh
 
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
