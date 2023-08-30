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
                          "subject": "Emailfunction",
                          "body": {
                            "contentType": "HTML",
                            "content": "Your <br>
                            <br>
                            <br>
                             <br>
                            <br>
                            <br>
                             <br>
                            <br>
                            Message.<br>
                            <br>
                            Here <br>
                            Please <br>
                            <br>
                            <br>
                            ATTENTION: You cannot respond to this e-mail! <br>

                            "
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "RECIEVING_EMAIL_ADDRESS"
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