
#request hash
$Hash = Read-Host "Please enter your MD5 or SHA256 value"

#request api key
$APIkey = Read-Host "Please enter your VirusTotal API key"

#define header
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("x-apikey", $APIkey)

#api call
$response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/files/$Hash" -Method GET -Headers $headers

#output status code
Write-Output "Your status code is " $response.StatusCode

#convert json
$data = $response.RawContent | ConvertFrom-Json
Write-Output $data

#test
if($data.Contains('"malicious": 0'))
{
    Write-Output "This file is clean."
} 
else
{
    Write-Output "This file is malicious."
}