<#
This program takes user input and performs an API call to VirusTotal.
User input is validated  by character length.
The Json response is parsed for status code and number of AV engines
that report the hash as malicious.
If API call fails, server status code is captured.
#>

#request hash from user and store in variable
$hash = Read-Host "`nPlease enter your MD5 or SHA256 hash"

#validate hash length
while($hash.Length -ne 64 -and $hash.Length -ne 32)
{
    $hash = Read-Host "`nInvalid hash format!`nPlease re-enter your MD5 or SHA hash"
}

#request api key from user and store in variable
$apiKey = Read-Host "`nPlease enter your VirusTotal API key"

#validate api key character length
while($apiKey.Length -ne 64)
{
    $apiKey = Read-Host "`nInvalid API key format!`nPlease re-enter your VirusTotal API key"
}

#define API Call header
$headers=@{}
$headers.Add("Accept", "application/json")

#insert api key variable into header
$headers.Add("x-apikey", $apiKey)

#try to reach web server
try
{
    #api call appends hash variable to url
    $response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/files/$hash" -Method GET -Headers $headers

    #output status code
    $code = $response.StatusCode
    Write-Output "`nYour status code is $code`n"

    #convert json to PS Object
    $data = $response.Content | ConvertFrom-Json

    #isolate malicious count data and assign to variable
    $mal = $data.data.attributes.last_analysis_stats.malicious

    <#
    test malicous count variable and output
    if count is 0, less than 5, or 5+
    #>

    if($mal -eq 0)
    {
        Write-Output "This file is clean."
    } 
    elseif($mal -lt 5)
    {
        Write-Output "This file is potentially malicious. $mal AV engines detected an issue."
    }
    else
    {
        Write-Output "This file is malicious. $mal AV engines detected an issue."
    }
}#end try

#catch if API call fails and captures status code
catch
{
    Write-Output "`nAPI Call failed. `nYour status code is $($_.Exception.Response.StatusCode.Value__)"
}
