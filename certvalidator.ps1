# PowerShell-based X.509 Certificate Expiration Tool

param (
    [string]$file = $(throw "-File parameter is required")
)

$remoteURLList = get-content -path $file
$remoteCertificateList = @()

foreach ($remoteURL in $remoteURLList) {
 
    # Define our Socket Object
    $socket = new-object Net.Sockets.TcpClient

    # Define the Output object of the information we want.
    $remotecertificateOutput = new-object -typename PSObject
    add-member -InputObject $remotecertificateOutput -MemberType NoteProperty -name Host -value $null
    add-member -InputObject $remotecertificateOutput -MemberType NoteProperty -name Subject -value $null
    add-member -InputObject $remotecertificateOutput -MemberType Noteproperty -name ExpireDays -value $null

    Try {
        $socket.connect($remoteURL,443)
        $sslStream = new-object Net.Security.SslStream($socket.GetStream(),$false)
        $sslStream.AuthenticateAsClient($remoteURL)
     
        $remoteCertificate = $sslStream.RemoteCertificate
        $remoteCertExpirationDateTime = [DateTime]$remoteCertificate.GetExpirationDateString()
        $remoteCertExpirationLength = new-timespan -start (Get-Date) -End $remoteCertExpirationDateTime

        $remotecertificateOutput.Host = $remoteURL
        $remotecertificateOutput.Subject = $remoteCertificate.Subject
        $remotecertificateOutput.ExpireDays = $remoteCertExpirationLength.Days

    }
    Catch [System.Security.Authentication.AuthenticationException] {
        # This will occur if the certificate is invalid.
    
        $remotecertificateOutput.Host = $remoteURL
        $remotecertificateOutput.Subject = "Invalid Certificate"
        $remotecertificateOutput.ExpireDays = "N/A"
    
    }
    Catch [System.Net.Sockets.SocketException] {
        # Unknown host exception
        $remotecertificateOutput.Host = "Unknown Host"
        $remotecertificateOutput.Subject = $null
        $remotecertificateOutput.ExpireDays = $null 
    }

    #$htmlStyle = "<Style>"
    #$htmlStyle = $htmlStyle + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
    #$htmlStyle = $htmlStyle + "TH{border-width: 1px;padding: 10px;border-style: solid;border-color: black}"
    #$htmlStyle = $htmlStyle + "TD{border-width: 1px;padding: 10px;border-style: solid;border-color: black}"
    #$htmlStyle = $htmlStyle + "</style>"
    #$certificateOutput | convertto-html -head $htmlStyle | o

    $remoteCertificateList += $remotecertificateOutput
    $sslStream.close()
    $socket.Close()
}

$remotecertificateList | fl *