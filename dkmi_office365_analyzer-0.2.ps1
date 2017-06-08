<#
    .SYNOPSIS

    script searches for special dns entries if they are available for exchange 365 dkmi settings (like dmarc selectors etc.)

    .DESCRIPTION

    this script analyses if there are special dns records available for dkmi in office 365 (exchange online) 
    DKIM (DomainKeys Identified Mail) is an authentication process that can help protect both senders and recipients from forged and phishing email. 
    Add DKIM signatures to your domains so recipients know that email messages actually came from users in your organization and weren't modified after they were sent.


    .EXAMPLE
    output in ise/powershell:
    ################# checking domain microsoft.com #################
 
    the domain microsoft.com was found!
    ################# finding mx records microsoft.com #################
 
    mx records:  
    microsoft-com.mail.protection.outlook.com
 
    preference:  
    10
 
    ############# Finding SPF-Record microsoft.com ##############
 
    SPF_record was detected: 
    docusign=d5a3737c-c23c-4bd0-9095-d2ff621f2840 v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.microsoft.com include:spf-a.hotm
    ail.com ip4:147.243.128.24 ip4:147.243.128.26 ip4:147.243.1.153 ip4:147.243.1.47 ip4:147.243.1.48 -all FbUF6DbkE+Aw1/wi9xgDi8KVrIIZus5v8L6tbIQZkGrQ/rVQKJi8CjQbBtWtE64ey4NJJwj5J65PIggVYNabdQ==
     google-site-verification=6P08Ow5E-8Q0m6vQ7FMAqAYIDprkVV8fUf_7hZ4Qvc8
 
    ################# Finding dmarc record for microsoft.com #############
 
    dmarc record is:   
    _dmarc.microsoft.com
 
    dmarc record value is:  
    v=DMARC1; p=reject; pct=100; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com; fo=1
 
    ############# finding dkmi settings microsoft.com ##############
 
    ############# finding selektor1 settings microsoft.com ##############
 
    selector1:  
    selector1._domainkey.microsoft.com
    CNAME
    selector1-microsoft-com._domainkey.microsoft.onmicrosoft.com
 
    selector1 dkmi value:  
    v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkHq3ztGIm1R8alD+7oZiaG5mTUttFdFOlpKHRBZCPFG4sugV1EfF5F6JpwbJDzZmyIlqYfTgUkmYOvbHsoYvW7rddLKVTh+vE1SZ5P9coIHrw759hXbpPDSQ9JNP8aN+Bfrg6Y
    MEWnOGA+PL+ZpyvswcB0jz9M6yMvowOxCHv5QIDAQAB; n=1024,1435867504,1
 
    ############# finding selektor2 settings microsoft.com ##############
 
    selector2:  
    selector2._domainkey.microsoft.com
    CNAME
    selector2-microsoft-com._domainkey.microsoft.onmicrosoft.com
 
    selector2 dkmi value:  
    v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD0h/iZtkr/tGvMKKZyv+w4uj754pDYKX4J6foqT0FliC4QnJ7fXRCtzSpPY+5H/R6r4kxu5JeQpLhf/yOXZxwq53flmrSGVmMDqCyd6xTXpa06nFy8jpwQtJzd8wF/WyiskLPeZ
    eMua+5925XgmDcdSlDfQrh/+pj27IUDOj/6RQIDAQAB; n=1024,1435867505,1
 
    ############# everything is ready to configure dkmi in exchange online ##############

    .Notes
    Please define variables 
    $dnsserver = define your own dns server or use a public server (dns has to be allowed on firewall)
    $domainname = ""
    copy complete script in ISE on your client or server and execute (F5) with your domain 
    go to https://blog.it-koehler.com/Archive/1450 and check all dns entries 

  
    ---------------------------------------------------------------------------------
                                                                                 
    Script:       dkmi_office365_analyzer-0.2.ps1                                      
    Author:       A. Koehler; blog.it-koehler.com
    ModifyDate:    08/06/2017                                                        
    Usage:        for use in ise/powershellconsole 
    Version:       0.2
                                                                                  
    ---------------------------------------------------------------------------------
#>
###### input from console 

Param
(
  [Parameter(Mandatory=$True)]
  [ValidatePattern('^[A-Z0-9.-]+\.[A-Z]{2,63}$')]
  [ValidateNotNullOrEmpty()]
  [ValidateLength(3,63)]
  [string]$topleveldomain,
  [Parameter(Mandatory=$true)]
  [ValidateScript({$_ -match [IPAddress]$_ })]  
  [string]$DNSServertoUse

 )

$domainname = $topleveldomain
$dnserver = $DNSServertoUse

####### script beginning #####

$domaindmarc = "_dmarc.$domainname"
$selector1 = "selector1._domainkey.$domainname"
$selector2 = "selector2._domainkey.$domainname"
#check if domain exists 
Write-Host "################# checking domain $domainname #################" -ForegroundColor Yellow
Write-Host " " -ForegroundColor Yellow
try
{
  $dnschk = Resolve-DnsName -Name $domainname -Server $dnserver -ErrorAction Stop
  if($dnschk.name -eq "$domainname")
    {
      Write-Host "the domain $domainname was found!" -ForegroundColor Green
      Write-Host " " -ForegroundColor Yellow
      $test = $true

      #check mx records
        try
        {
          $mxtest = (Resolve-DnsName -Type MX -Name $domainname -Server $dnserver -ErrorAction Stop)
          
        }
        catch
        {
          Write-Host 'NO mxrecord found '"$domainname"'found! Script canceled!' -ForegroundColor Red
          $test = $false
        }
   
   
        if($test -eq $true)
        {
          $test = $null
          Write-host "################# finding mx records $domainname #################" -ForegroundColor Yellow
          Write-Host " " -ForegroundColor Yellow
          $mxrecords = (Resolve-DnsName -Type MX -Name $domainname -Server $dnserver)
          Write-Host 'mx records:  ' -ForegroundColor White
          Write-host $mxrecords.NameExchange -ForegroundColor Green
          Write-Host " " -ForegroundColor Yellow
          Write-host 'preference:  ' -ForegroundColor White
          write-host $mxrecords.Preference -ForegroundColor Green
          Write-Host " " -ForegroundColor Yellow
        }
        else
        {
          Write-Host 'Can not resolve domain. NO DNS Record for '"$domainname" 'found! Script canceled!' -ForegroundColor Red
          $test = $false
          exit
      
        }
  
  
  
        Write-host "############# Finding SPF-Record $domainname ##############" -ForegroundColor Yellow
        Write-Host " " -ForegroundColor Yellow
        $spf = (Resolve-DnsName -Type txt -Name $domainname -Server $dnserver).strings
        if($spf -like '*v=spf*')
        {
          Write-Host 'SPF_record was detected: ' -ForegroundColor White
          Write-Host $spf -ForegroundColor Green
          Write-Host " " -ForegroundColor Yellow
        }
        else
        {

          Write-Host 'NO SPF Record was detected please check your settings! '"$spf" -ForegroundColor Red
          Write-Host 'SPF record is required before using dkmi please check' -ForegroundColor Cyan
          Write-Host 'https://blog.it-koehler.com/Archive/216'-ForegroundColor Cyan
          Write-Host " " -ForegroundColor Yellow
          
         }
    }
}
catch
{
  Write-Host 'Can not resolve domain. NO DNS Record for '"$domainname" 'found! Script canceled!' -ForegroundColor Red
  exit
}

#dkmi settings:
#check dmarc exists 
  Write-Host "################# Finding dmarc record for $domainname #############" -ForegroundColor Yellow
  Write-Host " " -ForegroundColor Yellow
  try
  {
    
    $dmarctest = Resolve-DnsName -Type txt -Name $domaindmarc -Server $dnserver -ErrorAction Stop
    if($dmarctest.name -eq "$domaindmarc")
    {
      $test = $true
    }
    else
    {
      Write-Host 'NO DMARC Record in ' "$domainname" 'found!' -ForegroundColor Red
      Write-Host 'a dmarc entry looks like this: ' -ForegroundColor Cyan
      Write-Host $domaindmarc -ForegroundColor Cyan
      Write-Host 'its a txt record where you should put information like described in link: ' -ForegroundColor Cyan
      Write-Host 'https://blog.it-koehler.com/Archive/1450'-ForegroundColor Cyan
      Write-Host 'https://technet.microsoft.com/en-us/library/mt734386(v=exchg.150).aspx#CreateDMARCRecord' -ForegroundColor Cyan
      Write-Host " " -ForegroundColor Yellow
      $test = $false
      
    }
    
  }
  catch
  {
      Write-Host 'NO DMARC Record in ' "$domainname" 'found!' -ForegroundColor Red
      Write-Host 'a dmarc entry looks like this: ' -ForegroundColor Cyan
      Write-Host $domaindmarc -ForegroundColor Cyan
      Write-Host 'its a txt record where you should put information like described in link: ' -ForegroundColor Cyan
      Write-Host 'https://blog.it-koehler.com/Archive/1450'-ForegroundColor Cyan
      Write-Host 'https://technet.microsoft.com/en-us/library/mt734386(v=exchg.150).aspx#CreateDMARCRecord' -ForegroundColor Cyan
      Write-Host " " -ForegroundColor Yellow
    
  }

if($test -eq $true)
{
  $test = $null
  
  $dmarc = (Resolve-DnsName -Type txt -Name $domaindmarc -Server $dnserver)
  Write-Host 'dmarc record is:   '-ForegroundColor White 
  Write-Host $dmarc.name -ForegroundColor Green
  Write-Host " " -ForegroundColor Yellow
  Write-Host 'dmarc record type is:  ' -ForegroundColor White 
  Write-Host $dmarc.Type -ForegroundColor Green
  Write-Host " " -ForegroundColor Yellow
  Write-Host 'dmarc record value is:  ' -ForegroundColor White 
  Write-host $dmarc.Strings -ForegroundColor Green
  Write-Host " " -ForegroundColor Yellow
  
}

#selektor 1 settings
    Write-host "############# finding dkmi settings $domainname ##############" -ForegroundColor Yellow
    Write-Host " " -ForegroundColor Yellow
    Write-host "############# finding selektor1 settings $domainname ##############" -ForegroundColor Yellow
    Write-Host " " -ForegroundColor Yellow
try
  {
    $dkmi1test = (Resolve-DnsName -Type txt -Name $selector1 -Server $dnserver -ErrorAction Stop).name
    if($dkmi1test -match "$selector1")
    {
      $test = $true
    }
    else
    {
      Write-Host 'NO selectorrecord1 in '"$domainname" 'found!' -ForegroundColor Red
      Write-Host 'the selector should look like this: ' -ForegroundColor Cyan
      Write-Host $selector1 -ForegroundColor Cyan
      Write-Host " " -ForegroundColor Yellow
      $test = $false
      
    }
    
  }
  catch
  {
    Write-Host 'NO selectorrecord1 in '"$domainname" 'found!' -ForegroundColor Red
    Write-Host 'the selector should look like this: ' -ForegroundColor Cyan
    Write-Host $selector1 -ForegroundColor Cyan
    Write-Host " " -ForegroundColor Yellow
    
  }
   
   
  if($test -eq $true)
  {
   
    $dkmi1cname = (Resolve-DnsName -Type txt -Name $selector1 -Server $dnserver | Select-Object * -First 1)
    $dkmi1txt = (Resolve-DnsName -Type txt -Name $selector1 -Server $dnserver | Select-Object * -Skip 1 |Select-Object * -First 2) 
    Write-Host 'selector1:  ' -ForegroundColor White
    Write-Host $dkmi1cname.Name -ForegroundColor Green
    Write-Host $dkmi1cname.QueryType -ForegroundColor Green
    Write-Host $dkmi1cname.NameHost -ForegroundColor Green
    Write-Host " " -ForegroundColor Yellow
    Write-host 'selector1 dkmi value:  ' -ForegroundColor White 
    Write-Host $dkmi1txt.strings -ForegroundColor Green
    Write-Host " " -ForegroundColor Yellow
  }
 
 #selektor2 settings
 
    Write-host "############# finding selektor2 settings $domainname ##############" -ForegroundColor Yellow
    Write-Host " " -ForegroundColor Yellow
    try
    {
  
  
      $dkmi2test = ((Resolve-DnsName -Type txt -Name $selector2 -Server $dnserver -ErrorAction Stop).name)  
      if($dkmi2test -match "$selector2")
      {
        $test = $true
       }
       else
      {
        Write-Host 'NO selectorrecord1 in '"$domainname" 'found!' -ForegroundColor Red
        Write-Host 'the selector should look like this: ' -ForegroundColor Cyan
        Write-Host $selector2 -ForegroundColor Cyan
        Write-Host " " -ForegroundColor Yellow
        $test = $false
      
      }
    }
    catch
    {
      Write-Host 'NO selectorrecord1 in '"$domainname" 'found!' -ForegroundColor Red
      Write-Host 'the selector should look like this: ' -ForegroundColor Cyan
      Write-Host $selector2 -ForegroundColor Cyan
      Write-Host " " -ForegroundColor Yellow
      Write-host '############# please check dkmi settings some dns settings are missing ##############' -ForegroundColor Cyan
      Write-Host " " -ForegroundColor Yellow
    }
      
  if($test -eq $true)
  {
    $test = $null
    
    $dkmi2cname = (Resolve-DnsName -Type txt -Name $selector2 -Server $dnserver | Select-Object * -First 1)
    $dkmi2txt = (Resolve-DnsName -Type txt -Name $selector2 -Server $dnserver | Select-Object * -Skip 1 |Select-Object * -First 2) 
    Write-Host 'selector2:  ' -ForegroundColor White
    Write-Host $dkmi2cname.Name -ForegroundColor Green
    Write-Host $dkmi2cname.QueryType -ForegroundColor Green
    Write-Host $dkmi2cname.NameHost -ForegroundColor Green
    Write-Host " " -ForegroundColor Yellow
    Write-host 'selector2 dkmi value:  ' -ForegroundColor White 
    Write-Host $dkmi2txt.strings -ForegroundColor Green
    Write-Host " " -ForegroundColor Yellow
    Write-host '############# everything is ready to configure dkmi in exchange online ##############' -ForegroundColor Cyan
    
  }

cmd -WindowStyle Hidden /c pause | out-null
