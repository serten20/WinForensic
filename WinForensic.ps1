Write-host ""
Write-Host @"
							  
		 ________  __         _______                                    __
		|  |  |  ||__|.-----.|    ___|.-----..----..-----..-----..-----.|__|.----.
		|  |  |  ||  ||     ||    ___||  _  ||   _||  -__||     ||__ --||  ||  __|
		|________||__||__|__||___|    |_____||__|  |_____||__|__||_____||__||____|


"@ -ForegroundColor Yellow 


# Verificar si se está ejecutando como administrador
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-Not $isAdmin) {
    Write-warning "Run powershell as administrator and try again"
    pause
    exit
}



$FormatoFecha = "MM'-'dd'-'yyyy HH':'mm':'ss"
$TiempoInicio = Get-Date -Format $FormatoFecha
#variable para conseguir la antiguedad de logs en meses
$meses ="3"
$mesAnterior = (Get-Date).AddMonths(-$meses)
$fechaActual = (Get-Date)


If ($meses -eq "1") {
	Write-host "Data collection:" -nonewline
	Write-host " $meses " -nonewline -ForegroundColor Green 
	Write-host "month"
} 
else {
	Write-host "Data collection:" -nonewline
	Write-host " $meses " -nonewline -ForegroundColor Green 
	Write-host "months"
	
}

Write-host ""

#exportlogs
Write-Host -Fore DarkCyan "[*] Collecting System, Application & Security events " -nonewline

$DirectorioLog = "EventViewer-Information"
Remove-Item -ErrorAction SilentlyContinue -Path $DirectorioLog -Recurse
$LogDirectory = mkdir $DirectorioLog
$EventosSistema = wevtutil epl System $LogDirectory/System_Event_Log.evtx 
$EventosAplicacion = wevtutil epl Application $LogDirectory/Application_Event_Log.evtx 
$EventosSeguridad = wevtutil epl Security $LogDirectory/Security_Event_Log.evtx 

Write-Host "(Done)" -ForegroundColor Green



#user&Account
Write-Host -Fore DarkCyan "[*] Collecting user & account information " -nonewline

#Se obtiene información sobre los usuarios locales del sistema.

$UsuariosLocales = Get-LocalUser | select Name, Enabled, PrincipalSource, PasswordRequired, PasswordLastSet, PasswordExpires,Description | ConvertTo-Html -Fragment

$PerfilesUsuario = Get-WmiObject -Class Win32_UserProfile | Select-object -property LocalPath, SID, @{Name='Last Used';Expression={$_.ConvertToDateTime($_.lastusetime)}} | ConvertTo-Html -Fragment 
$SesionesLogeadas = quser
$administradores = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | ConvertTo-Html -Fragment
$GrupoLocal = Get-LocalGroup | ConvertTo-Html -Fragment



#buscar en el visor de eventos eventos de usuarios creados
$FiltroUsuariosCreados = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=4720 }
$Usuarioscreados = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $FiltroUsuariosCreados | ForEach-Object {
    $UsuariosCreadosEventosXml = ([xml]$_.ToXml()).Event
    $UsuarioCreado = ($UsuariosCreadosEventosXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $Creador = ($UsuariosCreadosEventosXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    
    [PSCustomObject]@{
        Time     = [DateTime]$UsuariosCreadosEventosXml.System.TimeCreated.SystemTime
        CreatedUser = $UsuarioCreado
        CreatedBy = $Creador
		EventId = $_.Id
    }
} | ConvertTo-Html -fragment


#buscar en el visor intentos de restablecer contraseña
$FiltroModificacionUsuarios = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=@(4724,4723)}
$IntentoModificacionContrasena = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $FiltroModificacionUsuarios | ForEach-Object {
    $UsuarioModificadosEventosXml = ([xml]$_.ToXml()).Event
    $UsuarioModificado = ($UsuarioModificadosEventosXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $Creador = ($UsuarioModificadosEventosXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
	
    [PSCustomObject]@{
        Time     = [DateTime]$UsuarioModificadosEventosXml.System.TimeCreated.SystemTime
        ModifiedUser = $UsuarioModificado
        ModifiedBy = $Creador
		EventId = $_.Id
    }
} | ConvertTo-Html -fragment



#buscar en el visor de eventos eventos de usuarios eliminados
$FiltroUsuariosEliminados = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=4726 }
$UsuariosEliminados = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $FiltroUsuariosEliminados | ForEach-Object {
    $UsuariosEliminadosEventosXml = ([xml]$_.ToXml()).Event
    $UsuarioEliminado = ($UsuariosEliminadosEventosXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $Eliminador = ($UsuariosEliminadosEventosXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
    
    [PSCustomObject]@{
        Time     = [DateTime]$UsuariosEliminadosEventosXml.System.TimeCreated.SystemTime
        AddedUser = $UsuarioEliminado
        CreatedBy = $Eliminador
		EventId = $_.Id
    }
} | ConvertTo-Html -fragment





$RDPFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=4624; StartTime = $mesAnterior; EndTime = $fechaActual } 
$RDPLogins = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $RDPFilter | where {$_.properties[8].value -eq 10} | ForEach-Object {
     convert the event to XML and grab the Event node
    $RDPEventXml = ([xml]$_.ToXml()).Event
    $RDPLogonUser = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
	$RDPLogonUserDomain = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
    $RDPLogonIP = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
	$RDPLogonPort = ($RDPEventXml.EventData.Data | Where-Object { $_.Name -eq 'IpPort' }).'#text'
     output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$RDPEventXml.System.TimeCreated.SystemTime
        LogonUser = $RDPLogonUser
		LogonUserDomain = $RDPLogonUserDomain
       LogonIP = $RDPLogonIP
		Port = $RDPLogonPort
		LogonType = $_.LogonType
		EventId = $_.Id
    }
} | ConvertTo-Html -fragment


$loginFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=4624; StartTime = $mesAnterior; EndTime = $fechaActual } 
$Logins = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $loginFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $LoginsXml = ([xml]$_.ToXml()).Event
    $LogonUser = ($LoginsXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
	$LogonUserDomain = ($LoginsXml.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
    $LogonIP = ($LoginsXml.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
	$LogonPort = ($LoginsXml.EventData.Data | Where-Object { $_.Name -eq 'IpPort' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$LoginsXml.System.TimeCreated.SystemTime
        LogonUser = $LogonUser
		LogonUserDomain = $LogonUserDomain
        LogonIP = $LogonIP
		Port = $LogonPort
		LogonType = $_.LogonType
		EventId = $_.Id
    }
} | ConvertTo-Html -fragment



$FiltroLoginFallido = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=4625; StartTime = $mesAnterior; EndTime = $fechaActual } 
$LoginFallido = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $FiltroLoginFallido | ForEach-Object {
#$LoginFallido = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $FiltroLoginFallido | where {$_.properties[8].value -eq 2} | ForEach-Object {
    # convert the event to XML and grab the Event node
    $LoginFallidoEventosXml = ([xml]$_.ToXml()).Event
    $UsuarioLoginFallido = ($LoginFallidoEventosXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
	$DominioLoginFallido = ($LoginFallidoEventosXml.EventData.Data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
    $LoginFallidoIP = ($LoginFallidoEventosXml.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
	$LoginFallidoPuerto = ($LoginFallidoEventosXml.EventData.Data | Where-Object { $_.Name -eq 'IpPort' }).'#text'
	$LoginFallidotype = ($LoginFallidoEventosXml.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$LoginFallidoEventosXml.System.TimeCreated.SystemTime
        LogonUser = $UsuarioLoginFallido
		LogonUserDomain = $DominioLoginFallido 
        LogonIP = $LoginFallidoIP
		Port = $LoginFallidoPuerto
		LogonType = $LoginFallidotype
		EventId = $_.Id
    }
} | ConvertTo-Html -fragment


$GroupMembershipFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=4798; StartTime = $mesAnterior; EndTime = $fechaActual  }
$EnumeratedGroupMembership = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $GroupMembershipFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $EnumeratedGroupMembershipEventXml = ([xml]$_.ToXml()).Event
    $EnumeratedGroupMembershipEnumAccount = ($EnumeratedGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $EnumeratedGroupMembershipPerformedBy = ($EnumeratedGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
	$EnumeratedGroupMembershipPerformedLogon = ($EnumeratedGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
	$EnumeratedGroupMembershipPerformedPID = ($EnumeratedGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessId' }).'#text'
	$EnumeratedGroupMembershipPerformedProcess = ($EnumeratedGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessName' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$EnumeratedGroupMembershipEventXml.System.TimeCreated.SystemTime
        PerformedOn = $EnumeratedGroupMembershipEnumAccount
        PerformedBy = $EnumeratedGroupMembershipPerformedBy
		LogonType = $EnumeratedGroupMembershipPerformedLogon 
		PID = $EnumeratedGroupMembershipPerformedPID
		ProcessName = $EnumeratedGroupMembershipPerformedProcess
		EventId = $_.Id
    }
} | ConvertTo-Html -fragment


$LocalGroupMembershipFilter = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=4799; StartTime = $mesAnterior; EndTime = $fechaActual  }
$EnumeratedLocalGroupMembership = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $LocalGroupMembershipFilter | ForEach-Object {
    # convert the event to XML and grab the Event node
    $EnumeratedLocalGroupMembershipEventXml = ([xml]$_.ToXml()).Event
    $EnumeratedLocalGroupMembershipEnumAccount = ($EnumeratedLocalGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $EnumeratedLocalGroupMembershipPerformedBy = ($EnumeratedLocalGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
	$EnumeratedLocalGroupMembershipPerformedLogon = ($EnumeratedLocalGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'SubjectLogonId' }).'#text'
	$EnumeratedLocalGroupMembershipPerformedPID = ($EnumeratedLocalGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessId' }).'#text'
	$EnumeratedLocalGroupMembershipPerformedProcess = ($EnumeratedLocalGroupMembershipEventXml.EventData.Data | Where-Object { $_.Name -eq 'CallerProcessName' }).'#text'
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$EnumeratedLocalGroupMembershipEventXml.System.TimeCreated.SystemTime
        PerformedOn =  $EnumeratedLocalGroupMembershipEnumAccount
        PerformedBy = $EnumeratedLocalGroupMembershipPerformedBy
		LogonType = $EnumeratedLocalGroupMembershipPerformedLogon 
		PID = $EnumeratedLocalGroupMembershipPerformedPID
		ProcessName = $EnumeratedLocalGroupMembershipPerformedProcess
		EventId = $_.Id
    }
} | ConvertTo-Html -fragment

Write-Host "(Done)" -ForegroundColor Green



#RED
Write-Host -Fore DarkCyan "[*] Collecting Network Information " -nonewline

#$ConexionesTCP = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}| ConvertTo-Html -Fragment
$ConexionesTCPRemotas = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Where-Object -FilterScript { $_.RemoteAddress -Ne "0.0.0.0" } | Where-Object -FilterScript { $_.RemoteAddress -Ne "::" } | Where-Object -FilterScript { $_.RemoteAddress -Ne "127.0.0.1" } | Sort-Object -Property State| ConvertTo-Html -Fragment
$ConexionesTCPLocales = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process";Expression={(Get-Process -eq $_.OwningProcess).ProcessName}} | Where {($_.RemoteAddress -eq "0.0.0.0" -or $_.RemoteAddress -eq "::" -or $_.RemoteAddress -eq "127.0.0.1" )} | Sort-Object -Property State | convertTo-Html -fragment

#revisar
$RutasCompartidas = Get-SMBShare | select description, path, volume | convertTo-Html -fragment

$RutasDestinoNoLocal = Get-NetRoute | Where-Object -FilterScript { $_.NextHop -Ne "::" } | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0,6) -Ne "fe80::") } | select Publish, State,AddressFamily,Protocol,NextHop,DestinationAddress,DestinationPrefix,InterfaceMetric,ElementName,PSComputerName,Description | Sort-Object -Property NextHop |  convertTo-Html -fragment
$RutasDestinoLocal =  Get-NetRoute | Where {($_.NextHop -eq "::" -or $_.NextHop -eq "0.0.0.0" -or $_.NextHop.SubString(0,6) -eq "fe80::")} | select Publish, State,AddressFamily,Protocol,NextHop,DestinationAddress,DestinationPrefix,InterfaceMetric,ElementName,PSComputerName,Description | Sort-Object -Property NextHop | convertTo-Html -fragment
#Get network adapters that have IP routes to non-local destinations

#| select Publish, State,AddressFamily,Protocol,NextHop,DestinationAddress,DestinationPrefix,InterfaceMetric,ElementName,PSComputerName,Description
$AdaptHops = Get-NetRoute | Where-Object -FilterScript {$_.NextHop -Ne "::"} | Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" } | Where-Object -FilterScript { ($_.NextHop.SubString(0,6) -Ne "fe80::") } | Get-NetAdapter | convertTo-Html -fragment
#$adapatadoresdeRed = Get-CimInstance -Class Win32_NetworkAdapterConfiguration | select Description,DHCPEnabled,DHCPServer  | convertTo-Html -fragment
$adapatadoresdeRed2 = Get-NetAdapter | select Name, InterfaceDescription, Status, MacAddress, LinkSpeed | ConvertTo-Html -fragment
 
Write-Host "(Done)" -ForegroundColor Green





#SystemInfo
Write-Host -Fore DarkCyan "[*] Collecting system information " -nonewline

#$InformacionSistema = Get-WmiObject -Class Win32_ComputerSystem | select Name, Domain, Workgroup, DNSHostName, Manufacturer, Model, PrimaryOwnerName, TotalPhysicalMemory   | ConvertTo-Html -Fragment
$ProgressPreference = 'SilentlyContinue'
$InformacionSistema = Get-ComputerInfo | select CSName, CsDomain, CsManufacturer, CsModel, OsArchitecture, OsName, OsVersion, OsLocale   | ConvertTo-Html -Fragment


$hotfix = Get-Hotfix | Select-Object -Property CSName, Caption,Description, HotfixID, InstalledBy, InstalledOn | ConvertTo-Html -fragment 
$archivoHosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$contenidoHosts = Get-Content -Path $archivoHosts
$TareasProgramadas = Get-ScheduledTask | Select-Object TaskName, TaskPath,Description,Date, Author, State, LastRunTime, NextRunTime | Sort-Object -Property Date -Descending | ConvertTo-Html -Fragment 
$ProcesosMaquina = get-process | select Id,Name,PriorityClass,ProcessName,Product,Path,StartTime,TotalProcessorTime | Sort-Object -Property Name | ConvertTo-Html -Fragment 




$Filtronuevosprocesos = @{LogName='Security';ProviderName='Microsoft-Windows-Security-Auditing';ID=4688; StartTime = $mesAnterior; EndTime = $fechaActual  }
$nuevosprocesos = Get-WinEvent -ErrorAction SilentlyContinue -FilterHashtable $Filtronuevosprocesos | ForEach-Object {
    # convert the event to XML and grab the Event node
    $nuevosprocesosXml = ([xml]$_.ToXml()).Event
    $nuevosprocesosNewProcessName = ($nuevosprocesosXml.EventData.Data | Where-Object { $_.Name -eq 'NewProcessName' }).'#text'
	$nuevosprocesosParentProcessName = ($nuevosprocesosXml.EventData.Data | Where-Object { $_.Name -eq 'ParentProcessName' }).'#text'
	
    # output the properties you need
    [PSCustomObject]@{
        Time     = [DateTime]$nuevosprocesosXml.System.TimeCreated.SystemTime
        NewProcessName = $nuevosprocesosNewProcessName
		ParentProcessName = $nuevosprocesosParentProcessName 
		EventId = $_.Id
    }
} | ConvertTo-Html -fragment



$Servicios = Get-Service |select Status,StartType,ServiceName,DisplayName | Sort-Object -Property Status | ConvertTo-Html -Fragment 
$ProgramasInstalados = Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage | Sort-Object -Property Vendor| ConvertTo-Html -Fragment
$ProgramasInstaladosRegistro = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |Sort-Object -Property Publisher| ConvertTo-Html -Fragment



Write-Host "(Done)" -ForegroundColor Green


Write-Host -Fore DarkCyan "[*] Collecting Suspicious Information " -nonewline


# Comprobar si existen claves sospechosas en las claves de registro
$registro1 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | ConvertTo-Html -Fragment
$registro11 = Get-ItemProperty -Path"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion" -ErrorAction SilentlyContinue | ConvertTo-Html -Fragment
$registro2 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | ConvertTo-Html -Fragment
$registro3 = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | ConvertTo-Html -Fragment

$AppDataPath = "$env:USERPROFILE\AppData\Roaming"
$TempPath = "$env:TEMP"

$ArchivosSospechososAppData = Get-ChildItem -Path $AppDataPath -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.Extension -eq ".exe" -or $_.Extension -eq ".bat" -or $_.Extension -eq ".vbs" -or $_.Extension -eq ".dll" -or $_.Extension -eq ".js" -or $_.Extension -eq ".msi"  -or $_.Extension -eq ".pif"}| Sort-Object -Property FullName | Select-Object Name,FullName, Extension,CreationTime,LastWriteTime | ConvertTo-Html -Fragment
$ArchivosSospechososTemp = Get-ChildItem -Path $TempPath -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.Extension -eq ".exe" -or $_.Extension -eq ".bat" -or $_.Extension -eq ".vbs" -or $_.Extension -eq ".dll" -or $_.Extension -eq ".js" -or $_.Extension -eq ".msi"  -or $_.Extension -eq ".pif"} | Select-Object Name,FullName, Extension,CreationTime,LastWriteTime | ConvertTo-Html -Fragment
Write-Host "(Done)" -ForegroundColor Green

Write-Host -Fore DarkCyan "[*] Generating html file " -nonewline

$html = @"
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">

        <title>WinForensic</title>
		
			
	<style>
	
body {
    font-family: 'Poppins', sans-serif;
    background: #fafafa;
  
}

p {
    font-family: 'Poppins', sans-serif;
    font-size: 1.1em;
    font-weight: 300;
    line-height: 1.7em;
    color: #999;
  
}

a,
a:hover,
a:focus {
    color: inherit;
    text-decoration: none;
    transition: all 0.3s;
  
}

.navbar {
    padding: 15px 10px;
	text-align: center;
    background: #fff;
    border: none;
    border-radius: 0;
    margin-bottom: 40px;
    box-shadow: 10px 10px 30px rgba(0, 0, 0, 0.1);
  
}

section {
margin-left: -300px;
  
}




.line {
    width: 100%;
    height: 1px;
    border-bottom: 1px dashed #ddd;
    margin: 40px 0;
}

/* ---------------------------------------------------
    SIDEBAR STYLE
----------------------------------------------------- */

.wrapper {
    display: flex;
    width: 100%;
    align-items: stretch;
}

#sidebar {
    min-width: 250px;
    max-width: 250px;
    background: #7386D5;
    color: #fff;
    transition: all 0.3s;
    border-radius: 25px;
   
	
}

#sidebar2 {
    min-width: 250px;
    max-width: 250px;
    background: #7386D5;
    color: #fff;
    transition: all 0.3s;
    border-radius: 25px;
  position: fixed;
}



#sidebar .sidebar-header {
    padding: 20px;
    background: #6d7fcc44444;
    text-align:center;
    font-size: 24px 
}

#sidebar ul.components {
    padding: 20px 0;
   
}

#sidebar ul p {
    color: #fff;
    padding: 10px;
  
}

#sidebar ul li a {
    padding: 10px;
    font-size: 1.1em;
    display: block;
   
  
}

#sidebar ul li a:hover {
    color: #7386D5;
    background: #fff;
  
}



a[data-toggle="collapse"] {
    position: relative;
  
}

.dropdown-toggle::after {
    display: block;
    position: absolute;
    top: 50%;
    right: 20px;
    transform: translateY(-50%);
  
}

ul ul a {
    font-size: 0.9em !important;
    padding-left: 30px !important;
    background: #6d7fcc;
}

ul.CTAs {
    padding: 20px;
}



a.download {
    background: #fff;
    color: #7386D5;
}




/* ---------------------------------------------------
    CONTENT STYLE
----------------------------------------------------- */

#content {
    width: 100%;
    padding: 20px;
    min-height: 100vh;
    transition: all 0.3s;
    border-radius: 10px;
  
  
}

/* ---------------------------------------------------
    MEDIAQUERIES
----------------------------------------------------- */

@media (max-width: 768px) {
    #sidebar {
        margin-left: -250px;
    }
    #sidebar.active {
        margin-left: 0;
    }
    #sidebarCollapse span {
        display: none;
    }
}

TABLE{
	padding: 30px;
	border-width: 1px;
	border-style: solid;
	border-color: black;
  border-collapse: collapse;
	
  
  border-radius: 20px;
 
} 

TH{
	font-size:1.1em;
	color:#f6ebf4; 
	border-width: 1px;
	padding: 2px;
	border-style: solid;
	border-color: black;
	background-color: black
     
      
      
}

tr:nth-child(even){background-color: #436699;color: white}

TD{
	border-width:1px;
	padding: 2px;
	border-style: solid;
	border-color: black; 
	
}

H2 {
    color:#436699;
}




.accordion {
  background-color: #eee;
  color: #444;
  cursor: pointer;
  padding: 18px;
  width: 100%;
  text-align: left;
  border: none;
  outline: none;
  transition: 0.4s;
  border-radius: 20px;
  
}

/* Add a background color to the button if it is clicked on (add the .active class with JS), and when you move the mouse over it (hover) */
.active, .accordion:hover {
  background-color: #ccc;
}

/* Style the accordion panel. Note: hidden by default */
.panel {
  padding: 0 18px;
  background-color: white;
  display: none;
  overflow: scroll;
  background: #fafafa;
}

.Subaccordion {
  background-color: #eee;
  color: #444;
  cursor: pointer;
  padding: 18px;
  width: 100%;
  text-align: left;
  border: none;
  outline: none;
  transition: 0.4s;
  border-radius: 20px;
  
}

.active, .Subaccordion:hover {
  background-color: #ccc;
}

/* Style the accordion panel. Note: hidden by default */
.panel2 {
  padding: 0 18px;
  background-color: white;
  display: none;
  overflow: scroll;
  background: #fafafa;
}

.enlace {
  color: red;
  font-weight: bold;
  outline: none;
  padding:6px;
  margin-right: 0.625%;
  text-align: center;
  line-height: 3;
  color: black;
  border-radius: 10px;
}

.enlace:hover {
  background: #7386D5;
  color: white;
}


</style>
    </head>
    <body>



        <div class="wrapper">
            <!-- Sidebar Holder -->
            <nav id="sidebar">
              
                <div class="sidebar-header">
                    <h3>WinForensic</h3>
                </div>
                <nav id="sidebar2">   

                <ul class="list-unstyled components">
                    <p>MENU</p>
                 
                    <li>
                        <a href="#Usuarios">Users & Account</a>
                    </li>
					<li>
                        <a href="#ActividadUsuarios">User Activity</a>
                    </li>
					<li>
                        <a href="#Network">Network Info</a>
                    </li>
                    <li>
                        <a href="#Systeminfo">System Info</a>
                    </li>
					<li>
                        <a href="#Suspicious">Suspicious</a>
                    </li>
					
                </ul>

            </nav>
            </nav>

            <!-- Page Content Holder -->
            <div id="content">

                <nav class="navbar navbar-default">
                    <div class="container-fluid">

                        <div class="navbar-header">
                           <H1>WinForensic executed $TiempoInicio on $env:computername </H1>
                        </div>

                        <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
                           
                        </div>
                    </div>
                </nav>

                
						
					
					
                

				
				
         <div class="line"></div>
					<section id="Usuarios">
					</section>
						<h2>Users & Acounts</h2>
							<button class="accordion">Local Users</button>
								<div class="panel">
										</br>
										$UsuariosLocales
										</br>
								</div>
								</br>
								</br>
							<button class="accordion">Administrators</button>
								<div class="panel">
										</br>
										$administradores
									
										</br>
								</div>
								</br>
								</br>
							<button class="accordion">User Profiles</button>
								<div class="panel">
										</br>
										$PerfilesUsuario
										</br>
								</div>
								</br>
								</br>			
							<button class="accordion">Local Group</button>
								<div class="panel">
										</br>
										$GrupoLocal
										</br>
								</div>
								</br>
								
			
		<div class="line"></div>
					<section id="ActividadUsuarios">
					</section>
						<h2>User Activity</h2>
						<button class="accordion">Created Users</button>
								<div class="panel">
										</br>
										$Usuarioscreados
										</br>
								</div>
								</br>
								</br>
						<button class="accordion">Users Deleted</button>
								<div class="panel">
										</br>
										$UsuariosEliminados
										</br>
								</div>
								</br>
								</br>
						<button class="accordion">Attempts to modify password</button>
								<div class="panel">
										</br>
										$IntentoModificacionContrasena
										</br>
								</div>
								</br>
								</br>
						<button class="accordion">Logon Sesions</button>
								<div class="panel">
										</br>
										</br>
										$SesionesLogeadas
										</br>
										</br>
								</div>
								</br>
								</br>
						<button class="accordion">Successful Login Activity (Last $meses Months)</button>
								<div class="panel">
								
			
										</br>
										<a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624" class="enlace" target="_blank">Info - Windows Logon Types</a>
										</br>
										$Logins
										</br>
											<button class="Subaccordion">RDP Logins (Last $meses Months) - Remote Interactive</button>
												<div class="panel2">
													</br>
													$RDPLogins
													</br>
												</div>	
										</br>
										
								</div>
								</br>
								</br>
						<button class="accordion">Unsucessfull Login Activity (Last $meses Months)</button>
								<div class="panel">
										</br>
										<a href="https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625" class="enlace" target="_blank">Info - Windows Logon Types</a>
										</br>
										$LoginFallido
										</br>
								</div>
								</br>
								</br>
						<button class="accordion">Local Group membership enumerated (Last $meses Months)</button>
								<div class="panel">
										</br>
										$EnumeratedGroupMembership
										</br>
								</div>
								</br>
								</br>
						<button class="accordion">Security Local Group membership enumerated (Last $meses Months)</button>
								<div class="panel">
										</br>
										$EnumeratedLocalGroupMembership
										</br>
								</div>
								</br>
								</br>
						
					
							
						
			
					

		  <div class="line"></div>
					<section id="Network">
					</section>
						<h2>Network Info</h2>
							<button class="accordion">TCP Connections</button>
								<div class="panel">
										</br>
										<button class="Subaccordion">Remote TCP Connections </button>
												<div class="panel2">
													</br>
													$ConexionesTCPRemotas
													</br>
												</div>
										</br>
										</br>
											<button class="Subaccordion">Local TCP Connections</button>
												<div class="panel2">
													</br>
													$ConexionesTCPLocales
													</br>
												</div>
												
										</br>
										</br>
								</div>
								</br>
								</br>
								
						<button class="accordion">Network Adapter</button>
								<div class="panel">
										</br>
										$adapatadoresdeRed
										</br>
										$adapatadoresdeRed2
										</br>
								</div>
								</br>
								</br>
						<button class="accordion">Rutas Compartidas</button>
								<div class="panel">
										</br>
										$RutasCompartidas
										</br>
								</div>
								</br>
								</br>
						<button class="accordion">Routes</button>
								<div class="panel">
										</br>
											<button class="Subaccordion">Get IP routes to non-local destinations </button>
												<div class="panel2">
													</br>
													$RutasDestinoNoLocal
													</br>
												</div>
										</br>
										</br>
											<button class="Subaccordion">Get IP routes to local destinations</button>
												<div class="panel2">
													</br>
													$RutasDestinoLocal
													</br>
												</div>
												
										</br>
										</br>
						
								</div>
								</br>
								</br>
						

					

		 <div class="line"></div>
					<section id="Systeminfo">
					</section>
						<h2>System Info</h2>
							<button class="accordion">System Information</button>
								<div class="panel">
								
										</br>
										$InformacionSistema
										</br>
											<button class="Subaccordion">Hotfix</button>
												<div class="panel2">
													</br>
													$hotfix
													</br>
												</div>
												
										</br>
										</br>
											<button class="Subaccordion">Host file</button>
												<div class="panel2">
													</br>
													$contenidoHosts
													</br>
												</div>
												
										</br>
										</br>
										
								</div>
								</br>
								</br>
							<button class="accordion">Scheduled Task</button>
								<div class="panel">
										</br>
										$TareasProgramadas
										</br>
								</div>
								</br>
								</br>
							<button class="accordion">Process</button>
								<div class="panel">
										 
										</br>
										</br>
											<button class="Subaccordion">New Process (Last $meses Months)</button>
												<div class="panel2">
													</br>
													$nuevosprocesos
													</br>
												</div>
										</br>
										</br>
											<button class="Subaccordion">All Process</button>
												<div class="panel2">
													</br>
													$ProcesosMaquina
													</br>
												</div>
												
										</br>
										</br>
								</div>
								</br>
								</br>	
							<button class="accordion">Services</button>
								<div class="panel">
										</br>
										$Servicios 
										</br>
								</div>
								</br>
								</br>
							<button class="accordion">Programs</button>
								<div class="panel">
										</br>
										</br>
											<button class="Subaccordion">installed programs </button>
												<div class="panel2">
													</br>
													$ProgramasInstalados
													</br>
												</div>
										</br>
										</br>
											<button class="Subaccordion">installed programs from Registry</button>
												<div class="panel2">
													</br>
													$ProgramasInstaladosRegistro
													</br>
												</div>
												
										</br>
										</br>
								</div>
								</br>
							
						
						
								
                <div class="line"></div>
					<section id="Suspicious">
					</section>
						<h2>Suspicious</h2>
							<button class="accordion">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</button>
								<div class="panel">
										</br>
										<p>This registry key is used to tell Windows which programs should run automatically at system startup. Malware can add keys to this path to ensure its persistence on the system.</p>
										</br>
										$registro1
										</br>
								</div>
								</br>
								</br>
							<button class="accordion">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</button>
								<div class="panel">
										</br>
										<p>This registry key is only executed once at system startup. Malware can use this key to run a malicious process on the system and then delete itself.</p>
										</br>
										$registro2
										</br>
								</div>
								</br>
								</br>
							<button class="accordion">HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</button>
								<div class="panel">
										</br>
										<p>This registry key is used to tell Windows which programs should run automatically at system startup, but only affects the current user.</p>
										</br>
										$registro3
										</br>
								</div>
								</br>
								</br>
								<button class="accordion">Potentially suspicious files</button>
								<div class="panel">
										</br>
											<button class="Subaccordion">Files in App data directory</button>
												<div class="panel2">
													</br>
													$ArchivosSospechososAppData
													</br>
												</div>
										</br>
										</br>
											<button class="Subaccordion">Files in Temp directory</button>
												<div class="panel2">
													</br>
													$ArchivosSospechososTemp
													</br>
												</div>
												
										</br>
										</br>

                
          
</div>
        </div>


<script>
var acc = document.getElementsByClassName("accordion");
var i;

for (i = 0; i < acc.length; i++) {
  acc[i].addEventListener("click", function() {
    /* Toggle between adding and removing the "active" class,
    to highlight the button that controls the panel */
    this.classList.toggle("active");

    /* Toggle between hiding and showing the active panel */
    var panel = this.nextElementSibling;
    if (panel.style.display === "block") {
      panel.style.display = "none";
    } else {
      panel.style.display = "block";
    }
  });
}

var acc = document.getElementsByClassName("Subaccordion");
var i;

for (i = 0; i < acc.length; i++) {
  acc[i].addEventListener("click", function() {
    /* Toggle between adding and removing the "active" class,
    to highlight the button that controls the panel */
    this.classList.toggle("active");

    /* Toggle between hiding and showing the active panel */
    var panel = this.nextElementSibling;
    if (panel.style.display === "block") {
      panel.style.display = "none";
    } else {
      panel.style.display = "block";
    }
  });
}
</script>

       
    </body>
</html>
"@

$ReportName = "SummaryReport.html"
#$CustomReportName = [System.String]::Join("-", $Hostname, $ReportName)
Write-Host "(Done)" -ForegroundColor Green

$html |Out-File -FilePath "WinForensic-SummaryReport.html"
#Invoke-Expression .\$CustomReportName

PAUSE
