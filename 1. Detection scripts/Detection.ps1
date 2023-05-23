#***************************************** Part to fill ***************************************************
# Log analytics part
$LogType = "MissingInfos"
$CustomerId = "57dccf54-f9ee-4dae-bb35-e9413d90e7b1" # Log Analytics Workspace ID
$SharedKey = 'qA4hQu8vnRyiB92oNANwXIjLeIrBfVj06dlWqP1rbmxyiG8vW/H4vmBmtB0sVm3Whbm3P/8Dgd0Rp9/fbJVqvw==' # Log Analytics Workspace Primary Key
$TimeStampField = ""

# Log analytics functions
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}


Function Get_DeviceUpTime
	{
		param(
		[Switch]$Show_Days,
		[Switch]$Show_Uptime			
		)		
		
		$Last_reboot = Get-ciminstance Win32_OperatingSystem | Select -Exp LastBootUpTime
		$Check_FastBoot = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -ea silentlycontinue).HiberbootEnabled 
		If(($Check_FastBoot -eq $null) -or ($Check_FastBoot -eq 0))
			{
				$Boot_Event = Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot'| where {$_.ID -eq 27 -and $_.message -like "*0x0*"}
				If($Boot_Event -ne $null)
					{
						$Last_boot = $Boot_Event[0].TimeCreated
					}
			}
		ElseIf($Check_FastBoot -eq 1)
			{
				$Boot_Event = Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot'| where {$_.ID -eq 27 -and $_.message -like "*0x1*"}
				If($Boot_Event -ne $null)
					{
						$Last_boot = $Boot_Event[0].TimeCreated
					}
			}		
			
		If($Last_boot -eq $null)
			{
				$Uptime = $Uptime = $Last_reboot
			}
		Else
			{
				If($Last_reboot -ge $Last_boot)
					{
						$Uptime = $Last_reboot
					}
				Else
					{
						$Uptime = $Last_boot
					}
			}
		
		If($Show_Days)
			{
				$Current_Date = get-date
				$Diff_boot_time = $Current_Date - $Uptime
				$Boot_Uptime_Days = $Diff_boot_time.Days	
				$Real_Uptime = $Boot_Uptime_Days
			}
		ElseIf($Show_Uptime)
			{
				$Real_Uptime = $Uptime
				
			}
		ElseIf(($Show_Days -eq $False) -and ($Show_Uptime -eq $False))
			{
				$Real_Uptime = $Uptime				
			}			
		Return "$Real_Uptime"
	}

$Device_Uptime = Get_DeviceUpTime -Show_Uptime	

$win32_computersystem = gwmi win32_computersystem
$Manufacturer = $win32_computersystem.Manufacturer
$Model = $win32_computersystem.Model
If($Manufacturer -like "*lenovo*")
	{
		$Model_FriendlyName = $win32_computersystem.SystemFamily
		$Get_Current_Model =  $Model.Substring(0,4)
	}Else
	{
		$Model_FriendlyName = $Model
		$Get_Current_Model = $Model_FriendlyName
	}	
	
$Current_User_Profile = Get-ChildItem Registry::\HKEY_USERS | Where-Object { Test-Path "$($_.pspath)\Volatile Environment" } | ForEach-Object { (Get-ItemProperty "$($_.pspath)\Volatile Environment").USERPROFILE }
$Get_Current_user_Name = $Current_User_Profile.split("\")[2]
	
	
$win32_bios = gwmi win32_bios 
$BIOS_release_date = (gwmi win32_bios | select *).ReleaseDate	
$LA_BIOS_Date = [DateTime]::new((([wmi]"").ConvertToDateTime($BIOS_release_date)).Ticks, 'Local').ToUniversalTime()								

$BIOS_Maj_Version = $win32_bios.SystemBiosMajorVersion 
$BIOS_Min_Version = $win32_bios.SystemBiosMinorVersion 
$Get_Current_BIOS_Version = "$BIOS_Maj_Version.$BIOS_Min_Version"

$LA_FullBios_Version = $win32_bios.SMBIOSBIOSVersion
$LA_SN = $win32_bios.SerialNumber

$WMI_computersystem = gwmi win32_computersystem
$Get_Current_Model_FamilyName = $WMI_computersystem.SystemFamily.split(" ")[1]			
$PhysicalMemory = [Math]::Round(($WMI_computersystem.TotalPhysicalMemory / 1GB))

$BIOS_Ver_Model = "$Get_Current_BIOS_Version ($Get_Current_Model_FamilyName)"

$Get_WinDefender = Get-MpComputerStatus				
$RealTimeProtection = $Get_WinDefender.RealTimeProtectionEnabled
$AntivirusSignatureVersion = $Get_WinDefender.AntivirusSignatureVersion
$AntispywareSignatureVersion = $Get_WinDefender.AntispywareSignatureVersion
$NISSignatureVersion = $Get_WinDefender.NISSignatureVersion		
$AntispywareEnabled = $Get_WinDefender.AntispywareEnabled
$AntivirusEnabled = $Get_WinDefender.AntivirusEnabled

# Get device Guard info
$DeviceGuard_Status = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$SecurityServicesRunning = $DeviceGuard_Status.SecurityServicesRunning
		
If($SecurityServicesRunning -contains 1)
	{
		$Credential_Guard_Status = "Enable"			
	}
Else
	{
		$Credential_Guard_Status = "Disable"			
	}		
	
If($SecurityServicesRunning -contains 2)
	{
		$HVCI_Status = "Enable"			
	}
Else
	{			
		$HVCI_Status = "Disable"	
	}	
		

If($SecurityServicesRunning -contains 3)
	{
		$SystemGuard_Status = "Enable"			
	}
Else
	{
		$SystemGuard_Status = "Disable"		
	}			

$VBS_Status_Code = $DeviceGuard_Status.VirtualizationBasedSecurityStatus			
If($VBS_Status_Code -eq 0)
	{
		$VBS_Status = "Disable"				
	}
ElseIf($VBS_Status_Code -eq 1)
	{
		$VBS_Status = "Enable but not running"			
	}	
ElseIf($VBS_Status_Code -eq 2)
	{
		$VBS_Status = "Enable and running"			
	}	

Try
	{
		$Bitlocker_Info = (Get-BitLockerVolume -MountPoint c:)
		$Bitlocker_VolumeStatus = $Bitlocker_Info.VolumeStatus
		$Bitlocker_ProtectionStatus = $Bitlocker_Info.ProtectionStatus
		$Bitlocker_EncryptionPercentage = $Bitlocker_Info.EncryptionPercentage	
	}
Catch
	{
		$Bitlocker_VolumeStatus = $null
		$Bitlocker_ProtectionStatus = $null
		$Bitlocker_EncryptionPercentage = $null
	}
						


Try 
	{
		$TPM_Values = Get-Tpm -ErrorAction SilentlyContinue 
		$TPM_TpmPresent = $TPM_Values.TpmPresent
		$TPM_TpmReady = $TPM_Values.TpmReady
		$TPM_TpmEnabled = $TPM_Values.TpmEnabled
		$TPM_TpmActivated = $TPM_Values.TpmActivated
		$TPM_TpmOwned = $TPM_Values.TpmOwned
		$TPM_RestartPending = $TPM_Values.RestartPending
		$TPM_AutoProvisioning = $TPM_Values.AutoProvisioning
		$TPM_OwnerClearDisabled = $TPM_Values.OwnerClearDisabled
	} 
Catch 
	{
		$TPM_TpmPresent = $null
		$TPM_TpmReady = $null
		$TPM_TpmEnabled = $null
		$TPM_TpmActivated = $null
		$TPM_TpmOwned = $null
		$TPM_RestartPending = $null
		$TPM_AutoProvisioning = $null
		$TPM_OwnerClearDisabled = $null	
	}	

$Win32_OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
$Computer_InstallDate = $Win32_OperatingSystem.InstallDate	

$Get_Disk_info = Get-PhysicalDisk | where {$_.DeviceId -eq 0} 	
$Get_Disk_info_Details = $Get_Disk_info| Get-StorageReliabilityCounter | select *	
$Disk_FriendlyName = $Get_Disk_info.FriendlyName
$Disk_SerialNumber = $Get_Disk_info.SerialNumber
$Disk_MediaType = $Get_Disk_info.MediaType
$Disk_HealthStatus = $Get_Disk_info.HealthStatus
$Disk_Size = $Get_Disk_info.Size
$Disk_Wear = $Get_Disk_info_Details.Wear
$Disk_Temperature = $Get_Disk_info_Details.Temperature
$Disk_TemperatureMax = $Get_Disk_info_Details.TemperatureMax
$Disk_WriteErrorsTotal = $Get_Disk_info_Details.WriteErrorsTotal
If($Disk_WriteErrorsTotal -eq $null)
	{
		$Disk_WriteErrorsTotal = 0
	}
$Disk_WriteErrorsUncorrected = $Get_Disk_info_Details.WriteErrorsUncorrected		
If($Disk_WriteErrorsUncorrected -eq $null)
	{
		$Disk_WriteErrorsUncorrected = 0
	}		
$Disk_ReadErrorsTotal = $Get_Disk_info_Details.ReadErrorsTotal
If($Disk_ReadErrorsTotal -eq $null)
	{
		$Disk_ReadErrorsTotal = 0
	}		
$Disk_ReadErrorsUncorrected = $Get_Disk_info_Details.ReadErrorsUncorrected
If($Disk_ReadErrorsUncorrected -eq $null)
	{
		$Disk_ReadErrorsUncorrected = 0
	}			
	
	
# Create the object
$Properties = [Ordered] @{
    "UserName"               	   = $Get_Current_user_Name	
    "DeviceName"                   = $env:computername
    "DeviceModel"                  = $Get_Current_Model
	"BIOSVersionModel"      	   = $BIOS_Ver_Model		
    "DeviceModelFriendlyName"      = $Model_FriendlyName	
    "Manufacturer"  			   = $Manufacturer	
    "SerialNumber"  			   = $LA_SN		
    "FullBiosVersion"  			   = $LA_FullBios_Version		
    "BIOSVersion"  				   = $Get_Current_BIOS_Version		
    "BIOSDate"  			 	   = $LA_BIOS_Date
    "Bitlocker_Info"  			   = $Bitlocker_Info		
    "AntivirusEnabled"  		   = $AntivirusEnabled		
    "AntispywareEnabled"  		   = $AntispywareEnabled		
    "NISSignatureVersion"  		   = $NISSignatureVersion		
    "AntispywareSignatureVersion"  = $AntispywareSignatureVersion		
    "AntivirusSignatureVersion"    = $AntivirusSignatureVersion		
    "RealTimeProtection"  		   = $RealTimeProtection		
    "HVCI_Status"  			 	   = $HVCI_Status		
    "SecurityServicesRunning"  	   = $SecurityServicesRunning		
    "Credential_Guard_Status"  	   = $Credential_Guard_Status		
    "SystemGuard_Status"  		   = $SystemGuard_Status		
    "VBS_Status_Code"  			   = $VBS_Status_Code		
    "VBS_Status"  			 	   = $VBS_Status	
    "Device_Uptime"  			   = $Device_Uptime	
    "FirmwareType"  			   = $env:firmware_type	
    "PhysicalMemory"  			   = $PhysicalMemory				
    "TPM_TpmPresent"  			   = $TPM_TpmPresent				
    "TPM_TpmReady"  			   = $TPM_TpmReady				
    "TPM_TpmEnabled"  			   = $TPM_TpmEnabled				
    "TPM_TpmActivated"  		   = $TPM_TpmActivated				
    "TPM_TpmOwned"  			   = $TPM_TpmOwned				
    "TPM_RestartPending"  		   = $TPM_RestartPending				
    "TPM_AutoProvisioning"  	   = $TPM_AutoProvisioning				
    "TPM_OwnerClearDisabled"  	   = $TPM_OwnerClearDisabled
    "Bitlocker_VolumeStatus"  	   = $Bitlocker_VolumeStatus					
    "Bitlocker_ProtectionStatus"   = $Bitlocker_ProtectionStatus					
    "Bitlocker_EncryptionPercent"  = $Bitlocker_EncryptionPercentage	
    "ComputerInstallDate"  		   = $Computer_InstallDate						
    "Disk_FriendlyName"  		   = $Disk_FriendlyName						
    "Disk_SerialNumber"  		   = $Disk_SerialNumber						
    "Disk_MediaType"  			   = $Disk_MediaType						
    "Disk_HealthStatus"  		   = $Disk_HealthStatus						
    "Disk_Size"  			       = $Disk_Size						
    "Disk_Wear"  			       = $Disk_Wear						
    "Disk_Temperature"  		   = $Disk_Temperature						
    "Disk_TemperatureMax"  		   = $Disk_TemperatureMax						
    "Disk_WriteErrorsTotal"  	   = $Disk_WriteErrorsTotal						
    "Disk_WriteErrorsUncorrected"  = $Disk_WriteErrorsUncorrected						
    "Disk_ReadErrorsTotal"  	   = $Disk_ReadErrorsTotal						
    "Disk_ReadErrorsUncorrected"   = $Disk_ReadErrorsUncorrected						
	
}

$Infos = New-Object -TypeName "PSObject" -Property $Properties

# Submit the data to the API endpoint
$InfosJson = $Infos | ConvertTo-Json
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($InfosJson))
    LogType    = $LogType 
}
$LogResponse = Post-LogAnalyticsData @params
