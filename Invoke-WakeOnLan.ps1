function Invoke-WakeOnLan
{
<#
.SYNOPSIS
    Send Wake on LAN (WoL) MagicPacket via UDP
.DESCRIPTION
    Command to send a Wake-on-LAN (WoL) Packet via UDP targeting the machine with the given MAC-Address.
    The Packet is sent via local broadcast address to UDP port 9 using the default route interface.
.INPUTS
    Accepts MAC Addresses (single or multiple) via PipeLine to send WoL packets to.
.PARAMETER MacAddress
    A single or multiple MAC Address(es) to send WoL packets to.
    Either ':' or '-' are accepted as separator. 
.PARAMETER InterfaceIndex
    Use the network interface with the given 'InterfaceIndex' to send WoL packet out. 
.EXAMPLE
    Invoke-WakeOnLan -MacAddress "a0:b1:c2:d3:f4:e5"
    Send a single WoL packet to the target machine with the MAC address "a0:b1:c2:d3:f4:e5".
.EXAMPLE
    Invoke-WakeOnLan -MacAddress ("a0:b1:c2:d3:f4:e5","f0:a1:d2:b3:14:d5")
    Target multiple machines for WoL packets.
.EXAMPLE
    "a0:b1:c2:d3:f4:e5" | Invoke-WakeOnLan
    Using a pipeline variable to send a single WoL packet 
    to the target machine with the MAC address "a0:b1:c2:d3:f4:e5".
.NOTES
    Based on a script provided by https://www.pdq.com/blog/wake-on-lan-wol-magic-packet-powershell/
    Author: felix.buehl@febit.systems
    Filename: Invoke-WakeOnLan.ps1
.LINK
    https://github.com/thejoker8814/PowerShell-WakeOnLan
#>
  [CmdletBinding()]
  param
  (
    # one or more MAC-Addresses
    [Parameter(Mandatory,Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    # MAC address must be a following this regex pattern
    [ValidatePattern('^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$')]
    [string[]]
    $MacAddress,
    [Parameter(Position=1,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    # Interface Index as unsigned integer (32 bits)
    [uint32]
    $InterfaceIndex = 0
  )
 
  begin
  {
    # determine default interface
    $lIpaddr = $null
    $DEFAULT_ROUTE_METRIC = 0

    # use default route/ gateway interface
    if($InterfaceIndex -eq 0) {
      $InterfaceIndex = (Get-NetRoute -RouteMetric $DEFAULT_ROUTE_METRIC).InterfaceIndex
    }

    # use specified interface by index
    if($null -eq $lIpaddr -and $InterfaceIndex -gt 0) {
      try {
        $lIpAddrStr = [string]((Get-NetIPAddress -InterfaceIndex $InterfaceIndex -ErrorAction Stop).IPv4Address)
        $lIpaddr = [System.Net.IPAddress]::Parse($lIpAddrStr.Trim())
      } catch {
        Write-Warning ("No interface with index " + $InterfaceIndex + " found!")
      }
    }

    # fall back to determine interface by resolving hostname
    if($null -eq $lIpaddr) {
      $lIpaddr = [System.Net.Dns]::Resolve([System.Net.DNS]::GetHostName()).AddressList[0]
    }
    
	  $lIpEndpoint = new-object System.Net.IPEndPoint($lIpaddr,0)
    Write-Debug ("Using local interface address/ port " + $lIpEndpoint.ToString())
    # instantiate a UDP client
    $UDPclient = [System.Net.Sockets.UdpClient]::new($lIpEndpoint)
    $UDPclient.Client.EnableBroadcast = $true

    # prepare destination address and port
    $rIpAddress = [System.Net.IPAddress]::Broadcast
    $rUdpPort = 9
    $rIpEndPoint = [System.Net.IPEndPoint]::new($rIpAddress, $rUdpPort)
    Write-Debug ("UDP destination address/ port " + $rIpEndPoint.ToString())
  }
  process
  {
    foreach ($currentMacAddress in $MacAddress)
    {
      try {
        # $currentMacAddress = $_
        Write-Debug "MAC-Address $currentMacAddress read"       
        # get byte array from mac address
        # convert the hex number into byte
        $macByteArray = $currentMacAddress -split '[:-]' | ForEach-Object {
          [System.Convert]::ToByte($_, 16)
        }

        # create a byte array with 102 bytes size 
        # set the first 6 bytes to 255 / 0xFF
        # and add the mac address byte array 16 times (WoL) magic packet specification
        [byte[]] $packet = (,0xFF * 6) + ($macByteArray * 16)
        
        # send the magic packet to the broadcast address
        $result = $UDPclient.Send($packet, $packet.Length, $rIpEndPoint)
        Write-Debug ("UDP client sent " + $result.ToString() + " bytes")
        Write-Verbose ("Sent magic packet to " + $currentMacAddress)
      }
      catch 
      {
        Write-Warning "Unable to send ${mac}: $_"
        Write-Error "An error has ocurred ${Error[0]}"
      }
    }
  }
  end
  {
    # release the UDP client and free its memory
    $UDPclient.Close()
    $UDPclient.Dispose()
  }
}
