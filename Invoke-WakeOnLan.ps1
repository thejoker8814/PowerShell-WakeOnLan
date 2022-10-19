Set-StrictMode -Version Latest
function Invoke-WakeOnLan {
  <#
.SYNOPSIS
    Send Wake on LAN (WoL) Magic packet (UDP) to destination host(s).
.DESCRIPTION
    Send a single Wake on LAN (WoL) Magic packet (UDP) for destination host(s) specified by MAC address(es).
    Uses IPv4 broadcast address to target hosts in the local subnet. The primary network interface 
    (IPv4 default route) will be used automatically, to select a different interface specify an 
    interface index ($InterfaceIndex parameter). UDP destination port 9 is used by default.
.INPUTS
    Accepts MAC Address/es (single or multiple) via Pipeline to send WoL packets to.
.PARAMETER MacAddress
    Destination host(s) MAC address(es), accepts multiple addresses.
    Valid MAC address separators are ':', '-' and a mix of both.
.PARAMETER InterfaceIndex
    [Optional] Use the network interface by 'InterfaceIndex' to send the WoL packet.
    Defaults to primary interface (default IP route).
.EXAMPLE
    Invoke-WakeOnLan -MacAddress "a0:b1:c2:d3:f4:e5"
    Send a WoL packet for destination host with the MAC address "a0:b1:c2:d3:f4:e5".
.EXAMPLE
    Invoke-WakeOnLan -MacAddress ("a0:b1:c2:d3:f4:e5","f0-a1-d2-b3-14-d5")
    Send WoL packets for multiple hosts.
.EXAMPLE
    "a0:b1:c2:d3:f4:e5" | Invoke-WakeOnLan
    Using a pipeline variable to send a WoL packet for destination host with the
    MAC address "a0:b1:c2:d3:f4:e5".
.LINK
    Get-NetAdapter
.LINK
    https://github.com/thejoker8814/PowerShell-WakeOnLan
#>
  [CmdletBinding()]
  param
  (
    # one or more MAC-Addresses
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    # MAC address must be a following this regex pattern
    [ValidatePattern('^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', 
      ErrorMessage = "{0} is not a valid MAC address. Please use a valid MAC address format (i.e. a0:b1:c2:d3:f4:e5, f0-a1-d2-b3-14-d5)")]
    [string[]]
    $MacAddress,
    [Parameter(Position = 1, ValueFromPipelineByPropertyName)]
    # Interface Index as unsigned integer (32 bits)
    [uint32]
    $InterfaceIndex = 0
  )
  begin {
    # determine default interface
    $lIpaddr = $null
    $DEFAULT_ROUTE_METRIC = 0
    $DEFAULT_UDP_DEST_PORT = 9

    # default route/ gateway interface
    if ($InterfaceIndex -eq 0) {
      $InterfaceIndex = (Get-NetRoute -RouteMetric $DEFAULT_ROUTE_METRIC).InterfaceIndex
    }

    # select interface by InterfaceIndex
    if ($null -eq $lIpaddr -and $InterfaceIndex -gt 0) {
      try {
        $lIpAddrStr = [string]((Get-NetIPAddress -InterfaceIndex $InterfaceIndex -ErrorAction Stop).IPv4Address)
        $lIpaddr = [System.Net.IPAddress]::Parse($lIpAddrStr.Trim())
      }
      catch {
        Write-Warning ("No interface with InterfaceIndex: " + $InterfaceIndex + " found!")
      }
    }

    $lIpEndpoint = new-object System.Net.IPEndPoint($lIpaddr, 0)
    Write-Debug ("Using local interface address/ port " + $lIpEndpoint.ToString())
    # instantiate a UDP client
    $UDPclient = [System.Net.Sockets.UdpClient]::new($lIpEndpoint)
    $UDPclient.Client.EnableBroadcast = $true

    # prepare destination address and port
    $rIpAddress = [System.Net.IPAddress]::Broadcast
    $rUdpPort = $DEFAULT_UDP_DEST_PORT
    $rIpEndPoint = [System.Net.IPEndPoint]::new($rIpAddress, $rUdpPort)
    Write-Debug ("UDP destination address/ port " + $rIpEndPoint.ToString())
  }
  process {
    foreach ($currentMacAddress in $MacAddress) {
      try {
        Write-Debug "MAC address $currentMacAddress read"       
        # get byte array from mac address
        # convert the hex number into byte
        $macByteArray = $currentMacAddress -split '[:-]' | ForEach-Object {
          [System.Convert]::ToByte($_, 16)
        }

        # create a byte array with 102 bytes size 
        # set the first 6 bytes to 255 / 0xFF
        # and add the mac address byte array 16 times (WoL) magic packet specification
        [byte[]] $packet = (, 0xFF * 6) + ($macByteArray * 16)
        
        # send the magic packet to the broadcast address
        $result = $UDPclient.Send($packet, $packet.Length, $rIpEndPoint)
        Write-Verbose ("Sent WoL Magic packet for host " + $currentMacAddress)
        Write-Debug ("UDP client sent " + $result.ToString() + " bytes")
      }
      catch {
        Write-Warning "Unable to send ${mac}: $_"
        Write-Error "An error has ocurred ${Error[0]}"
      }
    }
  }
  end {
    # release the UDP client and free its memory
    $UDPclient.Close()
    $UDPclient.Dispose()
  }
}
