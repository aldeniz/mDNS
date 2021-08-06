A simple class for mDNS quering from PHP, worked with Arduino Microcontrollers ESP..., based on the ChrisRidings / PHPmDNS  repository.

The mDNS class worked only with Type A (IPv4 address record) queries. It was created and reworked to recognize Arduino microcontrollers (as ESP32, ESP8266 etc.) on the local network.

Example:

include "mdns-lib.php";

$a=scan("esp8266.local");
if ($a!="") $ip= $a; else echo $ip="Microcontroller not found!" ;
  
function scan($host) {
        $mdns = new mDNS();
        $host=strtolower($host);
        // For a more surety, send multiple search requests
        $mdns->query($host);
        $mdns->query($host);
        $mdns->query($host);
        $ip=null; $yes=0;
        $cc = 15;
        while ($cc>0) {
            $inpacket = $mdns->readIncoming();
            if (@$inpacket->packetheader->getAnswer()>0) {
                for ($x=0; $x < sizeof($inpacket->answer); $x++) {
                    if ($inpacket->answer[$x]->qtype == 1) {
                        $d = $inpacket->answer[$x]->data;
                        $d1= strtolower($inpacket->answer[$x]->name);
                        $ipa = $d[0] . "." . $d[1] . "." . $d[2] . "." . $d[3];
                        if ($d1 == $host) {
                               $ip = $ipa;
                               $yes=1;  
                               break; 
                        }
                    }
                }
                if ($yes==1) break;
            }
            $cc--;
        }
      if (!is_null($ip)) return  $ip; else return "";
}
