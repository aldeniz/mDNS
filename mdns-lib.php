<?php
class mDNS {
    // Simple MDNS, TYPE_A;
    private $socket; 

    public function __construct() {
        // Create $socket, bind to 5353 and join multicast group 224.0.0.251
        // IPv4 Internet based protocols, Supports datagrams, UDP 
        $this->socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP); 
        socket_set_option($this->socket,SOL_SOCKET,SO_REUSEADDR, 1);
        socket_set_option($this->socket, IPPROTO_IP, MCAST_JOIN_GROUP, array('group'=>'224.0.0.251', 'interface'=>0));
        socket_set_option($this->socket, SOL_SOCKET,SO_RCVTIMEO,array("sec"=>1,"usec"=>0));
        $bind = socket_bind($this->socket, "0.0.0.0", 5353);
    }

    public function query($name) {
        // Sends a query
        $packet = new DNSPacket;
        $packet->clear();
        $packet->packetheader->setTransactionID(rand(1,32767));
        $packet->packetheader->setQuestions(1);
        $question = new DNSQuestion();
        $question->name = $name;
        $question->qclass = 1;
        $question->qtype = 1;
        array_push($packet->questions, $question);
        $b = $packet->makePacket();
        // Send the packet
        $data = "";
        for ($x = 0; $x < sizeof($b); $x++) { 
            $data .= chr($b[$x]);
        }
        socket_sendto($this->socket, $data, strlen($data), 0, '224.0.0.251',5353);    
    }

    public function readIncoming() {
        // Read incoming data 
        $response = "";
        try {
            $response = socket_read($this->socket, 1024, PHP_BINARY_READ);
        } catch (Exception $e) {
        }
        if (strlen($response) < 1) { return ""; }
        // Create an array to represent the bytes
        $bytes = array();
        for ($x = 0; $x < strlen($response); $x++) {
            array_push($bytes, ord(substr($response,$x,1)));
        }
        $p = new DNSPacket();
        $p->load($bytes);
        return $p;
    }

    public function load($data) {
        $p = new DNSPacket();
        $p->load($data);
        return $p;
    }

}

class DNSPacket {
    // Represents and processes a DNS packet
    public $packetheader; 
    public $questions; 
    public $answer; 
    public $offset = 0;

    public function __construct() {
        $this->clear();
    }

    public function clear() {
        $this->packetheader = new DNSPacketHeader();
        $this->packetheader->clear();
        $this->questions = array();
        $this->answer = array();

    }

    public function load($data) {
        // $data is an array of integers representing the bytes.
        // Load the data into the DNSPacket object.
        $this->clear();

        // Read the first 12 bytes and load into the packet header
        $headerbytes = array();
        for ($x=0; $x< 12; $x++) {
            $headerbytes[$x] = $data[$x];
        }
        $this->packetheader->load($headerbytes);
        $this->offset = 12;

        if ($this->packetheader->getQuestions() > 0) {
            // There are some questions in this DNS Packet. Read them!
            for ($xq = 1; $xq <= $this->packetheader->getQuestions(); $xq++) {
                $name = "";
                $size = 0;
                $resetoffsetto = 0;
                $firstreset = 0;
                while ($data[$this->offset]<>0) {
                    if ($size == 0) {
                        $size = $data[$this->offset];
                        if (($size & 192) == 192) {
                            if ($firstreset == 0 && $resetoffsetto <> 0) { $firstrest = $resetoffsetto; }
                            $resetoffsetto = $this->offset;
                            $this->offset = $data[$this->offset + 1];
                            $size = $data[$this->offset];
                        }
                    } else {
                        $name = $name . chr($data[$this->offset]);
                        $size--;
                        if ($size == 0) { $name = $name . "."; }
                    }
                    $this->offset++;
                }
                if ($firstreset <> 0) { $resetoffsetto = $firstreset; }
                if ($resetoffsetto <> 0) { $this->offset = $resetoffsetto + 1; }
                if (strlen($name) > 0) { $name = substr($name,0,strlen($name)-1); }
                $this->offset = $this->offset + 1;
                $qtype = ($data[$this->offset] * 256) + $data[$this->offset + 1];
                $qclass = ($data[$this->offset + 2] * 256) + $data[$this->offset + 3];
                $this->offset = $this->offset + 4;
                $r = new DNSQuestion();
                $r->name = $name;
                $r->qclass = $qclass;
                $r->qtype = $qtype;
                array_push($this->questions, $r);
            }
        }
        if ($this->packetheader->getAnswer() > 0) {
            // There are some answer in this DNS Packet. Read them!
            for ($xq = 1; $xq <= $this->packetheader->getAnswer(); $xq++) {
                $qr = $this->read($data);
                array_push($this->answer, $qr);
            }
        }

    }

    public function read($data) {
        // Returns a DNSResourceRecord object representing the $data (array of integers)
        $name = "";
        $size = 0;
        $resetoffsetto = 0;
        $firstreset = 0;
        $sectionsize = 0;

        while ($data[$this->offset]<>0) {
            if ($size == 0) {
                $size = $data[$this->offset];
                if ($sectionsize == 0) {
                    $sectionsize = $size;
                }
                if (($size & 192) == 192) {
                    if ($firstreset == 0 && $resetoffsetto <> 0) { $firstreset = $resetoffsetto; }
                    $resetoffsetto = $this->offset;
                    $this->offset = $data[$this->offset + 1] + (($data[$this->offset] - 192)*256);
                    $size = $data[$this->offset];
                }
            } else {
                $name = $name . chr($data[$this->offset]);
                $size--;
                if ($size == 0) { $name = $name . "."; }
            }
            $this->offset++;
        }
        if ($firstreset <> 0) { $resetoffsetto = $firstreset; }
        if ($resetoffsetto <> 0) { $this->offset = $resetoffsetto + 1; }
        if (strlen($name) > 0) { $name = substr($name,0,strlen($name)-1); }
        $this->offset = $this->offset + 1;
        $qtype = ($data[$this->offset] * 256) + $data[$this->offset + 1];
        $qclass = ($data[$this->offset + 2] * 256) + $data[$this->offset + 3];
        $this->offset = $this->offset + 4;
        $ttl = 1000;
        $this->offset = $this->offset + 4;
        // The next two bytes are the length of the data section
        $dl = ($data[$this->offset] * 256) + $data[$this->offset + 1];
        $this->offset = $this->offset + 2;
        $oldoffset = $this->offset;
        $ddata = array();
        for ($x=0; $x < $dl; $x++) {
            array_push($ddata, $data[$this->offset]); 
            $this->offset = $this->offset + 1;
        }
        $storeoffset = $this->offset;

        $datadecode = "";
        $size = 0;
        $resetoffsetto = 0;
        $this->offset = $storeoffset;
        $r = New DNSResourceRecord;
        $r->name = $name;
        $r->qclass = $qclass;
        $r->qtype = $qtype;
        $r->ttl = $ttl;
        $r->data = $ddata;
        return $r;
    }

    public function makePacket() {
        // For the current DNS packet produce an array of bytes to send.
        $bytes = array();
        // First copy the header in
        $header = $this->packetheader->getBytes();
        for ($x=0; $x < sizeof($header); $x++) {
            array_push($bytes, $header[$x]);
        }
        $this->offset = 12;
        if (sizeof($this->questions) > 0) {
            // questions to encode
            for ($pp = 0; $pp < sizeof($this->questions); $pp++) {
                $thisq = $this->questions[$pp];
                $thisname = $thisq->name;
                $undotted = "";
                while (strpos($thisname,".") > 0) {
                    $undotted .= chr(strpos($thisname,".")) . substr($thisname, 0,strpos($thisname,"."));
                    $thisname = substr($thisname, strpos($thisname,".") + 1);
                }
                $undotted .= chr(strlen($thisname)) . $thisname . chr(0);
                for ($pq = 0; $pq < strlen($undotted); $pq++) {
                    array_push($bytes, ord(substr($undotted,$pq,1)));
                }
                $this->offset = $this->offset + strlen($undotted);
                array_push($bytes,(int)($thisq->qtype/256));
                array_push($bytes, $thisq->qtype%256);
                $this->offset = $this->offset + 2;
                array_push($bytes,(int)($thisq->qclass/256));
                array_push($bytes,$thisq->qclass%256);
                $this->offset = $this->offset + 2;
            }
        }
        return $bytes;
    }
}
class DNSPacketHeader {
    // Represents the 12 byte packet header of a DNS request or response
    private $contents; // use an array of 12 integers here

    public function clear() {
        $this->contents = array(0,0,0,0,0,0,0,0,0,0,0,0);
    }

    public function getBytes() {
        return $this->contents;
    }

    public function load($data) {
        // Assume we're passed an array of bytes
        $this->clear();
        $this->contents = $data;
    }

    public function setTransactionID($value) {
        $this->contents[0] = (int)($value / 256);
        $this->contents[1] = $value % 256;
    }

    // The number of Questions in the packet
    public function getQuestions() {

        return ($this->contents[4] * 256) + $this->contents[5];
    }

    public function setQuestions($value) { 
        $this->contents[4] = (int)($value / 256); 
        $this->contents[5] = $value % 256;
    }

    // The number of Answer in the packet
    public function getAnswer() 
    {                    
        return ($this->contents[6] * 256) + $this->contents[7];
    }
}
class DNSQuestion {
    public $name; // String
    public $qtype; // UInt16
    public $qclass; // UInt16
}
class DNSResourceRecord {
    public $name; // String
    public $qtype; // UInt16
    public $qclass; // UInt16
    public $ttl; // UInt32
    public $data; // Byte ()
}
?>