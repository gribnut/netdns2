<?php

class Net_DNS2_SvcParam_IPv6Hint extends Net_DNS2_SvcParam
{
    /*
     * The name of the SvcParamKey
     */
    public $name = "ipv6hint";

    /*
     * The integer (wire) value of the SvcParamKey
     */
    public $id = IPV6HINT;

    /*
    * List of binary (packed) value(s) of the IPv6 address(es)
    */
    public $ipv6hints = [];

    /**
     * Constructor - builds a new Net_DNS2_SvcParam object
     *
     * @param $binary_data string binary string of a SvcParam (from wire)
     *
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public function __construct($binary_data = null)
    {
        parent::__construct();
        $element_length = 16;
        $x = unpack('nid/nlength', $binary_data);
        $remaining_data = substr($binary_data,4);
        if($x['id'] != $this->id || strlen($remaining_data) != $x['length'] ||
            $x['length']%$element_length != 0) {
            throw new Net_DNS2_Exception(
                'Invalid ' . $this->name . ' SvcParam: failed to expand ' . bin2hex($binary_data) .
                ', id=' . $x['id'] . ', length=' . $x['length'],
                Net_DNS2_Lookups::E_RR_INVALID
            );
        }
        $count = 0;
        while(!empty($remaining_data)) {
            $ipv6address = substr($remaining_data,0,$element_length);
            if(strlen($ipv6address) != $element_length || !inet_ntop($ipv6address)) {
                throw new Net_DNS2_Exception(
                    'Unable to parse IPv6 address for SvcParam ' . $this->name . ':' . bin2hex($ipv6address) .
                    ' (from ' . bin2hex($binary_data) . ')',
                    Net_DNS2_Lookups::E_RR_INVALID
                );
            }
            $this->ipv6hints[$count] = $ipv6address;
            $remaining_data = substr($remaining_data, $element_length);
            $count++;
        }
    }

    /**
     * magic __toString() method to return the Net_DNS2_SvcParam object object as a string
     *
     * @return string
     * @access public
     *
     */
    public function __toString()
    {
        $value = "";
        foreach ($this->ipv6hints as $k => $ipv6address) {
            if($k > 0) $value .= ',';
            $value .= inet_ntop($ipv6address);
        }
        return $this->name . '=' . $value;
    }


    protected function svcParamToString()
    {
        // TODO: Implement svcParamToString() method.
    }

    protected function svcParamFromString(array $data)
    {
        // TODO: Implement svcParamFromString() method.
    }

    protected function rrSet(Net_DNS2_Packet &$packet)
    {
        // TODO: Implement rrSet() method.
    }

    protected function rrGet(Net_DNS2_Packet &$packet)
    {
        // TODO: Implement rrGet() method.
    }
}
