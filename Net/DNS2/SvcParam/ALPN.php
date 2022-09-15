<?php

class Net_DNS2_SvcParam_ALPN extends Net_DNS2_SvcParam
{
    /*
     * The name of the SvcParamKey
     */
    public $name = "alpn";

    /*
     * The integer (wire) value of the SvcParamKey
     */
    public $id = ALPN;

    /*
    * List of mandatory parameter IDs
    * Index is integer ID of parameter and value is mnemonic/string name
    */
    public $alpns = [];

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
        $x = unpack('nid/nlength', $binary_data);
        $remaining_data = substr($binary_data, 4);
        if ($x['id'] != $this->id || strlen($remaining_data) != $x['length']) {
            throw new Net_DNS2_Exception(
                'Invalid ' . $this->name . ' SvcParam: failed to expand ' . bin2hex($binary_data) .
                ', id=' . $x['id'] . ', length=' . $x['length'],
                Net_DNS2_Lookups::E_RR_INVALID
            );
        }
        $count=0;
        while (!empty($remaining_data)) {
            // Each element uses one byte for length
            $alpn = unpack('clength', $remaining_data);
            if ($alpn['length'] < 1 || $alpn['length'] > 255 || strlen($remaining_data) < $alpn['length'] + 1) {
                throw new Net_DNS2_Exception(
                    'Unable to parse element for SvcParam ' . $this->name . ':' .
                    bin2hex(substr($remaining_data, 2, $alpn['length'])) . ' (from ' . bin2hex($binary_data) . ')',
                    Net_DNS2_Lookups::E_RR_INVALID
                );
            }
            $this->alpns[$count] = substr($remaining_data, 1, $alpn['length']);
            $remaining_data = substr($remaining_data, $alpn['length'] + 1);
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
        foreach ($this->alpns as $k => $alpn) {
            if ($k > 0) $value .= ',';
            $value .= $alpn;
        }
        return $this->name . '=' . $value;
    }
}
