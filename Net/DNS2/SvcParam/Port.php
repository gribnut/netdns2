<?php

class Net_DNS2_SvcParam_Port extends Net_DNS2_SvcParam
{
    /*
     * The name of the SvcParamKey
     */
    public $name = "port";

    /*
     * The integer (wire) value of the SvcParamKey
     */
    public $id = PORT;

    /*
     * The integer value of the specified port
     */
    public $port;

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
        $x = unpack('nid/nlength/nport', $binary_data);
        if($x['id'] != $this->id || $x['port'] < 0 || $x['port'] > 65535) {
            throw new Net_DNS2_Exception(
                'Invalid ' . $this->name . ' SvcParam: failed to expand ' . bin2hex($binary_data) .
                ', id=' . $x['id'] . ', port=' . $x['port'],
                Net_DNS2_Lookups::E_RR_INVALID
            );
        }
        $this->port = $x['port'];
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
        return $this->name . '=' . $this->port;
    }
}
