<?php

class Net_DNS2_SvcParam_ECH extends Net_DNS2_SvcParam
{
    /*
     * The name of the SvcParamKey
     */
    public $name = "ech";

    /*
     * The integer (wire) value of the SvcParamKey
     */
    public $id = ECH;

    /*
     * The binary value of the ECH configuration
     */
    public $ech;

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
        $object = unpack('nid/nlength', $binary_data);
        $ech = substr($binary_data,4);
        if($object['id'] != $this->id || empty($ech) || strlen($ech) != $object['length']) {
            throw new Net_DNS2_Exception(
                'Invalid ' . $this->name . ' SvcParam: failed to expand ' . bin2hex($binary_data) .
                ', id=' . $object['id'] . ', length=' . $object['length'] . ', ech=' . base64_encode($ech),
                Net_DNS2_Lookups::E_RR_INVALID
            );
        }
        $this->ech = $ech;
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
        return $this->name . '=' . base64_encode($this->ech);
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
