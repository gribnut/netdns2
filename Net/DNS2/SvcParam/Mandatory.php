<?php

class Net_DNS2_SvcParam_Mandatory extends Net_DNS2_SvcParam
{
    /*
     * The name of the SvcParamKey
     */
    public $name = "mandatory";

    /*
     * The integer (wire) value of the SvcParamKey
     */
    public $id = MANDATORY;

    /*
     * List of mandatory parameter IDs
     * Index is integer ID of parameter and value is mnemonic/string name
     */
    public $mandatory_ids = [];

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
        $element_length = 2;
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
        while(!empty($remaining_data)) {
            $x = unpack('nid', $remaining_data);
            if($x['id'] < 0 || $x['id'] > 65535) {
                throw new Net_DNS2_Exception(
                    'Unable to parse param ID for SvcParam ' . $this->name . ':' .
                    bin2hex(substr($remaining_data,0,$element_length)) . ' (from ' . bin2hex($binary_data) . ')',
                    Net_DNS2_Lookups::E_RR_INVALID
                );
            }
            $this->mandatory_ids[$x['id']] = "key".$x['id'];  // Use id as index so can be sorted by id order per RFC
            if(isset(Net_DNS2_Lookups::$svcparam_keys_by_id[$x['id']])) {
                $this->mandatory_ids[$x['id']] = Net_DNS2_Lookups::$svcparam_keys_by_id[$x['id']];
            }
            $remaining_data = substr($remaining_data, $element_length);
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
        $count = 0;
        foreach ($this->mandatory_ids as $id) {
            if($count > 0) $value .= ',';
            $value .= $id;
            $count++;
        }
        return $this->name . '=' . $value;
    }
}
