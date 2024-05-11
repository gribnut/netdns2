<?php

/**
 * DNS Library for handling lookups and updates. 
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 * @since     File available since Release 0.6.0
 *
 */

/**
 * This is the base class for SVCB SvcParams
 *
 * Each SvcParam type (defined in SvcParam/*.php) extends this class for
 * base functionality.
 *
 * This class handles parsing and constructing the common parts of the
 * SvcParam, while the specific functionality is handled in each
 * child class.
 *
 * See https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
 *
 */

/*
 * SvcParamKeys (see section 7 https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/)
 */
const MANDATORY = 0;
const ALPN = 1;
const NO_DEFAULT_ALPN = 2;
const PORT = 3;
const IPV4HINT = 4;
const ECH = 5;
const IPV6HINT = 6;
const DOHPATH = 7;

abstract class Net_DNS2_SvcParam
{
    /*
     * The name of the SvcParamKey
     */
    public $name;

    /*
     * The integer (wire) value of the SvcParamKey
     */
    public $id;

    /*
     * The SvcParam specific data as a packed binary string
     */
    public $binary_data;

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
        $this->binary_data = $binary_data;
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
        return $this->name . '=' . bin2hex($this->binary_data);
    }

    /**
     * return the same data as __toString(), but as an array, so each value can be 
     * used without having to parse the string.
     *
     * @return array
     * @access public
     *
     */
    public function toStringArray()
    {
        return [

            'name'  => $this->name,
            'id'    => $this->id,
            'data'  => bin2hex($this->binary_data)
        ];
    }

    /**
     * parses binary SvcParam data, and returns the appropriate Net_DNS2_SvcParam object,
     * based on the param type of the binary content.
     *
     * @param $binary_data  string binary string of a SvcParam (from wire)
     *
     * @return mixed                   returns a new Net_DNS2_SvcParm_* object for
     *                                 the given SvcParam data
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public static function parse($binary_data)
    {
        $object = unpack('nid', $binary_data);

        //
        // expand the name
        //
        $object['name'] = Net_DNS2_Lookups::$svcparam_keys_by_id[$object['id']];
        if (empty($object['name'])) {

            throw new Net_DNS2_Exception(
                'failed to parse SvcParam: failed to expand SvcParamKey ' . $object['id'] .
                ' (' . bin2hex($binary_data) . ')' ,
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        //
        // lookup the class to use
        //
        $class  = Net_DNS2_Lookups::$svcparam_id_to_class[$object['id']];

        if (isset($class)) {
            return new $class($binary_data);
        } else {
            throw new Net_DNS2_Exception(
                'un-implemented SvcParamKey: ' . $object['id'],
                Net_DNS2_Lookups::E_RR_INVALID
            );
        }
    }

    /**
     * cleans up some RR data
     * 
     * @param string $data the text string to clean
     *
     * @return string returns the cleaned string
     *
     * @access public
     *
     */
    public function cleanString($data)
    {
        return strtolower(rtrim($data, '.'));
    }

}
