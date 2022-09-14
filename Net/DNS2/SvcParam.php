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
     * abstract definition - method to return a RR as a string; not to 
     * be confused with the __toString() magic method.
     *
     * @return string
     * @access protected
     *
     */
    abstract protected function svcParamToString();

    /**
     * abstract definition - parses a RR from a standard DNS config line
     *
     * @param array $data a string split line of values
     *
     * @return boolean
     * @access protected
     *
     */
    abstract protected function svcParamFromString(array $data);

    /**
     * abstract definition - sets a Net_DNS2_RR from a Net_DNS2_Packet object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet to parse the RR from
     *
     * @return boolean
     * @access protected
     *
     */
    abstract protected function rrSet(Net_DNS2_Packet &$packet);

    /**
     * abstract definition - returns a binary packet DNS RR object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet use for 
     *                                 compressed names
     *
     * @return mixed                   either returns a binary packed string or 
     *                                 null on failure
     * @access protected
     *
     */
    abstract protected function rrGet(Net_DNS2_Packet &$packet);

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
    public function asArray()
    {
        return [

            'name'  => $this->name,
            'rdata' => $this->rrToString()
        ];
    }

    /**
     * return a formatted string; if a string has spaces in it, then return 
     * it with double quotes around it, otherwise, return it as it was passed in.
     *
     * @param string $string the string to format
     *
     * @return string
     * @access protected
     *
     */
    protected function formatString($string)
    {
        return '"' . str_replace('"', '\"', trim($string, '"')) . '"';
    }
    
    /**
     * builds an array of strings from an array of chunks of text split by spaces
     *
     * @param array $chunks an array of chunks of text split by spaces
     *
     * @return array
     * @access protected
     *
     */
    protected function buildString(array $chunks)
    {
        $data = [];
        $c = 0;
        $in = false;

        foreach ($chunks as $r) {

            $r = trim($r);
            if (strlen($r) == 0) {
                continue;
            }

            if ( ($r[0] == '"')
                && ($r[strlen($r) - 1] == '"')
                && ($r[strlen($r) - 2] != '\\')
            ) {

                $data[$c] = $r;
                ++$c;
                $in = false;

            } else if ($r[0] == '"') {

                $data[$c] = $r;
                $in = true;

            } else if ( ($r[strlen($r) - 1] == '"')
                && ($r[strlen($r) - 2] != '\\')
            ) {
            
                $data[$c] .= ' ' . $r;
                ++$c;  
                $in = false;

            } else {

                if ($in == true) {
                    $data[$c] .= ' ' . $r;
                } else {
                    $data[$c++] = $r;
                }
            }
        }        

        foreach ($data as $index => $string) {
            
            $data[$index] = str_replace('\"', '"', trim($string, '"'));
        }

        return $data;
    }

    /**
     * builds a new Net_DNS2_RR object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet or null to create
     *                                 an empty object
     * @param array           $rr      an array with RR parse values or null to 
     *                                 create an empty object
     *
     * @return boolean
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public function set(Net_DNS2_Packet &$packet, array $rr)
    {
        //
        // for RR OPT (41), the class value includes the requestors UDP payload size,
        // and not a class value
        //

        return $this->rrSet($packet);
    }

    /**
     * returns a binary packed DNS RR object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet used for 
     *                                 compressing names
     *
     * @return string
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public function get(Net_DNS2_Packet &$packet)
    {
        $data  = '';
        $rdata = '';

        //
        // pack the name
        //
        $data = $packet->compress($this->name, $packet->offset);

        //
        // pack the main values
        //
        if ($this->type == 'OPT') {

            //
            // pre-build the TTL value
            //
            $this->preBuild();

            //
            // the class value is different for OPT types
            //
            $data .= pack(
                'nnN', 
                Net_DNS2_Lookups::$rr_types_by_name[$this->type],
                $this->class,
                $this->ttl
            );
        } else {

            $data .= pack(
                'nnN', 
                Net_DNS2_Lookups::$rr_types_by_name[$this->type],
                Net_DNS2_Lookups::$classes_by_name[$this->class],
                $this->ttl
            );
        }

        //
        // increase the offset, and allow for the rdlength
        //
        $packet->offset += 10;

        //
        // get the RR specific details
        //
        if ($this->rdlength != -1) {

            $rdata = $this->rrGet($packet);
        }

        //
        // add the RR
        //
        $data .= pack('n', strlen($rdata)) . $rdata;

        return $data;
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

    /**
     * parses a standard RR format lines, as defined by rfc1035 (kinda)
     *
     * In our implementation, the domain *must* be specified- format must be
     *
     *        <name> [<ttl>] [<class>] <type> <rdata>
     * or
     *        <name> [<class>] [<ttl>] <type> <rdata>
     *
     * name, title, class and type are parsed by this function, rdata is passed
     * to the RR specific classes for parsing.
     *
     * @param string $line a standard DNS config line 
     *
     * @return mixed       returns a new Net_DNS2_RR_* object for the given RR
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public static function fromString($line)
    {
        if (strlen($line) == 0) {
            throw new Net_DNS2_Exception(
                'empty config line provided.',
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        $name   = '';
        $type   = '';
        $class  = 'IN';
        $ttl    = 86400;

        //
        // split the line by spaces
        //
        $values = preg_split('/[\s]+/', $line);
        if (count($values) < 3) {

            throw new Net_DNS2_Exception(
                'failed to parse config: minimum of name, type and rdata required.',
                Net_DNS2_Lookups::E_PARSE_ERROR
            );
        }

        //
        // assume the first value is the name
        //
        $name = trim(strtolower(array_shift($values)), '.');

        //
        // The next value is either a TTL, Class or Type
        //
        foreach ($values as $value) {

            switch(true) {
            case is_numeric($value):

                $ttl = array_shift($values);
                break;

            //
            // this is here because of a bug in is_numeric() in certain versions of
            // PHP on windows.
            //
            case ($value === 0):
                
                $ttl = array_shift($values);
                break;

            case isset(Net_DNS2_Lookups::$classes_by_name[strtoupper($value)]):

                $class = strtoupper(array_shift($values));
                break;

            case isset(Net_DNS2_Lookups::$rr_types_by_name[strtoupper($value)]):

                $type = strtoupper(array_shift($values));
                break 2;
                break;

            default:

                throw new Net_DNS2_Exception(
                    'invalid config line provided: unknown file: ' . $value,
                    Net_DNS2_Lookups::E_PARSE_ERROR
                );
            }
        }

        //
        // lookup the class to use
        //
        $o = null;
        $class_name = Net_DNS2_Lookups::$rr_types_id_to_class[
            Net_DNS2_Lookups::$rr_types_by_name[$type]
        ];

        if (isset($class_name)) {

            $o = new $class_name;
            if (!is_null($o)) {

                //
                // set the parsed values
                //
                $o->name    = $name;
                $o->class   = $class;
                $o->ttl     = $ttl;

                //
                // parse the rdata
                //
                if ($o->rrFromString($values) === false) {

                    throw new Net_DNS2_Exception(
                        'failed to parse rdata for config: ' . $line,
                        Net_DNS2_Lookups::E_PARSE_ERROR
                    );
                }

            } else {

                throw new Net_DNS2_Exception(
                    'failed to create new RR record for type: ' . $type,
                    Net_DNS2_Lookups::E_RR_INVALID
                );
            }

        } else {

            throw new Net_DNS2_Exception(
                'un-implemented resource record type: '. $type,
                Net_DNS2_Lookups::E_RR_INVALID
            );
        }

        return $o;
    }

}
