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
 *
 */

/**
 * HTTPS Resource Record - https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   SvcPriority                 |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   TargetName                  |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   SvcParams                   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
class Net_DNS2_RR_SVCB extends Net_DNS2_RR
{

    public $svcPriority;
    public $targetName;
    public $svcParams = [];


    /**
     * method to return the rdata portion of the packet as a string
     *
     * @return  string
     * @access  protected
     *
     */
    protected function rrToString()
    {
        $rr_string =  $this->svcPriority . ' ' . $this->cleanString($this->targetName) . '.';
        if(isset($this->svcParams) && count($this->svcParams) > 0) {
            foreach ($this->svcParams as $param) {
                $rr_string .= ' ' . $param;
            }
        }
        return $rr_string;
    }

    /**
     * parses the rdata portion from a standard DNS config line
     *
     * @param array $rdata a string split line of values for the rdata
     *
     * @return boolean
     * @access protected
     *
     */
    protected function rrFromString(array $rdata)
    {
        $this->svcPriority = $rdata[0];
        $this->targetName = $rdata[1];
        $this->svcParams[0] = $rdata[2];

        return true;
    }

    /**
     * parses the rdata of the Net_DNS2_Packet object
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet to parse the RR from
     *
     * @return boolean
     * @access protected
     *
     * @throws Net_DNS2_Exception
     */
    protected function rrSet(Net_DNS2_Packet &$packet)
    {
        if ($this->rdlength > 0) {

            // unpack the svcPriority
            $x = unpack('nsvcPriority', $this->rdata);

            $this->svcPriority = $x['svcPriority'];

            // Get targetName
            $offset             = $packet->offset + 2;
            $this->targetName   = Net_DNS2_Packet::expand($packet, $offset) ;

            // SvcParam data = rdata offset of:
            // 2 bytes for svcPriority +
            // 1 byte for trailing zero octet of null root label +
            // 1 byte for length octet + length of each non-root label.
            $offset = 3;
            // If targetName is not empty, calculate octets of labels by adding 1 byte
            // since embedded "."s account for all but one length octets
            if( strlen($this->targetName) > 0 ) {
                $offset += strlen($this->targetName) + 1;
            }
            $remaining_svcparam_data = substr($this->rdata, $offset);
            // Parse svc params if svc priority is not 0 and data exists
            if($this->svcPriority !=0 && !empty($remaining_svcparam_data)) {
                while(!empty($remaining_svcparam_data)) {
                    $x = unpack('nsvcParamKey/nsvcParamLength', $remaining_svcparam_data);
                    // Ensure we don't already have instance of this SvcParam (RFC specifies invalid if multiple)
                    if(isset($this->svcParams[$x['svcParamKey']])) {
                        throw new Net_DNS2_Exception(
                            'Multiple SvcParam keys for ' . $this->name . ':' . $x['svcParamKey'],
                            Net_DNS2_Lookups::E_RR_INVALID
                        );
                    }
                    // Length of param data is 4 (2 octets for key and 2 octets for length) + length
                    $binary_data_length = 4 + $x['svcParamLength'];
                    $this->svcParams[$x['svcParamKey']] =
                        Net_DNS2_SvcParam::parse(substr($remaining_svcparam_data, 0, $binary_data_length));
                    $remaining_svcparam_data = substr($remaining_svcparam_data, $binary_data_length);
                }
            }

            return true;
        }

        return false;
    }

    /**
     * returns the rdata portion of the DNS packet
     *
     * @param Net_DNS2_Packet &$packet a Net_DNS2_Packet packet use for
     *                                 compressed names
     *
     * @return mixed                   either returns a binary packed
     *                                 string or null on failure
     * @access protected
     *
     */
    protected function rrGet(Net_DNS2_Packet &$packet)
    {
        if (strlen($this->targetName) > 0) {

            $data = pack('n', $this->svcPriority);
            $packet->offset += 2;

            $data .= $packet->compress($this->targetName, $packet->offset);

            return $data;
        }

        return null;
    }

}

