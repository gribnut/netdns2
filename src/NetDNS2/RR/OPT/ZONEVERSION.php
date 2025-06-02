<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2025, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2025 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     1.6.0
 *
 */

namespace NetDNS2\RR\OPT;

/**
 * RFC 9660 - The DNS Zone Version (ZONEVERSION) Option
 *
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 0: |           LABELCOUNT          |            TYPE               |
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * 2: |                            VERSION                            |
 *    /                                                               /
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 */
final class ZONEVERSION extends \NetDNS2\RR\OPT
{
    /**
     * indicating the number of labels for the name of the zone that VERSION value refers to
     */
    protected int $label_count = 0;

    /**
     * an unsigned 1-octet type number (TYPE) distinguishing the format and meaning of VERSION
     */
    protected int $zone_version_type;

    /*
     * string conveying the zone version data (VERSION)
     */
    protected string $zone_version;

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->option_code->label() . ' ' . $this->option_length . ' ' . $this->label_count . ' ' . $this->zone_version_type . ' ' . $this->zone_version;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     */
    protected function rrFromString(array $_rdata): bool
    {
        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        if ($this->option_length == 0)
        {
            return true;
        }

        $val = unpack('Cx/Cy/H*z', $this->option_data);
        if ($val == false)
        {            
            return false;
        }

        list('x' => $this->label_count, 'y' => $this->zone_version_type, 'z' => $this->zone_version) = (array)$val;

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        //
        // empty option data for a request
        //
        $this->option_data   = '';
        $this->option_length = 0;

        //
        // build the parent OPT data
        //
        return parent::rrGet($_packet);        
    }
}
