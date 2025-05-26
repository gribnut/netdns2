<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2023, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2023 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     1.0.0
 *
 */

namespace NetDNS2\RR;

/**
 * HIP Resource Record - RFC5205 section 5
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  HIT length   | PK algorithm  |          PK length            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  ~                           HIT                                 ~
 *  |                                                               |
 *  +                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     |                                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+                                         +
 *  |                           Public Key                          |
 *  ~                                                               ~
 *  |                                                               |
 *  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *  |                                                               |
 *  ~                       Rendezvous Servers                      ~
 *  |                                                               |
 *  +             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             |
 *  +-+-+-+-+-+-+-+
 *
 */
final class HIP extends \NetDNS2\RR
{
    /**
     * The length of the HIT field
     */
    protected int $hit_length;

    /**
     * the public key cryptographic algorithm
     */
    protected int $pk_algorithm;

    /**
     * the length of the public key field
     */
    protected int $pk_length;
    
    /**
     * The HIT is stored as a binary value in network byte order.
     */
    protected string $hit;

    /**
     * The public key
     */
    protected string $public_key;

    /**
     * a list of rendezvous servers
     *
     * @var array<int,\NetDNS2\Data\Domain>
     */
    protected array $rendezvous_servers = [];

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        $out = $this->pk_algorithm . ' ' . $this->hit . ' ' . $this->public_key . ' ';

        foreach($this->rendezvous_servers as $index => $server)
        {
            $out .= $server . '. ';
        }

        return trim($out);
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->pk_algorithm = intval($this->sanitize(array_shift($_rdata)));
        $this->hit          = strtoupper($this->sanitize(array_shift($_rdata)));
        $this->public_key   = array_shift($_rdata);

        //
        // anything left on the array, must be one or more rendezevous servers. add them and strip off the trailing dot
        //
        foreach($_rdata as $data)
        {
            $this->rendezvous_servers[] = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $data);
        }

        //
        // base64 deocde the public key
        //
        $decode = base64_decode($this->public_key);
        if ($decode === false)
        {
            $decode = '';
        }

        //
        // store the lengths
        //
        $this->hit_length = strlen(pack('H*', $this->hit));
        $this->pk_length  = strlen($decode);

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrSet()
     */
    protected function rrSet(\NetDNS2\Packet &$_packet): bool
    {
        if ($this->rdlength == 0)
        {
            return false;
        }

        //
        // unpack the algorithm and length values
        //
        $val = unpack('Cx/Cy/nz', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('x' => $this->hit_length, 'y' => $this->pk_algorithm, 'z' => $this->pk_length) = (array)$val;
        $offset = 4;

        //
        // copy out the HIT value
        //
        $val = unpack('H*', substr($this->rdata, $offset, $this->hit_length));
        if ($val === false)
        {
            return false;
        }
        $this->hit = strtoupper(((array)$val)[1]);
        $offset += $this->hit_length;

        //
        // copy out the public key
        //
        $this->public_key = base64_encode(substr($this->rdata, $offset, $this->pk_length));
        $offset += $this->pk_length;

        //
        // copy out any possible rendezvous servers
        //
        while($offset < $this->rdlength)
        {
            $this->rendezvous_servers[] = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $this->rdata, $offset);
        }

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        if ( (strlen($this->hit) == 0) || (strlen($this->public_key) == 0) )
        {
            return '';
        }

        //
        // pack the length, algorithm and HIT values
        //
        $data = pack('CCnH*', $this->hit_length, $this->pk_algorithm, $this->pk_length, $this->hit);
            
        //
        // add the public key
        //
        $decode = base64_decode($this->public_key);
        if ($decode !== false)
        {
            $data .= $decode;
        }

        //
        // add each rendezvous server
        //
        foreach($this->rendezvous_servers as $index => $server)
        {
            $data .= $server->encode();
        }

        //
        // add the offset
        //
        $_packet->offset += strlen($data);

        return $data;
    }
}
