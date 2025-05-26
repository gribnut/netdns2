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
 * @since     0.6.0
 *
 * This file contains code based off the Net::DNS::SEC Perl module by Olaf M. Kolkman
 *
 * This is the copyright notice from the PERL Net::DNS::SEC module:
 *
 * Copyright (c) 2001 - 2005  RIPE NCC.  Author Olaf M. Kolkman 
 * Copyright (c) 2007 - 2008  NLnet Labs.  Author Olaf M. Kolkman 
 * <olaf@net-dns.org>
 *
 * All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of the author not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 *
 * THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO EVENT SHALL
 * AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
 * DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

namespace NetDNS2\RR;

/**
 * SIG Resource Record - RFC2535 section 4.1
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |        Type Covered           |  Algorithm    |     Labels    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Original TTL                          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Signature Expiration                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Signature Inception                      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Key Tag            |                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   /                                                               /
 *   /                            Signature                          /
 *   /                                                               /
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
final class SIG extends \NetDNS2\RR
{
    /**
     * and instance of a \NetDNS2\PrivateKey object
     */
    protected \NetDNS2\PrivateKey $private_key;

    /**
     * the RR type covered by this signature; we store the string value of the RR
     */
    protected string $typecovered;

    /**
     * the algorithm used for the signature
     */
    protected \NetDNS2\ENUM\DNSSEC\Algorithm $algorithm;
    
    /**
     * the number of labels in the name
     */
    protected int $labels;

    /**
     * the original TTL
     */
    protected string $origttl;

    /**
     * the signature expiration
     */
    protected string $sigexp;

    /**
     * the inception of the signature
    */
    protected string $sigincep;

    /**
     * the keytag used
     */
    protected int $keytag;

    /**
     * the signer's name
     */
    protected \NetDNS2\Data\Domain $signname;

    /**
     * the signature
     */
    protected string $signature = '';

    /**
     * @see \NetDNS2\RR::rrToString()
     */
    protected function rrToString(): string
    {
        return $this->typecovered . ' ' . $this->algorithm->value . ' ' . $this->labels . ' ' . $this->origttl . ' ' . $this->sigexp . ' ' . 
            $this->sigincep . ' ' . $this->keytag . ' ' . $this->signname . '. ' . $this->signature;
    }

    /**
     * @see \NetDNS2\RR::rrFromString()
     * @param array<string> $_rdata
     */
    protected function rrFromString(array $_rdata): bool
    {
        $this->typecovered  = strtoupper($this->sanitize(array_shift($_rdata)));
        $this->algorithm    = \NetDNS2\ENUM\DNSSEC\Algorithm::set(intval($this->sanitize(array_shift($_rdata))));
        $this->labels       = intval($this->sanitize(array_shift($_rdata)));
        $this->origttl      = $this->sanitize(array_shift($_rdata));
        $this->sigexp       = $this->sanitize(array_shift($_rdata));
        $this->sigincep     = $this->sanitize(array_shift($_rdata));
        $this->keytag       = intval($this->sanitize(array_shift($_rdata)));
        $this->signname     = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, array_shift($_rdata));

        foreach($_rdata as $line)
        {
            $this->signature .= $line;
        }

        $this->signature = trim($this->signature);

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

        $val = unpack('na/Cb/Cc/Nd/Ne/Nf/ng', $this->rdata);
        if ($val === false)
        {
            return false;
        }

        list('a' => $a, 'b' => $algorithm, 'c' => $this->labels, 'd' => $d, 'e' => $e, 'f' => $f, 'g' => $this->keytag) = (array)$val;

        $this->algorithm = \NetDNS2\ENUM\DNSSEC\Algorithm::set($algorithm);

        if (\NetDNS2\ENUM\RRType::exists($a) == true)
        {
            $this->typecovered = \NetDNS2\ENUM\RRType::set($a)->label();
        } else
        {
            $this->typecovered = 'TYPE' . $a;
        }

        $this->origttl     = \NetDNS2\Client::expandUint32($d);

        //
        // the dates are in GM time
        //
        $this->sigexp      = gmdate('YmdHis', $e);
        $this->sigincep    = gmdate('YmdHis', $f);

        //
        // get teh signers name and signature
        //
        $offset            = $_packet->offset + 18;
        $sigoffset         = $offset;

        $this->signname    = new \NetDNS2\Data\Domain(\NetDNS2\Data::DATA_TYPE_CANON, $_packet, $sigoffset);
        $this->signature   = base64_encode(substr($this->rdata, 18 + ($sigoffset - $offset)));

        return true;
    }

    /**
     * @see \NetDNS2\RR::rrGet()
     */
    protected function rrGet(\NetDNS2\Packet &$_packet): string
    {
        //
        // parse the values out of the dates
        //
        preg_match('/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/', $this->sigexp, $e);
        preg_match('/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/', $this->sigincep, $i);

        //
        // pack the value
        //
        $data = pack('nCCNNNn',
            \NetDNS2\ENUM\RRType::set($this->typecovered)->value,
            $this->algorithm->value,
            $this->labels,
            $this->origttl,
            gmmktime(intval($e[4]), intval($e[5]), intval($e[6]), intval($e[2]), intval($e[3]), intval($e[1])),
            gmmktime(intval($i[4]), intval($i[5]), intval($i[6]), intval($i[2]), intval($i[3]), intval($i[1])),
            $this->keytag
        );

        //
        // the signer name is special; it's not allowed to be compressed (see section 3.1.7)
        //
        $data .= $this->signname->encode($_packet->offset);

        //
        // if the signature is empty, and $this->private_key is an instance of a private key object, and we have access to openssl, then assume this
        // is a SIG(0), and generate a new signature
        //
        if ( (strlen($this->signature) == 0) && (extension_loaded('openssl') === true) )
        {
            //
            // create a new packet for the signature-
            //
            $new_packet = new \NetDNS2\Packet\Request('example.com', 'SOA', 'IN');

            //
            // copy the packet data over
            //
            $new_packet->copy($_packet);

            //
            // remove the SIG object from the additional list
            //
            array_pop($new_packet->additional);
            $new_packet->header->arcount = count($new_packet->additional);

            //
            // copy out the data
            //
            $sigdata = $data . $new_packet->get();

            //
            // based on the algorithm
            //
            $openssl_algorithm = $this->algorithm->openssl();

            //
            // sign the data
            //
            if (openssl_sign($sigdata, $this->signature, $this->private_key->instance, $openssl_algorithm) == false)
            {
                throw new \NetDNS2\Exception('OpenSSL error: ' . strval(openssl_error_string()), \NetDNS2\ENUM\Error::OPENSSL_ERROR);
            }

            //
            // build the signature value based
            //
            switch($this->algorithm)
            {
                //
                // RSA- add it directly
                //
                case \NetDNS2\ENUM\DNSSEC\Algorithm::RSAMD5:
                case \NetDNS2\ENUM\DNSSEC\Algorithm::RSASHA1:
                case \NetDNS2\ENUM\DNSSEC\Algorithm::RSASHA256:
                case \NetDNS2\ENUM\DNSSEC\Algorithm::RSASHA512:
                {
                    $this->signature = base64_encode($this->signature);
                }
                break;
                default:
                    ;
            }
        }

        //
        // add the signature
        //
        $decode = base64_decode($this->signature);
        if ($decode !== false)
        {
            $data .= $decode;
        }

        $_packet->offset += strlen($data);

        return $data;
    }
}
