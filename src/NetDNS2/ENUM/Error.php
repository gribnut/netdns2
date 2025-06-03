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
 * @copyright 2025 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     2.0.0
 *
 */

namespace NetDNS2\ENUM;

enum Error: int
{
    use \NetDNS2\ENUM\Base;

    //
    // error conditions mapped to DNS response codes
    //
    case NONE               = 0;    // \NetDNS2\ENUM\RR\Code::NOERROR
    case DNS_FORMERR        = 1;    // \NetDNS2\ENUM\RR\Code::FORMERR
    case DNS_SERVFAIL       = 2;    // \NetDNS2\ENUM\RR\Code::SERVFAIL
    case DNS_NXDOMAIN       = 3;    // \NetDNS2\ENUM\RR\Code::NXDOMAIN
    case DNS_NOTIMP         = 4;    // \NetDNS2\ENUM\RR\Code::NOTIMP
    case DNS_REFUSED        = 5;    // \NetDNS2\ENUM\RR\Code::REFUSED
    case DNS_YXDOMAIN       = 6;    // \NetDNS2\ENUM\RR\Code::YXDOMAIN
    case DNS_YXRRSET        = 7;    // \NetDNS2\ENUM\RR\Code::YXRRSET
    case DNS_NXRRSET        = 8;    // \NetDNS2\ENUM\RR\Code::NXRRSET
    case DNS_NOTAUTH        = 9;    // \NetDNS2\ENUM\RR\Code::NOTAUTH
    case DNS_NOTZONE        = 10;   // \NetDNS2\ENUM\RR\Code::NOTZONE
    case DNS_DSOTYPENI      = 11;   // \NetDNS2\ENUM\RR\Code::DSOTYPENI

    // 12-15 reserved

    case DNS_BADSIG         = 16;   // \NetDNS2\ENUM\RR\Code::BADSIG
    case DNS_BADKEY         = 17;   // \NetDNS2\ENUM\RR\Code::BADKEY
    case DNS_BADTIME        = 18;   // \NetDNS2\ENUM\RR\Code::BADTIME
    case DNS_BADMODE        = 19;   // \NetDNS2\ENUM\RR\Code::BADMODE
    case DNS_BADNAME        = 20;   // \NetDNS2\ENUM\RR\Code::BADNAME
    case DNS_BADALG         = 21;   // \NetDNS2\ENUM\RR\Code::BADALG
    case DNS_BADTRUNC       = 22;   // \NetDNS2\ENUM\RR\Code::BADTRUNC    
    case DNS_BADCOOKIE      = 23;   // \NetDNS2\ENUM\RR\Code::BADCOOKIE

    //
    // other internal error conditions - 3841-4095
    //
    case INT_PARSE_ERROR            = 3841;
    case INT_INVALID_PACKET         = 3842;
    case INT_INVALID_TYPE           = 3843;
    case INT_INVALID_CLASS          = 3844;
    case INT_INVALID_ENUM           = 3845;
    case INT_INVALID_IPV4           = 3846;
    case INT_INVALID_IPV6           = 3847;
    case INT_INVALID_EXTENSION      = 3848;
    case INT_INVALID_ALGORITHM      = 3849;
    case INT_INVALID_NAMESERVER     = 3850;
    case INT_INVALID_SOCKET         = 3851;
    case INT_INVALID_PRIVATE_KEY    = 3852;
    case INT_INVALID_CERTIFICATE    = 3853;

    case INT_FAILED_NAMESERVER      = 3854;
    case INT_FAILED_SOCKET          = 3855;
    case INT_FAILED_SHMOP           = 3856;
    case INT_FAILED_CURL            = 3857;
    case INT_FAILED_OPENSSL         = 3858;
    case INT_FAILED_MEMCACHED       = 3859;
    case INT_FAILED_REDIS           = 3860;

    public function label(): string
    {
        return match($this)
        {
            default => ''
        };
    }
}
