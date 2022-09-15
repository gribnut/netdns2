<?php

class Net_DNS2_SvcParam_NoDefaultALPN extends Net_DNS2_SvcParam
{
    /*
     * The name of the SvcParamKey
     */
    public $name = "no_default_alpn";

    /*
     * The integer (wire) value of the SvcParamKey
     */
    public $id = NO_DEFAULT_ALPN;

    /**
     * magic __toString() method to return the Net_DNS2_SvcParam object object as a string
     *
     * @return string
     * @access public
     *
     */
    public function __toString()
    {
        // no_default_alpn has no values.  Either exists (true) or doesn't (false)
        return $this->name;
    }
}
