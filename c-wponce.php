<?php

/*
  Plugin Name: WP Once Implemention
  Plugin URI:
  Description:
  Version: 1.0.0
  Author:
  Author URI:
  License: GPLv2
 */

class WP_NOnce {

    /**
     * Retrieve URL with nonce added to URL query.
     *
     *
     * @param string     $actionurl URL to add nonce action.
     * @param int|string $action    Optional. Nonce action name. Default -1.
     * @param string     $name      Optional. Nonce name. Default '_wpnonce'.
     * @return string Escaped URL with nonce action added.
     */
    public static function makeUrl($actionurl, $action = -1, $name = '_wpnonce') {
        return wp_nonce_url($bare_url, $action, $name);
    }

    /**
     * Retrieve nonce hidden field for forms.
     *
     * The nonce field is used to validate that the contents of the form came from
     * the location on the current site and not somewhere else. The nonce does not
     * offer absolute protection, but should protect against most cases. It is very
     * important to use nonce field in forms.
     *
     * The $action and $name are optional, but if you want to have better security,
     * it is strongly suggested to set those two parameters. It is easier to just
     * call the function without any parameters, because validation of the nonce
     * doesn't require any parameters, but since crackers know what the default is
     * it won't be difficult for them to find a way around your nonce and cause
     * damage.
     *
     * The input name will be whatever $name value you gave. The input value will be
     * the nonce creation value.
     *
     *
     * @param int|string $action  Optional. Action name. Default -1.
     * @param string     $name    Optional. Nonce name. Default '_wpnonce'.
     * @param bool       $referer Optional. Whether to set the referer field for validation. Default true.
     * @return string Nonce field HTML markup.
     */
    public static function makeField($action = -1, $name = "_wpnonce", $referer = true) {
        return wp_nonce_field($action, $name, $referer, false);
    }

    /**
     * Creates a cryptographic token tied to a specific action, user, user session,
     * and window of time.
     *
     * @param string|int $action Scalar value to add context to the nonce.
     * @return string The token.
     */
    public static function makeNonce($action = -1) {
        return wp_create_nonce($action);
    }

    /**
     * Retrieve or display referer hidden field for forms.
     *
     * The referer link is the current Request URI from the server super global. The
     * input name is '_wp_http_referer', in case you wanted to check manually.
     *
     *
     * @return string Referer field HTML markup.
     */
    public static function getRefererField() {
        return wp_referer_field(true);
    }

    /**
     * Display "Are You Sure" message to confirm the action being taken.
     *
     * If the action has the nonce explain message, then it will be displayed
     * along with the "Are you sure?" message.
     *
     *
     * @param string $action The nonce action.
     */
    public static function ays($action) {
        wp_nonce_ays($action);
    }

    /**
     *  Verifies the request to prevent processing requests with nonce
     *
     * To avoid security exploits.
     *
     *
     * @param int|string $action    Action nonce.
     * @param string     $query_arg Optional. Key to check for nonce in `$_REQUEST` .
     *                              Default '_wpnonce'.
     * @param string $type  type to verity. These are 3 type.
     *                                      `admin` : Makes sure that a user was referred from another admin page.
     *                                      `ajax`  : Verifies the AJAX request to prevent processing requests external of the blog.
     *                                      `other` : Verify that correct nonce was used with time limit.
     *                                      Default : admin 
     * 
     * @return false|int False if the nonce is invalid, 1 if the nonce is valid and generated between
     *                   0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
     */
    public static function verifyNonce($action = -1, $query_arg = '_wpnonce', $type = "admin") {
        switch (strtolower($type)) {


            case "ajax" :
                return check_ajax_referer($action, $query_arg, $type, true);

            case "other" :
                return wp_verify_nonce($query_arg, $action);

            default:
                return check_admin_referer($action, $query_arg);
        }
    }

    /**
     * applied to the lifespan of a nonce to generate or verify the nonce. Can be used to generate nonces which expire earlier  
     * @param int  $time  the time in number 
     * @param string $type  type of time : second | minute | hour . Default: second
     */
    public static function setNonceLifetime($time, $type = "minute") {
        switch ($type) {
            case "second" :
                $type = int($type);
                break;

            case "hour" :
                $type = int($type) * HOUR_IN_SECONDS;
                break;

            //default minute
            default :
                $type = int($type) * MINUTE_IN_SECONDS;
        }

        add_filter("nonce_life", function($time, $type) {
            return $time * $type;
        });
    }

    /**
     * change the error message sent when a nonce is not valid, by using the translation system. 
     * Example : 
     * @param type $fromWords  words to find
     * @param type $toWords  words to replace 
     */
    public static function setErrorMessage($fromWords, $toWords) {

        add_filter("gettext", function( $wordsToFind, $wordsToBeReplace, $wordsToChange ) {
            if ($wordsToFind == $wordsToBeReplace) {
                return $wordsToChange;
            } else {
                return strip_tags($wordsToFind);
            }
        });
    }

    /**
     * Display "Are You Sure todo <action> with <noun>"  message to confirm the action being taken.
     *
     * If the action has the nonce explain message, then it will be displayed
     * along with the "Are you sure?" message.
     *
     * @param type $verb  the action
     * @param type $noun  the noun
     * @param type $format  the string to be add $verb and $noun to , MUST contains 2 %s for placeholder of $verb and $action, for example : Are you sure you want to %s this %s ?
     */
    public static function setExplainNonce($verb, $noun, $format = "Are you sure you want to %s this %s ?") {
        $verb = strip_tags($verb);
        $noun = strip_tags($noun);

        if (preg_match_all("/\%s/", $format) != 2) {
            error_log("WP_NOnce::setExplainNonce \$format must contains two %s for placeholder of \$verb and \$noun ");
        }

        add_filter("explain_nonce_{$verb}-{$noun}", function( $format, $verb, $noun) {
            return sprintf($format, $verb, $noun);
        }, 10, 2);
    }

}


