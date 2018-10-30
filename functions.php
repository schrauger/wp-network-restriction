<?php

/*
Plugin Name: WordPress Network Restriction
Plugin URI: https://github.com/schrauger/wp-network-restriction
Description: Force user login to view pages, unless within a whitelisted ip range.
Version: 1.0
Author: Stephen Schrauger
Author URI: https://www.schrauger.com/
License: GPLv2 or later
*/

class wp_network_restriction{

public function __construct(){
	add_action('get_header', array($this, 'rl_redirect')); // force login when plugin is activated. using add_action prevents infinite loops
}

// force login for dev
function rl_redirect(){
	$allowed_ips = array(
		'127.0.0.1', // localhost
		'10.0.0.0/8', // ucf internal network
		'132.170.0.0/16', // ucf external ip
	); // list all allowed ips to view dev WITHOUT requiring login
	if (!is_user_logged_in()) {
		if (!$this->ip_in_array($_SERVER['REMOTE_ADDR'], $allowed_ips)) {
			auth_redirect();
		}
	}
}
/**
 * Loop through each allowed ip item and check the range against the user ip
 */
function ip_in_array( $ip, $array ) {
	$in_range = false;
	foreach ($array as $range ) {
		if ($this->ip_in_range($ip, $range)) {
			$in_range = true;
		}
	}
	return $in_range;
}
/**
 * Check if a given ip is in a network
 * @param  string $ip    IP to check in IPV4 format eg. 127.0.0.1
 * @param  string $range IP/CIDR netmask eg. 127.0.0.0/24, also 127.0.0.1 is accepted and /32 assumed
 * @return boolean true if the ip is in this range / false if not.
 */
function ip_in_range( $ip, $range ) {
	if ( strpos( $range, '/' ) == false ) {
		$range .= '/32';
	}
	// $range is in IP/CIDR format eg 127.0.0.1/24
	list( $range, $netmask ) = explode( '/', $range, 2 );
	$range_decimal = ip2long( $range );
	$ip_decimal = ip2long( $ip );
	$wildcard_decimal = pow( 2, ( 32 - $netmask ) ) - 1;
	$netmask_decimal = ~ $wildcard_decimal;
	return ( ( $ip_decimal & $netmask_decimal ) == ( $range_decimal & $netmask_decimal ) );
}

}

new wp_network_restriction();
