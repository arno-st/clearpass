<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2007 The Cacti Group                                      |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDTool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | This code is designed, written, and maintained by the Cacti Group. See  |
 | about.php and/or the AUTHORS file for specific developer information.   |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/


function plugin_clearpass_install () {
	api_plugin_register_hook('clearpass', 'config_settings', 'clearpass_config_settings', 'setup.php');
	api_plugin_register_hook('clearpass', 'api_device_new', 'clearpass_api_device_new', 'setup.php');
	api_plugin_register_hook('clearpass', 'utilities_action', 'clearpass_utilities_action', 'setup.php'); // add option to check if device exist or need to be added
	api_plugin_register_hook('clearpass', 'utilities_list', 'clearpass_utilities_list', 'setup.php');

// Device action
    api_plugin_register_hook('clearpass', 'device_action_array', 'clearpass_device_action_array', 'setup.php');
    api_plugin_register_hook('clearpass', 'device_action_execute', 'clearpass_device_action_execute', 'setup.php');
    api_plugin_register_hook('clearpass', 'device_action_prepare', 'clearpass_device_action_prepare', 'setup.php');

}

function plugin_clearpass_uninstall () {
	// Do any extra Uninstall stuff here

}

function plugin_clearpass_check_config () {
	// Here we will check to ensure everything is configured
	clearpass_check_upgrade();

	return true;
}

function plugin_clearpass_upgrade () {
	// Here we will upgrade to the newest version
	clearpass_check_upgrade();
	return false;
}

function clearpass_check_upgrade() {
	global $config;

	$version = plugin_clearpass_version ();
	$current = $version['version'];
	$old     = db_fetch_cell('SELECT version
		FROM plugin_config
		WHERE directory="clearpass"');

	if ($current != $old) {

		// Set the new version
		db_execute("UPDATE plugin_config SET version='$current' WHERE directory='clearpass'");
		db_execute("UPDATE plugin_config SET 
			version='" . $version['version'] . "', 
			name='"    . $version['longname'] . "', 
			author='"  . $version['author'] . "', 
			webpage='" . $version['homepage'] . "' 
			WHERE directory='" . $version['name'] . "' ");

	}
}

function plugin_clearpass_version () {
	global $config;
	$info = parse_ini_file($config['base_path'] . '/plugins/clearpass/INFO', true);
	return $info['info'];
}


function clearpass_utilities_list () {
	global $colors, $config;
	html_header(array("clearpass Plugin"), 4);
	form_alternate_row();
	?>
		<td class="textArea">
			<a href='utilities.php?action=clearpass_check'>Check if devices are on clearpass.</a>
		</td>
		<td class="textArea">
			Check all devices to see if they are on clearpass, if not add it.
		</td>
	<?php
	form_end_row();
}

function clearpass_utilities_action ($action) {
	global $item_rows;
	
	if ( $action == 'clearpass_check' ){
		if ($action == 'clearpass_check') {
	// get device list,  where serial number is empty, or type
			$dbquery = db_fetch_assoc("SELECT * FROM host 
			WHERE status = '3' AND disabled != 'on'
			AND snmp_sysDescr LIKE '%cisco%'
			ORDER BY id");
		// Upgrade the clearpass value
			if( $dbquery > 0 ) {
				$token = aruba_get_oauth();
				if( $token ) {
					foreach ($dbquery as $host) {
						// if device exist, just update it
						if( check_aruba_device( $host, $token) ) {
							update_aruba_device($host, $token);
						}
						else add_aruba_device($host, $token);
					}
				}
			}
		}
		top_header();
		utilities();
		bottom_footer();
	} 
	return $action;
}

function clearpass_config_settings () {
	global $tabs, $settings;
	$tabs["misc"] = "Misc";

	if (isset($_SERVER['PHP_SELF']) && basename($_SERVER['PHP_SELF']) != 'settings.php')
		return;

	$tabs['misc'] = 'Misc';
	$temp = array(
		"clearpass_general_header" => array(
			"friendly_name" => "clearpass",
			"method" => "spacer",
			),
		'clearpass_server' => array(
			'friendly_name' => "Aruba ClearPass URL server",
			'description' => 'URL of the Aruba server where will be addedd all newly discovered device',
			"method" => "textbox",
			"max_length" => 80,
			"default" => ""
		),
		'clearpass_access_token' => array(
			'friendly_name' => "Aruba ClearPass Access Token",
			'description' => 'The ClearPass Access Token API',
			"method" => "textbox_password",
			"max_length" => 80,
			"default" => ""
		),
		'clearpass_radius_secret' => array(
			'friendly_name' => "Aruba ClearPass radius secret",
			'description' => 'The radius secret for a new device',
			"method" => "textbox_password",
			"max_length" => 80,
			"default" => ""
		),
		'clearpass_tacacs_secret' => array(
			'friendly_name' => "Aruba ClearPass tacacs secret",
			'description' => 'The tacas secret for a new device',
			"method" => "textbox_password",
			"max_length" => 80,
			"default" => ""
		),
		'clearpass_log_debug' => array(
			'friendly_name' => 'Debug Log',
			'description' => 'Enable logging of debug messages during clearpass exchange',
			'method' => 'checkbox',
			'default' => 'off'
		)
	);
	
	if (isset($settings['misc']))
		$settings['misc'] = array_merge($settings['misc'], $temp);
	else
		$settings['misc']=$temp;
}

function clearpass_check_dependencies() {
	global $plugins, $config;

	return true;
}

function clearpass_device_action_array($device_action_array) {
    $device_action_array['check_clearpass'] = __('Check if device is on Clearpass');
        return $device_action_array;
}

function clearpass_device_action_execute($action) {
   global $config;
   if ($action != 'check_clearpass' ) {
           return $action;
   }

   $selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

	if ($selected_items != false) {
		if ($action == 'check_clearpass' ) {
			$token = aruba_get_oauth();
			if( $token ) {
				foreach( $selected_items as $hostid ) {
					if ($action == 'check_clearpass') {
						$dbquery = db_fetch_row("SELECT * FROM host WHERE id=".$hostid);
						// if device exist, just update it
						if( check_aruba_device( $dbquery, $token) ) {
							update_aruba_device($dbquery, $token);
						}
						else add_aruba_device($dbquery, $token);
					}
				}
			}
		}
	}

	return $action;
}

function clearpass_device_action_prepare($save) {
    global $host_list;

    $action = $save['drp_action'];

    if ($action != 'check_clearpass' ) {
		return $save;
    }

    if ($action == 'check_clearpass' ) {
		$action_description = 'Check if device is on Clearpass';
			print "<tr>
                    <td colspan='2' class='even'>
                            <p>" . __('Click \'Continue\' to %s on these Device(s)', $action_description) . "</p>
                            <p><div class='itemlist'><ul>" . $save['host_list'] . "</ul></div></p>
                    </td>
            </tr>";
    }
	return $save;
}

function clearpass_api_device_new( $host_id ) {
	cacti_log('Enter Clearpass', false, 'CLEARPASS' );
	
	// if device is disabled, or snmp has nothing, don't save on other
	if( array_key_exists('disabled', $host_id) && array_key_exists('snmp_version', $host_id) && array_key_exists('id', $host_id) ) {
		if ($host_id['disabled'] == 'on' || $host_id['snmp_version'] == 0 ) {
			clearpass_log('don t use ?!?!?: '.$host_id['description'] );
			cacti_log('End Clearpass', false, 'CLEARPASS' );
			return $host_id;
		}
	} else {
		clearpass_log('Recu: '. print_r($host_id, true) );
		cacti_log('End Clearpass', false, 'CLEARPASS' );
		return $host_id;
	}
	
	$usearuba = read_config_option("clearpass_server");
	if($usearuba){
		// call aruba REST API
		// get Auth Token
		$token = aruba_get_oauth();
		if($token) {
			// if device exist, just update it
			if( check_aruba_device( $host_id, $token) ) {
				update_aruba_device($host_id, $token);
			}
			else add_aruba_device($host_id, $token);
		}
	}
	cacti_log('End Clearpass', false, 'CLEARPASS' );

	return $host_id;
}

function aruba_get_oauth() {
	clearpass_log('Aruba OAUTH' );
	$arubaurl = read_config_option("clearpass_server");
	$aruba_access_token = read_config_option("clearpass_access_token");
	
	$url = $arubaurl . '/oauth';
//**** get the auth token
	$handle = curl_init();
	curl_setopt( $handle, CURLOPT_URL, $url );
	curl_setopt( $handle, CURLOPT_POST, true );
	curl_setopt( $handle, CURLOPT_HEADER, true );
	curl_setopt( $handle, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $handle, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $handle, CURLOPT_HTTPHEADER, array( 'Content-Type:application/json; charset=UTF-8','cache-control:no-cache') );
    curl_setopt( $handle, CURLOPT_POSTFIELDS, 
        '{
        "grant_type": "client_credentials",
        "client_id": "Cacti",
        "client_secret": "'.$aruba_access_token.'"
        }'
    );  //r4rL0DvX+/RQBeSoHvH5umxPJ40QTuoWRxh5g9o8lLIU


	$response = curl_exec($handle);
	$error = curl_error($handle);
	$result = array( 'header' => '',
                     'body' => '',
					 'curl_error' => '',
					 'http_code' => '',
					 'last_url' => ''
					 );

    $header_size = curl_getinfo($handle,CURLINFO_HEADER_SIZE);
	$result['header'] = substr($response, 0, $header_size);
	$result['body'] = substr( $response, $header_size );
	$result['http_code'] = curl_getinfo($handle,CURLINFO_HTTP_CODE);
	$result['last_url'] = curl_getinfo($handle,CURLINFO_EFFECTIVE_URL);


	if ( $result['http_code'] > "299" )
    {
		$result['curl_error'] = $error;
		clearpass_log("oauth error: ". $result['body'] );
		$token = false;
    } else {
       
		$response = json_decode( $result['body'], true );
		$token = $response['access_token'];
	}

	return $token;
}

function check_aruba_device( $host_id, $token ) {
	$arubaurl = read_config_option("clearpass_server");
	$arubatacacs = read_config_option("clearpass_tacacs_secret");
	$arubaradius = read_config_option("clearpass_radius_secret");
	
	clearpass_log('Enter Aruba check' );

	
//**** check if the device exist
	$url = $arubaurl . '/network-device/name/'.$host_id['description'];
	$handle = curl_init();
	curl_setopt( $handle, CURLOPT_URL, $url );
	curl_setopt( $handle, CURLOPT_HTTPGET, true );
	curl_setopt( $handle, CURLOPT_HEADER, true );
	curl_setopt( $handle, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $handle, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $handle, CURLOPT_HTTPHEADER, array( 'Content-Type:application/json; charset=UTF-8',
													 'cache-control:no-cache',
													 "Authorization: Bearer $token") );

	$response = curl_exec($handle);
	$error = curl_error($handle);
	$result = array( 'header' => '',
                     'body' => '',
					 'curl_error' => '',
					 'http_code' => '',
					 'last_url' => '');

    $header_size = curl_getinfo($handle,CURLINFO_HEADER_SIZE);
	$result['header'] = substr($response, 0, $header_size);
	$result['body'] = substr( $response, $header_size );
	$result['http_code'] = curl_getinfo($handle,CURLINFO_HTTP_CODE);
	$result['last_url'] = curl_getinfo($handle,CURLINFO_EFFECTIVE_URL);

	clearpass_log('Exit Aruba check' );

	if ( $result['http_code'] == "200" ) {
		return true;
	}
 
	return false;
}

function update_aruba_device( $host_id, $token ) {
	$arubaurl = read_config_option("clearpass_server");
	$arubatacacs = read_config_option("clearpass_tacacs_secret");
	$arubaradius = read_config_option("clearpass_radius_secret");
	
	clearpass_log('Enter Aruba Update' );
	
//**** add the device
	$ip = gethostbyname($host_id['hostname']);
	$url = $arubaurl . '/network-device/name/'.$host_id['description'];
	$handle = curl_init();
	curl_setopt( $handle, CURLOPT_URL, $url );
	curl_setopt( $handle, CURLOPT_CUSTOMREQUEST, 'PATCH');
	curl_setopt( $handle, CURLOPT_HEADER, true );
	curl_setopt( $handle, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $handle, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $handle, CURLOPT_HTTPHEADER, array( 'Content-Type:application/json; charset=UTF-8',
													 'cache-control:no-cache',
													 "Authorization: Bearer $token") );

    $desc = $host_id['description'];
    $name = $host_id['description'];
	$snmp_username =  '';
	$snmp_auth_protocol = ''; 
	$snmp_auth_key = '';
	$snmp_priv_protocol = '';
	$snmp_priv_passphrase = '';
    $snmp_sec_level = '';
	if( $host_id['snmp_version'] == '2' ) {
    	$snmp_version = "V2C";
    } else if( $host_id['snmp_version'] == '3' ) {
		$snmp_version = "V3";
		$snmp_username =  $host_id['snmp_username'];
		$snmp_auth_protocol = $host_id['snmp_auth_protocol']; 
		$snmp_auth_key = $host_id['snmp_password']; 
		if( $host_id['snmp_priv_protocol'] == 'DES' ) {
			$snmp_priv_protocol = 'DES_CBC';
		} elseif ( $host_id['snmp_priv_protocol'] == 'AES128' ) {
			$snmp_priv_protocol = 'AES_128';
		}
		$snmp_priv_passphrase = $host_id['snmp_priv_passphrase'];
		if( $host_id['snmp_priv_protocol'] == '[None]' ) {
			if( $snmp_auth_protocol == '[None]' ) 
				$snmp_sec_level = 'NOAUTH_NOPRIV';
			else $snmp_sec_level = 'AUTH_NOPRIV';
		} else $snmp_sec_level = 'AUTH_PRIV';
		
	} else $snmp_version = "V1";

    $snmp_community = $host_id['snmp_community'];
	
    curl_setopt( $handle, CURLOPT_POSTFIELDS,
        "{
			\"description\": \"$desc\",
			\"name\": \"$name\",
			\"ip_address\" : \"$ip\",
			\"radius_secret\": \"$arubaradius\",
			\"tacacs_secret\": \"$arubatacacs\",
			\"vendor_name\": \"Cisco\",
			\"coa_capable\": true,
			\"coa_port\":3799,
			\"snmp_read\": {
				\"force_read\": true,
				\"read_arp_info\": true,
				\"snmp_version\" : \"$snmp_version\",
				\"community_string\": \"$snmp_community\",
				\"security_level\": \"$snmp_sec_level\",
				\"user\": \"$snmp_username\",
				\"auth_protocol\": \"$snmp_auth_protocol\",
				\"auth_key\": \"$snmp_auth_key\",
				\"privacy_protocol\": \"$snmp_priv_protocol\",
				\"privacy_key\": \"$snmp_priv_passphrase\"
				}
        }"
    );
	
	$response = curl_exec($handle);
	$error = curl_error($handle);
	$result = array( 'header' => '',
                     'body' => '',
					 'curl_error' => '',
					 'http_code' => '',
					 'last_url' => '');

    $header_size = curl_getinfo($handle,CURLINFO_HEADER_SIZE);
	$result['header'] = substr($response, 0, $header_size);
	$result['body'] = substr( $response, $header_size );
	$result['http_code'] = curl_getinfo($handle,CURLINFO_HTTP_CODE);
	$result['last_url'] = curl_getinfo($handle,CURLINFO_EFFECTIVE_URL);

	if ( $result['http_code'] > "399" ) {
		clearpass_log("aruba add error: ". $result['body']);
	}
       
	clearpass_log('Exit Aruba update' );

}

function add_aruba_device( $host_id, $token ) {
	$arubaurl = read_config_option("clearpass_server");
	$arubatacacs = read_config_option("clearpass_tacacs_secret");
	$arubaradius = read_config_option("clearpass_radius_secret");
	
	clearpass_log('Enter Aruba Add' );

	
//**** add the device
	$ip = gethostbyname($host_id['hostname']);
	$url = $arubaurl . '/network-device';
	$handle = curl_init();
	curl_setopt( $handle, CURLOPT_URL, $url );
	curl_setopt( $handle, CURLOPT_POST, true );
	curl_setopt( $handle, CURLOPT_HEADER, true );
	curl_setopt( $handle, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $handle, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $handle, CURLOPT_HTTPHEADER, array( 'Content-Type:application/json; charset=UTF-8',
													 'cache-control:no-cache',
													 "Authorization: Bearer $token") );

    $desc = $host_id['description'];
    $name = $host_id['description'];
	$snmp_username = '';
	$snmp_auth_protocol = '';
	$snmp_auth_key = '';
	$snmp_priv_protocol = '';
	$snmp_sec_level = '';
	$snmp_priv_passphrase = '';
    if( $host_id['snmp_version'] == '2' ) {
    	$snmp_version = "V2C";
    } else if( $host_id['snmp_version'] == '3' ) {
		$snmp_version = "V3";
		$snmp_username =  $host_id['snmp_username'];
		$snmp_auth_protocol = $host_id['snmp_auth_protocol']; 
		$snmp_auth_key = $host_id['snmp_password']; 
		if( $host_id['snmp_priv_protocol'] == 'DES' ) {
			$snmp_priv_protocol = 'DES_CBC';
		} elseif ( $host_id['snmp_priv_protocol'] == 'AES128' ) {
			$snmp_priv_protocol = 'AES_128';
		}
		$snmp_priv_passphrase = $host_id['snmp_priv_passphrase'];
		if( $host_id['snmp_priv_protocol'] == '[None]' ) {
			if( $snmp_auth_protocol == '[None]' ) 
				$snmp_sec_level = 'NOAUTH_NOPRIV';
			else $snmp_sec_level = 'AUTH_NOPRIV';
		} else $snmp_sec_level = 'AUTH_PRIV';
		
	} else $snmp_version = "V1";

    $snmp_community = $host_id['snmp_community'];
	
    curl_setopt( $handle, CURLOPT_POSTFIELDS,
        "{
			\"description\": \"$desc\",
			\"name\": \"$name\",
			\"ip_address\" : \"$ip\",
			\"radius_secret\": \"$arubaradius\",
			\"tacacs_secret\": \"$arubatacacs\",
			\"vendor_name\": \"Cisco\",
			\"coa_capable\": true,
			\"coa_port\":3799,
			\"snmp_read\": {
				\"force_read\": true,
				\"read_arp_info\": true,
				\"snmp_version\" : \"$snmp_version\",
				\"community_string\": \"$snmp_community\",
				\"security_level\": \"$snmp_sec_level\",
				\"user\": \"$snmp_username\",
				\"auth_protocol\": \"$snmp_auth_protocol\",
				\"auth_key\": \"$snmp_auth_key\",
				\"privacy_protocol\": \"$snmp_priv_protocol\",
				\"privacy_key\": \"$snmp_priv_passphrase\"
				}
        }"
    );
	
	$response = curl_exec($handle);
	$error = curl_error($handle);
	$result = array( 'header' => '',
                     'body' => '',
					 'curl_error' => '',
					 'http_code' => '',
					 'last_url' => '');

    $header_size = curl_getinfo($handle,CURLINFO_HEADER_SIZE);
	$result['header'] = substr($response, 0, $header_size);
	$result['body'] = substr( $response, $header_size );
	$result['http_code'] = curl_getinfo($handle,CURLINFO_HTTP_CODE);
	$result['last_url'] = curl_getinfo($handle,CURLINFO_EFFECTIVE_URL);

	if ( $result['http_code'] > "299" ) {
		clearpass_log("aruba add error: ". $result['body']);
	}
       
	clearpass_log('Exit Aruba Add' );
}

function remove_aruba_device( $host_id ) {
	$arubaurl = read_config_option("clearpass_server");
	
	$token = aruba_get_oauth();
	if( ! $token ) {
		return $host_id;
	}
		
//**** remove the device
	$hostname = $host_id['hostname'];
	$url = $arubaurl . '/network-device/name/'.$hostname;
	$handle = curl_init();
	curl_setopt( $handle, CURLOPT_URL, $url );
	curl_setopt( $handle, CURLOPT_HEADER, true );
	curl_setopt( $handle, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $handle, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $handle, CURLOPT_HTTPHEADER, array( 'Content-Type:application/json; charset=UTF-8',
													 'cache-control:no-cache',
													 "Authorization: Bearer $token") );

    curl_setopt( $handle, CURLOPT_CUSTOMREQUEST, "DELETE" );
	$response = curl_exec($handle);
	$error = curl_error($handle);
	
	$result = array( 'header' => '',
                     'body' => '',
					 'curl_error' => '',
					 'http_code' => '',
					 'last_url' => '');

    $header_size = curl_getinfo($handle,CURLINFO_HEADER_SIZE);
	$result['header'] = substr($response, 0, $header_size);
	$result['body'] = substr( $response, $header_size );
	$result['http_code'] = curl_getinfo($handle,CURLINFO_HTTP_CODE);
	$result['last_url'] = curl_getinfo($handle,CURLINFO_EFFECTIVE_URL);

	if ( $result['http_code'] > "299" )
        {
			clearpass_log("aruba remove error: ". $result['body']);
        }
       
	clearpass_log( "aruba remove result: ". $result['body']  );

	return $host_id;
}

function clearpass_log( $text ){
    	$dolog = read_config_option('clearpass_log_debug');
	if( $dolog ) cacti_log( $text, false, "CLEARPASS" );
}

?>
