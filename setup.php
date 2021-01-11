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


function plugin_efficientip_install () {
	api_plugin_register_hook('efficientip', 'config_settings', 'efficientip_config_settings', 'setup.php');
	api_plugin_register_hook('efficientip', 'api_device_new', 'efficientip_api_device_new', 'setup.php');
	api_plugin_register_hook('efficientip', 'utilities_action', 'efficientip_utilities_action', 'setup.php'); // add option to check if device exist or need to be added
	api_plugin_register_hook('efficientip', 'utilities_list', 'efficientip_utilities_list', 'setup.php');

// Device action
    api_plugin_register_hook('efficientip', 'device_action_array', 'efficientip_device_action_array', 'setup.php');
    api_plugin_register_hook('efficientip', 'device_action_execute', 'efficientip_device_action_execute', 'setup.php');
    api_plugin_register_hook('efficientip', 'device_action_prepare', 'efficientip_device_action_prepare', 'setup.php');

}

function plugin_efficientip_uninstall () {
	// Do any extra Uninstall stuff here

}

function plugin_efficientip_check_config () {
	// Here we will check to ensure everything is configured
	efficientip_check_upgrade();

	return true;
}

function plugin_efficientip_upgrade () {
	// Here we will upgrade to the newest version
	efficientip_check_upgrade();
	return false;
}

function efficientip_check_upgrade() {
	global $config;

	$version = plugin_efficientip_version ();
	$current = $version['version'];
	$old     = db_fetch_cell('SELECT version
		FROM plugin_config
		WHERE directory="efficientip"');

	if ($current != $old) {

		// Set the new version
		db_execute("UPDATE plugin_config SET version='$current' WHERE directory='efficientip'");
		db_execute("UPDATE plugin_config SET 
			version='" . $version['version'] . "', 
			name='"    . $version['longname'] . "', 
			author='"  . $version['author'] . "', 
			webpage='" . $version['homepage'] . "' 
			WHERE directory='" . $version['name'] . "' ");

	}
}

function plugin_efficientip_version () {
	global $config;
	$info = parse_ini_file($config['base_path'] . '/plugins/efficientip/INFO', true);
	return $info['info'];
}


function efficientip_utilities_list () {
	global $colors, $config;
	html_header(array("efficientip Plugin"), 4);
	form_alternate_row();
	?>
		<td class="textArea">
			<a href='utilities.php?action=efficientip_check'>Check if devices are on EfficientIP.</a>
		</td>
		<td class="textArea">
			Check all devices to check if they are on EfficientIP, if not add it.
		</td>
	<?php
	form_end_row();
}

function efficientip_utilities_action ($action) {
	global $item_rows;
	
	if ( $action == 'efficientip_check' ){
		if ($action == 'efficientip_check') {
	// get device list,  where serial number is empty, or type
			$dbquery = db_fetch_assoc("SELECT * FROM host 
			WHERE (serial_no is NULL OR type IS NULL OR serial_no = '' OR type = '')
			AND status = '3' AND disabled != 'on'
			AND snmp_sysDescr LIKE '%cisco%'
			ORDER BY id");
		// Upgrade the efficientip value
			if( $dbquery > 0 ) {
				foreach ($dbquery as $host) {
					update_sn_type( $host );
				}
			}
		}
		top_header();
		utilities();
		bottom_footer();
	} 
	return $action;
}

function efficientip_config_settings () {
	global $tabs, $settings;
	$tabs["misc"] = "Misc";

	if (isset($_SERVER['PHP_SELF']) && basename($_SERVER['PHP_SELF']) != 'settings.php')
		return;

	$tabs['misc'] = 'Misc';
	$temp = array(
		"efficientip_general_header" => array(
			"friendly_name" => "EfficientIP",
			"method" => "spacer",
			),
		'efficientip_useipam' => array(
			'friendly_name' => 'Use the EfficientIP netchange ?',
			'description' => 'Fill EfficientIP Netchange product when a host is added.',
			'method' => 'checkbox',
			'default' => 'off'
			),
		"efficientip_url" => array(
			"friendly_name" => "URL of the EfficientIP server",
			"description" => "URL of the EfficientIP server.",
			"method" => "textbox",
			"max_length" => 80,
			"default" => ""
			), 
		'efficientip_log_debug' => array(
			'friendly_name' => 'Debug Log',
			'description' => 'Enable logging of debug messages during EfficientIP exchange',
			'method' => 'checkbox',
			'default' => 'off'
			)
	);
	
	if (isset($settings['misc']))
		$settings['misc'] = array_merge($settings['misc'], $temp);
	else
		$settings['misc']=$temp;
}

function efficientip_check_dependencies() {
	global $plugins, $config;

	return true;
}

function efficientip_device_action_array($device_action_array) {
    $device_action_array['check_efficentip'] = __('Check if device is on EfficiantIP netmange');
        return $device_action_array;
}

function efficientip_device_action_execute($action) {
   global $config;
   if ($action != 'check_efficentip' ) {
           return $action;
   }

   $selected_items = sanitize_unserialize_selected_items(get_nfilter_request_var('selected_items'));

	if ($selected_items != false) {
		if ($action == 'check_efficentip' ) {
			foreach( $selected_items as $hostid ) {
				if ($action == 'check_efficentip') {
					$dbquery = db_fetch_assoc("SELECT serial_no, description  FROM host WHERE id=".$hostid);
efficientip_log("Fill efficientip value: ".$hostid." - ".print_r($dbquery[0])." - ".$dbquery[0]['description']."\n");
				}
			}
		}
    }

	return $action;
}

function efficientip_device_action_prepare($save) {
    global $host_list;

    $action = $save['drp_action'];

    if ($action != 'check_efficentip' ) {
		return $save;
    }

    if ($action == 'check_efficentip' ) {
		$action_description = 'Check if device is on EfficiantIP netmange';
			print "<tr>
                    <td colspan='2' class='even'>
                            <p>" . __('Click \'Continue\' to %s on these Device(s)', $action_description) . "</p>
                            <p><div class='itemlist'><ul>" . $save['host_list'] . "</ul></div></p>
                    </td>
            </tr>";
    }
	return $save;
}

function efficientip_api_device_new( $host_id ) {
    cacti_log('Enter IPAM', false, 'EFFICIENTIP' );
	
	$useipam = read_config_option("efficientip_useipam");
	
	// if device is disabled, or snmp has nothing, don't save on IPAM
	if( array_key_exists('disabled', $host_id) && array_key_exists('snmp_version', $host_id) && array_key_exists('id', $host_id) ) {
		if ($host_id['disabled'] == 'on' || $host_id['snmp_version'] == 0 ) {
			efficientip_log('don t use IPAM: '.$host_id['description'] );
			cacti_log('End IPAM', false, 'EFFICIENTIP' );
			return $host_id;
		}
	} else {
		efficientip_log('Recu: '. print_r($host_id, true) );
		efficientip_log('field don t exist: '.$host_id['description']);
		cacti_log('End IPAM', false, 'EFFICIENTIP' );
		return $host_id;
	}
	
	if( $useipam ){
		$result = efficientip_check_exist( $host_id );
		
		// device does not exist
		if( !$result ) {
			// add device to IPAM
			efficientip_log( "Device not on IPAM: ". $host_id['description'] );	
			efficientip_add_device( $host_id );
		}
	}
    cacti_log('End IPAM', false, 'EFFICIENTIP' );
	
	return $host_id;
}

function efficientip_check_exist( $host_id ){
	$ipamurl = read_config_option("linkdiscovery_ipam_url");
	
	// check if device allready exist, if so continue if not add it.
	// https://ipam.lausanne.ch/rest/iplnetdev_list?WHERE=iplnetdev_name%20LIKE%20%27SE-CH9-40%25%27
	$url = $ipamurl . "/rest/iplnetdev_list?WHERE=iplnetdev_name%20LIKE%20%27".$host_id["description"]."%25%27";
	
    $handle = curl_init();
	curl_setopt( $handle, CURLOPT_URL, $url );
	curl_setopt( $handle, CURLOPT_POST, false );
	curl_setopt( $handle, CURLOPT_HEADER, true );
	curl_setopt( $handle, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $handle, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $handle, CURLOPT_HTTPHEADER, array( 'X-IPM-Username:c19jYWN0aW5ldHdvcmthZG0=', 'X-IPM-Password:VU5BVzJtM3NGRis5dVN6WmY=','Content-Type:application/json; charset=UTF-8','cache-control:no-cache') );

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

	efficientip_log( "ipam Return: ". print_r($result, true)  );
	$ret = true;   
    if ( $result['http_code'] > "299" ) {
		efficientip_log( "ipam URL: ". $url );
        $result['curl_error'] = $error;
		efficientip_log( "ipam error: ". print_r($result, true)  );
    } else if( $result['http_code'] == "204" ) {
		$ret = false;
	} else efficientip_log( "Device on IPAM: ". $host_id['description']. ' ('.$result['http_code'].')' );	

   
	curl_close($handle);

	return $ret;
}

function efficientip_add_device( $host_id ){
	//$host_id["hostname"] do a nslook if necessary
	$ip = gethostbyname($host_id["hostname"]);
	if( $host_id['snmp_version'] == 3 ){
		$snmp_profile = 5;
	} else {
		$snmp_profile = 4;
	}
	//https://ipam.lausanne.ch/rpc/iplocator_ng_import_device.php?hostaddr=$host_id&site_id=4&snmp_profile_id=5
	$ipamurl = read_config_option("linkdiscovery_ipam_url");
	$url = $ipamurl . "/rpc/iplocator_ng_import_device.php?hostaddr=". $ip ."&site_id=4&snmp_profile_id=". $snmp_profile;
	
	$handle = curl_init();
	curl_setopt( $handle, CURLOPT_URL, $url );
	curl_setopt( $handle, CURLOPT_POST, true );
	curl_setopt( $handle, CURLOPT_HEADER, true );
	curl_setopt( $handle, CURLOPT_SSL_VERIFYPEER, false );
	curl_setopt( $handle, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $handle, CURLOPT_HTTPHEADER, array( 'X-IPM-Username:c19jYWN0aW5ldHdvcmthZG0=', 'X-IPM-Password:VU5BVzJtM3NGRis5dVN6WmY=','Content-Type:application/json; charset=UTF-8','cache-control:no-cache') );

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
		$result['curl_error'] = $error;
		efficientip_log( "ipam URL: ". $url );
		efficientip_log( "ipam error: ". print_r($result, true)  );
	}

	curl_close($handle);
}

function efficientip_log( $text ){
    	$dolog = read_config_option('efficientip_log_debug');
	if( $dolog ) cacti_log( $text, false, "EFFICIENTIP" );
}

?>
