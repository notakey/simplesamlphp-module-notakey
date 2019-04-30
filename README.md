# Notakey module for SimpleSAMLphp

## Configuration 

### Authsource

Needs configuration in authsources listing all allowed backends

```
'notakey-auth' => array(
        'notakey:Process',
		// if username remember me is enabled 
		// remove domain from username when remembering 
		"attrs.stripdomain" =>  false,
		// the attribute to populate username
    	 	"user_id.attr" =>  "uid",
		// enable additional logging 
    	 	"debug" =>  true,
		// multiple endpints are possible (Notakey services) 
		// user will have option to select one during authentication
                'endpoints' => array(
					array(
    							'name' => "Notakey service 1",
    							'url' => 'https://core1.fid.notakey.com/',
    							'service_id' => '8c0b4f63-c1e9-4d1c-990e-8fc72740791c',
							'service_logo' => 'https://core1.fid.notakey.com/_cimg/8c0b4f63-c1e9-4d1c-990e-8fc72740791c',

    					),

	    				array(
	    						'name' => "Notakey service 2",
	    						'url' => 'https://core1.fid.notakey.com/',
	    						'service_id' => '2bcc897f-20ef-477b-b22d-18ad24a0424b',
							'service_logo' => 'https://core1.fid.notakey.com/_cimg/8c0b4f63-c1e9-4d1c-990e-8fc72740791c',

	    				),
	    				array(
	    						'name' => "Notakey service 3",
	    						'url' => 'https://core1.fid.notakey.com/',
	    						'service_id' => '4d003b23-61aa-4b22-bd17-1d92bfe75dd5',
							'service_logo' => 'https://core1.fid.notakey.com/_cimg/8c0b4f63-c1e9-4d1c-990e-8fc72740791c',

	    				),
		)
    )
```


### Filter mode

Filter configuration is possible as well, in this case user will pass primary authentication once (e.g. use password) and then prompted for  authentication with mobile.
In sequential logins on other SPs only mobile authentication will be verified. 


In base config:

```
"authproc.idp" => array(
	"90" => array(
				"class" => "notakey:Filter",
				"user_id.attr" => "uid",
				"debug" => true,
				"endpoints" => [
					array(
						'name' => "Notakey service 1",
                                                'service_logo' => 'https://core1.fid.notakey.com/_cimg/8c0b4f63-c1e9-4d1c-990e-8fc72740791c',
						"url" => "https://core1.fid.notakey.com/",
						"service_id" => "235879a9-a3f3-42b4-b13a-4836d0fd3bf8",
					)
				  ]
			 }

```
