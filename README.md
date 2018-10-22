Notakey module for SimpleSAMLphp
=============

- Needs configuration in authsources listing all backends enabled
```
	'notakey-auth' => array(
        'notakey:Process',
                'endpoints' => array(
					array(
    							'name' => "Swisscom",
    							'api' => 'https://core1.fid.notakey.com/api/v2/application/c497894f-94d4-4354-bdc8-406888b5a616',
    							'service_logo' => 'https://core1.fid.notakey.com/_cimg/8c0b4f63-c1e9-4d1c-990e-8fc72740791c',

    					),

	    				array(
	    						'name' => "UBS",
	    						'api' => 'https://core1.fid.notakey.com/api/v2/application/ed7bb511-7f4c-406b-b15f-c9b1ccfc1541',
	    						'service_logo' => 'https://core1.fid.notakey.com/_cimg/2bcc897f-20ef-477b-b22d-18ad24a0424b',

	    				),
	    				array(
	    						'name' => "Credit Suisse",
	    						'api' => 'https://core1.fid.notakey.com/api/v2/application/b6269c6b-9315-41de-8cf2-fb270ff4f8af',
	    						'service_logo' => 'https://core1.fid.notakey.com/_cimg/4d003b23-61aa-4b22-bd17-1d92bfe75dd5',

	    				),
		)
    ),
```