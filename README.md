# Notakey module for SimpleSAMLphp
=============

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
                            'name' => 'Notakey service 1',
                            'url' => 'https://api.mydomain.com/',
                            'service_id' => '8c0b4f63-c1e9-4d1c-990e-12312312312',
                            'client_id' => 'api-client-id',
                            'client_secret' => 'client-secret',
                            'service_logo' => '/userlogos/8c0b4f63-c1e9-4d1c-990e-8fc72740791c.png'
                        ),
                    array(
                            'name' => 'Notakey service 2',
                            'url' => 'https://api.mydomain.com/',
                            'service_id' => '8c0b4f63-c1e9-4d1c-990e-892746367623',
                            'client_id' => 'api-client-id',
                            'client_secret' => 'client-secret',
                            'service_logo' => '/userlogos/8c0b4f63-c1e9-4d1c-990e-8fc72740791c.png'
                        )
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

Notakey Authentication appliance
---------------------

If running in NAA environment configure using cli.

- As primary authentication source:

```
    ntk cfg :sso.auth '{
        "notakey-nopass": {
            "module": "notakey:Process",
            "endpoints": [
                {
                    "name": "Notakey",
                    "url": "https://mfa.mydomain.com/",
                    "service_id": "bcd05d09-40cb-4965-8d94-3142546576",
                    "client_id": "api-client-id",
                    "client_secret": "client-secret",
                    "service_logo": "/userlogos/somelogo.png"
                },
                -- define multiple if needed (e.g. using multiple services, one for internal users, another for externals)
            ]
        }' --json-input
```

- As additional factor to primary authentication:

```
    ntk cfg :sso.base.\"authproc.idp\".\"90\" '{
        "class": "notakey:Filter",
        -- this defines which attribute stores users username as it will be sent to Notakey API, defaults to sAMAccountName
        "user_id.attr": "uid",
        -- disables domain showing to user, if it is present in Notakey API response
        "attrs.stripdomain": false,
        "debug": true,
        "endpoints": [
            {
                "name": "Notakey",
                "url": "https://mfa.mydomain.com/",
                "service_id": "bcd05d09-40cb-4965-8d94-3142546576",
                "client_id": "api-client-id",
                "client_secret": "client-secret",
                "service_logo": "/userlogos/somelogo.png"
            },
            -- define multiple if needed (e.g. using multiple services, one for internal users, another for externals)
        ]
    }' --json-input
```

- Enables this module
```
    ntk cfg :sso.modules '[..., "notakey"]' --json-input
```