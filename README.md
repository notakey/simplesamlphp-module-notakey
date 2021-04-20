# Notakey module for SimpleSAMLphp

## Configuration

### Authsource

Needs configuration in authsources listing all allowed backends

```shell
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
            'service_logo' => '/userlogos/8c0b4f63-c1e9-4d1c-990e-8fc72740791c.png',
            // if using authentication profile, specify it here
            "profile_id" => "1231231-c1e9-4d1c-990e-12312312312",
            // Source name from authsources
            "stepup-source" =>  "ntk-radius",
            // Valid for 1 year
            "stepup-duration" => "P1Y"
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
                'name' => 'Notakey service 1',
                'url' => 'https://api.mydomain.com/',
                'service_id' => '8c0b4f63-c1e9-4d1c-990e-12312312312',
                'client_id' => 'api-client-id',
                'client_secret' => 'client-secret',
                'service_logo' => '/userlogos/8c0b4f63-c1e9-4d1c-990e-8fc72740791c.png'
            )
        ]
    )
)

```

### Customizing authentication requests

To customize authentication requests you can use authentication profiles.
These are configured in Notakey Autehntication Appliance administration dashboard for specific service.
This will allow use of localized authentication request messages according to user's language and to adjust authentication request timeout values and security requirements.

## Notakey Authentication Appliance

If running in NAA environment configure using cli.

- As primary authentication source:

```shell
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
                    "service_logo": "/userlogos/somelogo.png",
                    "profile_id": "bcd05d09-40cb-4965-8d94-3142546576" // if using authentication profile, specify it here
                },
                // define multiple if needed (e.g. using multiple services, one for internal users, another for external)
            ]
        }' --json-input
```

- As additional factor to primary authentication:

```shell
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
            -- define multiple if needed (e.g. using multiple services, one for internal users, another for external)
        ]
    }' --json-input
```

- Enables this module

```shell
    ntk cfg :sso.modules '[..., "notakey"]' --json-input
```
