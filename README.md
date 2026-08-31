# Zabbix-Disclosure-Reference
This repo contains disclosure details and timeline about my latest released vulnerability, IPMEye
CVSS String: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:H = 8.5


# Technical Analysis

I started with a black-box approach as usual. While analyzing the web interface I noticed that auto-complete fields and dropdown menus communicate with the jsrpc.php endpoint. One request to that endpoint triggered my senses. That request used the multiselect.get method and passed a filter array to search for hostnames. when reviewing vjsrpc.php, I saw this code:

method=multiselect.get&object_name=hosts&filter[name]=Zabbix

Following a classic offensive code review instinct, I wondered: how does the backend validate this input? And this was the point I decided to dive into the source code, right to the point where API constructs SQL queries from the user input. I discovered that Zabbix relies on a massive, centralized database schema array (found in schema.inc.phpor returned byDB::getSchema()). This array maps every table and column in the application. Here is the exact schema for the hosts table:

```
// Snippet from Zabbix Database Schema
'hosts' => [
    'key' => 'hostid',
    'fields' => [
        'hostid' => [
            'null' => false, 'type' => DB::FIELD_TYPE_ID, 'length' => 20
        ],
        'host' => [
            'null' => false, 'type' => DB::FIELD_TYPE_CHAR, 'length' => 128
        ],
        // ... [snip] ...
        
        // THE JUICY OTHER TARGETS (columns)
        'ipmi_password' => [
            'null' => false,
            'type' => DB::FIELD_TYPE_CHAR,
            'length' => 20,
            'default' => ''
        ],
        'tls_psk' => [
            'null' => false,
            'type' => DB::FIELD_TYPE_CHAR,
            'length' => 512,
            'default' => ''
        ],
        // ... [snip] ...
    ]
]
```


When the dbFilter() function processes the filterarray user input, it acts as a gatekeeper. However, its only job is to check if the provided column name exists in the schema array defined above. So when I send filter[ipmi_password]=someting, backend logic does the following:
`
    “Does the hosts table exist? Yes.”
    “Does the ipmi_password column exist in the schema for the hoststable? Yes.”
    “Does the user have read access to this host? Yes.” (As a low-privileged monitoring user, you are only allowed to see the host’s basic stats like CPU/RAM usage).
`
And as you can see, there is no access control in columns. I mean, the application never asks “Is this user authorized to query the ipmi_passwordcolumn?”

It perfectly escapes the input, preventing SQL injection and appends it to the WHERE clause. Because the API strips out sensitive fields from the final JSON response using unsetExtraFields. So I wasn’t able to read the password in the response body. But this is not how it ends.

I tried to put some password guesses into the filter array, filter[ipmi_password]=guess and the response became a true/false indicator. If it returns the host ID, that means true. If it returns an empty array, that means false. So, just like that, an innocent auto-complete endpoint turned into a data exfiltration point.

# PoC

1. Edit a monitored host as an admin and set an IPMI password.
2. Login as a low-privilege user that has read permissions for the host’s group.
3. Send the following POST request. Content-Type:application/x-www-form-urlencoded is enforced in order to bypass the JSON parameter validations. Otherwise, response will always be empty.

```
POST /zabbix/jsrpc.php?type=11 HTTP/1.1
Host: <ZABBIX_HOST>
Content-Type: application/x-www-form-urlencoded 
Cookie: zbx_session=<LOW_PRIV_SESSION_COOKIE>

method=multiselect.get&object_name=hosts&filter[ipmi_password]=<password attempt>
```

4. Response Behavior:
   - True Response Example: {"jsonrpc":"2.0","result":[{"name":"Zabbix server","id":"10084"}]}
   - False Response Example: {"jsonrpc":"2.0","result":[]}

# Disclosure Timeline

April 17, 2026: Vulnerability has been submitted through Zabbix's BBP on HackerOne.
April 28, 2026: CVSS score has been lowered by the Zabbix staff, telling me subsequent systems are out of scope in their program. Paid me their medium severity price.

Then I tried to get information about the fix and the CVE for months. They said the same things such as "AI wave made it harder, etc." everytime. 

August 23, 2026: I wanted to retest my vulnerability in the Latest version of the Zabbix and saw that they fixed it silently.

August 24, 2026: Since they fixed it, I made the vulnerability public. 
