 # NetBIOS name suffixes

 The one-byte suffix field identifies the service type registered under a
 NetBIOS name. These are the widely-used Microsoft values (see MS-NBTE).

 ## Unique names (registered per host)

 | Constant | Value | Service |
 |----------|-------|---------|
 | `WORKSTATION` | `0x00` | Workstation service (redirector) |
 | `MESSENGER` | `0x03` | Messenger service — identifies the logged-in user |
 | `RAS_SERVER` | `0x06` | Remote Access Server |
 | `DOMAIN_MASTER` | `0x1B` | Domain master browser |
 | `DOMAIN_CONTROLLER` | `0x1C` | Domain controller |
 | `MASTER_BROWSER` | `0x1D` | Local master browser |
 | `FILE_SERVER` | `0x20` | File and print server (Server service) |
 | `RAS_CLIENT` | `0x21` | Remote Access client |

 ## Group names (registered by multiple hosts)

 | Constant | Value | Service |
 |----------|-------|---------|
 | `BROWSER_ELECTIONS` | `0x1E` | Browser elections |
## Index


### Constants

| Name | Value |
| ---- | ----- |
| BROWSER_ELECTIONS | `(u8)0x1e` |
| DOMAIN_CONTROLLER | `(u8)0x1c` |
| DOMAIN_MASTER | `(u8)0x1b` |
| FILE_SERVER | `(u8)0x20` |
| MASTER_BROWSER | `(u8)0x1d` |
| MESSENGER | `(u8)0x03` |
| RAS_CLIENT | `(u8)0x21` |
| RAS_SERVER | `(u8)0x06` |
| WORKSTATION | `(u8)0x00` |
