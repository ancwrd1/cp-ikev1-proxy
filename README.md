# cp-ikev1-proxy

A MITM proxy which intercepts Check Point IKEv1/TCPT requests and dumps them to the debug output.
This is mainly a troubleshooting tool for the [snx-rs](https://github.com/ancwrd1/snx-rs) project.

## Usage

To get help with command-line parameters, use the `--help` option.

1. Build the proxy with `cargo build`
2. Run it as a root user: `sudo ./target/debug/cp-ikev1-proxy <vpn_server_address>`
3. In the Windows Check Point client, create a new VPN connection to the host where this proxy runs (make sure to open port 443 in the firewall)
4. Connect to the newly created connection
5. Collect the logs from the console

## Additional notes

* For certificate authentication, use the command line parameters `--cert-type`, `--cert-path` and `--cert-password`. 
 The provided certificate should match the one used by the upstream VPN client. 
* VPN protocol proxying is incomplete and the connection will eventually fail.


## License

Licensed under the [GNU Affero General Public License version 3](https://opensource.org/license/agpl-v3/).
