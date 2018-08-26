# openvpn-sso-portal

WIP 

The portal handles generating OpenVPN configs with embeded client certificates.  This allows you to:
- Hand out expiring configs.
- Push routes to clients.
- Firewall rules per profile.

Requires 
- A reverse proxy that handles SSO.
- An OpenVPN Server configured to pick-up rules.

Example config below.  Helm Chart should contain a fully working solution.

```
    listen: :8081
    host: localhost
    port: 1194
    banner: Secureweb VPN Portal
    logout-url: https://google.co.uk
    help-url: https://github.com/secureweb/openvpn-sso-portal/issues
    fullname-header: X-Auth-Fullname
    username-header: X-Auth-Username
    roles-header: X-Auth-Roles
    ca-certificate-file: tmp/ca/ca.pem
    ca-private-file: tmp/ca/ca-key.pem
    configdir-enabled: true
    configdir-path: tmp/profiles
    profiles:
    - name: livedata
      description: Live Data
      max-session: 2h
      roles:
        - vpn-livedata
      routes:
        - route: 192.168.1.0
          netmask: 255.255.255.0
      rules:
        - dest: 192.168.1.0/24
          port: 53
          protocol: tcp
          action: ACCEPT
    - name: notlivedata
      description: Not Live Data
      max-session: 8h
      roles:
        - vpn-notlivedata
      routes:
        - route: 172.16.0.0
          netmask: 255.255.255.0
      rules:
        - dest: 172.16.0.0/16
          port: 53
          protocol: udp
          action: ACCEPT

    template: |
      #
      # Expiration of Certificate: {{ .Session.ExpiresOn }}
      # Session Duration: {{ .Session.Duration }}
      # VPN Profile for: {{ .Session.Profile }}
      #

      client
      dev tun
      proto tcp
      remote {{ .Session.Hostname }} {{ .Session.Port }}
      resolv-retry infinite
      remote-cert-tls server
      nobind
      tls-version-min 1.2
      persist-key
      persist-tun
      ca [inline]
      cert [inline]
      key [inline]
      verb 1
      keepalive 10 900
      inactive 3600
      cipher AES-256-CBC
      tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256

      <ca>
      {{ .Session.IssuingCA }}</ca>

      <cert>
      {{ .Session.Certificate }}</cert>

      <key>
      {{ .Session.PrivateKey }}</key>
```
