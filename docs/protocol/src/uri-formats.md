# URI Formats

UMSH defines URI forms for nodes, channels, and CoAP resources.

## Node URIs

Nodes are identified by their 32-byte public key encoded in Base58.

Example:

```text
umsh:n:HJC9DJaaQEn88tAzbMM7BrYbsepNEB69RK1gZiKEYCPp
```

Node identity information may optionally be appended after a colon, encoded in a suitable representation of the identity structure and optional signature.

Example:

```text
umsh:n:HJC9DJaaQEn88tAzbMM7BrYbsepNEB69RK1gZiKEYCPp:Rgx5U993cN52iHc9rPEFPpLTB66o2JLaDvSpCxmhPdReNd3QtrYcyrACdWV89L1xfZPJz4rZGeHX9BypGtDDYJXbDrWKJZixp9A8d3qcDNFq
```

This allows a node identity bundle to be embedded in a QR code.

## Channel URIs

Internally, channels are identified by a 16-byte shared key.

Example direct-key URI:

```text
umsh:ck:J9axNdS22exxS8H9C8nj7w
```

Additional metadata may be attached as URI parameters:

```text
umsh:ck:J9axNdS22exxS8H9C8nj7w?n=MyPrivateChannel;mh=6;r=Eugine
```

Where, for example:

- `n` = channel name
- `mh` = recommended maximum flood hops
- `r` = recommended region

A channel may also be identified by a string from which the channel key is derived:

```text
umsh:cs:Public
```

## CoAP-over-UMSH URIs

CoAP resources on a node use the `coap-umsh` scheme, with the node public key as the authority component.

Example:

```text
coap-umsh://HJC9DJaaQEn88tAzbMM7BrYbsepNEB69RK1gZiKEYCPp/data/1
```
