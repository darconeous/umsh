//! The firmware's TLS provider against the production bridge server verifier.
use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::{Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use umsh_bridge::{
    identity::BridgeIdentity,
    tls::{self, Address, Credential},
};
use umsh_bridge_client::{ALPN, tls::IdentityProvider};

async fn handshake(wrong_pin: bool, unauthorized: bool, wrong_alpn: bool, omit_alpn: bool) -> bool {
    let server = BridgeIdentity::from_seed(&[0x11; 32]);
    let device = BridgeIdentity::from_seed(&[0x22; 32]);
    let credential = Credential::for_identity(&server).unwrap();
    let accepted = if unauthorized {
        vec![]
    } else {
        vec![Address(*device.public_key())]
    };
    let mut config = (*tls::server_config(&credential, accepted).unwrap()).clone();
    if wrong_alpn {
        config.alpn_protocols = vec![b"other/1".to_vec()];
    }
    if omit_alpn {
        config.alpn_protocols.clear();
    }
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    // Force both handshake and application records through fragmented I/O.
    let (client, server_io) = tokio::io::duplex(97);
    let expected = *device.public_key();
    let server_task = tokio::spawn(async move {
        let Ok(mut stream) = acceptor.accept(server_io).await else {
            return false;
        };
        let (_, connection) = stream.get_ref();
        assert_eq!(
            connection.alpn_protocol(),
            if omit_alpn { None } else { Some(ALPN) }
        );
        assert_eq!(
            tls::certificate_key(&connection.peer_certificates().unwrap()[0])
                .unwrap()
                .0,
            expected
        );
        let mut bytes = [0; 4];
        if stream.read_exact(&mut bytes).await.is_err() {
            return false;
        }
        assert_eq!(&bytes, b"UMSH");
        stream.write_all(b"OK").await.unwrap();
        // A standard-size incoming TLS record must fit even though decoded
        // tunnel bodies have a much smaller independent bound.
        stream.write_all(&[0x7e; 16 * 1024]).await.unwrap();
        stream.flush().await.unwrap();
        true
    });
    let pin = if wrong_pin {
        device.public_key()
    } else {
        server.public_key()
    };
    let mut provider =
        IdentityProvider::new(&[0x22; 32], &pin.0, ChaCha20Rng::from_seed([0x33; 32])).unwrap();
    assert_eq!(provider.public_key(), device.public_key().0);
    let mut read = [0; 18 * 1024];
    let mut write = [0; 4096];
    let mut connection =
        TlsConnection::<_, Aes128GcmSha256>::new(FromTokio::new(client), &mut read, &mut write);
    let config = TlsConfig::new().with_alpn(&[ALPN]);
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        connection
            .open(TlsContext::new(&config, &mut provider))
            .await?;
        if !provider.authenticated() {
            return Err(embedded_tls::TlsError::InvalidSignature);
        }
        connection.write(b"UMSH").await?;
        connection.flush().await?;
        let mut answer = [0; 2];
        let mut used = 0;
        while used < answer.len() {
            let n = connection.read(&mut answer[used..]).await?;
            assert!(n > 0);
            used += n;
        }
        assert_eq!(&answer, b"OK");
        let mut total = 0;
        let mut flags = [0; 512];
        while total < 16 * 1024 {
            let n = connection.read(&mut flags).await?;
            assert!(n > 0);
            assert!(flags[..n].iter().all(|byte| *byte == 0x7e));
            total += n;
        }
        Ok::<_, embedded_tls::TlsError>(())
    })
    .await;
    if !wrong_pin && !unauthorized && !wrong_alpn {
        assert!(
            result.as_ref().is_ok_and(|r| r.is_ok()),
            "embedded TLS exchange: {result:?}"
        );
    }
    drop(connection);
    let accepted = server_task.await.unwrap();
    result.is_ok_and(|r| r.is_ok()) && accepted
}

#[tokio::test]
async fn device_identity_authenticates_with_existing_server() {
    assert!(handshake(false, false, false, false).await);
}

#[tokio::test]
async fn wrong_server_pin_is_rejected() {
    assert!(!handshake(true, false, false, false).await);
}

#[tokio::test]
async fn unauthorized_device_is_rejected() {
    assert!(!handshake(false, true, false, false).await);
}

#[tokio::test]
async fn incompatible_alpn_is_rejected() {
    assert!(!handshake(false, false, true, false).await);
}

/// Documents upstream behavior: the protocol recommends offering ALPN but does
/// not require the client to reject an omitted server selection.
#[tokio::test]
async fn upstream_does_not_reject_an_omitted_alpn_selection() {
    assert!(handshake(false, false, false, true).await);
}
