//! The UDP-multicast fake radio, wearing a ULCP device's clothes.
//!
//! [`umsh::tokio_support::UdpMulticastRadio`] is the simulated PHY the
//! desktop examples share: raw UMSH frames on an IPv4 multicast group,
//! no framing, no measurements. Bridging it needs two things a real
//! device gives for free — receive metadata, which is synthesized from
//! configured values, and the `poll`-shaped receive the relay loop
//! polls alongside its transmit queue.
//!
//! It is for developing and demonstrating a bridge without hardware or
//! airtime. Nothing about it is a transport the spec knows.

use std::net::Ipv4Addr;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use umsh::tokio_support::UdpMulticastRadio;
use umsh::ulcp::{RawRxFrame, UlcpError};
use umsh_hal::{CadPolicy, Radio, TxError, TxOptions};
use umsh_ulcp::meta::RxMeta;

pub struct UdpFakeRadio {
    inner: UdpMulticastRadio,
    /// Pre-encoded receive metadata: every reception reports the same
    /// synthesized signal quality, because UDP measures none.
    metadata: Vec<u8>,
    buf: Vec<u8>,
}

impl UdpFakeRadio {
    pub async fn bind(group: Ipv4Addr, port: u16, rssi: i16, snr: i8) -> Result<Self> {
        let inner = UdpMulticastRadio::bind_v4(group, port)
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))
            .with_context(|| format!("joining the multicast group {group}:{port}"))?;

        let mut metadata = [0u8; RxMeta::WIRE_LEN];
        RxMeta {
            rssi_dbm: Some(rssi),
            lqi: None,
            snr_cb: Some(i16::from(snr) * 10),
        }
        .encode(&mut metadata)
        .expect("buffer sized with WIRE_LEN");

        let buf = vec![0u8; inner.max_frame_size()];
        Ok(Self {
            inner,
            metadata: metadata.to_vec(),
            buf,
        })
    }

    pub fn max_frame_size(&self) -> usize {
        self.inner.max_frame_size()
    }

    pub fn poll_receive_raw(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<RawRxFrame, UlcpError>> {
        match self.inner.poll_receive(cx, &mut self.buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(info)) => Poll::Ready(Ok(RawRxFrame {
                data: self.buf[..info.len].to_vec(),
                metadata: self.metadata.clone(),
            })),
            Poll::Ready(Err(error)) => Poll::Ready(Err(UlcpError::Io(std::io::Error::other(
                format!("{error:?}"),
            )))),
        }
    }

    /// The transmit metadata is discarded: a simulated PHY has no power
    /// setting to override and no channel to assess.
    pub async fn transmit_raw_with_meta(
        &mut self,
        data: &[u8],
        _metadata: &[u8],
    ) -> Result<(), TxError<UlcpError>> {
        self.inner
            .transmit(
                data,
                TxOptions {
                    cad: CadPolicy::Skip,
                },
            )
            .await
            .map_err(|error| {
                TxError::Io(UlcpError::Io(std::io::Error::other(format!("{error:?}"))))
            })
    }
}
