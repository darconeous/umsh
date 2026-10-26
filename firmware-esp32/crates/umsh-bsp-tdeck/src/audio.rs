//! I2S TX wiring to the MAX98357A speaker amplifier (§13): BCLK GPIO7, WS
//! GPIO5, DOUT GPIO6, and no MCLK, which the amplifier does not take. It
//! has no control lines and is powered whenever V3V is, so silence is the
//! clocks stopped. Borrow peripheral tokens so dropping TX releases clocks
//! and HAL power guards; ownership returns to the idle sound task without
//! stealing.
use esp_hal::{
    Async,
    i2s::master::{Channels, DataFormat, I2s, I2sTx, TdmConfig},
    peripherals::{DMA_CH1, GPIO5, GPIO6, GPIO7, I2S0},
    time::Rate,
};

pub fn transmitter<'a>(
    i2s: I2S0<'a>,
    dma: DMA_CH1<'a>,
    bclk: GPIO7<'a>,
    ws: GPIO5<'a>,
    dout: GPIO6<'a>,
) -> I2sTx<'a, Async> {
    let i2s = I2s::new(
        i2s,
        dma,
        TdmConfig::new_tdm_philips()
            .with_sample_rate(Rate::from_hz(16_000))
            .with_data_format(DataFormat::Data16Channel16)
            .with_channels(Channels::STEREO),
    )
    .expect("fixed T-Deck I2S configuration")
    .into_async();
    // Drop the unused RX creator too; it also owns a peripheral guard.
    drop(i2s.i2s_rx);
    i2s.i2s_tx
        .with_bclk(bclk)
        .with_ws(ws)
        .with_dout(dout)
        .build()
}
