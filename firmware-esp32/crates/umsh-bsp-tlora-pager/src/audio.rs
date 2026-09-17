//! I2S TX wiring. Borrow peripheral tokens so dropping TX releases clocks and
//! HAL power guards; ownership returns to the idle alert task without stealing.
use esp_hal::{
    Async,
    i2s::master::{Channels, DataFormat, I2s, I2sTx, TdmConfig},
    peripherals::{DMA_CH1, GPIO10, GPIO11, GPIO18, GPIO45, I2S0},
    time::Rate,
};

pub fn transmitter<'a>(
    i2s: I2S0<'a>,
    dma: DMA_CH1<'a>,
    mclk: GPIO10<'a>,
    bclk: GPIO11<'a>,
    ws: GPIO18<'a>,
    dout: GPIO45<'a>,
) -> I2sTx<'a, Async> {
    let i2s = I2s::new(
        i2s,
        dma,
        TdmConfig::new_tdm_philips()
            .with_sample_rate(Rate::from_hz(16_000))
            .with_data_format(DataFormat::Data16Channel16)
            .with_channels(Channels::STEREO),
    )
    .expect("fixed Pager I2S configuration")
    .with_mclk(mclk)
    .into_async();
    // Drop the unused RX creator too; it also owns a peripheral guard.
    drop(i2s.i2s_rx);
    i2s.i2s_tx
        .with_bclk(bclk)
        .with_ws(ws)
        .with_dout(dout)
        .build()
}
